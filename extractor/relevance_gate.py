"""Relevance gate for extracted entities (22R-4 and 22R-5).

Two plainly-wrong entity kinds are removed at extraction time, and each
removal is counted (the only removals the relevance tiers make):

* ``gazetteer_context``: a threat name that is also an ordinary English or
  technology word ("play", "royal", "tor", "php"; the list is
  data/ambiguous_threat_names.txt) typed as RANSOMWARE_GROUP, MALWARE_FAMILY
  or THREAT_ACTOR_HANDLE with no threat cue within about 8 tokens, on a page
  that is not directly about that same name.
* ``org_boilerplate``: an ORGANIZATION_NAME that is the page's own site or
  publisher name ("krebsonsecurity" on krebsonsecurity.com) or is on a short
  stoplist of protocols, CMSs and link-directory brands.

Agencies such as the FBI are never removed here; the entity tiers mark them
background unless they sit next to a direct match.

Deterministic, local, never calls the LLM. Never raises: a failure keeps the
entities as they were.
"""

from __future__ import annotations

import bisect
import json
import logging
import os
import re
import threading
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
AMBIGUOUS_PATH = os.path.join(_DATA_DIR, "ambiguous_threat_names.txt")
RELATIONS_PATH = os.path.join(_DATA_DIR, "threat_relations.json")
DICTIONARY_PATH = os.path.join(_DATA_DIR, "common_words_en.txt")

THREAT_TYPES = frozenset({"RANSOMWARE_GROUP", "MALWARE_FAMILY", "THREAT_ACTOR_HANDLE"})
CUE_WINDOW_TOKENS = 8

# Words that, near a name, say it is being used as a threat name.
THREAT_CUES = frozenset({
    "ransomware", "ransom", "group", "gang", "stealer", "infostealer", "malware", "loader",
    "botnet", "affiliate", "affiliates", "trojan", "backdoor", "apt", "extortion", "locker",
    "variant", "strain", "encryptor", "keylogger", "spyware", "wiper", "payload", "raas",
    "operators", "operator", "actor", "actors", "c2", "dropper", "rootkit", "worm",
})
THREAT_CUE_PHRASES = ("leak site", "threat actor", "data leak site", "leak blog")
# Case-sensitive cues: "RAT" is a cue, "rat" is an animal.
THREAT_CUES_EXACT = frozenset({"RAT", "RATs", "APT"})
# For handles, the structural phrases the handle extractor itself keys on.
HANDLE_CUES = frozenset({"posted", "user", "alias", "handle", "author", "nick", "nickname", "member", "vendor", "seller"})

# Technology, protocol and platform words. As threat names they are typed only
# when the query itself names them: "Android malware" or "PHP backdoor"
# describes a target platform, not a family called Android or PHP. Also the
# second input of scripts/build_relevance_data.py.
TECH_WORDS = frozenset("""
php tor android ios linux unix windows macos osx ubuntu debian centos redhat fedora
java javascript js python perl ruby golang rust kotlin swift scala lua bash powershell cmd
html css sql mysql postgres postgresql sqlite mongodb redis nginx apache iis tomcat
wordpress joomla drupal magento codeigniter laravel django flask nodejs node npm
chrome chromium firefox safari opera edge brave
google gmail youtube facebook instagram whatsapp telegram signal discord twitter tiktok
skype slack zoom teams outlook office excel word powerpoint onedrive dropbox github gitlab
amazon aws azure gcp cloudflare paypal bitcoin monero ethereum btc xmr eth usdt
vpn ssh ftp sftp smtp imap pop3 http https dns tls ssl rdp smb vnc irc xmpp tcp udp ip
api sdk cli gui ui ux url uri json xml yaml csv pdf zip rar exe dll apk ipa iso
oauth saml ldap kerberos ntlm jwt
ctf root admin login dev devops qa
""".split())

# 22R-5 stoplist: protocols, CMSs/frameworks, platforms and link-directory brands
# that spaCy labels ORG on almost any page. Compared on the alphanumeric key.
ORG_STOPLIST = frozenset({
    "oauth", "openid", "saml", "http", "https", "smtp", "tls", "ssl", "dns", "vpn", "rdp", "ssh",
    "tor", "torproject", "i2p",
    "wordpress", "joomla", "drupal", "codeigniter", "laravel", "django", "magento", "php",
    "nginx", "apache", "javascript", "jquery", "bootstrap",
    "onionland", "tordex", "megalinks", "torlib", "ahmia", "hiddenwiki", "thehiddenwiki",
    "darkfail", "torch", "haystak", "haystack", "excavator", "dargle", "onionlinks",
    "linkedin", "powerpoint", "telegram", "android", "github",
})

# Agencies: kept, but background unless next to a direct match (22R-5).
AGENCY_KEYS = frozenset({
    "fbi", "cisa", "nsa", "europol", "interpol", "doj", "departmentofjustice",
    "usdepartmentofjustice", "federalbureauofinvestigation", "ncsc", "nca",
    "nationalcrimeagency", "secretservice", "ussecretservice", "dhs",
    "departmentofhomelandsecurity", "homelandsecurity", "ofac", "treasury", "bka",
    "cybersecurityandinfrastructuresecurityagency", "ic3", "fincen", "eurojust",
})

_lock = threading.Lock()
_counts: dict[str, int] = {"gazetteer_context": 0, "org_boilerplate": 0}
_loaded: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def key(name: str) -> str:
    """Alphanumeric lower-case key (separators dropped), as the gazetteer uses."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _read_list(path: str) -> frozenset[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return frozenset(
                line.strip().lower() for line in fh if line.strip() and not line.startswith("#")
            )
    except FileNotFoundError:
        logger.warning("Relevance data file not found: %s", path)
        return frozenset()


def ambiguous_names() -> frozenset[str]:
    if "ambiguous" not in _loaded:
        _loaded["ambiguous"] = _read_list(AMBIGUOUS_PATH)
    return _loaded["ambiguous"]


def dictionary_words() -> frozenset[str]:
    if "dictionary" not in _loaded:
        _loaded["dictionary"] = _read_list(DICTIONARY_PATH)
    return _loaded["dictionary"]


def relations() -> dict[str, list[str]]:
    if "relations" not in _loaded:
        try:
            with open(RELATIONS_PATH, encoding="utf-8") as fh:
                _loaded["relations"] = json.load(fh)
        except (FileNotFoundError, ValueError):
            _loaded["relations"] = {}
    return _loaded["relations"]


def relations_of(name: str) -> list[str]:
    return list(relations().get(key(name), []))


def is_ambiguous(value: str, entity_type: str = "") -> bool:
    """True when *value* needs a threat cue to be typed as a threat name.

    The generated list covers gazetteer and dictionary names; a single
    dictionary word typed as ransomware or malware by another path (the LLM
    tier) is treated the same way.
    """
    k = key(value)
    if not k:
        return False
    if k in ambiguous_names():
        return True
    if entity_type in ("RANSOMWARE_GROUP", "MALWARE_FAMILY") and k.isalpha():
        return k in dictionary_words() and k not in _allow_override()
    return False


def _allow_override() -> frozenset[str]:
    if "allow" not in _loaded:
        _loaded["allow"] = _read_list(os.path.join(_DATA_DIR, "ambiguous_threat_names_allow.txt"))
    return _loaded["allow"]


# ---------------------------------------------------------------------------
# Counters (per run; the CLI runs one investigation per process)
# ---------------------------------------------------------------------------


def reset_counts() -> None:
    with _lock:
        for k in _counts:
            _counts[k] = 0


def removal_counts() -> dict[str, int]:
    with _lock:
        return dict(_counts)


def _count(kind: str, n: int = 1) -> None:
    with _lock:
        _counts[kind] = _counts.get(kind, 0) + n


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


class TokenIndex:
    """Token positions of a text, for cheap ``within N tokens`` checks."""

    def __init__(self, text: str):
        self.text = text or ""
        self.tokens: list[str] = []
        self.starts: list[int] = []
        for m in _TOKEN_RE.finditer(self.text):
            self.tokens.append(m.group(0))
            self.starts.append(m.start())

    def index_at(self, pos: int) -> int:
        return max(0, bisect.bisect_right(self.starts, pos) - 1)

    def window(self, start: int, end: int, n: int) -> tuple[list[str], str]:
        """Tokens within *n* tokens around [start, end), and that span's text."""
        if not self.tokens:
            return [], ""
        i = self.index_at(start)
        j = self.index_at(max(start, end - 1))
        lo, hi = max(0, i - n), min(len(self.tokens), j + n + 1)
        span_start = self.starts[lo]
        span_end = self.starts[hi - 1] + len(self.tokens[hi - 1])
        return self.tokens[lo:hi], self.text[span_start:span_end]


def name_pattern(name: str) -> Optional[re.Pattern]:
    """Token-bounded, case-insensitive pattern for *name* (separators flexible)."""
    parts = _TOKEN_RE.findall(name or "")
    if not parts:
        return None
    body = r"[\s\-_.]*".join(re.escape(p) for p in parts)
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.I)


def find_spans(text: str, name: str, limit: int = 50) -> list[tuple[int, int]]:
    pat = name_pattern(name)
    if pat is None or not text:
        return []
    out = []
    for m in pat.finditer(text):
        out.append(m.span())
        if len(out) >= limit:
            break
    return out


def has_cue(index: TokenIndex, span: tuple[int, int], name: str, entity_type: str) -> bool:
    tokens, window_text = index.window(span[0], span[1], CUE_WINDOW_TOKENS)
    lower = [t.lower() for t in tokens]
    own = {t.lower() for t in _TOKEN_RE.findall(name or "")}
    if any(t in THREAT_CUES and t not in own for t in lower):
        return True
    if any(t in THREAT_CUES_EXACT for t in tokens):
        return True
    wl = window_text.lower()
    if any(p in wl for p in THREAT_CUE_PHRASES):
        return True
    if entity_type == "THREAT_ACTOR_HANDLE" and any(t in HANDLE_CUES for t in lower):
        return True
    for rel in relations_of(name):
        if len(rel) >= 4 and name_pattern(rel) and name_pattern(rel).search(window_text):
            return True
    return False


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _intent_keys() -> frozenset[str]:
    """Keys of the current query's threat name and aliases (named_threat only)."""
    try:
        from voidaccess.relevance import current_intent
    except Exception:  # pragma: no cover - import guard
        return frozenset()
    intent = current_intent()
    if intent is None or intent.kind != "named_threat":
        return frozenset()
    return frozenset(key(a) for a in [*intent.terms, *intent.aliases] if key(a))


def keep_threat_name(
    value: str, entity_type: str, text: str, index: Optional[TokenIndex] = None
) -> bool:
    """22R-4: may *value* be typed as a threat name on a page with *text*?"""
    if entity_type not in THREAT_TYPES or not is_ambiguous(value, entity_type):
        return True
    if key(value) in _intent_keys():
        return True  # the page is direct for this same name
    if key(value) in TECH_WORDS:
        return False  # a platform word: only the query itself can make it a threat name
    spans = find_spans(text, value)
    if not spans:
        return False
    index = index or TokenIndex(text)
    return any(has_cue(index, s, value, entity_type) for s in spans)


def _host_keys(url: str) -> set[str]:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return set()
    labels = [l for l in host.split(".") if l]
    if labels and labels[0] == "www":
        labels = labels[1:]
    if not labels:
        return set()
    if labels[-1] == "onion":
        return set()  # a v3 address is not a brand; the title carries it
    core = labels[:-1] or labels
    keys = {key(l) for l in core if len(key(l)) >= 3}
    if len(core) >= 2 and len(core[-1]) <= 3:  # co.uk, com.au
        core = core[:-1]
    keys.add(key("".join(core)))
    return {k for k in keys if k}


_TITLE_SPLIT = re.compile(r"\s+[-|–—:·•]\s+|\s*\|\s*")


def _title_keys(title: str) -> set[str]:
    if not title:
        return set()
    parts = [p for p in _TITLE_SPLIT.split(title) if p.strip()]
    keys = set()
    for p in (parts[0], parts[-1]) if parts else ():
        k = key(p)
        if 3 <= len(k) <= 40:
            keys.add(k)
    return keys


# Trailing words that do not change which brand an organisation name is
# ("OnionLand Hosting", "WordPress.org", "Tordex Search").
_BRAND_TAIL = frozenset({
    "hosting", "host", "search", "engine", "links", "link", "wiki", "directory", "project",
    "foundation", "team", "network", "cms", "framework", "org", "com", "net", "io", "inc",
    "ltd", "llc", "official", "site", "website",
})


def _brand_keys(value: str) -> set[str]:
    """The value's key, plus the key without a TLD or a generic trailing word."""
    v = (value or "").strip()
    keys = {key(v)}
    v2 = re.sub(r"\.[a-z]{2,6}$", "", v, flags=re.I)
    words = [w for w in re.split(r"[\s._\-]+", v2) if w]
    while len(words) > 1 and words[-1].lower() in _BRAND_TAIL:
        words.pop()
    keys.add(key(" ".join(words)))
    return {k for k in keys if k}


def org_boilerplate_reason(value: str, page_url: str = "", page_title: str = "") -> Optional[str]:
    """22R-5: why ORGANIZATION_NAME *value* is boilerplate on this page, or None."""
    keys = _brand_keys(value)
    if not keys or keys & AGENCY_KEYS:
        return None
    if keys & ORG_STOPLIST:
        return "stoplist"
    if keys & _host_keys(page_url):
        return "own_site"
    if keys & _title_keys(page_title):
        return "own_site"
    return None


def is_agency(value: str) -> bool:
    return key(value) in AGENCY_KEYS


def _attr(entity: Any, name: str) -> Any:
    if isinstance(entity, dict):
        return entity.get(name)
    return getattr(entity, name, None)


def gate_entities(
    entities: Iterable[Any],
    page_text: str,
    page_url: str = "",
    page_title: str = "",
) -> list[Any]:
    """The entities of one page minus the two removal kinds, counting removals."""
    entities = list(entities or [])
    try:
        kept: list[Any] = []
        index: Optional[TokenIndex] = None
        gaz = org = 0
        for ent in entities:
            etype = str(_attr(ent, "entity_type") or "").upper()
            value = str(_attr(ent, "value") or "")
            if etype in THREAT_TYPES and is_ambiguous(value, etype):
                if index is None:
                    index = TokenIndex(page_text or "")
                if not keep_threat_name(value, etype, page_text or "", index):
                    gaz += 1
                    continue
            elif etype == "ORGANIZATION_NAME" and org_boilerplate_reason(value, page_url, page_title):
                org += 1
                continue
            kept.append(ent)
        if gaz:
            _count("gazetteer_context", gaz)
        if org:
            _count("org_boilerplate", org)
        return kept
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("relevance gate failed (kept all): %s", exc)
        return entities
