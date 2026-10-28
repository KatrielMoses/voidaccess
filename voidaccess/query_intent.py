"""What the user searched for, in a form the relevance tiers can match.

``classify_query`` reads the raw query and returns a :class:`QueryIntent`:

* ``selector``: the query is or contains an exact selector (e-mail, phone,
  domain, IP, CVE, hash, onion address, crypto wallet or @handle);
* ``named_threat``: the query names a known actor, malware family or
  ransomware group from the gazetteer (``LockBit ransomware``);
* ``person_or_org``: a short capitalised name (``John Smith``);
* ``topic``: anything else (``initial access broker``).

``ensure_refined_query`` post-processes the LLM-refined query so the selector
or the named-threat term is never lost: when the refined text dropped or
mangled it, the original query is used instead.

Everything here is deterministic, local and never calls the LLM.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Selector patterns
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,24}(?![\w-])"
)
_ONION_RE = re.compile(r"(?<![a-z2-7])(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.I)
_URL_HOST_RE = re.compile(r"\bhttps?://([^/\s:?#]+)", re.I)
_CVE_RE = re.compile(r"\bCVE[-_\s]?(\d{4})[-_\s]?(\d{4,8})\b", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_CAND_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_HASH_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_WALLET_RES = (
    re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    re.compile(r"\bT[A-HJ-NP-Za-km-z1-9]{33}\b"),
)
_HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z0-9_][A-Za-z0-9_.]{1,31})(?![\w@])")
_PHONE_RE = re.compile(r"(?<![\w+])(\+?\d[\d\s().\-]{5,20}\d)(?![\w])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w\-])", re.I
)

# Generic top-level domains accepted for a bare domain selector, plus every
# two-letter country code. A dotted word with any other suffix ("node.js",
# "LockBit 3.0") is not a domain.
_GTLDS = frozenset(
    "com net org info biz edu gov mil int io co ai app dev xyz online site top shop store tech "
    "cloud me tv cc ws pro name mobi asia tel travel jobs club live news blog email link click "
    "space website host digital network systems solutions agency company services group email "
    "bank finance money global world media inc ltd llc page one zone wiki".split()
)
_CCTLDS = frozenset(
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs "
    "bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee "
    "eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm "
    "hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb "
    "lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz "
    "na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs "
    "ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl "
    "tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw".split()
)

SELECTOR_KINDS = ("email", "phone", "domain", "ip", "cve", "hash", "onion", "wallet", "handle")
INTENT_KINDS = ("selector", "named_threat", "topic", "person_or_org")

# Words that qualify a threat name rather than name it ("LockBit ransomware").
THREAT_QUALIFIERS = frozenset({
    "ransomware", "ransom", "group", "gang", "crew", "team", "malware", "stealer", "infostealer",
    "rat", "trojan", "loader", "botnet", "backdoor", "apt", "actor", "actors", "threat",
    "family", "variant", "operator", "operators", "affiliate", "affiliates", "locker",
    "campaign", "virus", "worm", "spyware", "wiper", "keylogger", "dropper", "miner",
})

# Generic search vocabulary: never a "main term" and never enough on its own to
# make a page related (the refine step adds words like these).
GENERIC_TERMS = frozenset({
    "dark", "darkweb", "darknet", "deep", "deepweb", "web", "onion", "tor", "forum", "forums",
    "market", "markets", "marketplace", "leak", "leaks", "leaked", "data", "dump", "dumps",
    "database", "breach", "breaches", "breached", "credentials", "credential", "login", "logins",
    "password", "passwords", "account", "accounts", "sale", "sell", "selling", "buy", "latest",
    "news", "info", "information", "intel", "intelligence", "threat", "threats", "attack",
    "attacks", "hack", "hacked", "hacking", "hacker", "hackers", "exploit", "exploits",
    "vulnerability", "email", "emails", "phone", "number", "domain", "site", "website", "victim",
    "victims", "list", "search", "osint", "investigation", "report", "reports", "activity",
    "analysis", "details", "the", "and", "for", "with", "from", "about", "into", "over", "this",
    "that", "what", "who", "new", "recent", "update", "updates", "related", "online", "internet",
    "cyber", "security", "cybercrime", "criminal", "underground", "illegal", "black", "access",
    *THREAT_QUALIFIERS,
})


@dataclass(frozen=True)
class Selector:
    """One exact selector. ``value`` is normalised; ``forms`` are the matchable spellings."""

    kind: str
    value: str
    forms: tuple[str, ...] = ()


@dataclass
class QueryIntent:
    kind: str
    selectors: list[Selector] = field(default_factory=list)
    # Main terms, lower-cased: the threat name, the topic phrase or the name.
    terms: list[str] = field(default_factory=list)
    # Short human label for the query ("LockBit", "acme.com", "John Smith").
    display: str = ""
    original: str = ""
    # named_threat only: canonical gazetteer name and aliases (lower-cased).
    aliases: list[str] = field(default_factory=list)
    threat_category: Optional[str] = None
    # Words of 4+ characters that are not generic, used for the related tier.
    related_terms: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "selectors": [{"kind": s.kind, "value": s.value} for s in self.selectors],
            "terms": list(self.terms),
            "display": self.display,
        }


# ---------------------------------------------------------------------------
# Normalisers
# ---------------------------------------------------------------------------


def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", v)
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    v = v.rsplit("@", 1)[-1]
    v = v.split(":", 1)[0].strip(".")
    if v.startswith("www."):
        v = v[4:]
    return v


def normalize_phone(value: str) -> tuple[str, str]:
    """(E.164, digits-only). E.164 keeps the ``+`` only when there is a country code."""
    digits = re.sub(r"\D", "", value or "")
    if value.strip().startswith("00") and len(digits) > 2:
        digits = digits[2:]
    return "+" + digits, digits


def normalize_cve(value: str) -> str:
    m = _CVE_RE.search(value or "")
    if not m:
        return (value or "").upper()
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _is_domain(host: str) -> bool:
    host = host.lower()
    if host.endswith(".onion") or "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    return tld in _GTLDS or tld in _CCTLDS


# ---------------------------------------------------------------------------
# Selector detection
# ---------------------------------------------------------------------------


def find_selectors(query: str) -> list[Selector]:
    """Every exact selector in *query*, normalised, in a stable order."""
    q = query or ""
    found: list[Selector] = []
    taken: list[tuple[int, int]] = []

    def free(span: tuple[int, int]) -> bool:
        return all(span[1] <= a or span[0] >= b for a, b in taken)

    def add(kind: str, value: str, forms: tuple[str, ...], span: tuple[int, int]) -> None:
        taken.append(span)
        if not any(s.kind == kind and s.value == value for s in found):
            found.append(Selector(kind, value, tuple(dict.fromkeys(f for f in forms if f))))

    for m in _EMAIL_RE.finditer(q):
        v = m.group(0).lower()
        add("email", v, (v,), m.span())
    for m in _ONION_RE.finditer(q):
        if free(m.span()):
            v = m.group(0).lower()
            add("onion", v, (v,), m.span())
    for m in _URL_HOST_RE.finditer(q):
        if not free(m.span(1)):
            continue
        host = normalize_domain(m.group(1))
        if _is_domain(host):
            add("domain", host, (host,), (m.start(), m.end()))
    for m in _CVE_RE.finditer(q):
        if free(m.span()):
            v = normalize_cve(m.group(0))
            add("cve", v, (v,), m.span())
    for rx in _WALLET_RES:
        for m in rx.finditer(q):
            if free(m.span()):
                v = m.group(0)
                v = v.lower() if v.lower().startswith(("0x", "bc1")) else v
                add("wallet", v, (v,), m.span())
    for m in _HASH_RE.finditer(q):
        if free(m.span()):
            v = m.group(0).lower()
            add("hash", v, (v,), m.span())
    for m in _IPV4_RE.finditer(q):
        if not free(m.span()):
            continue
        try:
            v = str(ipaddress.IPv4Address(m.group(0)))
        except ValueError:
            continue
        add("ip", v, (v,), m.span())
    for m in _IPV6_CAND_RE.finditer(q):
        if not free(m.span()) or m.group(0).count(":") < 2:
            continue
        try:
            v = str(ipaddress.IPv6Address(m.group(0)))
        except ValueError:
            continue
        add("ip", v, (v,), m.span())
    for m in _HANDLE_RE.finditer(q):
        if free(m.span()):
            v = "@" + m.group(1).lower()
            add("handle", v, (v,), m.span())
    for m in _DOMAIN_RE.finditer(q):
        if not free(m.span()):
            continue
        host = normalize_domain(m.group(1))
        if _is_domain(host):
            add("domain", host, (host,), m.span())
    for m in _PHONE_RE.finditer(q):
        if not free(m.span()):
            continue
        raw = m.group(1)
        e164, digits = normalize_phone(raw)
        plus = raw.strip().startswith(("+", "00"))
        # A phone needs a country-code marker or a full national length; this
        # keeps years, prices and "7731" in ordinary queries out.
        if not (7 <= len(digits) <= 15) or (not plus and len(digits) < 10):
            continue
        add("phone", e164 if plus else digits, (e164, digits), m.span())
    return found


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.'\-]*")


def _words(text: str) -> list[str]:
    return [w.strip(".'-") for w in _WORD_RE.findall(text or "") if w.strip(".'-")]


def _ner_dictionary_category(phrase: str) -> Optional[str]:
    """Category from the extractor's bundled malware/ransomware dictionaries."""
    try:
        from extractor import ner
    except Exception:  # pragma: no cover - import guard
        return None
    key = _squash(phrase)
    if key in {_squash(n) for n in ner._RANSOMWARE_DICT}:
        return "ransomware"
    if key in {_squash(n) for n in ner._MALWARE_DICT}:
        return "malware"
    return None


def _gazetteer_match(words: list[str]) -> Optional[tuple[str, dict, str]]:
    """Longest run of *words* that names a known threat: (phrase, record, category).

    The gazetteer is tried first, then the extractor's bundled dictionaries
    (which carry a few names the MISP snapshot spells differently).
    """
    try:
        from extractor import gazetteer
    except Exception:  # pragma: no cover - import guard
        return None
    for width in range(min(len(words), 6), 0, -1):
        for start in range(0, len(words) - width + 1):
            chunk = words[start:start + width]
            if all(w.lower() in GENERIC_TERMS for w in chunk):
                continue
            phrase = " ".join(chunk)
            if len(phrase) < 3:
                continue
            category = gazetteer.category_of(phrase) or _ner_dictionary_category(phrase)
            if category is None:
                continue
            record = gazetteer.lookup(phrase) or {"canonical": phrase, "synonyms": []}
            return phrase, record, category
    return None


def threat_aliases(name: str) -> list[str]:
    """Canonical names and synonyms for *name* across all gazetteer categories."""
    try:
        from extractor import gazetteer
    except Exception:  # pragma: no cover - import guard
        return []
    out: list[str] = []
    for category in ("ransomware", "malware", "threat_actor"):
        record = gazetteer.lookup(name, category)
        if record:
            out.extend([record.get("canonical") or "", *(record.get("synonyms") or [])])
    return [a.lower() for a in dict.fromkeys(out) if a and len(a) >= 3]


def _strip_qualifiers(words: list[str]) -> list[str]:
    out = list(words)
    while out and out[-1].lower() in THREAT_QUALIFIERS:
        out.pop()
    while out and out[0].lower() in THREAT_QUALIFIERS:
        out.pop(0)
    return out


def _related_words(words: list[str], exclude: set[str]) -> list[str]:
    out: list[str] = []
    for w in words:
        lw = w.lower()
        if len(lw) >= 4 and lw not in GENERIC_TERMS and lw not in exclude and not lw.isdigit():
            out.append(lw)
    return list(dict.fromkeys(out))


def classify_query(query: str) -> QueryIntent:
    """Classify *query*; see the module docstring. Never raises."""
    original = (query or "").strip()
    try:
        return _classify(original)
    except Exception:  # pragma: no cover - defensive: relevance must never break a run
        return QueryIntent(kind="topic", terms=[original.lower()], display=original, original=original)


def _classify(original: str) -> QueryIntent:
    selectors = find_selectors(original)
    words = _words(original)
    if selectors:
        rest = original
        for s in selectors:
            rest = re.sub(re.escape(s.value), " ", rest, flags=re.I)
            for f in s.forms:
                rest = rest.replace(f, " ")
        related: list[str] = []
        for s in selectors:
            if s.kind == "email":
                local = s.value.split("@", 1)[0]
                if len(local) >= 4:
                    related.append(local)
            elif s.kind == "domain":
                label = s.value.split(".")[0]
                if len(label) >= 4 and label not in GENERIC_TERMS:
                    related.append(label)
        related += _related_words(_words(rest), set())
        return QueryIntent(
            kind="selector",
            selectors=selectors,
            terms=[s.value.lower() for s in selectors],
            display=", ".join(s.value for s in selectors),
            original=original,
            related_terms=list(dict.fromkeys(related)),
        )

    match = _gazetteer_match(words) if words else None
    if match is not None:
        phrase, record, category = match
        core_words = _strip_qualifiers(phrase.split()) or phrase.split()
        core = " ".join(core_words)
        aliases = [*threat_aliases(phrase), *threat_aliases(core)]
        canonical = (record.get("canonical") or "").strip().lower()
        if canonical:
            aliases.insert(0, canonical)
        exclude = {w.lower() for w in phrase.split()}
        return QueryIntent(
            kind="named_threat",
            terms=[core.lower()],
            display=core,
            original=original,
            aliases=list(dict.fromkeys([core.lower(), phrase.lower(), *aliases])),
            threat_category=category,
            related_terms=_related_words(words, exclude),
        )

    content = [w for w in words if w.lower() not in GENERIC_TERMS or w[:1].isupper()]
    is_name = (
        1 <= len(words) <= 4
        and all(w[:1].isupper() and w.replace("-", "").replace("'", "").isalpha() for w in words)
        and not any(w.lower() in THREAT_QUALIFIERS for w in words)
    )
    if is_name:
        phrase = " ".join(words)
        return QueryIntent(
            kind="person_or_org",
            terms=[phrase.lower()],
            display=phrase,
            original=original,
            related_terms=[],
        )

    phrase_words = [w for w in words if w.lower() not in _STOPWORDS] or words
    phrase = " ".join(phrase_words).lower()
    return QueryIntent(
        kind="topic",
        terms=[phrase] if phrase else [],
        display=" ".join(phrase_words) or original,
        original=original,
        related_terms=_related_words(content, set()),
    )


_STOPWORDS = frozenset(
    "a an the of for and or in on at to from by with about into over is are was were be".split()
)


# ---------------------------------------------------------------------------
# Refined-query guard (G2)
# ---------------------------------------------------------------------------


def _phone_digits_in(text: str) -> set[str]:
    return {re.sub(r"\D", "", m.group(1)) for m in _PHONE_RE.finditer(text or "")}


def selector_present(selector: Selector, text: str) -> bool:
    """True when *text* still carries *selector* exactly (normalised compare)."""
    if not text:
        return False
    low = text.lower()
    if selector.kind == "phone":
        digits = selector.forms[-1] if selector.forms else re.sub(r"\D", "", selector.value)
        return digits in _phone_digits_in(text) or digits in re.sub(r"[\s().\-]", "", text)
    if selector.kind == "cve":
        return any(normalize_cve(m.group(0)) == selector.value for m in _CVE_RE.finditer(text))
    if selector.kind == "domain":
        return any(
            normalize_domain(m.group(1)) == selector.value for m in _DOMAIN_RE.finditer(text)
        ) or any(normalize_domain(m.group(1)) == selector.value for m in _URL_HOST_RE.finditer(text))
    if selector.kind == "wallet":
        return selector.value.lower() in low
    return selector.value.lower() in low


def ensure_refined_query(refined: Optional[str], intent: QueryIntent) -> tuple[str, bool]:
    """(query to search with, True when the original query had to be restored).

    The refined query must still carry every selector exactly, the named-threat
    name (or one of its aliases), or the person/org name. Otherwise the LLM
    mangled or dropped it and the original query is searched instead.
    """
    original = intent.original
    text = (refined or "").strip()
    if not text:
        return original, bool(original)
    if intent.kind == "selector":
        if all(selector_present(s, text) for s in intent.selectors):
            return text, False
        return original, True
    if intent.kind == "named_threat":
        low = _squash(text)
        if any(_squash(a) and _squash(a) in low for a in (intent.aliases or intent.terms)):
            return text, False
        return original, True
    if intent.kind == "person_or_org":
        if all(_squash(t) in _squash(text) for t in intent.terms):
            return text, False
        return original, True
    return text, False


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())
