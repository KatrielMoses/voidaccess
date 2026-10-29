"""
utils/content_safety.py — Mandatory content safety filters for VoidAccess.

Operates at multiple layers: query intake, URL filtering, content scanning,
and post-extraction entity value filtering.
Never logs actual prohibited content — only event metadata.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import unicodedata
from bisect import bisect_left
from itertools import accumulate, compress, repeat
from typing import Any, Optional, Union
from urllib.parse import unquote_plus, urlsplit

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

BLOCKED_TERMS = [
    # CSAM related
    "child porn", "cp porn", "lolita", "pedo",
    "pedophil", "childporn", "child sex", "minor sex",
    "underage sex", "jailbait", "preteen sex",
    "child abuse material", "csam", "child model",
    "hurtcore", "daisy's destruction",
    # Gore related
    "gore site", "gore video", "snuff film",
    "murder video", "execution video", "beheading video",
    "torture video", "bestgore", "livegore",
    "watchpeopledie", "realsnuff",
]

BLOCKED_PATTERNS = [
    r'\bcp\b.{0,20}\bonion\b',      # "cp" near "onion"
    r'\bchild.{0,10}\bnaked\b',
    r'\bminor.{0,10}\bnaked\b',
    r'\bkid.{0,10}\bporn\b',
    r'\bteen.{0,10}\bporn\b',
]

BLOCKED_URL_TERMS = [
    "pedo", "loli", "jailbait", "childporn",
    "hurtcore", "csam", "bestgore", "livegore",
    "watchpeople", "realsnuff", "daisy",
]

CONTENT_BLOCKLIST = [
    "child pornography", "child porn",
    "child sexual abuse", "csam",
    "snuff film", "murder porn",
]

# ---------------------------------------------------------------------------
# Detector vocabularies — one structure, so later releases extend it in one place.
# Every term is written in normalised form (see ``normalize_for_safety``).
#   minor / sexual: a minor term within PROXIMITY_WINDOW tokens of a sexual term,
#                   in either order, or both joined into one token.
#   gore:           gore phrases, matched like CONTENT_BLOCKLIST.
# ---------------------------------------------------------------------------

SAFETY_VOCAB: dict[str, tuple[str, ...]] = {
    "minor": (
        "child", "children", "kid", "kids", "minor", "minors", "underage",
        "preteen", "pre teen", "toddler", "baby", "babies", "infant",
        "loli", "lolita", "pedo", "paedo", "jailbait", "cp",
        "young girl", "young boy",
    ),
    "sexual": (
        "porn", "porno", "sex", "sexual", "nude", "nudes", "naked",
        "rape", "raped", "molest", "molested", "explicit", "xxx", "fuck",
        "hardcore",
    ),
    "gore": (
        "snuff film", "snuff video", "murder porn",
        "hurtcore", "bestgore", "livegore", "realsnuff",
    ),
}

# A minor term and a sexual term at most this many tokens apart (adjacent = 1).
PROXIMITY_WINDOW = 4

# Rule ids returned by ``detect_prohibited`` (never the matched text).
RULE_PHRASE = "phrase"
RULE_PATTERN = "pattern"
RULE_URL_TERM = "url_term"
RULE_PROXIMITY = "proximity"
RULE_GORE = "gore"
RULE_HOST = "host"
RULE_ERROR = "error"

# ---------------------------------------------------------------------------
# Entity value blocklist — applied after extraction, before DB storage
# Only checked against text-based entity types (not technical IOCs)
# ---------------------------------------------------------------------------

ENTITY_VALUE_BLOCKLIST: list[str] = [
    # Adult content categories
    "porn", "blowjob", "bdsm", "hardcore",
    "xxx", "nude", "nudes", "naked", "escort",
    "onlyfans", "cam girl", "sex tape",
    "adult content", "adult site",
    # Gore/violence
    "snuff", "gore", "murder video",
    "execution video", "beheading",
    # Exploitation
    "jailbait", "pedo", "csam",
    "child", "minor",
]


# Common-password substring patterns — anything matching one of these as
# a *value* (case-insensitive) is treated as a known weak password and
# must never be stored as an entity.  These are deliberately not in the
# main ENTITY_VALUE_BLOCKLIST because that list is only checked against
# text-based entity types (ORG/handle/person/malware).  Passwords can
# only appear as raw stealer-log values, which we now also filter via
# ``_looks_like_common_password`` below.
COMMON_PASSWORD_SUBSTRINGS: tuple[str, ...] = (
    "password", "passwd", "p@ssw0rd", "p@ssword",
    "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
    "letmein", "welcome", "admin", "admin123", "admin1234",
    "iloveyou", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "superman",
    "trustno1", "starwars", "passw0rd",
    "hunter2", "shadow", "master", "jordan",
    "michael", "thomas", "robert", "george",
    "charlie", "andrew", "matthew", "access",
    "hello", "secret", "love", "freedom",
)


def _looks_like_common_password(value: str) -> bool:
    """
    Return True if *value* matches any COMMON_PASSWORD_SUBSTRINGS entry.

    Used as a defensive guard for stealer-log password fields and for any
    entity value the generic API_KEY extractor surfaces.  Never logs the
    value — only the boolean outcome.
    """
    if not value:
        return False
    v = value.lower().strip()
    if not v:
        return False
    for needle in COMMON_PASSWORD_SUBSTRINGS:
        if needle in v:
            return True
    return False

# Entity types where prohibited content can appear as names/labels.
# Technical IOC types (hashes, IPs, CVEs, wallets, onion URLs) are
# intentionally omitted — they cannot contain prohibited content.
_TEXT_ENTITY_TYPES: frozenset[str] = frozenset({
    "ORGANIZATION_NAME",
    "THREAT_ACTOR_HANDLE",
    "PERSON_NAME",
    "MALWARE_FAMILY",
})

# Entity types whose value is a URL or a host: checked against the host
# blocklist and, like any URL, the detector.
_URL_ENTITY_TYPES: frozenset[str] = frozenset({
    "ONION_URL",
    "ONION_ADDRESS",
    "URL",
    "PASTE_URL",
    "DOMAIN",
    "DOMAIN_NAME",
})


# ---------------------------------------------------------------------------
# Normaliser and detector
# ---------------------------------------------------------------------------

# Common digit/symbol substitutions become letters; every other ASCII
# character that is not a-z0-9 becomes a space.
_ASCII_MAP = str.maketrans({
    **{chr(c): " " for c in range(128) if not chr(c).isalnum() or chr(c).isupper()},
    **dict(zip("013457@$", "oieastas")),
})
# Format characters (zero-width, bidi controls, soft hyphen, variation
# selectors) and combining marks. Only consulted for non-ASCII text.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    "\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff"
    "\u0300-\u036f\u0483-\u0489\u0591-\u05bd\u0610-\u061a\u064b-\u065f"
    "\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]"
)
def _normalized_tokens(text: str) -> list[str]:
    if text.isascii():  # NFKC is the identity on ASCII; casefold is lower()
        return text.lower().translate(_ASCII_MAP).split()
    s = unicodedata.normalize("NFKC", text).casefold()
    if not s.isascii():
        s = _INVISIBLE_RE.sub("", unicodedata.normalize("NFKD", s))
        # Any other non-ASCII character becomes "?", which the map turns into
        # a space.
        s = s.encode("ascii", "replace").decode("ascii")
    return s.translate(_ASCII_MAP).split()


def normalize_for_safety(text: str) -> tuple[str, str]:
    """Return ``(spaced, squashed)`` forms of *text* for the content checks.

    ``spaced``: NFKC, casefolded, invisible characters and combining marks
    removed, common digit/symbol substitutions mapped to letters, and every
    run of anything that is not ``a-z0-9`` replaced by one space.
    ``squashed``: ``spaced`` with the spaces removed. Linear time.
    """
    if not text:
        return "", ""
    tokens = _normalized_tokens(text)
    return " ".join(tokens), "".join(tokens)


# A needle: a term with its spaces removed, plus the offsets of its inner word
# boundaries when it may also match as a plain substring of the spaced form
# (``None``: it matches only where a token starts).
_Needle = tuple[str, Optional[tuple[int, ...]]]


def _needles(terms, *, substring: bool, skip: tuple[_Needle, ...] = ()) -> tuple[_Needle, ...]:
    """Needles for *terms*, minus any that an earlier one (in *skip*, or a
    shorter term here) already finds wherever it matches."""

    def covers(short: _Needle, long: _Needle) -> bool:
        # Every needle matches where a token starts; only substring needles
        # match elsewhere, and only with the same inner word boundaries.
        if not long[0].startswith(short[0]):
            return False
        if long[1] is None:
            return True
        if short[1] is None:
            return False
        return short[1] == tuple(b for b in long[1] if b < len(short[0]))

    out: list[_Needle] = []
    for term in sorted(set(terms), key=lambda t: len(t.replace(" ", ""))):
        words = term.split()
        needle: _Needle = (
            "".join(words),
            tuple(accumulate(map(len, words[:-1]))) if substring else None,
        )
        if not any(covers(other, needle) for other in (*skip, *out)):
            out.append(needle)
    return tuple(out)


_MINOR, _SEXUAL, _COMPOUND = 1, 2, 3
# Multi-word minor terms are matched as one token.
_MINOR_BIGRAMS = tuple(
    (t, t.replace(" ", "")) for t in SAFETY_VOCAB["minor"] if " " in t
)


def _build_token_classes() -> dict[str, int]:
    # Whole tokens: every term counts, including those that start with another.
    minors = {t.replace(" ", "") for t in SAFETY_VOCAB["minor"]}
    sexual = SAFETY_VOCAB["sexual"]
    classes = dict.fromkeys(sexual, _SEXUAL)
    classes.update(dict.fromkeys(minors, _MINOR))
    for m in minors:
        for x in sexual:
            classes[m + x] = _COMPOUND
            classes[x + m] = _COMPOUND
    return classes


_TOKEN_CLASS = _build_token_classes()
_MINOR_TOKENS = frozenset(t for t, c in _TOKEN_CLASS.items() if c == _MINOR)
_SEXUAL_TOKENS = frozenset(t for t, c in _TOKEN_CLASS.items() if c == _SEXUAL)
_COMPOUND_TOKENS = frozenset(t for t, c in _TOKEN_CLASS.items() if c == _COMPOUND)
# BLOCKED_PATTERNS with the leading word boundary checked by hand, so the
# regex engine can scan for the literal prefix.
_PATTERNS_RE = tuple(re.compile(p.removeprefix(r"\b")) for p in BLOCKED_PATTERNS)
# Needles are checked in rule order; each list leaves out what an earlier one
# already finds. Phrases and gore terms match as substrings of the spaced form
# or token-anchored in the squashed form; URL terms only token-anchored.
_PHRASE_NEEDLES = _needles(CONTENT_BLOCKLIST, substring=True)
_GORE_NEEDLES = _needles(SAFETY_VOCAB["gore"], substring=True, skip=_PHRASE_NEEDLES)
# A bare name: blocked in URLs (is_blocked_url's raw check) but too common in prose.
URL_ONLY_TERMS = ("daisy",)
_URL_TERM_NEEDLES = _needles(
    [t for t in BLOCKED_URL_TERMS if t not in URL_ONLY_TERMS],
    substring=False,
    skip=_PHRASE_NEEDLES + _GORE_NEEDLES,
)
# A run of one-character tokens ("k i d s") in " " + spaced + " ".
_SINGLE_CHAR_RUN_RE = re.compile(r" ((?:[a-z0-9] )+[a-z0-9])(?= )")


class _Normalized:
    """One normalisation of a text, shared by every rule."""

    __slots__ = ("tokens", "spaced", "squashed", "_starts")

    def __init__(self, text: str):
        self.tokens = _normalized_tokens(text)
        self.spaced = " ".join(self.tokens)
        self.squashed = "".join(self.tokens)
        self._starts: Optional[list[int]] = None

    def token_starts(self) -> list[int]:
        """Offsets in ``squashed`` at which a token starts, ascending."""
        if self._starts is None:
            self._starts = list(accumulate(map(len, self.tokens), initial=0))
        return self._starts


def _needle_hit(norm: _Normalized, needles: tuple[_Needle, ...]) -> bool:
    """True when a needle occurs in the squashed form either where a token
    starts, or (substring needles) with its inner word boundaries exactly on
    token boundaries, i.e. as a substring of the spaced form.

    Anchoring at a token start keeps letter-spaced and punctuated forms
    ("c.s.a.m") while ignoring accidental joins of unrelated words.
    """
    squashed = norm.squashed
    for needle, inner in needles:
        i = squashed.find(needle)
        while i != -1:
            starts = norm.token_starts()
            k = bisect_left(starts, i)
            if k < len(starts) and starts[k] == i:
                return True
            if inner is not None:
                inside = starts[k:bisect_left(starts, i + len(needle), k)]
                if inside == [i + b for b in inner]:
                    return True
            i = squashed.find(needle, i + 1)
    return False


def _pattern_hit(spaced: str) -> bool:
    for rx in _PATTERNS_RE:
        m = rx.search(spaced)
        while m is not None:
            start = m.start()
            if start == 0 or spaced[start - 1] == " ":
                return True
            m = rx.search(spaced, start + 1)
    return False


def _proximity_hit(tokens: list[str]) -> bool:
    """A minor term within PROXIMITY_WINDOW tokens of a sexual term (either
    order), or both joined into one token."""
    if not _COMPOUND_TOKENS.isdisjoint(tokens):
        return True
    if _MINOR_TOKENS.isdisjoint(tokens) or _SEXUAL_TOKENS.isdisjoint(tokens):
        return False
    classes = list(map(_TOKEN_CLASS.get, tokens, repeat(0)))
    last = {_MINOR: -PROXIMITY_WINDOW - 1, _SEXUAL: -PROXIMITY_WINDOW - 1}
    for i in compress(range(len(classes)), classes):
        cls = classes[i]
        if cls == _COMPOUND:
            return True
        other = _SEXUAL if cls == _MINOR else _MINOR
        if i - last[other] <= PROXIMITY_WINDOW:
            return True
        last[cls] = i
    return False


def _proximity_tokens(norm: _Normalized) -> list[str]:
    """The tokens with multi-word minor terms joined into one token."""
    spaced = norm.spaced
    merged = False
    for pair, joined in _MINOR_BIGRAMS:
        if pair in spaced:
            spaced = spaced.replace(pair, joined)
            merged = True
    return spaced.split(" ") if merged else norm.tokens


def _joined_runs(spaced: str, tokens: list[str]) -> Optional[list[str]]:
    """*tokens* with each run of one-character tokens ("k i d s") joined into
    one token, or ``None`` when no joined run is a vocabulary term."""
    if not any(
        m.group(1).replace(" ", "") in _TOKEN_CLASS
        for m in _SINGLE_CHAR_RUN_RE.finditer(f" {spaced} ")
    ):
        return None
    single = bytes(map((1).__eq__, map(len, tokens)))
    out: list[str] = []
    done = 0
    i = single.find(b"\x01\x01")
    while i != -1:
        end = single.find(b"\x00", i)
        if end == -1:
            end = len(single)
        out.extend(tokens[done:i])
        out.append("".join(tokens[i:end]))
        done = end
        i = single.find(b"\x01\x01", end)
    out.extend(tokens[done:])
    return out


def detect_prohibited(text: str) -> Optional[str]:
    """Return the id of the first content rule *text* trips, else ``None``.

    Never returns or logs the matched text. Raises only on a bug; callers
    treat an exception as a hit (fail closed).
    """
    if not text:
        return None
    norm = _Normalized(text)
    spaced = norm.spaced
    if not spaced:
        return None
    if _needle_hit(norm, _PHRASE_NEEDLES):
        return RULE_PHRASE
    if _needle_hit(norm, _GORE_NEEDLES):
        return RULE_GORE
    if _needle_hit(norm, _URL_TERM_NEEDLES):
        return RULE_URL_TERM
    if _pattern_hit(spaced):
        return RULE_PATTERN
    tokens = _proximity_tokens(norm)
    if _proximity_hit(tokens):
        return RULE_PROXIMITY
    joined = _joined_runs(spaced, tokens)
    if joined is not None and _proximity_hit(joined):
        return RULE_PROXIMITY
    return None


def _detect_fail_closed(text: str) -> Optional[str]:
    """``detect_prohibited``, but a detector error counts as a hit."""
    try:
        return detect_prohibited(text)
    except Exception as exc:
        _logger.warning("Content safety detector error (fail-closed): %s", type(exc).__name__)
        return RULE_ERROR


# ---------------------------------------------------------------------------
# Host blocklist: SHA-256 of normalised hosts, never the hosts themselves
# ---------------------------------------------------------------------------

BLOCKED_HOSTS_FILENAME = "blocked_hosts.sha256"
_blocked_host_hashes: Optional[frozenset[str]] = None
_blocked_hosts_lock = threading.Lock()


def normalize_host(value: str) -> str:
    """Lower-case host of *value* (a URL or a bare host): no scheme, userinfo,
    port, path or trailing dot. ``""`` when there is no host."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw.lstrip("/")
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def host_hash(host: str) -> str:
    """SHA-256 hex of the normalised form of *host*."""
    return hashlib.sha256(normalize_host(host).encode("utf-8")).hexdigest()


def _blocked_hosts_path() -> Optional[str]:
    try:
        from importlib.resources import files

        candidate = files("data").joinpath(BLOCKED_HOSTS_FILENAME)
        if candidate.is_file():
            return str(candidate)
    except Exception:
        pass
    local = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        BLOCKED_HOSTS_FILENAME,
    )
    return local if os.path.isfile(local) else None


def blocked_host_hashes() -> frozenset[str]:
    """The host blocklist, loaded once. Missing file: empty set and a warning
    (the content rules still apply)."""
    global _blocked_host_hashes
    if _blocked_host_hashes is not None:
        return _blocked_host_hashes
    with _blocked_hosts_lock:
        if _blocked_host_hashes is None:
            hashes: set[str] = set()
            path = _blocked_hosts_path()
            if path is None:
                _logger.warning("Host blocklist %s not found", BLOCKED_HOSTS_FILENAME)
            else:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            hashes.add(line)
            _blocked_host_hashes = frozenset(hashes)
    return _blocked_host_hashes


# ---------------------------------------------------------------------------
# Ahmia banned-onion list (defence in depth): MD5 of "<address>.onion"
# ---------------------------------------------------------------------------
# Ahmia publishes the MD5 of every onion host it has banned (CSAM and similar)
# at its /blacklist/banned/ page. That list is generated live from Ahmia's
# index and is not published in any Ahmia repository, so it is not vendored
# here. An operator who has obtained a copy points AHMIA_BANNED_ENV at it (one
# 32-hex MD5 per line, "#" comments allowed: the page body as served), or
# drops it at data/ahmia_banned.md5. Hashes only, never hosts. The engine never
# fetches it itself. Missing file: empty set, the other rules still apply.

AHMIA_BANNED_FILENAME = "ahmia_banned.md5"
AHMIA_BANNED_ENV = "VOIDACCESS_AHMIA_BANNED_MD5"
_MD5_LINE_RE = re.compile(r"^[0-9a-f]{32}$")
_ahmia_banned: Optional[frozenset[str]] = None
_ahmia_banned_lock = threading.Lock()


def _ahmia_banned_path() -> Optional[str]:
    env_path = (os.environ.get(AHMIA_BANNED_ENV) or "").strip()
    if env_path:
        if os.path.isfile(env_path):
            return env_path
        _logger.warning("%s is set but the file does not exist", AHMIA_BANNED_ENV)
        return None
    local = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        AHMIA_BANNED_FILENAME,
    )
    return local if os.path.isfile(local) else None


def ahmia_banned_md5s() -> frozenset[str]:
    """The Ahmia banned-host MD5 set, loaded once (empty when not supplied)."""
    global _ahmia_banned
    if _ahmia_banned is not None:
        return _ahmia_banned
    with _ahmia_banned_lock:
        if _ahmia_banned is None:
            hashes: set[str] = set()
            path = _ahmia_banned_path()
            if path is not None:
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.strip().lower()
                            if _MD5_LINE_RE.match(line):
                                hashes.add(line)
                except OSError as exc:
                    _logger.warning("Ahmia banned list unreadable: %s", type(exc).__name__)
                _logger.info("Ahmia banned list loaded: %d hashes", len(hashes))
            _ahmia_banned = frozenset(hashes)
    return _ahmia_banned


def reset_ahmia_banned_cache() -> None:
    """Forget the loaded Ahmia list (tests, or after the file changes)."""
    global _ahmia_banned
    with _ahmia_banned_lock:
        _ahmia_banned = None


def is_ahmia_banned_host(value: str) -> bool:
    """True when the onion service host of *value* is on the Ahmia list."""
    host = normalize_host(value)
    if not host.endswith(".onion"):
        return False
    hashes = ahmia_banned_md5s()
    if not hashes:
        return False
    service = ".".join(host.split(".")[-2:])  # drop any subdomain
    return hashlib.md5(service.encode("utf-8"), usedforsecurity=False).hexdigest() in hashes


def is_blocked_host(value: str) -> bool:
    """True when the host of *value*, or a parent domain of it, is on the
    host blocklist or (onion hosts) the Ahmia banned list."""
    host = normalize_host(value)
    if not host:
        return False
    if is_ahmia_banned_host(host):
        return True
    hashes = blocked_host_hashes()
    if not hashes:
        return False
    labels = host.split(".")
    for i in range(len(labels) - 1):
        if host_hash(".".join(labels[i:])) in hashes:
            return True
    return host_hash(host) in hashes


# ---------------------------------------------------------------------------
# Drop counters: counts only, so operators can see the gate working
# ---------------------------------------------------------------------------

DROP_KINDS = ("page", "title", "url", "entity")
_drop_counts: dict[str, int] = dict.fromkeys(DROP_KINDS, 0)
_drop_lock = threading.Lock()


def record_safety_drop(kind: str, n: int = 1) -> None:
    if kind not in _drop_counts or n <= 0:
        return
    with _drop_lock:
        _drop_counts[kind] += n


def safety_drop_counts() -> dict[str, int]:
    with _drop_lock:
        return dict(_drop_counts)


def reset_safety_drop_counts() -> None:
    with _drop_lock:
        for kind in DROP_KINDS:
            _drop_counts[kind] = 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_blocked_query(query: str) -> tuple[bool, str]:
    """
    Check if a query should be blocked.
    Returns (is_blocked, reason).
    Never logs the actual query.
    """
    query_lower = query.lower()

    for term in BLOCKED_TERMS:
        if term in query_lower:
            return True, "Query contains prohibited content"

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, query_lower, re.IGNORECASE):
            return True, "Query contains prohibited content"

    if _detect_fail_closed(query):
        return True, "Query contains prohibited content"

    return False, ""


def is_blocked_entity_value(entity_type: str, value: str) -> bool:
    """
    Return True if an entity value should be dropped before storage.

    Only applies to text-based entity types where prohibited content can
    appear as organisation/actor names (ORGANIZATION_NAME, THREAT_ACTOR_HANDLE,
    PERSON_NAME, MALWARE_FAMILY).

    Never applies to technical IOC types such as FILE_HASH_*, IP_ADDRESS, CVE,
    ONION_URL, or wallet addresses \u2014 these cannot contain prohibited content
    by definition and are intentionally excluded.

    Additional defensive check: any entity whose value looks like a
    common-password substring (``hunter2``, ``password123``, etc.) is
    always blocked, regardless of entity type.  This catches the case
    where the generic API_KEY extractor picks up a weak password as an
    ``api_key`` value, and the stealer-log path leaking a password into
    a downstream column.

    The check is case-insensitive substring matching against
    ENTITY_VALUE_BLOCKLIST and COMMON_PASSWORD_SUBSTRINGS.  The actual
    value is never logged.
    """
    return _entity_block_reason(entity_type, value) is not None


def _entity_block_reason(entity_type: str, value: str) -> Optional[str]:
    """``None`` to keep, else ``"empty"``, ``"password"`` or ``"safety"``."""
    if not value:
        return "empty"  # empty values are blocked outright

    # Layer 1: known common-password substring filter (applies to every type).
    if _looks_like_common_password(value):
        return "password"

    # Layer 2: URL and host values — host blocklist plus the URL checks.
    if (entity_type or "").upper() in _URL_ENTITY_TYPES:
        return "safety" if is_blocked_url(value)[0] else None

    # Layer 3: prohibited-content filter (only for text-based entity types).
    if entity_type not in _TEXT_ENTITY_TYPES:
        return None

    value_lower = value.lower()
    for term in ENTITY_VALUE_BLOCKLIST:
        if term in value_lower:
            return "safety"

    if _detect_fail_closed(value):
        return "safety"

    return None


def is_blocked_url(url: str) -> tuple[bool, str]:
    """
    Check if a URL should be blocked from scraping.
    Returns (is_blocked, reason).

    Checks the raw URL, the host against the host blocklist, and the
    percent-decoded URL (host, path and query) against the content rules.
    """
    url_lower = url.lower()
    for term in BLOCKED_URL_TERMS:
        if term in url_lower:
            return True, "URL blocked — prohibited content"
    if is_blocked_host(url):
        return True, "URL blocked — prohibited content"
    if _detect_fail_closed(unquote_plus(unquote_plus(url))):
        return True, "URL blocked — prohibited content"
    return False, ""


def search_result_block_reason(result: dict) -> Optional[str]:
    """``"url"`` or ``"title"`` (title or snippet) when a search result must be
    dropped, else ``None``. Fail-closed: a result the gate cannot judge is
    ``"url"``."""
    try:
        url = str(result.get("link") or result.get("url") or "")
        if url and is_blocked_url(url)[0]:
            return "url"
        for key in ("title", "snippet"):
            if _detect_fail_closed(str(result.get(key) or "")):
                return "title"
        return None
    except Exception as exc:
        _logger.warning("Search result safety gate error (fail-closed): %s", exc)
        return "url"


def gate_search_results(results: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split search results into (kept, dropped) by URL and title. Counts each
    drop; never logs the title or the URL."""
    kept: list[dict] = []
    dropped: list[dict] = []
    for result in results:
        reason = search_result_block_reason(result)
        if reason is None:
            kept.append(result)
            continue
        dropped.append(result)
        record_safety_drop(reason)
    if dropped:
        _logger.warning("Search results blocked — prohibited content: %d", len(dropped))
    return kept, dropped


def content_hash_prefix(value: str) -> str:
    """SHA-256 hex prefix for logs and audit events (never log raw content)."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def scan_page_text(
    url: str,
    text: str,
    *,
    user_id: Optional[int] = None,
) -> tuple[str, bool]:
    """
    Layer-4 scan for one page. Returns (clean_text, dropped).

    Fail-closed: gate errors treat the page as blocked.
    """
    url_key = url or content_hash_prefix(text or "")
    try:
        clean, flagged = sanitize_content(text or "")
        if flagged:
            record_safety_drop("page")
            url_hash = content_hash_prefix(url_key)
            _logger.warning(
                "Page content blocked — prohibited content. Page hash: %s",
                url_hash,
            )
            log_content_safety_event(
                event_type="content_blocked",
                content_hash=url_hash,
                user_id=user_id,
            )
            return "", True
        return clean, False
    except Exception as exc:
        record_safety_drop("page")
        url_hash = content_hash_prefix(url_key)
        _logger.warning(
            "Content safety gate error (fail-closed). Page hash: %s: %s",
            url_hash,
            exc,
        )
        log_content_safety_event(
            event_type="content_blocked",
            content_hash=url_hash,
            user_id=user_id,
        )
        return "", True


def url_is_blocked(
    url: str,
    *,
    user_id: Optional[int] = None,
) -> bool:
    """Return True when the URL must not be fetched (fail-closed on gate errors)."""
    if not url:
        return True
    url_hash = content_hash_prefix(url)
    try:
        blocked, _reason = is_blocked_url(url)
        if blocked:
            record_safety_drop("url")
            _logger.warning(
                "URL blocked — prohibited content. URL hash: %s",
                url_hash,
            )
            log_content_safety_event(
                event_type="url_blocked",
                content_hash=url_hash,
                user_id=user_id,
            )
            return True
        return False
    except Exception as exc:
        record_safety_drop("url")
        _logger.warning(
            "URL safety gate error (fail-closed). URL hash: %s: %s",
            url_hash,
            exc,
        )
        log_content_safety_event(
            event_type="url_blocked",
            content_hash=url_hash,
            user_id=user_id,
        )
        return True


def entity_value_is_blocked(entity_type: str, value: str) -> bool:
    """Fail-closed wrapper around ``is_blocked_entity_value``."""
    try:
        blocked = is_blocked_entity_value(entity_type, value)
        if blocked and _entity_block_reason(entity_type, value) == "safety":
            record_safety_drop("entity")
        return blocked
    except Exception as exc:
        record_safety_drop("entity")
        _logger.warning(
            "Entity safety gate error (fail-closed): type=%s err=%s",
            entity_type,
            exc,
        )
        return True


def entity_is_unsafe(entity_type: str, value: str) -> bool:
    """True when an entity must be dropped for content safety only (not for
    being empty or password-like). Fail-closed; counts each drop."""
    try:
        unsafe = bool(value) and _entity_block_reason(entity_type, value) == "safety"
    except Exception as exc:
        _logger.warning(
            "Entity safety gate error (fail-closed): type=%s err=%s",
            entity_type,
            type(exc).__name__,
        )
        unsafe = True
    if unsafe:
        record_safety_drop("entity")
    return unsafe


def gate_pages(
    pages: Union[dict[str, str], list[dict[str, Any]]],
    *,
    user_id: Optional[int] = None,
) -> tuple[Union[dict[str, str], list[dict[str, Any]]], int]:
    """
    Scan page text before persistence, caching, extraction, or summarization.

    Accepts either ``{url: text}`` (API scrape pool) or a list of page
    records with ``url``/``link`` and ``text``/``content`` keys (CLI/API).

    Returns (clean_pages, dropped_count).
    """
    dropped = 0
    if isinstance(pages, dict):
        clean: dict[str, str] = {}
        for page_url, page_text in pages.items():
            clean_text, was_dropped = scan_page_text(
                page_url, page_text or "", user_id=user_id
            )
            if was_dropped:
                dropped += 1
            else:
                clean[page_url] = clean_text
        return clean, dropped

    clean_records: list[dict[str, Any]] = []
    for record in pages:
        page_url = (
            record.get("url")
            or record.get("link")
            or ""
        )
        page_text = (
            record.get("text")
            or record.get("content")
            or record.get("cleaned_text")
            or record.get("text_content")
            or ""
        )
        clean_text, was_dropped = scan_page_text(
            page_url, page_text, user_id=user_id
        )
        if was_dropped:
            dropped += 1
            continue
        updated = dict(record)
        updated["text"] = clean_text
        if any(k in record for k in ("content", "text", "cleaned_text", "text_content")):
            updated["content"] = clean_text
        clean_records.append(updated)
    return clean_records, dropped


def sanitize_content(text: str) -> tuple[str, bool]:
    """
    Scan scraped text for CSAM/gore indicators.
    Returns (sanitized_text, was_flagged).
    If flagged, returns empty string — the original text is never stored.
    """
    if not text:
        return text, False

    text_lower = text.lower()
    for term in CONTENT_BLOCKLIST:
        if term in text_lower:
            return "", True

    if _seen_clean(text):
        return text, False
    if _detect_fail_closed(text):
        return "", True
    _remember_clean(text)

    return text, False


# Page texts recently found clean. The same text reaches the gate more than
# once in a run (the scraper, then the post-scrape gate); a repeat skips the
# rescan. The detector is deterministic, so a hit cannot change the outcome.
_RECENT_CLEAN_MAX = 32
_RECENT_CLEAN_MAX_CHARS = 200_000
_recent_clean: dict[str, None] = {}
_recent_clean_lock = threading.Lock()


def _seen_clean(text: str) -> bool:
    with _recent_clean_lock:
        return text in _recent_clean


def _remember_clean(text: str) -> None:
    if len(text) > _RECENT_CLEAN_MAX_CHARS:
        return
    with _recent_clean_lock:
        _recent_clean[text] = None
        while len(_recent_clean) > _RECENT_CLEAN_MAX:
            del _recent_clean[next(iter(_recent_clean))]


def log_content_safety_event(
    event_type: str,
    content_hash: Optional[str] = None,
    user_id: Optional[int] = None,
) -> None:
    """
    Persist a content safety block event to the DB for operator review.
    Fails silently — never disrupts the calling pipeline.
    event_type: one of "query_blocked", "url_blocked", "content_blocked"
    content_hash: SHA-256 hex prefix (≤16 chars) of the blocked item, for correlation only.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return
        from db.session import get_session
        from db.models import ContentSafetyEvent
        from datetime import datetime, timezone

        with get_session() as session:
            event = ContentSafetyEvent(
                event_type=event_type,
                user_id=user_id,
                content_hash=content_hash,
                timestamp=datetime.now(timezone.utc),
            )
            session.add(event)
            session.commit()
    except Exception as exc:
        _logger.debug("content_safety: DB log failed (non-critical): %s", exc)
