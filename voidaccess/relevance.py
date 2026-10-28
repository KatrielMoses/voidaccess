"""Relevance tiers: how each page, entity and relationship relates to the query.

* ``direct``: it mentions the query (the selector, the threat name or one of
  its aliases, the topic phrase, the person or organisation name);
* ``related``: no direct mention, but a known alias part, a relation of the
  query's threat (gazetteer/MISP) or a refined-query term of 4+ characters;
* ``background``: collected, but nothing to do with the query.

Nothing is removed here: an off-topic item stays in the output labelled
``background`` with a reason. Matching is deterministic, local, token-aware
and case-insensitive, and never calls the LLM.

Public interface
----------------
set_current_intent(intent) / current_intent()
QueryMatcher(intent, refined_query)
classify_page_kind(page, text) -> str
annotate_pages(pages, matcher) -> None          (adds relevance fields in place)
annotate_entities(entities, pages, matcher) -> None
annotate_relationships(relationships, entities) -> None
build_relevance_block(...) -> dict
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from extractor import relevance_gate as _gate
from voidaccess.query_intent import (
    GENERIC_TERMS,
    THREAT_QUALIFIERS,
    QueryIntent,
    Selector,
    classify_query,
)

TIERS = ("direct", "related", "background")
_RANK = {"direct": 0, "related": 1, "background": 2}
PAGE_KINDS = (
    "directory", "search_portal", "market_listing", "forum_thread", "leak_post",
    "paste", "news_article", "feed_item", "other",
)
# 22R-6: an entity on a direct page is direct when it sits within this many
# characters of a direct match.
ENTITY_WINDOW_CHARS = 400
# 22R-5: an agency is direct only within this many characters (~8 tokens) of
# a direct match; otherwise it is background.
AGENCY_WINDOW_CHARS = 60
# 22R-2: a "real text" line for directory/search pages.
REAL_LINE_MIN_WORDS = 8

_lock = threading.Lock()
_current: Optional[QueryIntent] = None


def set_current_intent(intent: Optional[QueryIntent]) -> None:
    """Publish the run's query intent (process-wide; the CLI runs one query)."""
    global _current
    with _lock:
        _current = intent


def current_intent() -> Optional[QueryIntent]:
    return _current


def weaker(a: str, b: str) -> str:
    return a if _RANK.get(a, 2) >= _RANK.get(b, 2) else b


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_SEP = r"[\s\-_.]?"
_VERSION = r"(?:[\s\-_.]?v?\d+(?:\.\d+)*)?"
_TOKEN = re.compile(r"[a-z0-9]+")


def _threat_name_regex(name: str) -> Optional[str]:
    """Token-bounded name with an optional version: "lockbit", "LockBit 3.0", "lockbit3"."""
    parts = _TOKEN.findall((name or "").lower())
    if not parts:
        return None
    body = _SEP.join(re.escape(p) for p in parts)
    return rf"(?<![a-z0-9]){body}{_VERSION}(?![a-z0-9])"


def _phrase_regex(words: list[str], plural: bool = False) -> Optional[str]:
    parts = [p for w in words for p in _TOKEN.findall(w.lower())]
    if not parts:
        return None
    suffix = r"(?:s|es)?" if plural else ""
    body = r"[\s\-_/]+".join(re.escape(p) + suffix for p in parts)
    return rf"(?<![a-z0-9]){body}(?![a-z0-9])"


def _selector_regex(sel: Selector) -> list[str]:
    v = sel.value
    if sel.kind == "email":
        return [rf"(?<![\w.+\-]){re.escape(v)}(?![\w\-])"]
    if sel.kind == "phone":
        digits = sel.forms[-1] if sel.forms else re.sub(r"\D", "", v)
        out = [r"(?<!\d)\+?" + r"[\s().\-]*".join(re.escape(d) for d in digits) + r"(?!\d)"]
        if len(digits) >= 11:  # the national number without the country code
            national = digits[-10:]
            out.append(r"(?<![\d+])(?:[08][\s().\-]*)?" + r"[\s().\-]*".join(national) + r"(?!\d)")
        return out
    if sel.kind == "domain":
        return [rf"(?<![\w\-@]){re.escape(v)}(?![\w\-]|\.[a-z0-9])", rf"\.{re.escape(v)}(?![\w\-]|\.[a-z0-9])"]
    if sel.kind == "cve":
        m = re.match(r"CVE-(\d{4})-(\d+)", v)
        if m:
            return [rf"cve[-_\s]?{m.group(1)}[-_\s]?{m.group(2)}(?!\d)"]
    if sel.kind == "ip":
        return [rf"(?<![\d.]){re.escape(v)}(?!\d|\.\d)"]
    return [rf"(?<![A-Za-z0-9]){re.escape(v)}(?![A-Za-z0-9])"]


def _clean_alias(alias: str) -> str:
    return re.sub(r"\s+-\s+[st]\d{4}$", "", (alias or "").strip().lower())


@dataclass
class Match:
    start: int
    end: int
    reason: str


class QueryMatcher:
    """Direct and related matching for one query intent."""

    def __init__(self, intent: QueryIntent, refined_query: str = ""):
        self.intent = intent
        self.direct: list[tuple[re.Pattern, str]] = []
        self.direct_exact: list[tuple[re.Pattern, str]] = []  # case-sensitive extras
        self.related: list[tuple[re.Pattern, str, bool]] = []  # (pattern, reason, refined_only)
        self.ambiguous_core = False
        self._build(refined_query)

    # -- construction -----------------------------------------------------
    def _add_direct(self, regex: Optional[str], reason: str) -> None:
        if regex:
            self.direct.append((re.compile(regex, re.I), reason))

    def _add_related(self, word: str, reason: str, refined_only: bool = False) -> None:
        regex = _threat_name_regex(word) if reason.startswith("relation") else _phrase_regex([word])
        if regex:
            self.related.append((re.compile(regex, re.I), reason, refined_only))

    def _build(self, refined: str) -> None:
        it = self.intent
        used: set[str] = set()
        if it.kind == "selector":
            for sel in it.selectors:
                for rx in _selector_regex(sel):
                    self._add_direct(rx, "selector_match")
        elif it.kind == "named_threat":
            core = (it.terms or [""])[0]
            self.ambiguous_core = _gate.is_ambiguous(core)
            self._add_direct(_threat_name_regex(core), f"term_match:{core}")
            used.add(_gate.key(core))
            for alias in it.aliases:
                a = _clean_alias(alias)
                words = [w for w in a.split() if w not in THREAT_QUALIFIERS]
                name = " ".join(words)
                k = _gate.key(name)
                if len(k) < 4 or k in used or _gate.is_ambiguous(name):
                    continue
                used.add(k)
                self._add_direct(_threat_name_regex(name), f"alias_match:{name}")
            for name in {*(it.aliases or []), core}:
                for rel in _gate.relations_of(name):
                    rk = _gate.key(rel)
                    if rk and rk not in used:
                        used.add(rk)
                        self._add_related(rel, f"relation:{rel}")
        elif it.kind == "person_or_org":
            words = (it.terms or [""])[0].split()
            self._add_direct(_phrase_regex(words), f"term_match:{' '.join(words)}")
            if len(words) == 2:
                self._add_direct(
                    rf"(?<![a-z0-9]){re.escape(words[1])},\s*{re.escape(words[0])}(?![a-z0-9])",
                    f"term_match:{' '.join(words)}",
                )
        else:  # topic
            words = (it.terms or [""])[0].split()
            if words:
                self._add_direct(_phrase_regex(words, plural=True), f"term_match:{' '.join(words)}")
                alpha = [w for w in words if w.isalpha()]
                if len(words) >= 3 and len(alpha) == len(words):
                    acro = "".join(w[0] for w in words).upper()
                    self.direct_exact.append(
                        (re.compile(rf"(?<![A-Za-z0-9]){acro}s?(?![A-Za-z0-9])"), f"alias_match:{acro.lower()}")
                    )
        main_keys = {_gate.key(t) for t in it.terms} | used
        for word in it.related_terms:
            if _gate.key(word) not in main_keys:
                self._add_related(word, f"term_part:{word}")
                main_keys.add(_gate.key(word))
        for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-]*", refined or ""):
            lw = word.lower()
            if len(lw) < 4 or lw in GENERIC_TERMS or lw.isdigit() or _gate.key(lw) in main_keys:
                continue
            if any(_gate.key(lw) in _gate.key(t) for t in it.terms):
                continue
            main_keys.add(_gate.key(lw))
            original = lw in (it.original or "").lower()
            self._add_related(lw, "refined_term", refined_only=not original)

    # -- matching -----------------------------------------------------------
    def direct_matches(self, text: str, limit: int = 200) -> list[Match]:
        out: list[Match] = []
        if not text:
            return out
        for pat, reason in self.direct:
            for m in pat.finditer(text):
                out.append(Match(m.start(), m.end(), reason))
                if len(out) >= limit:
                    break
        for pat, reason in self.direct_exact:
            for m in pat.finditer(text):
                out.append(Match(m.start(), m.end(), reason))
                if len(out) >= limit:
                    break
        if out and self.ambiguous_core:
            index = _gate.TokenIndex(text)
            core = (self.intent.terms or [""])[0]
            out = [
                m for m in out
                if not m.reason.startswith("term_match")
                or _gate.has_cue(index, (m.start, m.end), core, "RANSOMWARE_GROUP")
            ]
        out.sort(key=lambda m: m.start)
        return out

    def related_match(self, text: str, fallback: bool = False) -> Optional[str]:
        if not text:
            return None
        for pat, reason, refined_only in self.related:
            if fallback and refined_only:
                continue
            if pat.search(text):
                return reason
        return None

    def value_is_query(self, value: str) -> Optional[str]:
        """Reason when an entity value *is* the selector or the threat name/alias."""
        v = (value or "").strip()
        if not v:
            return None
        if self.intent.kind == "selector":
            low = v.lower()
            for sel in self.intent.selectors:
                if low == sel.value.lower() or low in (f.lower() for f in sel.forms):
                    return "selector_entity"
                if sel.kind == "phone" and re.sub(r"\D", "", v) == (sel.forms[-1] if sel.forms else ""):
                    return "selector_entity"
            return None
        words = [w for w in v.split() if w.lower() not in THREAT_QUALIFIERS]
        core = " ".join(words) or v
        for pat, reason in self.direct:
            m = pat.search(core)
            if m and m.start() == 0 and m.end() == len(core):
                return "alias_entity" if reason.startswith("alias") else "query_entity"
        return None


# ---------------------------------------------------------------------------
# Page kind (22R-2)
# ---------------------------------------------------------------------------

_ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)
_URL_RE = re.compile(r"https?://\S+|www\.\S+|[a-z2-7]{16,56}\.onion\S*", re.I)
_WORDS_RE = re.compile(r"[^\W\d_]{2,}", re.U)
_DIRECTORY_TITLE = re.compile(r"\b(links?|director(y|ies)|wiki|lists?|index|onions?|catalog|top\s*\d+)\b", re.I)
_SEARCH_TITLE = re.compile(r"\b(search|engine|finder|ahmia|torch|haystak|excavator|tordex|onionland)\b", re.I)
_MARKET_CUES = ("add to cart", "escrow", "vendor", "in stock", "buy now", "shipping", "price", "usd", "btc", "xmr", "checkout", "listing")
_FORUM_CUES = ("reply", "replies", "posted by", "joined", "posts:", "thread", "quote", "registered", "member", "reputation", "last post")
_LEAK_CUES = ("leak", "leaked", "published", "data size", "files", "deadline", "countdown", "victim", "download", "exfiltrated", "ransom")
_PASTE_HOSTS = ("pastebin", "paste.ee", "dpaste", "rentry", "ghostbin", "privatebin", "controlc", "justpaste")
_PASTE_SOURCES = {"paste_sites", "pastebin", "paste_ee", "dpaste", "rentry", "paste"}
_NEWS_SOURCES = {"rss", "rss_feed", "fbi_doj_press", "cisa_advisory"}


def _cue_hits(low: str, cues: Iterable[str]) -> int:
    return sum(1 for c in cues if c in low)


def classify_page_kind(page: dict, text: Optional[str] = None) -> str:
    """Cheap page-kind heuristic: source type, link density and title cues."""
    text = text if text is not None else (page.get("text") or page.get("content") or "")
    url = str(page.get("url") or page.get("link") or "")
    source = str(page.get("source_type") or page.get("source") or "").lower()
    title = str(page.get("title") or "")
    if page.get("recency_only"):
        return "feed_item"
    host = ""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        pass
    if source in _PASTE_SOURCES or any(h in host for h in _PASTE_HOSTS):
        return "paste"
    head = title or text[:200]
    low = text[:20000].lower()
    words = len(_WORDS_RE.findall(text[:20000])) or 1
    onions = len(_ONION_RE.findall(text[:20000]))
    urls = len(_URL_RE.findall(text[:20000]))
    link_ratio = urls / max(1.0, words / 10.0)  # links per 10 words
    lines = [l for l in text[:20000].splitlines() if l.strip()]
    short = sum(1 for l in lines if len(l.split()) <= 4)
    short_ratio = short / len(lines) if lines else 0.0
    if source in _NEWS_SOURCES:
        return "news_article"
    if _SEARCH_TITLE.search(head) and ("search" in low[:3000] or "results" in low[:3000]):
        return "search_portal"
    if "search?" in url.lower() or "/search" in url.lower():
        return "search_portal"
    if onions >= 15 or link_ratio >= 0.6 or (onions >= 5 and (_DIRECTORY_TITLE.search(head) or short_ratio > 0.6)):
        return "directory"
    if _cue_hits(low, _MARKET_CUES) >= 4:
        return "market_listing"
    if _cue_hits(low, _LEAK_CUES) >= 4 and ("leak" in low or "published" in low):
        return "leak_post"
    if _cue_hits(low, _FORUM_CUES) >= 3:
        return "forum_thread"
    if words >= 300 and link_ratio < 0.1 and short_ratio < 0.5:
        return "news_article"
    return "other"


def _in_real_text_line(text: str, m: Match) -> bool:
    """True when match *m* sits in a line of prose rather than a link list."""
    start = text.rfind("\n", 0, m.start) + 1
    end = text.find("\n", m.end)
    line = text[start:end if end != -1 else len(text)]
    tokens = line.split()
    if len(_WORDS_RE.findall(line)) < REAL_LINE_MIN_WORDS:
        return False
    url_tokens = sum(1 for t in tokens if _URL_RE.search(t))
    return url_tokens / max(1, len(tokens)) < 0.3


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


def page_text(page: dict) -> str:
    return str(
        page.get("text") or page.get("content") or page.get("cleaned_text")
        or page.get("text_content") or ""
    )


def page_relevance(page: dict, matcher: QueryMatcher) -> tuple[str, str, list[Match]]:
    """(tier, reason, direct matches) for one page; also used for the page kind rule."""
    text = page_text(page)
    title = str(page.get("title") or "")
    hay = f"{title}\n{text}" if title else text
    kind = page.get("page_kind") or classify_page_kind(page, text)
    matches = matcher.direct_matches(hay)
    if matches and kind in ("directory", "search_portal"):
        real = [m for m in matches if _in_real_text_line(hay, m)]
        if not real:
            return "related", "link_list_only", []
        matches = real
    if matches:
        reason = matches[0].reason
        if reason.startswith("term_match") and matcher.intent.kind == "selector":
            reason = "selector_match"
        return "direct", reason, _shift(matches, len(title) + 1 if title else 0)
    rel = matcher.related_match(hay, fallback=bool(page.get("via_fallback")))
    if rel:
        return "related", rel, []
    return "background", "none", []


def _shift(matches: list[Match], offset: int) -> list[Match]:
    if not offset:
        return matches
    return [Match(max(0, m.start - offset), max(0, m.end - offset), m.reason) for m in matches]


def annotate_pages(pages: list[dict], matcher: QueryMatcher) -> None:
    """Add ``relevance``, ``relevance_reason`` and ``page_kind`` to each page in place."""
    for page in pages:
        try:
            text = page_text(page)
            kind = page.get("page_kind") or classify_page_kind(page, text)
            page["page_kind"] = kind
            if page.get("recency_only"):
                tier, reason, matches = "background", "recency_only", []
                direct = matcher.direct_matches(f"{page.get('title') or ''}\n{text}")
                if direct:  # the article does mention the query after all
                    tier, reason, matches = page_relevance(page, matcher)
            else:
                tier, reason, matches = page_relevance(page, matcher)
        except Exception:  # pragma: no cover - defensive
            tier, reason, matches = "background", "none", []
        page["relevance"] = tier
        page["relevance_reason"] = reason
        page["_direct_spans"] = [(m.start, m.end) for m in matches]


# ---------------------------------------------------------------------------
# Entities and relationships (22R-6)
# ---------------------------------------------------------------------------


def _value_spans(low_text: str, value: str, limit: int = 40) -> list[int]:
    v = (value or "").strip().lower()
    if len(v) < 3:
        return []
    out = []
    i = low_text.find(v)
    while i != -1 and len(out) < limit:
        out.append(i)
        i = low_text.find(v, i + 1)
    return out


def _near(positions: list[int], spans: list[tuple[int, int]], window: int, vlen: int) -> bool:
    for p in positions:
        for a, b in spans:
            if p <= b + window and p + vlen >= a - window:
                return True
    return False


def annotate_entities(
    entities: list[dict],
    pages: list[dict],
    matcher: QueryMatcher,
    window: int = ENTITY_WINDOW_CHARS,
) -> None:
    """Add ``relevance`` and ``relevance_reason`` to each entity in place."""
    by_url = {str(p.get("url") or ""): p for p in pages}
    direct_pages = [p for p in pages if p.get("relevance") == "direct"]
    related_pages = [p for p in pages if p.get("relevance") == "related"]
    lowered: dict[int, str] = {}

    def low(p: dict) -> str:
        k = id(p)
        if k not in lowered:
            lowered[k] = page_text(p).lower()
        return lowered[k]

    for ent in entities:
        try:
            tier, reason = _entity_tier(ent, by_url, direct_pages, related_pages, matcher, window, low)
        except Exception:  # pragma: no cover - defensive
            tier, reason = "background", "none"
        ent["relevance"] = tier
        ent["relevance_reason"] = reason


def _entity_tier(ent, by_url, direct_pages, related_pages, matcher, window, low) -> tuple[str, str]:
    values = [str(ent.get("value") or ""), str(ent.get("canonical_value") or "")]
    values = [v for v in dict.fromkeys(values) if v]
    agency = _gate.is_agency(values[0] if values else "")
    hit = None
    for v in values:
        hit = matcher.value_is_query(v)
        if hit and not agency:
            return "direct", hit
    # Direct pages: near a match, or elsewhere on the page.
    on_direct = False
    for p in direct_pages:
        spans = p.get("_direct_spans") or []
        lt = low(p)
        for v in values:
            pos = _value_spans(lt, v)
            if not pos:
                continue
            on_direct = True
            if spans and _near(pos, spans, AGENCY_WINDOW_CHARS if agency else window, len(v)):
                return "direct", "near_direct_match"
    if agency:
        return "background", "agency_not_near_match"
    if on_direct:
        return "related", "direct_page"
    src = by_url.get(str(ent.get("source_url") or ""))
    if src is not None and src.get("relevance") == "direct":
        return "related", "direct_page"
    if src is not None and src.get("relevance") == "related":
        return "related", "related_page"
    for p in related_pages:
        lt = low(p)
        if any(_value_spans(lt, v, limit=1) for v in values):
            return "related", "related_page"
    return "background", "none"


def annotate_relationships(relationships: list[dict], entities: list[dict]) -> None:
    """A relationship takes the weaker tier of its two ends."""
    tiers = {str(e.get("id")): e.get("relevance", "background") for e in entities}
    for rel in relationships:
        a = tiers.get(str(rel.get("entity_a_id")), "background")
        b = tiers.get(str(rel.get("entity_b_id")), "background")
        rel["relevance"] = weaker(a, b)


def tier_counts(items: Iterable[dict]) -> dict[str, int]:
    out = dict.fromkeys(TIERS, 0)
    for item in items:
        t = item.get("relevance")
        out[t if t in out else "background"] += 1
    return out


def build_relevance_block(
    intent: QueryIntent,
    pages: list[dict],
    entities: list[dict],
    relationships: list[dict],
    removed: dict[str, int],
    feed_items_capped: int,
    filter_fallback: bool,
    refined_query_restored: bool,
) -> dict[str, Any]:
    return {
        "query_intent": intent.kind,
        "pages": tier_counts(pages),
        "entities": tier_counts(entities),
        "relationships": tier_counts(relationships),
        "removed": {
            "gazetteer_context": int(removed.get("gazetteer_context", 0)),
            "org_boilerplate": int(removed.get("org_boilerplate", 0)),
        },
        "feed_items_capped": int(feed_items_capped),
        "filter_fallback": bool(filter_fallback),
        "refined_query_restored": bool(refined_query_restored),
    }


def sort_by_tier(items: list[dict]) -> list[dict]:
    """Stable sort: direct, then related, then background."""
    return sorted(items, key=lambda x: _RANK.get(x.get("relevance", "background"), 2))


def no_direct_sentence(intent: Optional[QueryIntent]) -> str:
    label = (intent.display if intent else "") or "the query"
    return f"No collected page mentions {label} directly."


def prepend_no_direct_sentence(summary: str, intent: Optional[QueryIntent]) -> str:
    """Open *summary* with the no-direct-match sentence (once)."""
    sentence = no_direct_sentence(intent)
    text = (summary or "").lstrip()
    if text.startswith(sentence):
        return text
    return f"{sentence}\n\n{text}" if text else sentence


def intent_for(query: str) -> QueryIntent:
    return current_intent() or classify_query(query)
