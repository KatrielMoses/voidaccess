"""Retrieval precision (22S): fetch the search results that name the query first.

The Tor engines return mostly generic onion pages whatever the query, so the
pages fetched used to be close to the engines' own order. This module ranks the
candidates deterministically, before anything is fetched, by whether a
result's title, snippet or URL carries what the user searched for, using the
22R matcher (``voidaccess.relevance.QueryMatcher``):

* ``direct``: the selector, the main term or one of its aliases;
* ``related``: a related term (refined-only words do not count here, the same
  rule the fallback path uses for pages);
* ``none``: neither.

The order is stable inside a tier, so the LLM filter's (or the heuristic's)
ranking still decides among equals. Nothing here fetches, so the fetch count
and the time budget are unchanged: the same number of pages is fetched, the
matching ones first.

It also builds the exact query (the original query, or its selectors) that the
search fan-out issues next to the refined query, and the filter that keeps
only matching results from that extra fan-out.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Optional
from urllib.parse import unquote, urlsplit

TIER_DIRECT = "direct"
TIER_RELATED = "related"
TIER_NONE = "none"
_ORDER = {TIER_DIRECT: 0, TIER_RELATED: 1, TIER_NONE: 2}

# Fields a search result may carry besides its title (engine-dependent).
_SNIPPET_KEYS = ("snippet", "description", "summary")
_URL_SEPARATORS = re.compile(r"[/_\-+.=?&#%]+")


def candidate_text(item: dict) -> str:
    """Title, snippet and URL of a search result, as one matchable string.

    The URL is unquoted and its separators turned into spaces, so a path such
    as ``/lumma-stealer-logs`` matches the phrase "lumma stealer"."""
    if not isinstance(item, dict):
        return ""
    parts = [str(item.get("title") or "")]
    for key in _SNIPPET_KEYS:
        value = item.get(key)
        if value:
            parts.append(str(value)[:500])
    url = str(item.get("link") or item.get("url") or "")
    if url:
        parts.append(url)
        try:
            split = urlsplit(url)
            tail = unquote(f"{split.path} {split.query}")
        except ValueError:
            tail = ""
        if tail.strip():
            parts.append(tail)
            parts.append(_URL_SEPARATORS.sub(" ", tail))
    return " \n ".join(p for p in parts if p)


def candidate_tier(item: dict, matcher) -> str:
    """``direct`` / ``related`` / ``none`` for one search result."""
    if matcher is None:
        return TIER_NONE
    text = candidate_text(item)
    if not text:
        return TIER_NONE
    try:
        if matcher.direct_matches(text, limit=1):
            return TIER_DIRECT
        if matcher.related_match(text, fallback=True):
            return TIER_RELATED
    except Exception:  # ranking must never break a run
        return TIER_NONE
    return TIER_NONE


def tier_sort(items: list[dict], matcher) -> list[dict]:
    """*items* reordered direct, related, none; stable inside each tier."""
    if matcher is None or not items:
        return list(items or [])
    tiers = [candidate_tier(item, matcher) for item in items]
    order = sorted(range(len(items)), key=lambda i: (_ORDER[tiers[i]], i))
    return [items[i] for i in order]


def _sensitive(item: dict) -> bool:
    """A title or host the trace would mask: never promoted past the filter."""
    try:
        from progress.trace import is_sensitive_name

        title = str(item.get("title") or "")
        host = urlsplit(str(item.get("link") or item.get("url") or "")).hostname or ""
        return is_sensitive_name(title) or is_sensitive_name(host)
    except Exception:
        return True


def precision_order(
    candidates: list[dict],
    picked: list[dict],
    matcher,
    *,
    promote_unpicked: bool = True,
) -> tuple[list[dict], dict[str, int]]:
    """The fetch order: matching results first, then the filter's other picks.

    ``(ranked, counts)``. *picked* is what the relevance filter kept, in its
    order. Direct matches it kept come first, then direct matches it did not
    keep (when *promote_unpicked*; never one whose title or host is a
    sensitive name), then related picks, then the remaining picks. The caller
    still applies the diversity rule and the top-N cap, so the number of pages
    fetched does not change. ``counts`` has the candidate tiers and how many
    unpicked direct matches were promoted (counts only, for logs)."""
    picked = list(picked or [])
    counts = {"direct": 0, "related": 0, "none": 0, "promoted": 0}
    if matcher is None:
        return picked, counts
    tiers: dict[int, str] = {}
    for item in candidates or []:
        tier = candidate_tier(item, matcher)
        tiers[id(item)] = tier
        counts[tier] += 1
    for item in picked:
        if id(item) not in tiers:
            tiers[id(item)] = candidate_tier(item, matcher)
    picked_ids = {id(item) for item in picked}
    direct_picked = [i for i in picked if tiers[id(i)] == TIER_DIRECT]
    promoted: list[dict] = []
    if promote_unpicked:
        promoted = [
            i for i in (candidates or [])
            if id(i) not in picked_ids and tiers.get(id(i)) == TIER_DIRECT and not _sensitive(i)
        ]
    counts["promoted"] = len(promoted)
    related_picked = [i for i in picked if tiers[id(i)] == TIER_RELATED]
    rest = [i for i in picked if tiers[id(i)] == TIER_NONE]
    return [*direct_picked, *promoted, *related_picked, *rest], counts


# ---------------------------------------------------------------------------
# Exact-query fan-out
# ---------------------------------------------------------------------------


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def exact_query(intent, refined: str) -> Optional[str]:
    """The query to issue next to *refined*, or None when it adds nothing.

    A selector query searches its selectors exactly (``jdoe1987@gmail.com``,
    ``CVE-2024-3400``); any other query searches the user's own words. None
    when that is the refined query already (ignoring case and punctuation)."""
    if intent is None:
        return None
    if getattr(intent, "kind", "") == "selector" and intent.selectors:
        text = " ".join(s.value for s in intent.selectors)
    else:
        text = (getattr(intent, "original", "") or "").strip()
    text = text.strip()
    if not text or _squash(text) == _squash(refined or ""):
        return None
    return text


def matching_filter(matcher) -> Callable[[dict], bool]:
    """Keep a result of the exact-query fan-out only when it matches the query.

    The extra fan-out returns as many generic pages as the first; keeping only
    matching ones leaves the candidate list (and the LLM filter prompt) about
    the same size."""

    def keep(item: dict) -> bool:
        return candidate_tier(item, matcher) != TIER_NONE

    return keep


def count_tiers(items: Iterable[dict], matcher) -> dict[str, int]:
    counts = {"direct": 0, "related": 0, "none": 0}
    for item in items or []:
        counts[candidate_tier(item, matcher)] += 1
    return counts
