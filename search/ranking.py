"""
search/ranking.py — P3.2: merge the owned index into the fan-out + rank by
semantic relevance.

Two headline differentiators (requirement 1.8, points 1 and 4) live here:

* **Merge owned-index retrieval into the fan-out (1.5).** ``merge_and_rank`` queries
  the owned index's hybrid search alongside the external-engine results and merges
  the two, deduped by normalized URL. Because the owned index survives any external
  engine's death, a query the index can answer still returns results even when the
  entire external fan-out fails — the survive-engine-death guarantee.

* **Semantic ranking (1.7).** The merged candidates are ordered by *semantic
  relevance to the query* — a single, uniform, explainable score across sources —
  replacing the old static ``ENGINE_WEIGHTS`` ordering (which only substring-matched
  3 of 18 engines). We compute one query-embedding cosine over each candidate's
  ``title + snippet`` for *all* sources (owned and external alike), rather than
  blending Meili's hybrid score for owned hits with a cosine for external ones:
  one score, one explanation, source-agnostic. Owned hits carry a content snippet
  so they get a richer embedding input; external hits embed their title (the only
  text an engine result carries).

**ENGINE_WEIGHTS is retired as the ordering key** and kept only as a *deterministic
tiebreak* when two candidates have equal semantic score (rare) — so ordering is
reproducible without letting a shallow per-engine constant drive relevance.

Reuse, not reinvention: embeddings come from the existing ``vector.embed_text`` /
``vector.embed_batch`` (MiniLM + SHA-256 fallback) — no new embedding service. The
owned-index query no-ops cleanly when Meilisearch is unconfigured, so the local/$0
install degrades to external-only fan-out with no regression.
"""

from __future__ import annotations

import logging
import math
from typing import Callable, Optional

from vector import embed_batch, embed_text  # the ONE embedding reuse point

logger = logging.getLogger(__name__)

#: Synthetic engine name stamped on merged owned-index hits.
OWNED_INDEX_SOURCE = "owned_index"

#: How many owned-index hits to pull into the merge.
OWNED_SEARCH_LIMIT = 50

#: Tiebreak-only weight for owned hits (the owned index is a curated, semantically
#: matched source). Never the primary ordering key — semantic score is.
_OWNED_SOURCE_WEIGHT = 0.85


def _normalize_url(url: str) -> str:
    """Same normalization the fan-out dedup uses (lowercase, no trailing slash,
    http-folded), kept local to avoid a circular import with ``search.search``."""
    if not url:
        return ""
    return url.lower().rstrip("/").replace("https://", "http://")


def _rank_text(candidate: dict) -> str:
    """The text embedded for a candidate: title + snippet, host as a fallback."""
    parts = [candidate.get("title") or "", candidate.get("snippet") or ""]
    text = " ".join(p for p in parts if p).strip()
    if text:
        return text
    # No title/snippet (bare engine link) — fall back to the onion host so the
    # candidate still has *some* signal to embed.
    link = candidate.get("link") or ""
    try:
        from urllib.parse import urlparse

        return urlparse(link).hostname or link
    except Exception:
        return link


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 on degenerate input."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


async def _query_owned_index(query: str, *, limit: int = OWNED_SEARCH_LIMIT) -> list[dict]:
    """Hybrid-search the owned index and project hits to fan-out link dicts.

    Returns ``[]`` when the index is unconfigured (graceful) or on any error, so
    the caller always falls back cleanly to the external results.
    """
    try:
        from owned_index import search_index

        hits = await search_index(query, limit=limit)
    except Exception as exc:  # never let the owned-index query break search
        logger.debug("owned-index query failed (non-fatal): %s", exc)
        return []

    links: list[dict] = []
    for h in hits:
        if not getattr(h, "url", None):
            continue
        links.append(
            {
                "link": h.url,
                "title": h.title or "",
                "snippet": getattr(h, "snippet", None) or "",
                "source_engine": OWNED_INDEX_SOURCE,
                "source_weight": _OWNED_SOURCE_WEIGHT,
                "liveness": getattr(h, "liveness", None),
            }
        )
    return _filter_dead_onions(links)


#: Liveness values excluded from active retrieval (P3.3). ``DiscoveredOnion.status``
#: is authoritative (the freshness loop keeps it current), so a dead/dropped onion
#: is filtered from owned-index results rather than wasting a scrape slot.
_EXCLUDED_LIVENESS = frozenset({"dead", "dropped"})


def _filter_dead_onions(links: list[dict]) -> list[dict]:
    """Drop owned-index hits whose onion is currently dead/dropped (P3.3).

    Liveness truth lives in ``discovered_onions.status`` (updated by the freshness
    loop), not the possibly-stale index doc, so this consults the DB. No-ops when
    there is no database (local/$0 already has no owned index) or on any error.
    """
    if not links:
        return links
    import os

    if not os.getenv("DATABASE_URL"):
        return links

    hosts = set()
    for item in links:
        try:
            from urllib.parse import urlparse

            host = (urlparse(item.get("link", "")).hostname or "").lower()
        except Exception:
            host = ""
        if host:
            item["_onion_host"] = host
            hosts.add(host)
    if not hosts:
        return links

    try:
        from db.session import get_session
        from shared_corpus import DiscoveredOnion

        with get_session() as session:
            rows = (
                session.query(DiscoveredOnion.onion_address, DiscoveredOnion.status)
                .filter(DiscoveredOnion.onion_address.in_(hosts))
                .all()
            )
        status_by_host = {addr: status for addr, status in rows}
    except Exception as exc:  # DB hiccup must never break retrieval
        logger.debug("liveness filter skipped (non-fatal): %s", exc)
        return [{k: v for k, v in item.items() if k != "_onion_host"} for item in links]

    kept: list[dict] = []
    for item in links:
        host = item.pop("_onion_host", None)
        if host and status_by_host.get(host) in _EXCLUDED_LIVENESS:
            continue
        kept.append(item)
    return kept


def _merge(external: list[dict], owned: list[dict]) -> list[dict]:
    """Merge external + owned link dicts, deduped by normalized URL.

    An onion found by both a live engine and the owned index collapses to one
    candidate; when the external entry lacks a snippet, the owned index's snippet
    enriches it so it ranks on real content rather than a bare title.
    """
    by_norm: dict[str, dict] = {}
    merged: list[dict] = []
    for item in external:
        norm = _normalize_url(item.get("link", ""))
        merged.append(item)
        if norm:
            by_norm.setdefault(norm, item)
    for item in owned:
        norm = _normalize_url(item.get("link", ""))
        if not norm:
            continue
        existing = by_norm.get(norm)
        if existing is not None:
            if not existing.get("snippet") and item.get("snippet"):
                existing["snippet"] = item["snippet"]
        else:
            by_norm[norm] = item
            merged.append(item)
    return merged


def semantic_rank(
    query: str,
    candidates: list[dict],
    *,
    embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
) -> list[dict]:
    """Order *candidates* by semantic relevance to *query* (in place, returned).

    A single query-embedding cosine over ``title + snippet`` is the ordering key
    for every candidate, source-agnostic; ``source_weight`` is only a tiebreak.
    Each candidate gets a ``semantic_score`` for explainability. Degrades to the
    prior static-weight order (no regression) when the embedder is unavailable,
    and no-ops on empty input.

    ``embedder`` (a single-text function) is injected in tests; in production the
    query uses ``vector.embed_text`` and candidates are embedded in one
    ``vector.embed_batch`` call.
    """
    if not candidates:
        return candidates

    if embedder is None:
        query_vec = embed_text(query)
        cand_vecs = embed_batch([_rank_text(c) for c in candidates])
    else:
        query_vec = embedder(query)
        cand_vecs = [embedder(_rank_text(c)) for c in candidates]

    if not query_vec:
        # Embedder unavailable — preserve the previous static-weight ordering so
        # this is never a regression relative to pre-P3.2 behavior.
        candidates.sort(key=lambda r: r.get("source_weight", 0.5), reverse=True)
        return candidates

    for cand, vec in zip(candidates, cand_vecs):
        cand["semantic_score"] = _cosine(query_vec, vec) if vec else 0.0

    candidates.sort(
        key=lambda r: (r.get("semantic_score", 0.0), r.get("source_weight", 0.5)),
        reverse=True,
    )
    return candidates


async def merge_and_rank(
    query: str,
    external_links: list[dict],
    *,
    embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
    owned_limit: int = OWNED_SEARCH_LIMIT,
) -> list[dict]:
    """Merge owned-index hits into *external_links* and semantically rank the union.

    The single shared entry point both the API and CLI search paths call, so their
    merged-result ordering is identical (API↔CLI parity). Queries the owned index
    once (no-op when unconfigured), dedups by normalized URL, and ranks the union
    by semantic relevance to *query*.
    """
    owned = await _query_owned_index(query, limit=owned_limit)
    merged = _merge(external_links or [], owned)
    return semantic_rank(query, merged, embedder=embedder)
