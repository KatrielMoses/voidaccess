"""
tests/test_search_ranking.py — P3.2 hybrid retrieval merge + semantic ranking.

Offline: no Tor, no Meilisearch, no model load. The owned-index query is faked at
``owned_index.search_index`` (or ``search.ranking._query_owned_index``), the
external fan-out is faked at ``search.search._search_async``, and the embedder is
a controlled keyword embedder injected into the ranker so "semantic relevance"
is deterministic.

Coverage maps to the P3.2 acceptance criteria:
* owned-index hits merge with external results, deduped by URL;
* with every external engine failing, search still returns owned-index results;
* the merged set is ranked by semantic relevance, not static weight (a relevant
  low-weight result outranks an irrelevant high-weight one);
* unconfigured index → external-only, no regression;
* the ranker reuses vector.embed_text (no new embedding service).
"""

from __future__ import annotations

from pathlib import Path

import config
from owned_index import SearchHit
from search import ranking
from search.ranking import (
    _merge,
    merge_and_rank,
    semantic_rank,
)


def _kw_embedder(text):
    """Deterministic 'semantic' embedder: relevant iff it mentions 'bitcoin'."""
    if not text:
        return None
    return [1.0, 0.0] if "bitcoin" in text.lower() else [0.0, 1.0]


# ---------------------------------------------------------------------------
# Merge / dedup
# ---------------------------------------------------------------------------

def test_merge_dedups_by_url_and_enriches_snippet():
    external = [
        {"title": "Dup", "link": "http://dup.onion/", "source_engine": "ahmia"},
        {"title": "OnlyExt", "link": "http://ext.onion/", "source_engine": "torch"},
    ]
    owned = [
        {"link": "https://dup.onion", "snippet": "rich owned content", "source_engine": "owned_index"},
        {"link": "http://newowned.onion/", "title": "NewOwned", "source_engine": "owned_index"},
    ]
    merged = _merge(external, owned)
    links = [m["link"] for m in merged]
    # The dup onion (http vs https, trailing slash) collapses to one entry.
    assert "http://dup.onion/" in links
    assert "http://newowned.onion/" in links
    assert len(merged) == 3
    # The external dup entry is enriched with the owned index's snippet.
    dup = next(m for m in merged if m["link"] == "http://dup.onion/")
    assert dup["snippet"] == "rich owned content"


# ---------------------------------------------------------------------------
# Semantic ranking beats static weight (requirement 1.7 — point 4 of 1.8)
# ---------------------------------------------------------------------------

def test_semantic_rank_beats_static_weight():
    candidates = [
        {"title": "cooking recipes and gardening", "link": "http://hi.onion/", "source_weight": 0.9},
        {"title": "bitcoin mixing service", "link": "http://lo.onion/", "source_weight": 0.5},
    ]
    ranked = semantic_rank("bitcoin tumbler", candidates, embedder=_kw_embedder)
    # The semantically-relevant, LOW static-weight result ranks first.
    assert ranked[0]["link"] == "http://lo.onion/"
    assert ranked[0]["semantic_score"] > ranked[1]["semantic_score"]


def test_semantic_rank_empty_is_noop():
    assert semantic_rank("q", [], embedder=_kw_embedder) == []


def test_semantic_rank_falls_back_to_weight_when_embedder_unavailable():
    candidates = [
        {"title": "a", "link": "http://a.onion/", "source_weight": 0.3},
        {"title": "b", "link": "http://b.onion/", "source_weight": 0.9},
    ]
    # Embedder returns None for everything (model unavailable) → preserve the
    # prior static-weight ordering (no regression).
    ranked = semantic_rank("q", candidates, embedder=lambda t: None)
    assert [c["link"] for c in ranked] == ["http://b.onion/", "http://a.onion/"]


# ---------------------------------------------------------------------------
# merge_and_rank — the shared API/CLI entry point
# ---------------------------------------------------------------------------

async def _fake_owned(monkeypatch, hits):
    async def fake_search_index(query, **kwargs):
        return hits

    import owned_index

    monkeypatch.setattr(owned_index, "search_index", fake_search_index)


async def test_merge_and_rank_merges_owned_hits(monkeypatch):
    await _fake_owned(
        monkeypatch,
        [SearchHit(content_hash="a" * 64, url="http://owned.onion/", title="bitcoin market", snippet="bitcoin listings")],
    )
    external = [{"title": "unrelated forum", "link": "http://ext.onion/", "source_weight": 0.9}]
    ranked = await merge_and_rank("bitcoin", external, embedder=_kw_embedder)
    links = [r["link"] for r in ranked]
    assert "http://owned.onion/" in links and "http://ext.onion/" in links
    # The owned, on-topic hit outranks the irrelevant high-weight external one.
    assert ranked[0]["link"] == "http://owned.onion/"


async def test_survives_all_engines_failing(monkeypatch):
    """Requirement 1.5 acceptance: every external engine fails, owned index answers."""
    await _fake_owned(
        monkeypatch,
        [SearchHit(content_hash="b" * 64, url="http://owned.onion/", title="bitcoin", snippet="bitcoin")],
    )
    # External fan-out returned nothing (all engines down).
    ranked = await merge_and_rank("bitcoin", [], embedder=_kw_embedder)
    assert [r["link"] for r in ranked] == ["http://owned.onion/"]


async def test_unconfigured_index_is_external_only(monkeypatch):
    """Local/$0 install: no Meilisearch → external-only, no regression, no crash."""
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    external = [
        {"title": "bitcoin news", "link": "http://a.onion/", "source_weight": 0.5},
        {"title": "unrelated", "link": "http://b.onion/", "source_weight": 0.9},
    ]
    ranked = await merge_and_rank("bitcoin", external, embedder=_kw_embedder)
    assert {r["link"] for r in ranked} == {"http://a.onion/", "http://b.onion/"}
    assert ranked[0]["link"] == "http://a.onion/"  # relevant one still ranked first


# ---------------------------------------------------------------------------
# Integration: the CLI entry point (get_search_results_async) merges owned hits
# ---------------------------------------------------------------------------

async def test_get_search_results_async_merges_owned(monkeypatch):
    import search.search as search_mod

    async def fake_search_async(query, max_workers=10, llm_client=None, **kwargs):
        return [search_mod.EngineResult(name="ahmia", links=[{"title": "ext", "link": "http://ext.onion/"}])]

    monkeypatch.setattr(search_mod, "_search_async", fake_search_async)
    await _fake_owned(
        monkeypatch,
        [SearchHit(content_hash="c" * 64, url="http://owned.onion/", title="owned result", snippet="content")],
    )

    results = await __import__("asyncio").to_thread(
        search_mod.get_search_results_async, "bitcoin", 5, None
    )
    links = {r["link"] for r in results}
    assert links == {"http://ext.onion/", "http://owned.onion/"}


# ---------------------------------------------------------------------------
# Reuse: no new embedding service; API↔CLI both route through merge_and_rank
# ---------------------------------------------------------------------------

def test_ranking_reuses_vector_embedder():
    src = Path(ranking.__file__).read_text(encoding="utf-8")
    assert "from vector import embed_batch, embed_text" in src
    assert "sentence_transformers" not in src
    assert "SentenceTransformer" not in src


def test_both_search_paths_route_through_merge_and_rank():
    """API↔CLI parity: both call the one shared merge_and_rank."""
    root = Path(ranking.__file__).parent.parent
    cli = (root / "search" / "search.py").read_text(encoding="utf-8")
    api = (root / "api" / "routes" / "investigations.py").read_text(encoding="utf-8")
    assert "merge_and_rank" in cli
    assert "merge_and_rank" in api
