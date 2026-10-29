"""22S-1: retrieval precision. Search results that name the query are fetched
first, and the user's own words (or the selector) go to every engine next to
the refined query. Synthetic titles and URLs only; no network."""

from __future__ import annotations

import asyncio

import pytest

from search import precision as pr
from voidaccess.query_intent import classify_query
from voidaccess.relevance import QueryMatcher


def _matcher(query: str, refined: str = "") -> QueryMatcher:
    return QueryMatcher(classify_query(query), refined or query)


def _r(title: str, link: str, **extra) -> dict:
    return {"title": title, "link": link, **extra}


# --------------------------------------------------------------------------- #
# candidate_tier / candidate_text
# --------------------------------------------------------------------------- #


def test_title_match_is_direct():
    m = _matcher("LockBit ransomware")
    assert pr.candidate_tier(_r("LockBit 3.0 affiliate notes", "http://a.onion/"), m) == "direct"


def test_url_path_match_is_direct():
    m = _matcher("Lumma Stealer malware")
    item = _r("Forum thread", "http://b.onion/threads/lumma-stealer-logs.123/")
    assert pr.candidate_tier(item, m) == "direct"


def test_url_encoded_selector_is_direct():
    m = _matcher("jdoe1987@gmail.com")
    item = _r("results", "http://c.onion/search?q=jdoe1987%40gmail.com")
    assert pr.candidate_tier(item, m) == "direct"


def test_snippet_match_is_direct():
    m = _matcher("CVE-2024-3400")
    item = _r("Exploit index", "http://d.onion/", snippet="PoC for CVE-2024-3400 in a firewall")
    assert pr.candidate_tier(item, m) == "direct"


def test_unrelated_result_is_none():
    m = _matcher("LockBit ransomware")
    assert pr.candidate_tier(_r("Hidden Wiki links", "http://e.onion/"), m) == "none"
    # A different group whose name contains the letters is not a match.
    assert pr.candidate_tier(_r("blockbit market", "http://f.onion/"), m) == "none"


def test_related_term_is_related():
    m = _matcher("initial access broker")
    item = _r("Trusted broker for corporate networks", "http://g.onion/")
    assert pr.candidate_tier(item, m) == "related"


def test_no_matcher_or_bad_item_is_none():
    assert pr.candidate_tier(_r("LockBit", "http://a.onion/"), None) == "none"
    assert pr.candidate_tier({}, _matcher("LockBit")) == "none"
    assert pr.candidate_text("not a dict") == ""  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# tier_sort / precision_order
# --------------------------------------------------------------------------- #


def test_tier_sort_is_stable_inside_tiers():
    m = _matcher("LockBit ransomware")
    items = [
        _r("generic 1", "http://g1.onion/"),
        _r("LockBit leak A", "http://l1.onion/"),
        _r("generic 2", "http://g2.onion/"),
        _r("LockBit leak B", "http://l2.onion/"),
    ]
    out = pr.tier_sort(items, m)
    assert [i["link"] for i in out] == [
        "http://l1.onion/", "http://l2.onion/", "http://g1.onion/", "http://g2.onion/",
    ]
    assert pr.tier_sort(items, None) == items


def test_precision_order_puts_direct_picks_first_and_keeps_count():
    m = _matcher("LockBit ransomware")
    cands = [_r(f"generic {i}", f"http://g{i}.onion/") for i in range(6)]
    cands.insert(4, _r("LockBit victims list", "http://lb.onion/"))
    picked = cands[:]  # the filter kept everything, in engine order
    ranked, counts = pr.precision_order(cands, picked, m)
    assert ranked[0]["link"] == "http://lb.onion/"
    assert len(ranked) == len(picked)  # same number of candidates: no extra fetches
    assert counts["direct"] == 1 and counts["none"] == 6 and counts["promoted"] == 0


def test_precision_order_promotes_unpicked_direct_after_picked_direct():
    m = _matcher("LockBit ransomware")
    a = _r("LockBit panel", "http://a.onion/")
    b = _r("generic", "http://b.onion/")
    c = _r("LockBit 3.0 blog", "http://c.onion/")
    d = _r("other generic", "http://d.onion/")
    ranked, counts = pr.precision_order([a, b, c, d], [b, c], m)
    # picked direct (c), then unpicked direct (a), then the other picks (b)
    assert [i["link"] for i in ranked] == ["http://c.onion/", "http://a.onion/", "http://b.onion/"]
    assert counts["promoted"] == 1


def test_precision_order_never_promotes_a_sensitive_name(monkeypatch):
    import progress.trace as tr

    monkeypatch.setattr(tr, "is_sensitive_name", lambda text: "MARKER" in (text or ""))
    m = _matcher("LockBit ransomware")
    flagged = _r("LockBit MARKER", "http://x.onion/")
    ok = _r("LockBit notes", "http://y.onion/")
    ranked, counts = pr.precision_order([flagged, ok], [], m)
    assert [i["link"] for i in ranked] == ["http://y.onion/"]
    assert counts["promoted"] == 1


def test_precision_order_can_skip_promotion():
    m = _matcher("LockBit ransomware")
    a = _r("LockBit panel", "http://a.onion/")
    ranked, _ = pr.precision_order([a], [], m, promote_unpicked=False)
    assert ranked == []


def test_precision_order_without_matcher_returns_picks():
    picks = [_r("x", "http://x.onion/")]
    assert pr.precision_order(picks, picks, None)[0] == picks


# --------------------------------------------------------------------------- #
# exact query
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("query, refined, expected", [
    ("Lumma Stealer malware", "Lumma Stealer darkweb", "Lumma Stealer malware"),
    ("acme.com credentials leak", "acme.com leaked credentials", "acme.com"),
    ("jdoe1987@gmail.com", "jdoe1987@gmail.com breach", "jdoe1987@gmail.com"),
    ("CVE-2024-3400", "CVE-2024-3400 exploit", "CVE-2024-3400"),
    ("John Smith", "john smith", None),            # same words: nothing to add
    ("RedLine stealer", "RedLine  Stealer!", None),  # punctuation/case only
])
def test_exact_query(query, refined, expected):
    assert pr.exact_query(classify_query(query), refined) == expected


def test_exact_query_without_intent():
    assert pr.exact_query(None, "x") is None


def test_matching_filter_keeps_only_matches():
    keep = pr.matching_filter(_matcher("Lumma Stealer malware"))
    assert keep(_r("Lumma logs for sale", "http://a.onion/"))
    assert not keep(_r("Hidden services list", "http://b.onion/"))


def test_count_tiers():
    m = _matcher("LockBit ransomware")
    items = [_r("LockBit", "http://a.onion/"), _r("x", "http://b.onion/")]
    assert pr.count_tiers(items, m) == {"direct": 1, "related": 0, "none": 1}


# --------------------------------------------------------------------------- #
# search fan-out with the exact query
# --------------------------------------------------------------------------- #


def _fake_fanout(calls: list, by_query: dict):
    import search.search as search_mod

    async def fake_search_async(query, max_workers=10, llm_client=None, **kwargs):
        calls.append((query, kwargs))
        if kwargs.get("record_summary", True):
            search_mod._LAST_SEARCH_SUMMARY = {"results": len(by_query.get(query, [])), "who": query}
        return [search_mod.EngineResult(name="engine", links=[dict(l) for l in by_query.get(query, [])])]

    return fake_search_async


async def _no_rank(query, links):
    return links


def test_exact_query_fanout_adds_only_matching_results(monkeypatch):
    import search.ranking as ranking
    import search.search as search_mod

    by_query = {
        "Lumma Stealer darkweb": [_r("generic", "http://g.onion/")],
        "Lumma Stealer malware": [
            _r("Lumma builder thread", "http://l.onion/"),
            _r("unrelated directory", "http://u.onion/"),
            _r("generic", "http://g.onion/"),  # duplicate of a refined-query hit
        ],
    }
    calls: list = []
    monkeypatch.setattr(search_mod, "_search_async", _fake_fanout(calls, by_query))
    monkeypatch.setattr(ranking, "merge_and_rank", _no_rank)
    keep = pr.matching_filter(_matcher("Lumma Stealer malware", "Lumma Stealer darkweb"))

    out = search_mod.get_search_results_async(
        "Lumma Stealer darkweb", 4, None, "Lumma Stealer malware", keep
    )
    assert [r["link"] for r in out] == ["http://g.onion/", "http://l.onion/"]
    # Both queries were sent; the exact one never diversifies and never
    # overwrites the refined query's summary.
    queries = {q: kw for q, kw in calls}
    assert set(queries) == {"Lumma Stealer darkweb", "Lumma Stealer malware"}
    assert queries["Lumma Stealer malware"]["allow_diversify"] is False
    assert queries["Lumma Stealer malware"]["record_summary"] is False
    assert queries["Lumma Stealer malware"]["query_index"] == search_mod.EXACT_QUERY_INDEX
    assert search_mod.get_last_search_summary()["who"] == "Lumma Stealer darkweb"


def test_no_exact_query_means_one_fanout(monkeypatch):
    import search.ranking as ranking
    import search.search as search_mod

    calls: list = []
    monkeypatch.setattr(
        search_mod, "_search_async", _fake_fanout(calls, {"q": [_r("a", "http://a.onion/")]})
    )
    monkeypatch.setattr(ranking, "merge_and_rank", _no_rank)
    out = search_mod.get_search_results_async("q", 4, None)
    assert len(calls) == 1 and [r["link"] for r in out] == ["http://a.onion/"]


def test_failing_exact_fanout_keeps_refined_results(monkeypatch):
    import search.ranking as ranking
    import search.search as search_mod

    async def fake_search_async(query, max_workers=10, llm_client=None, **kwargs):
        if query == "exact":
            raise RuntimeError("boom")
        return [search_mod.EngineResult(name="e", links=[_r("a", "http://a.onion/")])]

    monkeypatch.setattr(search_mod, "_search_async", fake_search_async)
    monkeypatch.setattr(ranking, "merge_and_rank", _no_rank)
    out = search_mod.get_search_results_async("refined", 4, None, "exact", None)
    assert [r["link"] for r in out] == ["http://a.onion/"]


def test_exact_fanout_runs_concurrently(monkeypatch):
    """Both fan-outs overlap, so the search stage takes no longer."""
    import time

    import search.ranking as ranking
    import search.search as search_mod

    async def slow(query, max_workers=10, llm_client=None, **kwargs):
        await asyncio.sleep(0.3)
        return []

    monkeypatch.setattr(search_mod, "_search_async", slow)
    monkeypatch.setattr(ranking, "merge_and_rank", _no_rank)
    t = time.monotonic()
    search_mod.get_search_results_async("refined", 4, None, "exact", None)
    assert time.monotonic() - t < 0.55


# --------------------------------------------------------------------------- #
# The investigate pipeline wires it in
# --------------------------------------------------------------------------- #


def test_investigate_wires_precision_into_search_and_filter():
    from pathlib import Path

    import voidaccess_cli.commands.investigate as inv

    src = Path(inv.__file__).read_text(encoding="utf-8")
    assert "exact_query(query_intent, refined)" in src
    assert "matching_filter(precision_matcher)" in src
    assert src.count("precision_order(") >= 3  # LLM, LLM-error and heuristic paths
    assert "tier_sort(search_links" in src
    assert "_scrape_github(github_query)" in src
