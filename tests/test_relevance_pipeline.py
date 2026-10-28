"""22R-7 / 22R-9: fallback marking, trace event, output block and Markdown (synthetic)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from progress import CallbackSink, ProgressEmitter
from progress import trace as tr
from tests.test_trace_events import _full_run, _validator


# --- 22R-7 ------------------------------------------------------------------------


def test_clearnet_filter_fallback_marks_pages():
    import voidaccess_cli.commands.investigate as inv
    from voidaccess.llm import FilterSelection

    pages = [{"url": f"https://example.test/{i}", "text": "body text " * 20, "title": f"t{i}"} for i in range(3)]
    fallback = FilterSelection([{"link": "https://example.test/0"}])
    fallback.fallback = True
    with patch("voidaccess.llm.filter_results", return_value=fallback):
        kept = inv._filter_clearnet_pages(pages, "q", 5, llm=object())
    assert [p["url"] for p in kept] == ["https://example.test/0"]
    assert all(p["via_fallback"] for p in kept)

    with patch("voidaccess.llm.filter_results", return_value=[]):
        kept = inv._filter_clearnet_pages(pages, "q", 5, llm=object())
    assert len(kept) == 3 and all(p["via_fallback"] for p in kept)

    usable = FilterSelection([{"link": "https://example.test/1"}])
    with patch("voidaccess.llm.filter_results", return_value=usable):
        kept = inv._filter_clearnet_pages(pages, "q", 5, llm=object())
    assert [p.get("via_fallback", False) for p in kept] == [False]


def test_filter_fallback_trace_event_has_counts_only_and_validates():
    got = []
    emitter = ProgressEmitter([CallbackSink(got.append)], trace=True)
    tr.bind(emitter)
    try:
        tr.filter_fallback("clearnet", 12, 12)
    finally:
        tr.bind(None)
        emitter.close()
    event = next(e for e in got if e.type == "trace")
    assert event.kind == "filter_fallback"
    assert event.data == {"scope": "clearnet", "candidates": 12, "kept": 12}
    _validator().validate(json.loads(json.dumps(event.to_dict())))


# --- 22R-9 output -------------------------------------------------------------------


@pytest.fixture(scope="module")
def run_output(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    try:
        tmp = tmp_path_factory.mktemp("relevance-full")
        _full_run(tmp, mp)
        out = next((tmp / "out").glob("*.json"))
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        mp.undo()


def test_output_has_relevance_block_and_fields(run_output):
    block = run_output["relevance"]
    assert block["query_intent"] == "named_threat"
    assert set(block["pages"]) == set(block["entities"]) == set(block["relationships"]) == {
        "direct", "related", "background"}
    assert sum(block["entities"].values()) == len(run_output["entities"])
    assert sum(block["relationships"].values()) == len(run_output["relationships"])
    assert sum(block["pages"].values()) == len(run_output["pages_scraped"])
    assert set(block["removed"]) == {"gazetteer_context", "org_boilerplate"}
    assert isinstance(block["feed_items_capped"], int)
    assert block["filter_fallback"] is False
    for e in run_output["entities"]:
        assert e["relevance"] in ("direct", "related", "background")
        assert isinstance(e["relevance_reason"], str) and e["relevance_reason"]
    for r in run_output["relationships"]:
        assert r["relevance"] in ("direct", "related", "background")
    for p in run_output["pages_scraped"]:
        assert p["relevance"] in ("direct", "related", "background")
        assert p["page_kind"] in (
            "directory", "search_portal", "market_listing", "forum_thread", "leak_post",
            "paste", "news_article", "feed_item", "other")
    # Existing fields keep their names and types.
    for key, typ in (("id", str), ("query", str), ("refined_query", str), ("summary", str),
                     ("entities", list), ("relationships", list), ("pages_scraped", list),
                     ("sources_used", dict), ("content_safety", dict), ("communities", dict)):
        assert isinstance(run_output[key], typ), key
    assert block["pages"]["direct"] >= 1  # the synthetic pages mention LockBit


def test_markdown_groups_entities_by_tier():
    import voidaccess_cli.commands.investigate as inv

    payload = {
        "query": "q", "created_at": "now", "summary": "s", "sources_used": {},
        "entities": [
            {"id": "1", "entity_type": "IP_ADDRESS", "value": "10.0.0.1", "confidence": 0.9, "relevance": "direct"},
            {"id": "2", "entity_type": "IP_ADDRESS", "value": "10.0.0.2", "confidence": 0.9, "relevance": "related"},
            {"id": "3", "entity_type": "DOMAIN", "value": "bg.example", "confidence": 0.9, "relevance": "background"},
        ],
        "relevance": {"query_intent": "topic", "pages": {"direct": 1, "related": 0, "background": 2},
                      "removed": {"gazetteer_context": 4, "org_boilerplate": 1}, "filter_fallback": False},
    }
    md = inv._render_markdown(payload)
    d, r, b = md.index("### Direct (1)"), md.index("### Related (1)"), md.index("## Background (1 entities")
    assert d < r < md.index("## Sources used") < b
    assert "- DOMAIN (1): bg.example" in md
    assert "4 common word(s) typed as threat names" in md
    # Without tiers (older payloads) the layout is unchanged.
    old = inv._render_markdown({**payload, "relevance": None})
    assert "### Direct" not in old and "## Background" not in old
