"""22R-3 (RSS relevance) and 22R-8 (summary prompts, content rule)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

import voidaccess.llm as llm_mod
from sources import rss_scraper
from sources.rss_scraper import RSS_RECENCY_ONLY_CAP, RSSFeedScraper
from utils.content_safety import detect_prohibited
from voidaccess import relevance
from voidaccess.query_intent import classify_query


def _date(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%a, %d %b %Y %H:%M:%S +0000")


@pytest.fixture(autouse=True)
def _intent():
    relevance.set_current_intent(None)
    yield
    relevance.set_current_intent(None)


def test_recency_alone_is_not_relevance():
    s = RSSFeedScraper()
    s._matcher = relevance.QueryMatcher(classify_query("LockBit ransomware"))
    recent_unrelated = {"title": "Patch Tuesday roundup", "summary": "Updates.", "published": _date(1)}
    generic_word = {"title": "New ransomware strain spotted", "summary": "Details.", "published": _date(1)}
    matching = {"title": "LockBit affiliate arrested", "summary": "x", "published": _date(40)}
    feed = {"tags": ["ransomware"], "weight": 10}
    assert s._score_article(recent_unrelated, ["lockbit", "ransomware"], feed) == 0
    assert s._score_article(generic_word, ["lockbit", "ransomware"], feed) == 0
    assert s._score_article(matching, ["lockbit", "ransomware"], feed) > 0


def test_recency_orders_matching_articles():
    s = RSSFeedScraper()
    s._matcher = relevance.QueryMatcher(classify_query("LockBit ransomware"))
    feed = {"tags": [], "weight": 5}
    new = s._score_article({"title": "LockBit news", "summary": "", "published": _date(1)}, ["lockbit"], feed)
    old = s._score_article({"title": "LockBit news", "summary": "", "published": _date(60)}, ["lockbit"], feed)
    assert new > old > 0


def test_recency_only_articles_are_capped_background_feed_items():
    relevance.set_current_intent(classify_query("zqxvjwk plorbtank"))
    rss_scraper.reset_run_stats()
    articles = [
        {"url": f"https://news.example/{i}", "title": f"Security story {i}", "summary": "news", "published": _date(1)}
        for i in range(9)
    ]
    feeds = [{"name": "Feed", "url": "https://news.example/feed", "weight": 5, "tags": []}]

    async def run():
        async with RSSFeedScraper() as s:
            s._cache = type("C", (), {"get": lambda self, u: None, "set": lambda self, u, a: None})()
            with (
                patch.object(s, "_fetch_and_parse", new=AsyncMock(return_value=articles)),
                patch.object(s, "_fetch_article_content", new=AsyncMock(return_value="Body text. " * 30)),
                patch.object(rss_scraper, "RSS_FEEDS", feeds),
            ):
                return await s.fetch_relevant_articles("zqxvjwk plorbtank")

    out = asyncio.run(run())
    assert len(out) == RSS_RECENCY_ONLY_CAP == 5
    assert all(p.get("recency_only") for p in out)
    assert rss_scraper.last_run_stats() == {"recency_only_kept": 5, "feed_items_capped": 4}
    pages = [{"url": p["url"], "text": p["text_content"], "source": "rss", "source_type": "rss_feed",
              "recency_only": True} for p in out]
    relevance.annotate_pages(pages, relevance.QueryMatcher(classify_query("zqxvjwk plorbtank")))
    assert {(p["relevance"], p["page_kind"]) for p in pages} == {("background", "feed_item")}


# --- prompts --------------------------------------------------------------------


def _all_prompt_templates() -> list[str]:
    prompts = [
        llm_mod.OSINT_SYSTEM_PROMPT,
        llm_mod.CONTENT_RULE,
        llm_mod.SAFETY_BYPASS_PROMPT,
        llm_mod._refine_system_prompt(),
        llm_mod._filter_system_prompt("example query", 10),
        *llm_mod.PRESET_PROMPTS.values(),
    ]
    for tiered in (False, True):
        for direct in (0, 3):
            prompts.append(llm_mod._summary_user_prompt(
                "example query", "", 3, "SOURCE: x\nCONTENT: y", tiered=tiered,
                direct_pages=direct, display="example",
            ))
    return prompts


def test_no_prompt_template_is_flagged_by_the_safety_detector():
    for prompt in _all_prompt_templates():
        assert detect_prohibited(prompt) is None, prompt[:120]


def test_content_rule_says_never_restate_it():
    assert "Never restate" in llm_mod.CONTENT_RULE
    assert llm_mod.CONTENT_RULE in llm_mod.OSINT_SYSTEM_PROMPT
    assert llm_mod.CONTENT_RULE in llm_mod._filter_system_prompt("q", 5)


def test_tiered_summary_prompt_rules():
    with_direct = llm_mod._summary_user_prompt("q", "", 2, "c", tiered=True, direct_pages=2, display="LockBit")
    assert "Lead with what the DIRECT pages say about LockBit" in with_direct
    assert "Never present BACKGROUND material as a finding" in with_direct
    none = llm_mod._summary_user_prompt("q", "", 2, "c", tiered=True, direct_pages=0, display="LockBit")
    assert "No collected page mentions LockBit directly" in none
    assert "do not repeat it" in none


def test_tiered_page_selection_puts_direct_first_and_labels_tiers():
    pages = [
        {"url": "b", "text": "background " * 40, "relevance": "background"},
        {"url": "r", "text": "related " * 40, "relevance": "related"},
        {"url": "d", "text": "direct " * 2000, "relevance": "direct"},
    ]
    picked = llm_mod._select_tiered_pages(pages, max_chars=6000)
    assert [p["url"] for p in picked][0] == "d"
    assert len(picked[0]["_summary_text"]) <= 6000

    from langchain_core.runnables import RunnableLambda

    seen: dict = {}

    def fake_llm(prompt_value):
        seen["prompt"] = prompt_value.to_string()
        return "ok"

    pages[2]["text"] = "direct " * 500
    out = llm_mod.generate_summary(
        RunnableLambda(fake_llm), "q", pages, relevance_intent=classify_query("LockBit")
    )
    assert out == "ok"
    assert "RELEVANCE: DIRECT" in seen["prompt"]
    assert seen["prompt"].index("RELEVANCE: DIRECT") < seen["prompt"].index("RELEVANCE: RELATED")


def test_filter_results_marks_unusable_llm_output_as_fallback():
    results = [{"link": f"http://x{i}.onion", "title": f"t{i}"} for i in range(5)]
    with patch.object(llm_mod, "ChatPromptTemplate") as tpl:
        chain = tpl.return_value.__or__.return_value.__or__.return_value
        chain.invoke.return_value = "I cannot help with that."
        picked = llm_mod.filter_results(object(), "q", results, 3)
        assert picked.fallback is True and len(picked) == 3
        chain.invoke.return_value = "[2, 4]"
        picked = llm_mod.filter_results(object(), "q", results, 3)
        assert picked.fallback is False and [p["title"] for p in picked] == ["t1", "t3"]
