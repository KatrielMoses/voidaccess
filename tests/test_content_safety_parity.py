"""CLI/API content-safety parity and fail-closed gate tests (ENGINE E1)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from utils.content_safety import (
    CONTENT_BLOCKLIST,
    gate_pages,
    scan_page_text,
    url_is_blocked,
    entity_value_is_blocked,
)

# Test marker from existing content-safety integration tests (not real prohibited material).
_BLOCKED_MARKER = CONTENT_BLOCKLIST[0]


def _blocked_page_text() -> str:
    return ("benign context. " * 40) + f" {_BLOCKED_MARKER} " + ("more context. " * 40)


def _clean_page_text() -> str:
    return (
        "LockBit ransomware affiliate recruitment and leak site infrastructure "
        "discussion for defensive threat intelligence."
    )


# ---------------------------------------------------------------------------
# (c) Fail-closed gates
# ---------------------------------------------------------------------------


def test_scan_page_text_fail_closed_when_sanitize_raises(monkeypatch):
    def _boom(_text):
        raise RuntimeError("gate failure")

    monkeypatch.setattr("utils.content_safety.sanitize_content", _boom)
    clean, dropped = scan_page_text("http://example.onion/", "harmless")
    assert dropped is True
    assert clean == ""


def test_url_is_blocked_fail_closed_when_checker_raises(monkeypatch):
    monkeypatch.setattr(
        "utils.content_safety.is_blocked_url",
        lambda _url: (_ for _ in ()).throw(RuntimeError("url gate")),
    )
    assert url_is_blocked("http://example.onion/") is True


def test_entity_value_is_blocked_fail_closed_when_checker_raises(monkeypatch):
    monkeypatch.setattr(
        "utils.content_safety.is_blocked_entity_value",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("entity gate")),
    )
    assert entity_value_is_blocked("ORGANIZATION_NAME", "Acme Corp") is True


# ---------------------------------------------------------------------------
# (d) Clean-content parity
# ---------------------------------------------------------------------------


def test_gate_pages_preserves_clean_dict_pages():
    before = {"http://clean.onion/page": _clean_page_text()}
    after, dropped = gate_pages(dict(before))
    assert dropped == 0
    assert after == before


def test_gate_pages_preserves_clean_record_pages_for_extraction():
    before = [
        {
            "url": "http://clean.onion/page",
            "text": _clean_page_text(),
            "content": _clean_page_text(),
            "source": "tor_search",
        }
    ]
    after, dropped = gate_pages([dict(r) for r in before])
    assert dropped == 0
    assert after[0]["text"] == before[0]["text"]
    assert after[0]["content"] == before[0]["content"]


# ---------------------------------------------------------------------------
# (a) CLI path — blocked Tor page dropped before downstream use
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cli_scrape_multiple_skips_sqlite_pages_for_blocked_tor_page(
    db_engine, monkeypatch,
):
    """Blocked Tor text must not reach ``pages`` via scrape_multiple persistence."""
    from db.queries import get_page_by_url
    from db.session import get_session
    from scraper import scrape as scrape_module

    url = "http://cli-blocked-parity.onion/page"
    display = f"Title - {_blocked_page_text()}"
    db_text = _blocked_page_text()
    raw = b"<html>blocked</html>"

    async def _fake_gather(*_args, **_kwargs):
        return [(url, display, raw, db_text, None)]

    monkeypatch.setattr(scrape_module, "_gather_all", _fake_gather)
    monkeypatch.setattr(scrape_module, "validate_urls_for_scraping", lambda urls: (urls, []))

    result = await scrape_module.scrape_multiple([{"link": url, "title": "Title"}])
    assert url not in result

    with get_session() as session:
        assert get_page_by_url(session, url) is None


def test_cli_investigate_merge_drops_blocked_before_extraction_and_json():
    """Mirror CLI post-scrape ``gate_pages`` — blocked URLs never enter outputs."""
    blocked_url = "http://cli-json-block.onion/"
    pages = [
        {"url": blocked_url, "text": _blocked_page_text(), "source": "tor_search"},
        {"url": "http://clean.onion/", "text": _clean_page_text(), "source": "tor_search"},
    ]
    clean_pages, dropped = gate_pages(pages)
    assert dropped == 1
    assert all(p["url"] != blocked_url for p in clean_pages)

    json_manifest = [
        {"page_id": None, "url": p["url"], "source": p.get("source", "")}
        for p in clean_pages
    ]
    assert blocked_url not in {entry["url"] for entry in json_manifest}


@pytest.mark.asyncio
async def test_cli_vector_store_not_called_for_blocked_page(monkeypatch):
    stored: list[dict] = []
    monkeypatch.setattr(
        "vector.store.store_page",
        lambda **kwargs: stored.append(kwargs) or True,
    )
    pages, dropped = gate_pages(
        {"http://blocked-vector.onion/": _blocked_page_text()}
    )
    assert dropped == 1
    assert not pages
    for url, text in pages.items():
        if text and len(text) > 100:
            from vector.store import store_page

            store_page(url=url, content=text, metadata={"source": "scraper"})
    assert stored == []


# ---------------------------------------------------------------------------
# (b) API path — scan before vector cache and pages table
# ---------------------------------------------------------------------------


def test_api_gate_order_blocks_before_vector_cache_write(monkeypatch):
    """Reproduce API Step 5.75 → 5.5 ordering."""
    stored: list[str] = []
    freshly_scraped = {
        "http://api-blocked.onion/a": _blocked_page_text(),
        "http://api-clean.onion/b": _clean_page_text(),
    }
    scraped_pages = dict(freshly_scraped)
    scraped_pages, blocked_count = gate_pages(scraped_pages)
    assert blocked_count == 1

    for page_url, page_text in freshly_scraped.items():
        if page_url not in scraped_pages:
            continue
        if page_text and len(page_text) > 100:
            stored.append(page_url)

    assert stored == ["http://api-clean.onion/b"]


@pytest.mark.asyncio
async def test_api_scrape_pool_blocked_page_not_in_pages_table(db_engine, monkeypatch):
    from db.queries import get_page_by_url
    from db.session import get_session
    from scraper import scrape as scrape_module

    url = "http://api-pages-block.onion/x"
    row = (url, f"T - {_blocked_page_text()}", b"raw", _blocked_page_text(), None)

    async def _fake_gather(*_args, **_kwargs):
        return [row]

    monkeypatch.setattr(scrape_module, "_gather_all", _fake_gather)
    monkeypatch.setattr(scrape_module, "validate_urls_for_scraping", lambda urls: (urls, []))

    await scrape_module.scrape_multiple([{"link": url, "title": "T"}])
    with get_session() as session:
        assert get_page_by_url(session, url) is None


def test_api_side_source_records_gated_before_extraction():
    page_records = [
        {
            "url": "https://paste.example/raw/1",
            "text": _blocked_page_text(),
            "content": _blocked_page_text(),
            "source_type": "paste_site",
        },
        {
            "url": "https://paste.example/raw/2",
            "text": _clean_page_text(),
            "content": _clean_page_text(),
            "source_type": "paste_site",
        },
    ]
    safe_records, dropped = gate_pages(page_records)
    assert dropped == 1
    assert len(safe_records) == 1
    assert safe_records[0]["url"].endswith("/2")


# ---------------------------------------------------------------------------
# (e) VOIDACCESS_SAFETY_BYPASS_PROMPT=off
# ---------------------------------------------------------------------------


def _fake_llm(reply: str):
    """A real LangChain Runnable standing in for the model: records every prompt it receives."""
    from langchain_core.runnables import RunnableLambda

    captured: list[str] = []

    def _respond(prompt_value):
        captured.append(prompt_value.to_string())
        return reply

    return RunnableLambda(_respond), captured


def _prompts_sent(fn, reply, *args, **kwargs) -> str:
    llm, captured = _fake_llm(reply)
    fn(llm, *args, **kwargs)
    assert captured, f"{fn.__name__} never called the model"
    return "\n".join(captured)


_SUMMARY_PAGES = [{"url": "http://a.onion", "text": _clean_page_text() * 5}]


def _all_prompts(llm_mod) -> dict[str, str]:
    prompts = {
        "refine": _prompts_sent(llm_mod.refine_query, "lockbit", "lockbit ransomware"),
        "filter": _prompts_sent(
            llm_mod.filter_results, "[1]", "lockbit",
            [{"link": "http://a.onion", "title": "a"}], top_n=5,
        ),
    }
    for preset in llm_mod.PRESET_PROMPTS:
        prompts[f"summary:{preset}"] = _prompts_sent(
            llm_mod.generate_summary, "summary text", "lockbit", _SUMMARY_PAGES, preset=preset,
        )
    return prompts


def test_safety_bypass_prompt_off_removes_text_from_refine_filter_summary(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_SAFETY_BYPASS_PROMPT", "off")
    import voidaccess.llm as llm

    assert llm.safety_bypass_prompt_fragment() == ""
    for name, sent in _all_prompts(llm).items():
        assert "CRITICAL AUTHORIZATION" not in sent, name


def test_safety_bypass_prompt_on_retains_fragment(monkeypatch):
    monkeypatch.delenv("VOIDACCESS_SAFETY_BYPASS_PROMPT", raising=False)
    import voidaccess.llm as llm

    assert "CRITICAL AUTHORIZATION" in llm.safety_bypass_prompt_fragment()
    for name, sent in _all_prompts(llm).items():
        assert "CRITICAL AUTHORIZATION" in sent, name
