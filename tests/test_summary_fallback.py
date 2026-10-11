"""Summary phase: timeout -> reduced-context retry -> deterministic fallback."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from voidaccess.summary_fallback import build_fallback_summary


def test_fallback_summary_uses_top_entities_and_sources_only():
    entities = [
        {"entity_type": "RANSOMWARE_GROUP", "value": "LockBit", "confidence": 0.9},
        {"entity_type": "RANSOMWARE_GROUP", "value": "Royal", "confidence": 0.5},
        {"entity_type": "CVE", "value": "CVE-2023-4966", "confidence": 0.8},
        {"entity_type": "EMAIL", "value": "victim@example.com", "confidence": 1.0},
        {"entity_type": "PASSWORD", "value": "hunter2", "confidence": 1.0},
        {"entity_type": "DOMAIN", "value": "hidden.example", "confidence": 0.7, "suppressed": True},
    ]
    pages = [{"url": "http://a.onion/x"}, {"url": "http://a.onion/x"}, {"url": "http://b.onion/y"}]
    text = build_fallback_summary("lockbit", entities, pages)
    assert "LockBit" in text and "CVE-2023-4966" in text
    assert text.index("LockBit") < text.index("Royal")
    assert "victim@example.com" not in text and "hunter2" not in text
    assert "hidden.example" not in text
    assert text.count("http://a.onion/x") == 1 and "http://b.onion/y" in text
    assert text.strip()


def test_fallback_summary_never_empty_with_no_entities():
    assert build_fallback_summary("q", [], [{"url": "http://a.onion/x"}]).strip()


def _run(tmp_path, monkeypatch, generate_summary, summary_timeout="3"):
    import voidaccess.llm as llm_mod
    import voidaccess_cli.commands.investigate as inv
    import db.session as session_module

    db_path = tmp_path / "inv.db"
    monkeypatch.setenv("VOIDACCESS_DB_PATH", str(db_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("VOIDACCESS_PRIVATE_MODE", "1")
    monkeypatch.setenv("VOIDACCESS_SUMMARY_TIMEOUT", summary_timeout)
    monkeypatch.setattr(session_module, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    session_module._get_engine_cached.cache_clear()
    monkeypatch.setitem(inv.CLI_PHASE_TIMEOUTS, "summary", int(summary_timeout))

    async def _none(_q):
        return []

    async def _page(_q):
        return [{
            "url": "https://example.com/lockbit-report",
            "text": "LockBit ransomware exploited CVE-2023-4966 against many organisations. " * 20,
            "source": "rss", "source_type": "rss_feed", "title": "LockBit report",
        }]

    for name in ("_scrape_pastes", "_scrape_github", "_scrape_gitlab"):
        monkeypatch.setattr(inv, name, _none)
    monkeypatch.setattr(inv, "_scrape_rss", _page)

    async def _no_enrich(*_a, **_k):
        return []

    monkeypatch.setattr("sources.enrichment.enrich_investigation", _no_enrich)
    monkeypatch.setattr(llm_mod, "get_llm", lambda *a, **k: object())
    monkeypatch.setattr(llm_mod, "refine_query", lambda llm, q: q)
    monkeypatch.setattr(llm_mod, "filter_results", lambda llm, q, links, n=15: links)
    monkeypatch.setattr(llm_mod, "generate_summary", generate_summary)
    monkeypatch.setattr(inv, "_filter_clearnet_pages", lambda pages, q, n, llm: pages)

    import extractor.pipeline as pipeline

    real = pipeline.extract_entities_from_pages

    async def _extract(*a, **k):
        k["run_llm_extraction"] = False
        return await real(*a, **k)

    monkeypatch.setattr(pipeline, "extract_entities_from_pages", _extract)

    from voidaccess_cli import config as cli_config

    monkeypatch.setattr(cli_config, "get_llm_key", lambda cfg: "k")
    asyncio.run(
        inv._run_investigation(
            query="lockbit ransomware", out_dir=tmp_path, model="m", no_tor=True,
            no_llm=False, depth="shallow", fmt="json", quiet=True,
        )
    )
    session_module._get_engine_cached.cache_clear()
    return json.loads(next(tmp_path.glob("*.json")).read_text())


def test_cli_summary_success_is_marked_llm(tmp_path, monkeypatch):
    payload = _run(tmp_path, monkeypatch, lambda llm, q, pages, *a, **k: "A real summary.")
    assert payload["summary"] == "A real summary."
    assert payload["summary_kind"] == "llm"


def test_cli_summary_timeout_retries_with_reduced_context(tmp_path, monkeypatch):
    calls = []

    def gen(llm, q, pages, *a, **k):
        calls.append((len(pages), k.get("max_summary_chars")))
        if len(calls) == 1:
            time.sleep(4)
            return "late"
        return "Retry summary."

    payload = _run(tmp_path, monkeypatch, gen, summary_timeout="3")
    assert payload["summary"] == "Retry summary."
    assert payload["summary_kind"] == "llm"
    assert len(calls) == 2 and calls[1][1] is not None


def test_cli_summary_total_failure_produces_fallback(tmp_path, monkeypatch):
    def gen(llm, q, pages, *a, **k):
        raise RuntimeError("provider down")

    payload = _run(tmp_path, monkeypatch, gen)
    assert payload["summary_kind"] == "fallback"
    assert payload["summary"].strip()
    assert "LockBit" in payload["summary"]
