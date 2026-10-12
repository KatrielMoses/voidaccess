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


# ---------------------------------------------------------------------------
# E1C / C1: generate_summary raises SummaryUnavailable; callers retry then fall back
# ---------------------------------------------------------------------------

SECRET = "sk-live-PROVIDER-SECRET-999"


def test_cli_summary_unavailable_retries_once_then_falls_back(tmp_path, monkeypatch):
    from voidaccess.llm import SummaryUnavailable

    calls = []

    def gen(llm, q, pages, *a, **k):
        calls.append(k.get("max_summary_chars"))
        raise SummaryUnavailable("llm_error") from RuntimeError(f"provider said {SECRET}")

    payload = _run(tmp_path, monkeypatch, gen)
    assert len(calls) == 2 and calls[0] is None and calls[1] is not None  # reduced context
    assert payload["summary_kind"] == "fallback"
    assert "LockBit" in payload["summary"]
    # A failed LLM never surfaces as llm, and no raw exception text is user-facing.
    assert "Summary unavailable" not in payload["summary"]
    assert SECRET not in json.dumps(payload)


def test_cli_summary_unavailable_then_retry_success_is_llm(tmp_path, monkeypatch):
    from voidaccess.llm import SummaryUnavailable

    calls = []

    def gen(llm, q, pages, *a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise SummaryUnavailable("llm_error")
        return "Recovered summary."

    payload = _run(tmp_path, monkeypatch, gen)
    assert payload["summary"] == "Recovered summary."
    assert payload["summary_kind"] == "llm"


def test_cli_summary_kind_none_when_llm_disabled(tmp_path, monkeypatch):
    from tests import e1c_harness as h

    inv = h.prepare(tmp_path, monkeypatch)
    h.run(inv, tmp_path, no_llm=True)
    payload = h.read_payload(tmp_path)
    assert payload["summary_kind"] == "none"


def test_cli_empty_llm_text_is_not_marked_llm(tmp_path, monkeypatch):
    payload = _run(tmp_path, monkeypatch, lambda llm, q, pages, *a, **k: "   ")
    assert payload["summary_kind"] == "fallback"


def test_cli_progress_never_shows_raw_exception(tmp_path, monkeypatch, capfd):
    """The display line for a failed summary is generic, not the exception text."""
    def gen(llm, q, pages, *a, **k):
        raise RuntimeError(f"provider said {SECRET}")

    from tests import e1c_harness as h

    inv = h.prepare(tmp_path, monkeypatch, generate_summary=gen)
    h.run(inv, tmp_path, quiet=False)
    out = capfd.readouterr()
    assert SECRET not in out.out + out.err


def test_summarize_with_fallback_no_pages_is_none():
    from voidaccess.summary_fallback import summarize_with_fallback

    async def call(pages, **kw):  # pragma: no cover - must not be called
        raise AssertionError("no LLM call without pages")

    outcome = asyncio.run(
        summarize_with_fallback(call, [], query="q", budget_s=5, fallback_entities=lambda: [])
    )
    assert outcome.kind == "none" and outcome.text == "" and outcome.attempts == 0


def test_summarize_with_fallback_failure_reports_class_name_only():
    from voidaccess.llm import SummaryUnavailable
    from voidaccess.summary_fallback import summarize_with_fallback

    async def call(pages, **kw):
        raise SummaryUnavailable("llm_error") from RuntimeError(SECRET)

    outcome = asyncio.run(
        summarize_with_fallback(
            call,
            [{"url": "http://a.onion/x", "text": "t"}],
            query="q",
            budget_s=5,
            fallback_entities=lambda: [{"entity_type": "CVE", "value": "CVE-2023-4966"}],
        )
    )
    assert outcome.kind == "fallback" and outcome.attempts == 2
    assert outcome.failure == "SummaryUnavailable"
    assert SECRET not in outcome.text and "CVE-2023-4966" in outcome.text


def test_api_summary_phase_falls_back_without_exception_text(monkeypatch):
    """The API path: failed LLM -> retry -> deterministic fallback, no raw text."""
    import api.routes.investigations as api
    import voidaccess.llm as llm_mod
    from voidaccess.llm import SummaryUnavailable

    calls = []

    def gen(llm, query, content, entities=None, **k):
        calls.append(k.get("max_summary_chars"))
        raise SummaryUnavailable("llm_error") from RuntimeError(f"provider said {SECRET}")

    monkeypatch.setattr(llm_mod, "generate_summary", gen)

    class _Result:
        entities = [
            {"entity_type": "RANSOMWARE_GROUP", "value": "LockBit", "confidence": 0.9},
        ]

    import uuid

    text = asyncio.run(
        api._generate_summary_phase(
            [_Result()],
            [{"url": "http://a.onion/x", "text": "LockBit ransomware", "content": "LockBit ransomware"}],
            "lockbit",
            object(),
            uuid.uuid4(),
            "inv-1",
            1,
            1,
        )
    )
    assert len(calls) == 2 and calls[1] is not None
    assert "LockBit" in text
    assert SECRET not in text and "Summary unavailable" not in text


def test_api_summary_phase_success_returns_llm_text(monkeypatch):
    import uuid

    import api.routes.investigations as api
    import voidaccess.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "generate_summary", lambda llm, query, content, entities=None, **k: "API summary."
    )
    text = asyncio.run(
        api._generate_summary_phase(
            [], [{"url": "http://a.onion/x", "text": "x", "content": "x"}],
            "q", object(), uuid.uuid4(), "inv-1", 1, 0,
        )
    )
    assert text == "API summary."
