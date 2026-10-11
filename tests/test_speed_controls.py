"""Opt-in speed controls: search deadline, worker overrides, CLI page cap."""

from __future__ import annotations

import asyncio
import time

import pytest

from search import config as search_config
import search.search as search_mod


def test_search_deadline_unset_is_none(monkeypatch):
    monkeypatch.delenv("VOIDACCESS_SEARCH_DEADLINE", raising=False)
    assert search_config.search_deadline() is None


@pytest.mark.parametrize("raw,expected", [("12", 12.0), ("0", None), ("-3", None), ("abc", None), ("", None)])
def test_search_deadline_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("VOIDACCESS_SEARCH_DEADLINE", raw)
    assert search_config.search_deadline() == expected


def _patch_search(monkeypatch, delays):
    async def fake_fetch(engine, query, session, semaphore):
        await asyncio.sleep(delays[engine["name"]])
        return search_mod.EngineResult(name=engine["name"], links=[{"link": f"http://{engine['name']}.onion/", "title": "t"}])

    async def stats():
        return []

    async def skip(_name):
        return False

    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", stats)
    monkeypatch.setattr(search_mod, "should_skip_engine_async", skip)
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", lambda *a, **k: None)
    monkeypatch.setattr(search_mod, "get_engine_timeout", lambda stats: 30)
    monkeypatch.setattr(search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda key: None)


ENGINES = [
    {"name": "fast", "url": "http://fast.onion/?q={query}", "status": "active"},
    {"name": "slow", "url": "http://slow.onion/?q={query}", "status": "active"},
]


def test_search_deadline_returns_partial_results(monkeypatch):
    _patch_search(monkeypatch, {"fast": 0.05, "slow": 30})
    monkeypatch.setenv("VOIDACCESS_SEARCH_DEADLINE", "1")
    t0 = time.monotonic()
    results = asyncio.run(search_mod._search_async("q", engines=ENGINES, allow_diversify=False))
    assert time.monotonic() - t0 < 5
    by_name = {r.name: r for r in results}
    assert by_name["fast"].links and by_name["fast"].error is None
    assert by_name["slow"].error == "deadline" and not by_name["slow"].links


def test_search_without_deadline_waits_for_every_engine(monkeypatch):
    _patch_search(monkeypatch, {"fast": 0.05, "slow": 0.3})
    monkeypatch.delenv("VOIDACCESS_SEARCH_DEADLINE", raising=False)
    results = asyncio.run(search_mod._search_async("q", engines=ENGINES, allow_diversify=False))
    assert all(r.links and r.error is None for r in results)


def test_worker_env_overrides_depth_preset(monkeypatch):
    import voidaccess_cli.commands.investigate as inv

    preset = inv.DEPTH_PRESETS["shallow"]
    monkeypatch.delenv(inv.SCRAPE_WORKERS_ENV, raising=False)
    assert inv._preset_workers(preset, "max_workers", inv.SCRAPE_WORKERS_ENV) == preset["max_workers"]
    monkeypatch.setenv(inv.SCRAPE_WORKERS_ENV, "12")
    assert inv._preset_workers(preset, "max_workers", inv.SCRAPE_WORKERS_ENV) == 12
    monkeypatch.setenv(inv.SCRAPE_WORKERS_ENV, "nope")
    assert inv._preset_workers(preset, "max_workers", inv.SCRAPE_WORKERS_ENV) == preset["max_workers"]


def test_llm_page_cap_honours_env(monkeypatch):
    import voidaccess_cli.commands.investigate as inv

    monkeypatch.delenv("MAX_LLM_PAGES_PER_INV", raising=False)
    assert inv._max_llm_pages() == 10
    monkeypatch.setenv("MAX_LLM_PAGES_PER_INV", "3")
    assert inv._max_llm_pages() == 3


def test_enrichment_timeout_is_opt_in(monkeypatch):
    import voidaccess_cli.commands.investigate as inv

    monkeypatch.delenv("VOIDACCESS_ENRICHMENT_TIMEOUT", raising=False)
    assert inv._explicit_enrichment_timeout() is None
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_TIMEOUT", "25")
    assert inv._explicit_enrichment_timeout() == 25
