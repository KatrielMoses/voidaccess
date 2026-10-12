"""Cooperative cancel checkpoints inside the long stages (E1C / C4)."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from tests import e1c_harness as h
from utils import cancel

REPO = Path(__file__).resolve().parent.parent

# scraper.scrape._gather_all runs clearnet fetches under Semaphore(15).
SCRAPE_CLEARNET_CONCURRENCY = 15


# --------------------------------------------------------------------------- #
# The shared helper
# --------------------------------------------------------------------------- #
def test_pipeline_cancelled_is_not_swallowed_by_except_exception():
    """The pipeline is full of ``except Exception``; a cancel must pass through."""
    token = cancel.CancelToken()
    cancel.set_current(token)
    token.cancel("test")

    def stage():
        try:
            cancel.checkpoint("stage")
        except Exception:  # noqa: BLE001 - this is exactly what must not catch it
            return "swallowed"

    with pytest.raises(cancel.PipelineCancelled) as excinfo:
        stage()
    assert excinfo.value.checkpoint == "stage"
    assert not isinstance(excinfo.value, Exception)


def test_no_active_token_means_no_cancellation():
    assert cancel.current() is None
    assert cancel.is_cancelled() is False
    cancel.checkpoint("anything")  # a no-op


def test_token_is_visible_from_threads_and_other_loops_when_process_wide():
    token = cancel.CancelToken()
    cancel.set_current(token, process_wide=True)
    seen = []

    import threading

    def worker():
        seen.append(cancel.is_cancelled())

    token.cancel()
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen == [True]


def test_wait_cancellable_returns_early_on_cancel(monkeypatch):
    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    token = cancel.CancelToken()
    cancel.set_current(token)

    async def go():
        tasks = {asyncio.ensure_future(asyncio.sleep(30)), asyncio.ensure_future(asyncio.sleep(0))}
        asyncio.get_running_loop().call_later(0.1, token.cancel)
        started = time.monotonic()
        done, pending = await cancel.wait_cancellable(tasks, timeout=None)
        elapsed = time.monotonic() - started
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return done, pending, elapsed

    done, pending, elapsed = asyncio.run(go())
    assert len(done) == 1 and len(pending) == 1
    assert elapsed < 1.0


def test_run_cancellable_gives_grace_then_stops(monkeypatch):
    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    monkeypatch.setenv(cancel.CANCEL_GRACE_ENV, "0.15")
    token = cancel.CancelToken()
    cancel.set_current(token)
    finished = []

    async def slow():
        try:
            await asyncio.sleep(30)
            finished.append("done")
        except asyncio.CancelledError:
            finished.append("stopped")
            raise

    async def go():
        asyncio.get_running_loop().call_later(0.05, token.cancel)
        started = time.monotonic()
        with pytest.raises(cancel.PipelineCancelled) as excinfo:
            await cancel.run_cancellable(slow(), "fetch")
        return time.monotonic() - started, excinfo.value.checkpoint

    elapsed, checkpoint = asyncio.run(go())
    assert finished == ["stopped"]
    assert checkpoint == "fetch"
    assert elapsed < 2.0  # ~ cancel (0.05) + grace (0.15), not the 30 s sleep


def test_run_cancellable_lets_a_fast_item_finish_within_grace(monkeypatch):
    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    monkeypatch.setenv(cancel.CANCEL_GRACE_ENV, "2")
    token = cancel.CancelToken()
    cancel.set_current(token)
    finished = []

    async def quick():
        await asyncio.sleep(0.2)
        finished.append("done")
        return 1

    async def go():
        asyncio.get_running_loop().call_later(0.05, token.cancel)
        with pytest.raises(cancel.PipelineCancelled):
            await cancel.run_cancellable(quick(), "fetch")

    asyncio.run(go())
    assert finished == ["done"]  # the current item finished, then the stage stopped


def test_run_cancellable_without_a_token_is_a_plain_await():
    async def work():
        return 7

    assert asyncio.run(cancel.run_cancellable(work(), "x")) == 7


# --------------------------------------------------------------------------- #
# Between pages in fetch and scrape: 50 slow pages, cancelled mid-stage
# --------------------------------------------------------------------------- #
class _Content:
    async def iter_chunked(self, _n):
        yield b"<html><body><p>" + b"LockBit ransomware report. " * 30 + b"</p></body></html>"


class _FetchResp:
    status = 200
    headers = {"Content-Type": "text/html"}
    charset = "utf-8"
    content = _Content()


class _SlowSession:
    """Counts fetches and cancels the token when the *cancel_after*-th one starts."""

    def __init__(self, token, delay, cancel_after):
        self.token, self.delay, self.cancel_after = token, delay, cancel_after
        self.started = 0

    def get(self, url, **kw):
        session = self

        class _CM:
            async def __aenter__(self_inner):
                session.started += 1
                if session.started == session.cancel_after:
                    session.token.cancel("test")
                await asyncio.sleep(session.delay)
                return _FetchResp()

            async def __aexit__(self_inner, *exc):
                return False

        return _CM()


def _patch_scraper(monkeypatch, session):
    import scraper.scrape as scrape

    monkeypatch.setattr(scrape, "get_direct_session_cached", lambda: session)
    monkeypatch.setattr(scrape, "is_safe_url", lambda url: True)
    monkeypatch.setattr(scrape, "validate_urls_for_scraping", lambda items: (items, []))
    monkeypatch.setattr(scrape, "_persist_pages", lambda items: None)
    return scrape


def _links(n):
    return [{"link": f"https://example.com/page-{i}", "title": f"page {i}"} for i in range(n)]


def test_scrape_of_50_slow_pages_stops_at_the_cancel(monkeypatch):
    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    token = cancel.CancelToken()
    cancel.set_current(token)
    session = _SlowSession(token, delay=0.1, cancel_after=20)
    scrape = _patch_scraper(monkeypatch, session)

    async def go():
        started = time.monotonic()
        results = await scrape.scrape_multiple(_links(50), max_workers=5)
        return results, time.monotonic() - started

    results, elapsed = asyncio.run(go())

    # Within one item: only fetches already in flight when the cancel landed
    # (at most one concurrency window of 15) finish; nothing queued behind them
    # starts.
    assert 20 <= session.started <= 20 + SCRAPE_CLEARNET_CONCURRENCY
    assert session.started < 50
    # Failed/skipped pages carry only their title; real pages carry the body.
    fetched = sum(1 for text in results.values() if "LockBit ransomware report" in text)
    assert fetched == session.started
    # A full run is 4 waves of 15 at 0.1 s; a cancelled one is cut short.
    assert elapsed < 0.1 * 4


def test_scrape_without_a_cancel_fetches_every_page(monkeypatch):
    """Self-hosters / no token: behaviour is unchanged."""
    token = cancel.CancelToken()  # never cancelled, never set as current
    session = _SlowSession(token, delay=0.0, cancel_after=-1)
    scrape = _patch_scraper(monkeypatch, session)

    results = asyncio.run(scrape.scrape_multiple(_links(50), max_workers=5))
    assert session.started == 50
    assert sum(1 for text in results.values() if "LockBit ransomware report" in text) == 50


# --------------------------------------------------------------------------- #
# Between engines in the search fan-out
# --------------------------------------------------------------------------- #
def test_search_fan_out_skips_engines_after_a_cancel(monkeypatch):
    import search.search as search_mod

    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    monkeypatch.setenv(cancel.CANCEL_GRACE_ENV, "0.1")
    token = cancel.CancelToken()
    cancel.set_current(token)

    engines = [{"name": f"e{i}", "url": f"http://e{i}.onion/?q={{query}}"} for i in range(8)]
    attempted: list[str] = []
    recorded: list[str] = []

    async def fake_fetch(engine, query, session, semaphore):
        async with semaphore:
            attempted.append(engine["name"])
            if len(attempted) == 2:
                token.cancel("test")
            await asyncio.sleep(0.05)
            return search_mod.EngineResult(name=engine["name"], links=[{"link": "http://x.onion"}])

    async def no_stats():
        return []

    async def never_skip(_name):
        return False

    def record(name, success, n, took_ms):
        recorded.append(name)
        return None

    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", no_stats)
    monkeypatch.setattr(search_mod, "should_skip_engine_async", never_skip)
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", record)
    monkeypatch.setattr(
        search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k")
    )
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda k: None)

    results = asyncio.run(
        search_mod._search_async("lockbit", max_workers=1, engines=engines, allow_diversify=False)
    )

    # max_workers=1 serialises the engines, so a cancel after the 2nd stops the rest.
    assert len(attempted) < len(engines)
    cancelled = [r for r in results if r.error == "cancelled"]
    assert cancelled, "engines that never ran are reported as cancelled"
    # A cancel is not an engine failure: nothing cancelled is recorded against
    # the circuit breaker.
    assert not set(recorded) & {r.name for r in cancelled}


# --------------------------------------------------------------------------- #
# Between sources in enrichment
# --------------------------------------------------------------------------- #
def test_enrichment_keeps_finished_sources_and_stops_the_rest(monkeypatch):
    from sources.enrichment import _gather_with_partial_results

    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    token = cancel.CancelToken()
    cancel.set_current(token)

    async def fast():
        return ["fast-result"]

    async def slow():
        await asyncio.sleep(30)
        return ["never"]

    async def go():
        asyncio.get_running_loop().call_later(0.1, token.cancel)
        started = time.monotonic()
        out = await _gather_with_partial_results(
            [("fast", fast()), ("slow", slow())], timeout=60, phase_label="test"
        )
        return out, time.monotonic() - started

    out, elapsed = asyncio.run(go())
    assert out["fast"] == ["fast-result"]
    assert out["slow"] == []
    assert elapsed < 2.0


def test_enrich_investigation_does_nothing_once_cancelled():
    import sources.enrichment as enrichment

    token = cancel.CancelToken()
    cancel.set_current(token)
    token.cancel()
    assert asyncio.run(enrichment.enrich_investigation("lockbit")) == []


def test_historical_and_blocklist_loops_stop_between_items(monkeypatch):
    import feeds
    from sources import historical_intel

    token = cancel.CancelToken()
    cancel.set_current(token)
    token.cancel()

    fetched = []

    async def fake_mitre():
        fetched.append("mitre")
        return {}

    monkeypatch.setattr(historical_intel, "_fetch_mitre_index", fake_mitre)
    out = asyncio.run(
        historical_intel.enrich_historical(
            {"THREAT_ACTOR": [{"value": "LockBit"}, {"value": "Conti"}]}
        )
    )
    assert out == [] and fetched == []

    pages, stats = asyncio.run(feeds.enrich_blocklists([{"entity_type": "DOMAIN", "value": "x.com"}]))
    assert pages == [] and stats == {}


# --------------------------------------------------------------------------- #
# The whole pipeline: cancel mid-fetch
# --------------------------------------------------------------------------- #
def _prepare_fetch_pipeline(tmp_path, monkeypatch, n_pages, cancel_after, token):
    """A no-LLM pipeline run whose fetch stage scrapes *n_pages* slow pages."""
    import search as search_pkg
    import sources.engines as engines
    import voidaccess_cli.tor_detect as tor_detect

    inv = h.prepare(tmp_path, monkeypatch)
    monkeypatch.setenv(cancel.CANCEL_POLL_INTERVAL_ENV, "0.02")
    monkeypatch.setenv(cancel.CANCEL_GRACE_ENV, "0.5")
    monkeypatch.setattr(inv, "LLM_FILTER_TOP_N", n_pages)

    class _Tor:
        proxy_url = "socks5://127.0.0.1:9050"
        host = "127.0.0.1"
        port = 9050

    monkeypatch.setattr(tor_detect, "detect_tor", lambda: _Tor())
    links = [
        {"link": f"https://example.com/lockbit-{i}", "title": f"lockbit ransomware {i}",
         "snippet": "lockbit ransomware"}
        for i in range(n_pages)
    ]
    monkeypatch.setattr(search_pkg, "get_search_results_async", lambda q, w, llm: list(links))
    monkeypatch.setattr(search_pkg, "get_last_search_summary", lambda: {"active": 1, "total": 1})

    async def no_onion(_q):
        return []

    monkeypatch.setattr(engines, "search_onionsearch", no_onion)
    session = _SlowSession(token, delay=0.1, cancel_after=cancel_after)
    scrape = _patch_scraper(monkeypatch, session)
    return inv, session, scrape


def test_cancel_during_fetch_emits_cancelled_with_accurate_stages_and_no_output(
    tmp_path, monkeypatch
):
    token = cancel.CancelToken()
    inv, session, _scrape = _prepare_fetch_pipeline(tmp_path, monkeypatch, 50, 20, token)
    events_path = tmp_path / "events.jsonl"
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    started = time.monotonic()
    with pytest.raises(cancel.PipelineCancelled):
        h.run(
            inv, out_dir, no_tor=False, no_llm=True, quiet=True,
            events_jsonl=events_path, cancel_token=token,
        )
    elapsed = time.monotonic() - started

    events = h.read_events(events_path)
    assert events[-1]["type"] == "cancelled"
    assert events[-1]["stages_completed"] == ["refine", "collect", "filter"]
    assert sum(1 for e in events if e["type"] in ("completed", "failed", "cancelled")) == 1
    started_stages = [e["stage"] for e in events if e["type"] == "stage" and e["status"] == "start"]
    assert started_stages[-1] == "fetch"  # cancelled inside fetch, never reached extract

    # Within one item: only the fetches already in flight finished.
    assert 20 <= session.started <= 20 + SCRAPE_CLEARNET_CONCURRENCY
    assert session.started < 50
    assert elapsed < 10

    # No output file, partial or temporary.
    assert list(out_dir.iterdir()) == []


def test_cancel_row_is_marked_cancelled_not_running(tmp_path, monkeypatch):
    token = cancel.CancelToken()
    inv, _session, _scrape = _prepare_fetch_pipeline(tmp_path, monkeypatch, 20, 5, token)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(cancel.PipelineCancelled):
        h.run(inv, out_dir, no_tor=False, no_llm=True, quiet=True, cancel_token=token)

    from voidaccess_cli.adapters import sqlite as sqlite_adapter

    assert [r["status"] for r in sqlite_adapter.list_investigations()] == ["cancelled"]


def test_cancel_during_finalize_leaves_no_partial_file(tmp_path, monkeypatch):
    """The outputs are staged and renamed after the last checkpoint."""
    token = cancel.CancelToken()
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=lambda *a, **k: "A summary.")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    real_render = inv._render_markdown

    def render_then_cancel(payload):
        text = real_render(payload)
        token.cancel("test")  # lands after the .json was staged, before the rename
        return text

    monkeypatch.setattr(inv, "_render_markdown", render_then_cancel)
    with pytest.raises(cancel.PipelineCancelled):
        h.run(inv, out_dir, quiet=True, fmt="both", cancel_token=token)
    assert list(out_dir.iterdir()) == []


def test_pipeline_without_a_token_is_unchanged(tmp_path, monkeypatch):
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=lambda *a, **k: "A summary.")
    events_path = tmp_path / "events.jsonl"
    h.run(inv, tmp_path, quiet=True, events_jsonl=events_path)
    assert h.read_events(events_path)[-1]["type"] == "completed"
    assert cancel.current() is None


# --------------------------------------------------------------------------- #
# SIGTERM on the real CLI process
# --------------------------------------------------------------------------- #
_DRIVER = textwrap.dedent(
    """
    import asyncio, sys
    sys.path.insert(0, {repo!r})
    import voidaccess_cli.commands.investigate as inv

    async def hang(_q):
        await asyncio.sleep(120)   # the collect stage is "running" until cancelled
        return []

    async def none(_q):
        return []

    inv._scrape_rss = hang
    inv._scrape_pastes = none
    inv._scrape_github = none
    inv._scrape_gitlab = none

    # The real console-script entry point, with the real argv.
    sys.argv = ["voidaccess", "investigate", "lockbit ransomware", "--no-tor",
                "--no-llm", "--depth", "shallow", "--quiet",
                "--events-jsonl", {events!r}, "--output", {out!r}]
    from voidaccess_cli.main import run
    run()
    """
)


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM semantics")
def test_sigterm_on_the_cli_cancels_cleanly(tmp_path):
    events = tmp_path / "events.jsonl"
    out = tmp_path / "out"
    home = tmp_path / "home"
    home.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "VOIDACCESS_DB_PATH": str(tmp_path / "inv.db"),
        "DATABASE_URL": f"sqlite:///{(tmp_path / 'inv.db').as_posix()}",
        "VOIDACCESS_PRIVATE_MODE": "1",
        "JWT_SECRET": "test-secret-not-for-production",
        "VOIDACCESS_CANCEL_GRACE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.pop("VOIDACCESS_DISABLED_SOURCES", None)
    env.pop("VOIDACCESS_ENRICHMENT_SOURCES", None)
    proc = subprocess.Popen(
        [sys.executable, "-c", _DRIVER.format(repo=str(REPO), events=str(events), out=str(out))],
        env=env,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(f"driver exited early: {proc.communicate()}")
            if events.exists() and any(
                '"stage": "collect"' in line and '"status": "start"' in line
                for line in events.read_text().splitlines()
            ):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("collect stage never started")
        sent_at = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()

    assert proc.returncode == 143, (proc.returncode, stdout, stderr)
    assert time.monotonic() - sent_at < 15
    lines = [json.loads(line) for line in events.read_text().splitlines() if line.strip()]
    assert lines[-1]["type"] == "cancelled"
    assert lines[-1]["stages_completed"] == ["refine"]
    assert sum(1 for e in lines if e["type"] in ("completed", "failed", "cancelled")) == 1
    assert not out.exists() or list(out.iterdir()) == []
    # --quiet: a cancel is silent too (not even the config warning or banner),
    # and never echoes the query.
    assert stdout.strip() == "" and stderr.strip() == "", (stdout, stderr)
