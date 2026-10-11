"""Progress hook: event order, numeric counts, sink isolation, JSONL, Rich parity."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest
from rich.console import Console

from progress import (
    COUNT_KEYS,
    STAGE_ORDER,
    CallbackSink,
    JsonlSink,
    ProgressEmitter,
    ProgressEvent,
    Stage,
)


def _pipeline_events(tmp_path, monkeypatch, extra_sinks=None, events_jsonl=None):
    """Run the real CLI pipeline offline (--no-tor --no-llm, side sources stubbed)."""
    import asyncio

    import voidaccess_cli.commands.investigate as inv

    db_path = tmp_path / "inv.db"
    monkeypatch.setenv("VOIDACCESS_DB_PATH", str(db_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("VOIDACCESS_PRIVATE_MODE", "1")
    import db.session as session_module

    monkeypatch.setattr(session_module, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    session_module._get_engine_cached.cache_clear()

    async def _none(_q):
        return []

    for name in ("_scrape_pastes", "_scrape_github", "_scrape_gitlab", "_scrape_rss"):
        monkeypatch.setattr(inv, name, _none)

    async def _no_enrich(*_a, **_k):
        return []

    monkeypatch.setattr("sources.enrichment.enrich_investigation", _no_enrich)

    events: list[ProgressEvent] = []
    sinks = [CallbackSink(events.append)] + list(extra_sinks or [])
    asyncio.run(
        inv._run_investigation(
            query="lockbit ransomware",
            out_dir=tmp_path,
            model=None,
            no_tor=True,
            no_llm=True,
            depth="shallow",
            fmt="json",
            quiet=True,
            events_jsonl=events_jsonl,
            sinks=sinks,
        )
    )
    session_module._get_engine_cached.cache_clear()
    return events


@pytest.fixture(scope="module")
def pipeline_run(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    try:
        tmp = tmp_path_factory.mktemp("progress")
        jsonl = tmp / "events.jsonl"
        events = _pipeline_events(tmp, mp, events_jsonl=jsonl)
    finally:
        mp.undo()
    return events, jsonl


def test_event_order_covers_all_eight_stages(pipeline_run):
    events, _ = pipeline_run
    stage_events = [e for e in events if e.type == "stage"]
    expected = []
    for stage in STAGE_ORDER:
        expected += [(stage, "start"), None]
    seq = [(e.stage, e.status) for e in stage_events]
    started = [s for s, st in seq if st == "start"]
    ended = [s for s, st in seq if st != "start"]
    assert started == list(STAGE_ORDER)
    assert ended == list(STAGE_ORDER)
    # Each stage starts before it ends, and stages never overlap.
    for i in range(0, len(seq), 2):
        assert seq[i][1] == "start" and seq[i + 1][0] == seq[i][0]
    assert {e.stage_index for e in stage_events} == set(range(1, 9))
    assert all(e.stage_total == 8 for e in stage_events)
    assert [e.seq for e in events] == sorted(e.seq for e in events)
    assert events[-1].type in ("completed", "failed")
    assert sum(e.type in ("completed", "failed", "cancelled") for e in events) == 1
    assert any(e.type == "refined" and e.refined_queries for e in events)


def test_counts_are_numeric(pipeline_run):
    events, _ = pipeline_run
    with_counts = [e for e in events if e.counts is not None]
    assert with_counts
    for e in with_counts:
        assert set(e.counts) == set(COUNT_KEYS)
        assert all(isinstance(v, int) and not isinstance(v, bool) for v in e.counts.values())


def test_jsonl_sink_writes_valid_lines(pipeline_run):
    events, jsonl = pipeline_run
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(line) for line in lines]
    assert len(parsed) == len(events)
    assert parsed[0]["seq"] == 1
    assert all(p["type"] != "display" for p in parsed)
    assert {p["stage"] for p in parsed if "stage" in p} == {s.value for s in Stage}
    assert parsed[-1]["type"] in ("completed", "failed")


def test_raising_sink_does_not_break_a_run(tmp_path, monkeypatch):
    class Boom:
        def handle(self, event):
            raise RuntimeError("sink exploded")

    events = _pipeline_events(tmp_path, monkeypatch, extra_sinks=[Boom()])
    assert events[-1].type in ("completed", "failed")
    assert [e.stage for e in events if e.type == "stage" and e.status == "start"] == list(STAGE_ORDER)


def test_slow_sink_does_not_block_emit():
    def slow(_event):
        time.sleep(0.5)

    emitter = ProgressEmitter([CallbackSink(slow)])
    t0 = time.monotonic()
    for stage in STAGE_ORDER:
        emitter.stage_start(stage)
        emitter.stage_end(stage)
    assert time.monotonic() - t0 < 0.4
    emitter.close(timeout=0.1)


def test_full_queue_drops_counts_but_keeps_stage_and_terminal_events():
    import threading

    gate = threading.Event()
    got: list[ProgressEvent] = []

    def blocked(event):
        gate.wait(5)
        got.append(event)

    emitter = ProgressEmitter([CallbackSink(blocked)], queue_max=4)
    for _ in range(50):
        emitter.emit(ProgressEvent(type="counts", counts={k: 0 for k in COUNT_KEYS}))
    emitter.stage_start(Stage.REFINE)
    emitter.failed("error")
    assert emitter.dropped > 0
    gate.set()
    emitter.close()
    types = [e.type for e in got]
    assert "stage" in types and "failed" in types


def test_sink_exception_is_logged_not_raised():
    class Boom:
        def handle(self, event):
            raise ValueError("x")

    emitter = ProgressEmitter([Boom()])
    emitter.stage_start(Stage.REFINE)
    emitter.close()


def test_rich_display_output_unchanged():
    """Routing display calls through the reporter yields byte-identical output."""
    from voidaccess_cli.display import InvestigationDisplay, RichDisplaySink
    from voidaccess_cli.reporter import PipelineReporter

    steps = ["Refining query", "Searching dark web", "Building graph"]

    def script(d):
        d.set_proxy_state("off")
        d.start("lockbit", steps=steps)
        d.update_step("Refining query", "active")
        d.update_step("Refining query", "ok", "→ 'lockbit'")
        d.update_substep("Searching dark web", "Tor engines", "ok")
        d.update_step("Searching dark web", "ok", "3 links + side sources")
        d.update_step("Building graph", "fail", "timeout")
        d.complete({"entity_count": 2, "page_count": 1, "sources_used": 1, "source_details": {}})

    direct_buf = io.StringIO()
    direct = InvestigationDisplay(console=Console(file=direct_buf, width=100, force_terminal=False), quiet=True)
    script(direct)

    routed_buf = io.StringIO()
    routed_display = InvestigationDisplay(console=Console(file=routed_buf, width=100, force_terminal=False), quiet=True)
    emitter = ProgressEmitter([RichDisplaySink(routed_display)])
    script(PipelineReporter(emitter))
    emitter.close()

    assert routed_buf.getvalue() == direct_buf.getvalue()
    assert "Refining query" in routed_buf.getvalue()
