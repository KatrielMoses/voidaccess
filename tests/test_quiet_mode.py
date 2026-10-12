"""--quiet is quiet: nothing on stdout/stderr but fatal errors (never echoing the query)."""

from __future__ import annotations

import re

from typer.testing import CliRunner

from tests import e1c_harness as h

QUERY = "zebracorn ransomware lockbit"  # distinctive: must never be echoed


def _summary_ok(llm, q, pages, *a, **k):
    return "A real summary."


def _assert_silent(captured):
    combined = captured.out + captured.err
    assert combined.strip() == "", combined
    assert "zebracorn" not in combined and QUERY not in combined
    assert "VoidAccess" not in combined
    assert not re.search(r"\x1b\[", combined)  # no ANSI/Rich styling


def test_quiet_run_writes_nothing_to_stdout_or_stderr(tmp_path, monkeypatch, capfd):
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=_summary_ok)
    h.run(inv, tmp_path, query=QUERY, quiet=True, fmt="both")
    _assert_silent(capfd.readouterr())
    # The outputs are still written (their names embed the query slug, which is
    # why the paths are not printed).
    assert list(tmp_path.glob("*.json")) and list(tmp_path.glob("*.md"))


def test_quiet_run_with_data_only_is_silent_too(tmp_path, monkeypatch, capfd):
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=_summary_ok)
    h.run(inv, tmp_path, query=QUERY, quiet=True, fmt="json")
    _assert_silent(capfd.readouterr())


def test_non_quiet_run_still_shows_the_display(tmp_path, monkeypatch, capfd):
    """Self-hosters see no change: without --quiet the display is unchanged."""
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=_summary_ok)
    h.run(inv, tmp_path, query=QUERY, quiet=False)
    captured = capfd.readouterr()
    assert "Investigation complete" in captured.out


def test_quiet_does_not_silence_jsonl_or_callback_sinks(tmp_path, monkeypatch, capfd):
    from progress import CallbackSink

    inv = h.prepare(tmp_path, monkeypatch, generate_summary=_summary_ok)
    events_path = tmp_path / "events.jsonl"
    seen = []
    h.run(
        inv,
        tmp_path,
        query=QUERY,
        quiet=True,
        events_jsonl=events_path,
        sinks=[CallbackSink(seen.append)],
    )
    capfd.readouterr()

    events = h.read_events(events_path)
    stages_done = [e["stage"] for e in events if e["type"] == "stage" and e["status"] != "start"]
    assert stages_done == [
        "refine", "collect", "filter", "fetch", "extract", "enrich", "graph", "summarize",
    ]
    assert events[-1]["type"] == "completed"
    # The output paths travel in the completed event, not on the terminal.
    assert events[-1]["metrics"]["data_path"] == str(next(tmp_path.glob("*.json")))
    assert seen and seen[-1].type == "completed"
    assert any(e.type == "stage" for e in seen)


def test_quiet_fatal_errors_do_not_echo_the_query():
    """A fatal error under --quiet must not echo the query text."""
    from voidaccess_cli.main import app

    result = CliRunner().invoke(app, ["investigate", "zz", "--quiet"])
    assert result.exit_code == 2
    assert "zz" not in result.output.replace("Query too short", "")
    assert "'zz'" not in result.output


def test_non_quiet_short_query_error_is_unchanged():
    from voidaccess_cli.main import app

    result = CliRunner().invoke(app, ["investigate", "zz"])
    assert result.exit_code == 2
    assert "'zz'" in result.output


def test_quiet_failed_run_does_not_leak_secrets_or_query(tmp_path, monkeypatch, capfd):
    """Even a pipeline stage that raises prints nothing under --quiet."""
    secret = "sk-live-SECRET-TOKEN-123"

    async def _boom(_q):
        raise RuntimeError(f"upstream said {secret} for {QUERY}")

    inv = h.prepare(
        tmp_path,
        monkeypatch,
        generate_summary=_summary_ok,
        side_sources={"_scrape_rss": _boom},
    )
    h.run(inv, tmp_path, query=QUERY, quiet=True)
    captured = capfd.readouterr()
    _assert_silent(captured)
    payload = h.read_payload(tmp_path)
    # The source error is reported by class name only, never the message.
    assert payload["sources_used"]["rss"]["status"] == "error"
    assert secret not in str(payload["sources_used"])
