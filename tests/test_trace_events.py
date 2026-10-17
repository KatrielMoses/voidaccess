"""Schema-2 trace events: helpers, emitter guarantees, safety, and pipeline runs."""

from __future__ import annotations

import asyncio
import json
import random
import re
import string
import threading
import time
from pathlib import Path

import pytest

from progress import (
    STAGE_ORDER,
    CallbackSink,
    JsonlSink,
    ProgressEmitter,
    ProgressEvent,
    Stage,
)
from progress import trace as tr

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "progress" / "schema" / "progress-v2.schema.json"

# A v3-length onion label (56 chars) with a recognisable head and tail.
ONION_LABEL = "lockbit3" + "a" * 44 + "xyz7"
ONION = f"http://{ONION_LABEL}.onion"


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


# --------------------------------------------------------------------------- #
# Display forms
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url, expected",
    [
        (f"{ONION}/leaks/acme?id=1#x", "lockbit3…xyz7[.]onion"),
        (f"http://forum.{ONION_LABEL}.onion:8080/thread/9", "lockbit3…xyz7[.]onion"),
        ("http://short.onion/", "short[.]onion"),
        ("https://user:pw@Example.COM:443/a/b?q=secret", "example[.]com"),
        ("https://sub.example.co.uk/path", "sub[.]example[.]co[.]uk"),
        ("http://45.33.32.156/admin", "45[.]33[.]32[.]156"),
        ("http://[2001:db8::1]/x", "2001[:]db8[:][:]1"),
        ("pastebin.com/raw/abc", "pastebin[.]com"),
    ],
)
def test_display_host_forms(url, expected):
    assert tr.display_host(url) == expected


@pytest.mark.parametrize(
    "label", ["kidflix4", "onlykids", "porntes5", "hitman3c", "teenleak", "xxxhub77"]
)
def test_vanity_onion_names_that_say_too_much_are_masked(label):
    shown = tr.display_host(f"http://{label}{'a' * 44}wxyz.onion/")
    assert shown == "********…wxyz[.]onion"
    assert label[:4] not in shown


def test_sensitive_clearnet_hosts_and_titles_mask_the_name():
    assert tr.display_host("https://free-porn-tube.example.com/x") == "********[.]com"
    assert tr.display_host(f"{ONION}/x") == "lockbit3…xyz7[.]onion"
    emitter, got = _collect()
    try:
        tr.url_found("collect", f"{ONION}/a", engine="Ahmia", title="Teen leaks archive")
        tr.url_found("collect", f"{ONION}/b", engine="Ahmia", title="LockBit 3.0 leak site")
    finally:
        tr.bind(None)
        emitter.close()
    hosts = [e.data["host"] for e in got if e.kind == "url.found"]
    assert hosts == ["********…xyz7[.]onion", "lockbit3…xyz7[.]onion"]
    assert "Teen" not in json.dumps([e.to_dict() for e in got])


@pytest.mark.parametrize("url", ["", "http://", "not a url at all", "http:///path-only"])
def test_display_host_rejects_hostless_input(url):
    assert tr.display_host(url) is None


def _rand(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def test_display_host_never_leaks_path_query_or_userinfo():
    rng = random.Random(7)
    for _ in range(500):
        host = _rand(rng, string.ascii_lowercase + string.digits, rng.randint(3, 20))
        tld = rng.choice(["com", "net", "org", "io", "onion"])
        if tld == "onion":
            host = _rand(rng, "abcdefghijklmnopqrstuvwxyz234567", 56)
        path = "/" + _rand(rng, string.ascii_letters, 12)
        query = "token=" + _rand(rng, string.ascii_letters + string.digits, 16)
        user = _rand(rng, string.ascii_lowercase, 6)
        url = f"https://{user}:pw@{host}.{tld}:8443{path}?{query}"
        shown = tr.display_host(url)
        assert shown
        for secret in (path, query, user + ":", "8443", "://", "/"):
            assert secret not in shown
        assert "." not in shown.replace("[.]", "")
        assert len(shown) <= 80


# --------------------------------------------------------------------------- #
# Entity masking (property-style over generated, real-looking fixtures)
# --------------------------------------------------------------------------- #
def _emails(rng, n):
    for _ in range(n):
        local = _rand(rng, string.ascii_lowercase + ".", rng.randint(4, 14)).strip(".") or "jdoe"
        domain = _rand(rng, string.ascii_lowercase, rng.randint(4, 10))
        yield f"{local}@{domain}.com", local


def _aws(rng):
    return "AKIA" + _rand(rng, string.ascii_uppercase + "234567", 16)


def _github(rng):
    return "ghp_" + _rand(rng, string.ascii_letters + string.digits, 36)


def _jwt(rng):
    part = lambda: _rand(rng, string.ascii_letters + string.digits + "-_", 24)  # noqa: E731
    return f"eyJhbGciOiJIUzI1NiJ9.{part()}.{part()}"


def test_mask_emails_never_show_the_address():
    rng = random.Random(11)
    for email, local in _emails(rng, 400):
        for etype in ("EMAIL_ADDRESS", "EMAIL", "XMPP_JID"):
            shown = tr.mask_entity(etype, email)
            assert email not in shown
            assert "@" not in shown.replace("[@]", "")
            if len(local) > 2:
                assert local not in shown


def test_mask_phones_and_names_never_show_the_value():
    rng = random.Random(13)
    first = ["Alice", "Dmitri", "Mohammed", "Chen", "Olusegun", "Priya", "Jean-Luc"]
    last = ["Ivanov", "Okafor", "Smith", "Nakamura", "Kowalski", "Haddad"]
    for _ in range(300):
        phone = f"+{rng.randint(1, 99)} {rng.randint(100, 999)} {rng.randint(100, 999)} {rng.randint(1000, 9999)}"
        assert tr.mask_entity("PHONE_NUMBER", phone) == "[phone]"
        name = f"{rng.choice(first)} {rng.choice(last)}"
        shown = tr.mask_entity("PERSON_NAME", name)
        for word in name.split():
            assert word not in shown
        assert tr.mask_entity("LOCATION", f"12 {rng.choice(last)} Street") == "[location]"


def test_mask_credentials_never_show_the_secret():
    rng = random.Random(17)
    for _ in range(300):
        cases = {
            "AWS_ACCESS_KEY": _aws(rng),
            "AWS_SECRET_KEY": _rand(rng, string.ascii_letters + string.digits + "/+", 40),
            "GITHUB_TOKEN": _github(rng),
            "JWT_TOKEN": _jwt(rng),
            "API_KEY": _rand(rng, string.ascii_letters + string.digits, 32),
            "STRIPE_KEY": "sk_live_" + _rand(rng, string.ascii_letters + string.digits, 24),
            "SLACK_TOKEN": "xoxb-" + _rand(rng, string.digits, 12) + "-" + _rand(rng, string.ascii_letters, 24),
            "SESSION_ID": _rand(rng, string.hexdigits, 32),
            "COMBO_LIST_ENTRY": f"{next(_emails(rng, 1))[0]}:{_rand(rng, string.ascii_letters, 10)}",
            "STEALER_LOG_ENTRY": "URL: https://bank.example/login USER: bob PASS: hunter2xyz",
            "CRYPTO_SEED_PHRASE": " ".join(_rand(rng, string.ascii_lowercase, 5) for _ in range(12)),
            "DATABASE_URL": f"postgres://admin:{_rand(rng, string.ascii_letters, 12)}@db.internal:5432/prod",
        }
        for etype, secret in cases.items():
            shown = tr.mask_entity(etype, secret)
            assert "[REDACTED]" in shown, etype
            body = secret[8:] if len(secret) > 8 else secret
            assert body not in shown, etype
            # No 8-character run of the secret beyond a known public prefix.
            prefix = shown.split("[REDACTED]")[0]
            assert len(prefix) <= len("github_pat_"), etype


def test_mask_network_indicators_are_defanged_and_bounded():
    assert tr.mask_entity("IP_ADDRESS", "45.33.32.156") == "45[.]33[.]32[.]156"
    assert tr.mask_entity("DOMAIN", "evil-c2.example.net") == "evil-c2[.]example[.]net"
    assert tr.mask_entity("ONION_URL", f"{ONION}/leaks/acme-corp") == "lockbit3…xyz7[.]onion"
    assert tr.mask_entity("URL", "https://paste.example/raw/abc?k=1") == "paste[.]example"
    assert tr.mask_entity("CVE_NUMBER", "CVE-2021-44228") == "CVE-2021-44228"
    assert tr.mask_entity("YARA_RULE", "rule x { strings: $a = \"secret\" }") == "[YARA rule]"
    assert tr.mask_entity("SOMETHING_NEW", "anything") == "[REDACTED]"
    long_hash = "a" * 200
    assert len(tr.mask_entity("FILE_HASH_SHA512", long_hash)) <= 80
    assert "\n" not in tr.mask_entity("ORGANIZATION_NAME", "Acme\nCorp")


# --------------------------------------------------------------------------- #
# Emitter: opt-in, schema, caps, ordering, queue
# --------------------------------------------------------------------------- #
def test_every_event_carries_schema_2():
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter([CallbackSink(got.append)])
    emitter.stage_start(Stage.REFINE)
    emitter.refined(["q"])
    emitter.failed("error")
    emitter.close()
    assert got and all(e.to_dict()["schema"] == 2 for e in got)


def test_tracing_off_emits_nothing_and_hooks_are_noops():
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter([CallbackSink(got.append)])
    assert not emitter.trace_enabled
    emitter.trace(Stage.COLLECT, "url.found", {"url_id": "u1", "host": "x[.]com"})
    tr.bind(emitter)
    try:
        assert not tr.active()
        tr.url_found("collect", "http://example.com/")
        tr.page_fetched("http://example.com/", "ok")
    finally:
        tr.bind(None)
    emitter.close()
    assert got == []


def test_trace_event_shape_and_seq_across_schema1():
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter([CallbackSink(got.append)], trace=True)
    emitter.stage_start(Stage.COLLECT)
    emitter.trace("collect", "search.request", {"engine": "Ahmia", "query_index": 0})
    emitter.stage_end(Stage.COLLECT)
    emitter.trace(Stage.FILTER, "url.kept", {"url_id": "u1"})
    emitter.completed()
    emitter.close()
    assert [e.seq for e in got] == list(range(1, len(got) + 1))
    trace = [e.to_dict() for e in got if e.type == "trace"]
    assert trace[0] == {
        "type": "trace", "schema": 2, "run_id": "", "seq": 2, "at": trace[0]["at"],
        "stage": "collect", "kind": "search.request",
        "data": {"engine": "Ahmia", "query_index": 0},
    }
    validator = _validator()
    for e in got:
        validator.validate(e.to_dict())


def test_caps_emit_one_truncation_per_kind_before_the_terminal():
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter(
        [CallbackSink(got.append)], trace=True, trace_caps={"url.found": 3, "url.kept": 1}
    )
    for i in range(10):
        emitter.trace("collect", "url.found", {"url_id": f"u{i + 1}", "host": "x[.]com"})
    for i in range(4):
        emitter.trace("filter", "url.kept", {"url_id": f"u{i + 1}"})
    emitter.completed()
    emitter.trace("collect", "url.found", {"url_id": "u99", "host": "x[.]com"})  # after terminal
    emitter.close()
    kinds = [(e.kind, e.data) for e in got if e.type == "trace"]
    assert sum(k == "url.found" for k, _ in kinds) == 3
    assert sum(k == "url.kept" for k, _ in kinds) == 1
    truncated = [d for k, d in kinds if k == "trace.truncated"]
    assert truncated == [{"kind": "url.found", "dropped": 7}, {"kind": "url.kept", "dropped": 3}]
    assert got[-1].type == "completed"
    assert all(e.type != "trace" for e in got[got.index(got[-1]):])


def test_total_trace_events_are_capped(monkeypatch):
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter([CallbackSink(got.append)], trace=True, trace_max_events=40)
    for kind in tr.TRACE_KINDS[:-1]:
        for _ in range(50):
            emitter.trace("collect", kind, {})
    emitter.failed("error")
    emitter.close()
    traces = [e for e in got if e.type == "trace"]
    assert len(traces) <= 40
    assert {e.kind for e in traces if e.kind != "trace.truncated"}
    assert any(e.kind == "trace.truncated" for e in traces)


def test_caps_are_configurable_from_the_environment(monkeypatch):
    monkeypatch.setenv(tr.TRACE_CAPS_ENV, "url.found=2,bogus=5,entity.found=x")
    monkeypatch.setenv(tr.TRACE_MAX_EVENTS_ENV, "100")
    state = tr.TraceState()
    assert state.caps["url.found"] == 2
    assert state.caps["entity.found"] == tr.DEFAULT_CAPS["entity.found"]
    assert "bogus" not in state.caps
    assert state.max_events == 100


def test_full_queue_drops_traces_before_counts_and_never_stage_or_terminal():
    gate = threading.Event()
    got: list[ProgressEvent] = []

    def blocked(event):
        gate.wait(5)
        got.append(event)

    emitter = ProgressEmitter([CallbackSink(blocked)], trace=True, queue_max=4)
    emitter._queue_max = 4  # the trace floor would otherwise raise it
    for i in range(30):
        emitter.trace("collect", "url.found", {"url_id": f"u{i + 1}", "host": "x[.]com"})
    emitter.emit(ProgressEvent(type="counts", counts={}))
    emitter.stage_start(Stage.FETCH)
    emitter.stage_end(Stage.FETCH)
    emitter.failed("error")
    assert emitter.dropped_traces > 0
    gate.set()
    emitter.close()
    types = [e.type for e in got]
    assert types.count("stage") == 2 and "failed" in types


def test_slow_sink_with_a_trace_backlog_still_gets_the_terminal_event():
    got: list[ProgressEvent] = []

    def slow(event):
        time.sleep(0.01)
        got.append(event)

    emitter = ProgressEmitter([CallbackSink(slow)], trace=True)
    t0 = time.monotonic()
    for i in range(2000):
        emitter.trace("collect", "url.found", {"url_id": f"u{i + 1}", "host": "x[.]com"})
    emitter.completed()
    assert time.monotonic() - t0 < 1.0, "emitting must never wait on a sink"
    emitter.close(timeout=1.0)
    time.sleep(0.05)
    assert any(e.type == "completed" for e in got)


def test_an_exception_while_building_a_trace_is_swallowed(monkeypatch):
    emitter = ProgressEmitter(trace=True)

    def boom(self, kind):
        raise RuntimeError("cap bookkeeping exploded")

    monkeypatch.setattr(tr.TraceState, "admit", boom)
    emitter.trace("collect", "url.found", {"url_id": "u1", "host": "x[.]com"})
    tr.bind(emitter)
    try:
        tr.url_found("collect", "http://example.com/")
        tr.page_entities("http://example.com/", [{"entity_type": "CVE_NUMBER", "value": "CVE-1"}])
    finally:
        tr.bind(None)
    emitter.close()


# --------------------------------------------------------------------------- #
# Safety in the hooks
# --------------------------------------------------------------------------- #
def _collect(trace=True):
    got: list[ProgressEvent] = []
    emitter = ProgressEmitter([CallbackSink(got.append)], trace=trace)
    tr.bind(emitter)
    return emitter, got


def test_a_url_blocked_by_safety_yields_only_id_and_reason():
    from utils.content_safety import BLOCKED_URL_TERMS

    emitter, got = _collect()
    try:
        bad = f"{ONION}/{BLOCKED_URL_TERMS[0].replace(' ', '-')}/index"
        tr.url_found("collect", bad, engine="Ahmia")
        tr.url_kept("filter", bad, 0.9)
        tr.page_fetched(bad, "ok", http_status=200, nbytes=10, ms=5)
        tr.url_dropped("fetch", bad, "safety")
    finally:
        tr.bind(None)
        emitter.close()
    traces = [e.to_dict() for e in got if e.type == "trace"]
    assert [t["data"] for t in traces] == [{"url_id": "u1", "reason": "safety"}]


def test_a_page_dropped_by_safety_yields_only_id_and_outcome():
    emitter, got = _collect()
    url = f"{ONION}/post/1"
    try:
        tr.url_found("collect", url, engine="Ahmia")
        tr.note_fetch(url, http_status=200, nbytes=5000, ms=900)
        tr.page_fetched(url, "safety_dropped")
        tr.page_fetched(url, "ok")
        tr.page_entities(url, [{"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228"}])
    finally:
        tr.bind(None)
        emitter.close()
    traces = [e.to_dict()["data"] for e in got if e.type == "trace"]
    assert traces[1] == {"url_id": "u1", "outcome": "safety_dropped"}
    assert len(traces) == 2


def test_blocked_entity_values_are_never_traced():
    from utils.content_safety import CONTENT_BLOCKLIST

    emitter, got = _collect()
    url = f"{ONION}/post/2"
    try:
        tr.url_found("collect", url)
        tr.page_entities(url, [
            {"entity_type": "ORGANIZATION_NAME", "value": f"x {CONTENT_BLOCKLIST[0]} y"},
            {"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228", "confidence": 0.9},
        ])
    finally:
        tr.bind(None)
        emitter.close()
    blob = json.dumps([e.to_dict() for e in got])
    assert CONTENT_BLOCKLIST[0] not in blob
    entities = [e.data for e in got if e.kind == "entity.found"]
    assert entities == [{
        "entity_id": "e1", "type": "CVE_NUMBER", "display": "CVE-2021-44228",
        "confidence": 0.9, "url_id": "u1",
    }]


def test_scrape_multiple_reports_ssrf_drops_without_hosts(monkeypatch):
    import scraper.scrape as scrape

    async def fake_gather(urls, workers, extract_typed_relationships=False):
        return []

    monkeypatch.setattr(scrape, "_gather_all", fake_gather)
    emitter, got = _collect()
    try:
        tr.url_found("collect", "http://127.0.0.1/admin")
        asyncio.run(scrape.scrape_multiple([{"link": "http://127.0.0.1/admin", "title": "t"}]))
    finally:
        tr.bind(None)
        emitter.close()
    data = [e.data for e in got if e.kind == "url.dropped"]
    assert data == [{"url_id": "u1", "reason": "ssrf"}]


# --------------------------------------------------------------------------- #
# Pipeline runs
# --------------------------------------------------------------------------- #
PAGE_TEXT = (
    "LockBit ransomware affiliate notes. The group exploited CVE-2021-44228 against "
    "victim infrastructure. Contact the negotiator at negotiator.lb@protonmail.com or "
    "+1 415 555 0134. Leaked key AKIAIOSFODNN7EXAMPLE found in the dump. C2 server "
    "45.33.32.156 and evil-c2.example.net. Bitcoin 1A1zP1eFEfi6DMPpUFzqhXTTmfZ3XXKZ1M. "
)


def _isolate_db(tmp_path, monkeypatch):
    db_path = tmp_path / "inv.db"
    monkeypatch.setenv("VOIDACCESS_DB_PATH", str(db_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("VOIDACCESS_PRIVATE_MODE", "1")
    for var in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", tr.TRACE_ENV, tr.TRACE_CAPS_ENV):
        monkeypatch.delenv(var, raising=False)
    import db.session as session_module

    monkeypatch.setattr(session_module, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    session_module._get_engine_cached.cache_clear()
    return session_module


def _stub_enrichment(monkeypatch):
    async def no_pages(*_a, **_k):
        return []

    async def passthrough(results, *_a, **_k):
        return results, {}

    async def no_ip(*_a, **_k):
        return None

    async def no_hibp(_pages):
        return None, {"status": "ok", "pwned": 0}

    monkeypatch.setattr("sources.enrichment.enrich_investigation", no_pages)
    monkeypatch.setattr("credential_presence.scan_pages_for_pwned_credentials", no_hibp)
    monkeypatch.setattr("sources.ip_reputation.enrich_ip_entities", no_ip)
    for target in (
        "sources.domain_reputation.enrich_domain_entities",
        "sources.hash_reputation.enrich_hash_entities",
        "sources.email_reputation.enrich_email_entities",
        "sources.breach_lookup.enrich_breach_entities",
        "sources.infostealer.enrich_infostealer_entities",
    ):
        monkeypatch.setattr(target, passthrough)


def _offline_run(tmp_path, monkeypatch, *, trace):
    """--no-tor --no-llm run with one paste page, so the report has entities."""
    import voidaccess_cli.commands.investigate as inv

    session_module = _isolate_db(tmp_path, monkeypatch)
    _stub_enrichment(monkeypatch)

    async def paste(_q):
        return [{"url": "https://pastebin.com/raw/lb3notes", "text": PAGE_TEXT * 3,
                 "title": "lockbit ransomware notes", "source": "paste_sites"}]

    async def none(_q):
        return []

    monkeypatch.setattr(inv, "_scrape_pastes", paste)
    for name in ("_scrape_github", "_scrape_gitlab", "_scrape_rss"):
        monkeypatch.setattr(inv, name, none)

    events: list[ProgressEvent] = []
    out = tmp_path / "out"
    out.mkdir(parents=True)
    asyncio.run(inv._run_investigation(
        query="lockbit ransomware", out_dir=out, model=None, no_tor=True, no_llm=True,
        depth="shallow", fmt="both", quiet=True, sinks=[CallbackSink(events.append)],
        trace=trace,
    ))
    session_module._get_engine_cached.cache_clear()
    return events, out


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?")


def _canon(value):
    """Ids and timestamps masked, lists order-free (entity rows come back in
    UUID order, so two untraced runs already differ in row order)."""
    if isinstance(value, str):
        return _TS.sub("<ts>", _UUID.sub("<uuid>", value))
    if isinstance(value, dict):
        return {_canon(k): _canon(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def _normalised(path: Path):
    """A report with the run-to-run noise that exists without tracing removed.

    Two untraced runs already differ in: entity ids and timestamps, row order
    (no ORDER BY), ``rank`` among equal priority scores (ties fall to UUID
    order) and ``communities`` (keyed by entity UUID). Communities are compared
    as a partition of (type, value); everything else must match exactly.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".json":
        return sorted(_canon(text.splitlines()))
    data = json.loads(text)
    by_id = {e["id"]: (e["entity_type"], e["value"]) for e in data["entities"]}
    groups: dict = {}
    for eid, community in (data.get("communities") or {}).items():
        groups.setdefault(community, []).append(list(by_id.get(eid, ("?", eid))))
    data["communities"] = sorted(sorted(g) for g in groups.values())
    for entity in data["entities"]:
        entity.pop("rank", None)
    return _canon(data)


def test_tracing_off_outputs_are_identical_to_traced_outputs(tmp_path, monkeypatch):
    off_events, off_out = _offline_run(tmp_path / "off", monkeypatch, trace=False)
    on_events, on_out = _offline_run(tmp_path / "on", monkeypatch, trace=True)

    assert not [e for e in off_events if e.type == "trace"]
    assert [e for e in on_events if e.type == "trace"]
    # Schema-1 events are the same sequence of types/stages either way.
    shape = lambda evs: [(e.type, e.stage, e.status) for e in evs if e.type != "trace"]  # noqa: E731
    assert shape(off_events) == shape(on_events)

    for suffix in (".json", ".md"):
        (off_file,) = off_out.glob(f"*{suffix}")
        (on_file,) = on_out.glob(f"*{suffix}")
        assert _normalised(off_file) == _normalised(on_file)
    report = json.loads((next(off_out.glob("*.json"))).read_text())
    assert report["entities"], "the comparison must cover a report with findings"


def test_trace_env_var_turns_tracing_on(tmp_path, monkeypatch):
    import voidaccess_cli.commands.investigate as inv

    seen = {}

    async def fake_impl(query, out_dir, model, no_tor, no_llm, depth, fmt, quiet, emitter):
        seen["trace"] = emitter.trace_enabled
        seen["bound"] = tr.current() is emitter
        emitter.failed("error")

    monkeypatch.setattr(inv, "_run_investigation_impl", fake_impl)
    for value, expected in (("1", True), ("", False)):
        monkeypatch.setenv(tr.TRACE_ENV, value)
        asyncio.run(inv._run_investigation(
            query="lockbit ransomware", out_dir=tmp_path, model=None, no_tor=True,
            no_llm=True, depth="shallow", fmt="json", quiet=True,
        ))
        assert seen == {"trace": expected, "bound": expected}
        assert tr.current() is None


def test_a_blocked_query_never_traces_even_when_asked(tmp_path, monkeypatch):
    import voidaccess_cli.commands.investigate as inv
    from utils.content_safety import BLOCKED_TERMS

    seen = {}

    async def fake_impl(query, out_dir, model, no_tor, no_llm, depth, fmt, quiet, emitter):
        seen["trace"] = emitter.trace_enabled
        emitter.failed("error")

    monkeypatch.setattr(inv, "_run_investigation_impl", fake_impl)
    asyncio.run(inv._run_investigation(
        query=f"find {BLOCKED_TERMS[0]} now", out_dir=tmp_path, model=None, no_tor=True,
        no_llm=True, depth="shallow", fmt="json", quiet=True, trace=True,
    ))
    assert seen == {"trace": False}


def test_cli_trace_flag_with_a_blocked_query_writes_no_trace(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from utils.content_safety import BLOCKED_TERMS
    from voidaccess_cli.main import app

    jsonl = tmp_path / "e.jsonl"
    monkeypatch.setenv("VOIDACCESS_HOME", str(tmp_path))
    result = CliRunner().invoke(app, [
        "investigate", f"find {BLOCKED_TERMS[0]} now", "--no-llm", "--no-tor",
        "--trace", "--events-jsonl", str(jsonl),
    ])
    assert result.exit_code == 1
    lines = [json.loads(line) for line in jsonl.read_text().splitlines()]
    assert [line["type"] for line in lines] == ["failed"]
    assert lines[0]["reason"] == "blocked_query"


def test_cli_trace_flag_reaches_the_pipeline(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import voidaccess_cli.commands.investigate as inv
    from voidaccess_cli.main import app

    seen = {}

    async def fake_run(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(inv, "_run_investigation", fake_run)
    monkeypatch.setenv("VOIDACCESS_HOME", str(tmp_path))
    for args, expected in ((["--trace"], True), ([], None)):
        seen.clear()
        result = CliRunner().invoke(app, [
            "investigate", "lockbit ransomware", "--no-llm", "--no-tor",
            "--events-jsonl", str(tmp_path / "e.jsonl"), "--output", str(tmp_path), *args,
        ])
        assert result.exit_code == 0, result.output
        assert seen["trace"] is expected


# --- mocked Tor run that exercises every kind ---------------------------------

def _onion(tag: str) -> str:
    label = (tag + "abcdefghijklmnopqrstuvwxyz234567" * 2)[:56]
    return f"http://{label}.onion"


class _Content:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _n):
        yield self.body


class _Resp:
    def __init__(self, status: int, body: bytes = b""):
        self.status = status
        self.headers = {"Content-Type": "text/html"}
        self.charset = "utf-8"
        self.content = _Content(body)


class _FakeSession:
    def __init__(self, routes):
        self.routes = routes

    def get(self, url, headers=None, **_kw):
        action = self.routes.get(url, "ok")

        class _CM:
            async def __aenter__(self_inner):
                if action == "timeout":
                    raise asyncio.TimeoutError()
                if isinstance(action, int):
                    return _Resp(action)
                body = {
                    "ok": f"<html><body><article><p>{PAGE_TEXT * 4}</p></article></body></html>",
                    "empty": "<html><body></body></html>",
                    "blocked": "<html><body><p>{}</p></body></html>",
                }[action]
                if action == "blocked":
                    from utils.content_safety import CONTENT_BLOCKLIST

                    body = body.format(("context " * 50) + CONTENT_BLOCKLIST[0] + (" context" * 50))
                return _Resp(200, body.encode())

            async def __aexit__(self_inner, *exc):
                return False

        return _CM()


def _full_run(tmp_path, monkeypatch, caps=""):
    import scraper.scrape as scrape
    import search.search as search_mod
    import voidaccess_cli.commands.investigate as inv
    from utils.content_safety import BLOCKED_URL_TERMS

    session_module = _isolate_db(tmp_path, monkeypatch)
    _stub_enrichment(monkeypatch)
    if caps:
        monkeypatch.setenv(tr.TRACE_CAPS_ENV, caps)
    # 15 onion pages (the shallow default) so the 22 candidates include drops.
    monkeypatch.setenv("VOIDACCESS_ONION_TOP_N", "15")

    good = [f"{_onion(f'lb{i}')}/lockbit-ransomware-{i}" for i in range(6)]
    special = {
        f"{_onion('nf')}/lockbit-ransomware-gone": 404,
        f"{_onion('bad')}/lockbit-ransomware-err": 503,
        f"{_onion('slow')}/lockbit-ransomware-slow": "timeout",
        f"{_onion('blk')}/lockbit-ransomware-pg": "blocked",
        f"{_onion('emp')}/lockbit-ransomware-empty": "empty",
    }
    unsafe = f"{_onion('uns')}/{BLOCKED_URL_TERMS[0].replace(' ', '-')}/lockbit-ransomware"
    filler = [f"{_onion(f'f{i}')}/x{i}" for i in range(10)]
    engine_a = good + list(special) + [unsafe] + filler
    engine_b = [good[0], good[1] + "/"]  # same URL, and a dedup-equal variant

    engines = [
        {"name": "Ahmia", "url": "http://ahmia.onion/?q={query}"},
        {"name": "Torgle", "url": "http://torgle.onion/?q={query}"},
        {"name": "Amnesia", "url": "http://amnesia.onion/?q={query}"},
    ]

    async def fake_fetch(engine, query, session, semaphore):
        name = engine["name"]
        if name == "Amnesia":
            return search_mod.EngineResult(name=name, links=[], error="timeout")
        links = engine_a if name == "Ahmia" else engine_b
        return search_mod.EngineResult(
            name=name,
            links=[{"link": u, "title": "lockbit ransomware leak" if "lockbit" in u else "misc"} for u in links],
        )

    async def no_stats():
        return []

    async def never_skip(_name):
        return False

    monkeypatch.setattr(search_mod, "SEARCH_ENGINES", engines)
    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", no_stats)
    monkeypatch.setattr(search_mod, "should_skip_engine_async", never_skip)
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", lambda *a: None)
    monkeypatch.setattr(search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda k: None)

    session = _FakeSession(special)
    monkeypatch.setattr(scrape, "_acquire_tor_session", lambda url: (session, None))
    monkeypatch.setattr(scrape, "get_direct_session_cached", lambda: session)
    monkeypatch.setattr(scrape.pacing, "retry_plan", lambda n, d: (0, ()))

    async def no_seeds(**_kw):
        return 0

    monkeypatch.setattr(scrape, "_discover_seeds_from_one_page", no_seeds)

    async def no_page_seeds(*_a, **_k):
        return 0

    monkeypatch.setattr(inv, "_discover_seeds_from_pages", no_page_seeds)

    class _Tor:
        proxy_url = "socks5h://127.0.0.1:9050"
        host = "127.0.0.1"
        port = 9050

    monkeypatch.setattr("voidaccess_cli.tor_detect.detect_tor", lambda: _Tor())

    async def onion_engines(_q):
        return []

    monkeypatch.setattr("sources.engines.search_onionsearch", onion_engines)

    async def paste(_q):
        return [{"url": "https://pastebin.com/raw/lb3notes?k=1", "text": PAGE_TEXT * 3,
                 "title": "lockbit ransomware notes", "source": "paste_sites"}]

    async def github(_q):
        return [{"url": "https://github.com/someone/unrelated", "text": "weather recipes", "title": "x"}]

    async def gitlab(_q):
        raise RuntimeError("gitlab down")

    async def none(_q):
        return []

    monkeypatch.setattr(inv, "_scrape_pastes", paste)
    monkeypatch.setattr(inv, "_scrape_github", github)
    monkeypatch.setattr(inv, "_scrape_gitlab", gitlab)
    monkeypatch.setattr(inv, "_scrape_rss", none)

    jsonl = tmp_path / "events.jsonl"
    (tmp_path / "out").mkdir(parents=True)
    events: list[ProgressEvent] = []
    asyncio.run(inv._run_investigation(
        query="lockbit ransomware", out_dir=tmp_path / "out", model=None, no_tor=False,
        no_llm=True, depth="normal", fmt="json", quiet=True, events_jsonl=jsonl,
        sinks=[CallbackSink(events.append)], trace=True,
    ))
    session_module._get_engine_cached.cache_clear()
    lines = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    return events, lines, {"special": special, "unsafe": unsafe, "good": good}


@pytest.fixture(scope="module")
def full_run(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    try:
        tmp = tmp_path_factory.mktemp("trace-full")
        result = _full_run(tmp, mp, caps="search.request=2")
    finally:
        mp.undo()
    return result


def test_full_run_emits_every_kind_and_validates(full_run):
    events, lines, _ = full_run
    validator = _validator()
    for line in lines:
        validator.validate(line)
    kinds = {line["kind"] for line in lines if line["type"] == "trace"}
    assert kinds == set(tr.TRACE_KINDS), set(tr.TRACE_KINDS) - kinds
    assert [line["seq"] for line in lines] == list(range(1, len(lines) + 1))
    assert lines[-1]["type"] == "completed"
    started = [line["stage"] for line in lines if line["type"] == "stage" and line["status"] == "start"]
    assert started == [s.value for s in STAGE_ORDER]
    # Every trace sits inside a run that is still going.
    assert all(line["type"] != "trace" for line in lines[lines.index(lines[-1]):])


def _by_kind(lines, kind):
    return [line["data"] for line in lines if line.get("kind") == kind]


def test_full_run_follows_one_url_through_the_stages(full_run):
    _, lines, _ = full_run
    found = {d["url_id"]: d for d in _by_kind(lines, "url.found")}
    first = next(uid for uid, d in found.items() if d["host"].startswith("lb0abcde"))
    path = [
        line["kind"] for line in lines
        if line.get("type") == "trace" and line["data"].get("url_id") == first
    ]
    assert path[0] == "url.found"
    assert "url.kept" in path and "page.fetched" in path and "page.entities" in path
    fetched = [d for d in _by_kind(lines, "page.fetched") if d["url_id"] == first]
    assert fetched[0]["outcome"] == "ok" and fetched[0]["bytes"] > 0
    # Every id a later event uses was introduced by url.found or a safety drop.
    introduced = set(found) | {
        d["url_id"] for d in _by_kind(lines, "url.dropped") if d["reason"] == "safety"
    }
    for kind in ("url.kept", "url.dropped", "page.fetched", "page.entities"):
        for d in _by_kind(lines, kind):
            assert d["url_id"] in introduced, (kind, d)


def test_full_run_reports_fetch_outcomes_and_drop_reasons(full_run):
    _, lines, _ = full_run
    outcomes = {d["outcome"] for d in _by_kind(lines, "page.fetched")}
    assert {"ok", "http_404", "http_5xx", "timeout", "safety_dropped", "empty"} <= outcomes
    reasons = {d["reason"] for d in _by_kind(lines, "url.dropped")}
    assert {"duplicate", "irrelevant", "safety"} <= reasons
    results = {d["engine"]: d for d in _by_kind(lines, "search.result")}
    assert results["Ahmia"]["status"] == "ok" and results["Ahmia"]["results"] > 0
    assert results["Amnesia"]["status"] == "timeout"
    assert results["gitlab"]["status"] == "error"
    assert results["telegram"]["status"] == "no_key"
    # 3 engines + 6 side sources requested, 2 admitted under the test cap.
    assert _by_kind(lines, "trace.truncated") == [{"kind": "search.request", "dropped": 7}]
    assert _by_kind(lines, "summary.status") == [{"kind": "none", "attempt": 0}]
    assert _by_kind(lines, "query.refined") == [{"index": 0, "text": "lockbit ransomware"}]
    assert _by_kind(lines, "graph.progress")


def test_full_run_safety_drops_carry_nothing_else(full_run):
    _, lines, fx = full_run
    for d in _by_kind(lines, "url.dropped"):
        if d["reason"] == "safety":
            assert set(d) == {"url_id", "reason"}
    safety_pages = [d for d in _by_kind(lines, "page.fetched") if d["outcome"] == "safety_dropped"]
    assert safety_pages and all(set(d) == {"url_id", "outcome"} for d in safety_pages)
    blocked_ids = {d["url_id"] for d in safety_pages}
    assert not [d for d in _by_kind(lines, "page.entities") if d["url_id"] in blocked_ids]
    unsafe_label = fx["unsafe"].split("//")[1][:8]
    assert not [d for d in _by_kind(lines, "url.found") if d["host"].startswith(unsafe_label)]


def test_full_run_jsonl_leaks_nothing(full_run):
    """Hand-picked secrets and identifiers must not appear anywhere in the stream."""
    from utils.content_safety import BLOCKED_URL_TERMS, CONTENT_BLOCKLIST

    _, lines, fx = full_run
    blob = json.dumps([line for line in lines if line["type"] == "trace"])
    forbidden = [
        "negotiator.lb@protonmail.com", "negotiator", "415 555", "AKIAIOSFODNN7EXAMPLE",
        "IOSFODNN7", "45.33.32.156", "evil-c2.example.net", "pastebin.com",
        "lockbit-ransomware", "/raw/", "?k=1", "http://", "https://", ".onion",
        "LockBit ransomware affiliate", CONTENT_BLOCKLIST[0], BLOCKED_URL_TERMS[0],
        str(Path.home()), "inv.db",
    ]
    for needle in forbidden:
        assert needle not in blob, needle
    for d in _by_kind(lines, "url.found"):
        assert "/" not in d["host"] and "." not in d["host"].replace("[.]", "")
    displays = {d["type"]: d["display"] for d in _by_kind(lines, "entity.found")}
    assert displays.get("EMAIL_ADDRESS", "n[@]x").startswith("n***")
    assert displays.get("AWS_ACCESS_KEY", "AKIA[REDACTED]") == "AKIA[REDACTED]"
    assert displays.get("CVE_NUMBER") == "CVE-2021-44228"
