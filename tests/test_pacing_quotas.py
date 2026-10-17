"""
Tests for Requirement Brief 2.4 — quota guards, rolling windows, tier flags,
and server-declared backoff.

Six items, each of which addressed a measured production risk:

  1. GreyNoise per-investigation cap — the free tier is 50 lookups per WEEK and
     MAX_IPS is 50, so one investigation could exhaust a week's access.
  2. crt.sh pacing — 5 req/min per IP, previously 30 concurrent with no delay.
  3. ransomware.live pacing — 1 req/min PER ENDPOINT, previously unpaced.
  4. NVD rolling window — a flat delay enforces the mean rate but permits a
     burst-then-idle pattern that still violates a rolling window.
  5. VT_API_TIER — a premium key was paced at the free tier's 15 s.
  6. Retry-After / X-RateLimit-Reset — a 429's own guidance was discarded.
"""

from __future__ import annotations

import asyncio
import time
from email.utils import formatdate

import pytest

import pacing


def _set(monkeypatch, profile):
    monkeypatch.setenv(pacing.ENV_VAR, profile)


def _committed_constant(path: str, name: str) -> float:
    """Read a module-level numeric constant straight out of the source file."""
    import ast
    import io as _io

    tree = ast.parse(_io.open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return float(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found as a module constant in {path}")


class _FakeResponse:
    def __init__(self, status: int, payload=None, text: str = "", headers=None):
        self.status = status
        self._payload = payload if payload is not None else {}
        self._text = text
        self.headers = headers or {}

    async def json(self, *args, **kwargs):
        return self._payload

    async def text(self, *args, **kwargs):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    # The shared clearnet pool (netpool) checks ``.closed`` on every request to
    # rebuild a closed session, so a fake must expose it like aiohttp does.
    closed = False

    def __init__(self, responses, timestamps=None):
        self._responses = list(responses)
        self._timestamps = timestamps if timestamps is not None else []

    def get(self, *args, **kwargs):
        self._timestamps.append(time.perf_counter())
        if self._responses:
            return self._responses.pop(0)
        return _FakeResponse(200, {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def close(self):
        return None


# ---------------------------------------------------------------------------
# 1. GreyNoise per-investigation cap
# ---------------------------------------------------------------------------


def test_greynoise_cap_leaves_headroom_under_the_weekly_allowance():
    """
    The cap must be well under 50/week so several investigations can share a
    week without any cross-run tracking, and under MAX_IPS so it actually bites.
    """
    from sources import ip_reputation

    assert 0 < ip_reputation.MAX_GREYNOISE_LOOKUPS <= 15
    assert ip_reputation.MAX_GREYNOISE_LOOKUPS < ip_reputation.MAX_IPS
    # At least three investigations per week without exhausting the allowance.
    assert ip_reputation.MAX_GREYNOISE_LOOKUPS * 3 <= 50


def test_greynoise_budget_stops_at_the_cap():
    from sources.ip_reputation import GreyNoiseBudget

    budget = GreyNoiseBudget(limit=3)
    assert [budget.try_consume() for _ in range(5)] == [True, True, True, False, False]
    assert budget.used == 3
    assert budget.capped is True


def test_greynoise_budget_not_flagged_when_under_cap():
    from sources.ip_reputation import GreyNoiseBudget

    budget = GreyNoiseBudget(limit=5)
    budget.try_consume()
    assert budget.capped is False


@pytest.mark.asyncio
async def test_greynoise_lookups_stop_at_the_cap(monkeypatch):
    """
    MEASURED: 30 IPs, cap of 4 → exactly 4 outbound GreyNoise requests, and the
    remaining lookups degrade to {} rather than raising.
    """
    from sources import ip_reputation
    from sources.ip_reputation import GreyNoiseBudget

    monkeypatch.setattr(ip_reputation, "MAX_GREYNOISE_LOOKUPS", 4)
    calls: list[str] = []

    async def _fake_check(ip, api_key):
        calls.append(ip)
        return {"classification": "unknown"}

    monkeypatch.setattr(ip_reputation, "_check_greynoise", _fake_check)

    budget = GreyNoiseBudget()
    ips = [f"45.33.32.{i}" for i in range(1, 31)]
    results = await asyncio.gather(
        *[ip_reputation._cached_check_greynoise(ip, "k", budget) for ip in ips]
    )

    assert len(calls) == 4, f"expected 4 outbound lookups, got {len(calls)}"
    assert budget.used == 4
    assert budget.capped is True
    assert sum(1 for r in results if r) == 4
    assert sum(1 for r in results if r == {}) == 26


@pytest.mark.asyncio
async def test_greynoise_cache_hits_do_not_consume_budget(monkeypatch):
    """A cache hit issues no request, so it must not spend a weekly lookup."""
    from sources import ip_reputation
    from sources.ip_reputation import GreyNoiseBudget

    calls: list[str] = []

    async def _fake_check(ip, api_key):
        calls.append(ip)
        return {"classification": "unknown"}

    monkeypatch.setattr(ip_reputation, "_check_greynoise", _fake_check)

    budget = GreyNoiseBudget(limit=2)
    # Same IP three times: one miss populates the cache, two hits follow.
    for _ in range(3):
        await ip_reputation._cached_check_greynoise("45.33.32.9", "k", budget)

    assert len(calls) == 1
    assert budget.used == 1, "cache hits were charged against the quota"


@pytest.mark.asyncio
async def test_capped_investigation_reports_an_honest_status(monkeypatch):
    """
    The cap must be visible in sources_used, not a silent reduction in
    GreyNoise coverage.
    """
    from sources import ip_reputation

    monkeypatch.setattr(ip_reputation, "MAX_GREYNOISE_LOOKUPS", 2)
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    async def _fake_check(ip, api_key):
        return {"classification": "unknown"}

    async def _no_feeds():
        return {}

    monkeypatch.setattr(ip_reputation, "_check_greynoise", _fake_check)
    monkeypatch.setattr(ip_reputation, "load_feodo_feed", _no_feeds)
    monkeypatch.setattr(ip_reputation, "load_c2_feeds", _no_feeds)
    monkeypatch.setattr(
        ip_reputation, "_update_entity_reputations", lambda *a, **k: None
    )

    class _Entity:
        def __init__(self, value):
            self.entity_type = "IP_ADDRESS"
            self.value = value
            self.confidence = 1.0

    class _Result:
        def __init__(self, values):
            self.entities = [_Entity(v) for v in values]
            self.entity_count = len(self.entities)

    results = [_Result([f"45.33.32.{i}" for i in range(1, 7)])]
    _, stats = await ip_reputation.enrich_ip_entities(results, "inv-1")

    assert stats["greynoise_capped"] is True
    assert stats["greynoise_lookups"] == 2
    assert "greynoise_capped" in stats["ip_reputation"], stats["ip_reputation"]


# ---------------------------------------------------------------------------
# 2. crt.sh — 5 req/min per IP
# ---------------------------------------------------------------------------


def test_crt_sh_baseline_matches_the_documented_limit(monkeypatch):
    """5 req/min = 12.0 s; the committed constant must be at or above that."""
    from sources import domain_reputation

    committed = _committed_constant(
        "sources/domain_reputation.py", "CRT_MIN_INTERVAL"
    )
    assert committed >= 12.0, committed

    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        applied = pacing.rate_limit_delay(
            committed, domain_reputation.CRT_MAX_CONCURRENCY
        )
        assert applied >= 12.0, f"{profile}: {applied}"


@pytest.mark.asyncio
async def test_crt_sh_paces_sequential_requests(monkeypatch):
    """MEASURED: 5 crt.sh lookups respect the interval under `aggressive`."""
    from sources import domain_reputation

    monkeypatch.setattr(domain_reputation, "CRT_MIN_INTERVAL", 0.06)
    monkeypatch.setattr(domain_reputation, "_crt_semaphore", None)
    monkeypatch.setattr(domain_reputation, "_crt_budget_started", None)
    domain_reputation._crt_cache.clear()
    _set(monkeypatch, "aggressive")

    timestamps: list[float] = []
    monkeypatch.setattr(
        domain_reputation.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(
            [_FakeResponse(200, []) for _ in range(5)], timestamps
        ),
    )

    n = 5
    start = time.perf_counter()
    await asyncio.gather(
        *[domain_reputation.query_crt_sh(f"d{i}.example.com") for i in range(n)]
    )
    elapsed = time.perf_counter() - start

    observed_rate = n / elapsed
    allowed_rate = 1.0 / 0.06
    assert observed_rate <= allowed_rate * 1.15, (
        f"observed {observed_rate:.2f} req/s vs allowed {allowed_rate:.2f}"
    )


@pytest.mark.asyncio
async def test_crt_sh_pays_the_delay_on_429(monkeypatch):
    from sources import domain_reputation

    monkeypatch.setattr(domain_reputation, "CRT_MIN_INTERVAL", 0.05)
    monkeypatch.setattr(domain_reputation, "_crt_semaphore", None)
    monkeypatch.setattr(domain_reputation, "_crt_budget_started", None)
    domain_reputation._crt_cache.clear()

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(domain_reputation.asyncio, "sleep", _record)
    monkeypatch.setattr(
        domain_reputation.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(429, headers={})]),
    )

    result = await domain_reputation.query_crt_sh("blocked.example.com")
    assert result == []
    assert slept and slept[0] > 0, "429 skipped the crt.sh delay"


@pytest.mark.asyncio
async def test_crt_sh_soft_budget_stops_further_lookups(monkeypatch):
    """Past the budget, crt.sh degrades to [] instead of running for minutes."""
    from sources import domain_reputation

    # A negative budget, not 0.0 plus a short sleep: time.monotonic() has ~15.6 ms
    # granularity on Windows, so a 10 ms sleep may not tick the clock at all and
    # the budget reads as un-exhausted. This asserts the logic, not the clock.
    monkeypatch.setattr(domain_reputation, "CRT_SOFT_BUDGET", -1.0)
    domain_reputation._crt_cache.clear()
    domain_reputation.start_crt_budget()

    called: list[str] = []
    monkeypatch.setattr(
        domain_reputation.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(200, [])], called),
    )

    assert await domain_reputation.query_crt_sh("late.example.com") == []
    assert called == [], "soft budget did not prevent the request"


# ---------------------------------------------------------------------------
# 3. ransomware.live — 1 req/min PER ENDPOINT
# ---------------------------------------------------------------------------


def test_ransomware_live_baseline_matches_the_documented_limit(monkeypatch):
    """
    Reads the committed constant rather than the module attribute: conftest.py
    zeroes these intervals so the suite runs fast, which would make an assertion
    about the documented baseline vacuously pass.
    """
    committed = _committed_constant("sources/enrichment.py", "_RL_MIN_INTERVAL")
    assert committed >= 60.0, committed
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        assert pacing.scale_delay_floor(committed) >= 60.0


def test_route_key_collapses_path_parameters():
    """
    The limit is per ENDPOINT, so /group/lockbit and /group/alphv share one
    allowance while /groups and /v2/recentvictims are independent.
    """
    from sources.enrichment import _rl_route_key

    assert _rl_route_key("/group/lockbit") == _rl_route_key("/group/alphv")
    assert _rl_route_key("/groups") != _rl_route_key("/group/lockbit")
    assert _rl_route_key("/v2/recentvictims") != _rl_route_key("/v2/recentcyberattacks")
    assert _rl_route_key("/groups") == "/groups"


@pytest.mark.asyncio
async def test_same_route_is_serialised_and_distinct_routes_are_not(monkeypatch):
    """
    MEASURED: three calls to one route pay 2x the interval between them; three
    calls to three different routes pay nothing.
    """
    from sources import enrichment

    interval = 0.08
    monkeypatch.setattr(enrichment, "_RL_MIN_INTERVAL", interval)
    monkeypatch.setattr(enrichment, "_rl_route_lock", None)
    enrichment.reset_ransomware_live_pacing()
    _set(monkeypatch, "aggressive")

    start = time.perf_counter()
    await asyncio.gather(*[enrichment._rl_route_gate("/group/g%d" % i) for i in range(3)])
    same_route = time.perf_counter() - start

    enrichment.reset_ransomware_live_pacing()
    start = time.perf_counter()
    await asyncio.gather(
        enrichment._rl_route_gate("/groups"),
        enrichment._rl_route_gate("/v2/recentvictims"),
        enrichment._rl_route_gate("/v2/recentcyberattacks"),
    )
    distinct_routes = time.perf_counter() - start

    # 3 calls on one route → 2 gaps of `interval`.
    assert same_route >= interval * 2 * 0.9, same_route
    # Distinct routes never contend.
    assert distinct_routes < interval, distinct_routes


@pytest.mark.asyncio
async def test_group_detail_fanout_is_capped(monkeypatch):
    """At 1 req/min, five group details is five minutes — the cap must bite."""
    from sources import enrichment

    assert enrichment._RL_MAX_GROUP_DETAILS < 5
    assert enrichment._RL_MAX_GROUP_DETAILS >= 1


# ---------------------------------------------------------------------------
# 4. NVD rolling window
# ---------------------------------------------------------------------------


def test_rolling_window_allows_up_to_the_limit_then_blocks():
    window = pacing.RollingWindow(limit=3, window=30.0)
    now = 1000.0
    for i in range(3):
        assert window.wait_time(now=now) == 0.0
        window._times.append(now + i * 0.001)
    assert window.wait_time(now=now + 0.01) > 0


def test_rolling_window_catches_what_a_flat_delay_misses():
    """
    The exact failure a flat delay permits.

    Documented limit: 5 per rolling 30 s.  A caller pacing at a 6 s mean gap
    issues requests at t=0,6,12,18,24 — five requests inside 24 s, legal only
    because the 5th lands exactly on the boundary.  Now the caller idles and
    resumes: at t=30 the flat delay says "6 s since the last one, go ahead",
    but t=30 still has 4 requests inside its trailing 30 s window (t=6..24),
    so a burst here can exceed the limit.  The window knows; the delay cannot.
    """
    window = pacing.RollingWindow(limit=5, window=30.0)
    base = 1000.0
    for t in (0, 6, 12, 18, 24):
        window._times.append(base + t)

    # A flat 6 s delay would consider t=30 clear: 6 s since the last request.
    flat_delay_says_clear = (base + 30) - (base + 24) >= 6.0
    assert flat_delay_says_clear

    # The window agrees at t=30 (t=0 has aged out, leaving 4 in window)...
    assert window.wait_time(now=base + 30) == 0.0
    window._times.append(base + 30)

    # ...but now correctly refuses the NEXT one until t=36, when t=6 ages out —
    # whereas a flat 6 s delay would permit it at t=36 too, and any spacing
    # shorter than 6 s would let a 6th request into the window early.
    assert window.wait_time(now=base + 31) == pytest.approx(5.0, abs=0.01)
    assert window.wait_time(now=base + 36) == 0.0


def test_rolling_window_also_enforces_min_spacing():
    """
    A window limit alone permits `limit` requests back-to-back; NVD also
    documents a recommended gap, so both constraints live in one mechanism.
    """
    window = pacing.RollingWindow(limit=5, window=30.0)
    base = 1000.0
    window._times.append(base)

    assert window.wait_time(now=base + 1, min_spacing=0.0) == 0.0
    assert window.wait_time(now=base + 1, min_spacing=6.5) == pytest.approx(5.5, abs=0.01)


@pytest.mark.asyncio
async def test_rolling_window_acquire_sleeps_only_when_needed():
    window = pacing.RollingWindow(limit=2, window=0.3)

    slept_first = await window.acquire()
    slept_second = await window.acquire()
    assert slept_first == 0.0
    assert slept_second == 0.0

    start = time.perf_counter()
    slept_third = await window.acquire()
    elapsed = time.perf_counter() - start
    assert slept_third > 0
    assert elapsed >= 0.2, elapsed


@pytest.mark.asyncio
async def test_nvd_burst_then_idle_is_blocked_by_the_window(monkeypatch):
    """
    MEASURED, end to end: 6 NVD fetches against a window of 3-per-0.4s.

    A flat mean-rate delay would let all 6 through in ~6 x spacing.  The window
    must force a wait once 3 are in flight inside the window.
    """
    from sources import nvd

    monkeypatch.setattr(nvd, "_NVD_WINDOW_SECONDS", 0.4)
    monkeypatch.setattr(nvd, "_NVD_WINDOW_LIMIT_NO_KEY", 4)   # minus margin -> 3
    monkeypatch.setattr(nvd, "_NVD_DELAY_NO_KEY", 0.0)        # spacing off
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    nvd._reset_request_windows()
    import netpool

    monkeypatch.setattr(netpool, "_clearnet_session", None)  # build the pool from the fake below

    timestamps: list[float] = []
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "descriptions": [], "metrics": {}}}
        ]
    }
    monkeypatch.setattr(
        nvd.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(
            [_FakeResponse(200, payload) for _ in range(6)], timestamps
        ),
    )

    for i in range(6):
        await nvd.fetch_nvd_cve(f"CVE-2024-000{i}")

    assert len(timestamps) == 6
    # No 4 consecutive requests may fall inside any 0.4 s span.
    for i in range(len(timestamps) - 3):
        span = timestamps[i + 3] - timestamps[i]
        assert span >= 0.4 * 0.9, (
            f"4 requests inside {span:.3f}s — window limit violated"
        )


def test_nvd_window_limits_match_the_documented_quotas():
    from sources import nvd

    assert nvd._NVD_WINDOW_SECONDS == 30.0
    assert nvd._NVD_WINDOW_LIMIT_NO_KEY == 5
    assert nvd._NVD_WINDOW_LIMIT_WITH_KEY == 50
    # A margin slot is held back so clock skew cannot land us on the boundary.
    assert nvd._NVD_WINDOW_MARGIN >= 1


def test_nvd_window_is_per_key_tier(monkeypatch):
    from sources import nvd

    nvd._reset_request_windows()
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    no_key = nvd._request_window()
    monkeypatch.setenv("NVD_API_KEY", "abc")
    with_key = nvd._request_window()

    assert no_key is not with_key
    assert with_key.limit > no_key.limit


def test_nvd_no_longer_paces_in_its_enrich_loop():
    """
    The flat inter-request sleep was removed when the window took over; keeping
    both would double-count the same constraint.
    """
    import io

    source = io.open("sources/nvd.py", encoding="utf-8").read()
    assert "await asyncio.sleep(delay)" not in source
    assert "acquire(min_spacing=_request_delay())" in source


# ---------------------------------------------------------------------------
# 5. VirusTotal tier flag
# ---------------------------------------------------------------------------


def test_public_tier_keeps_the_documented_floor(monkeypatch):
    from sources import virustotal

    monkeypatch.setattr(virustotal, "VT_API_TIER", "public")
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        assert virustotal._vt_delay() >= 15.0


def test_unset_tier_defaults_to_public(monkeypatch):
    """Guessing premium wrongly earns a 429, so the default must be safe."""
    from sources import virustotal

    for value in ("", "   ", "nonsense", "free"):
        monkeypatch.setattr(virustotal, "VT_API_TIER", value)
        _set(monkeypatch, "normal")
        assert virustotal._vt_delay() >= 15.0, value


@pytest.mark.parametrize("tier", ["premium", "paid", "enterprise", "PREMIUM", " Premium "])
def test_premium_tier_changes_effective_pacing(monkeypatch, tier):
    from sources import virustotal

    monkeypatch.setattr(virustotal, "VT_API_TIER", tier)
    _set(monkeypatch, "normal")
    premium = virustotal._vt_delay()

    monkeypatch.setattr(virustotal, "VT_API_TIER", "public")
    public = virustotal._vt_delay()

    assert premium < public
    assert premium < 1.0
    # The whole point: a paying subscriber is no longer 25x slower.
    assert public / premium > 10


def test_premium_courtesy_delay_may_scale_down(monkeypatch):
    """
    Premium has no published limit, so this is the one enrichment delay where
    `aggressive` legitimately buys something.
    """
    from sources import virustotal

    monkeypatch.setattr(virustotal, "VT_API_TIER", "premium")
    _set(monkeypatch, "normal")
    normal = virustotal._vt_delay()
    _set(monkeypatch, "aggressive")
    assert virustotal._vt_delay() < normal


# ---------------------------------------------------------------------------
# 6. Retry-After / X-RateLimit-Reset
# ---------------------------------------------------------------------------


def test_retry_after_delta_seconds_is_honoured():
    assert pacing.retry_after_seconds({"Retry-After": "42"}, 5.0) == 42.0


def test_retry_after_http_date_is_honoured():
    now = time.time()
    when = formatdate(now + 30, usegmt=True)
    got = pacing.retry_after_seconds({"Retry-After": when}, 1.0, now=now)
    assert 25 <= got <= 35, got


def test_retry_after_is_case_insensitive():
    assert pacing.retry_after_seconds({"retry-after": "20"}, 1.0) == 20.0


def test_x_ratelimit_reset_epoch_seconds():
    now = 1_700_000_000.0
    got = pacing.retry_after_seconds(
        {"X-RateLimit-Reset": str(int(now + 45))}, 1.0, now=now
    )
    assert got == pytest.approx(45.0, abs=1.0)


def test_x_ratelimit_reset_epoch_milliseconds():
    now = 1_700_000_000.0
    got = pacing.retry_after_seconds(
        {"X-RateLimit-Reset": str(int((now + 20) * 1000))}, 1.0, now=now
    )
    assert got == pytest.approx(20.0, abs=1.0)


def test_missing_headers_fall_back_to_the_static_delay():
    assert pacing.retry_after_seconds({}, 15.0) == 15.0
    assert pacing.retry_after_seconds({"X-Other": "1"}, 6.5) == 6.5


def test_server_value_never_undercuts_the_documented_floor():
    """
    Both constraints bind: a provider saying "1 second" does not license
    undercutting a documented 15 s interval.
    """
    assert pacing.retry_after_seconds({"Retry-After": "1"}, 15.0) == 15.0


def test_explicit_floor_lets_a_shorter_server_value_win():
    """
    Where the fallback is a guess rather than a quota (the LLM retry path), a
    server asking for less must actually be honoured.
    """
    got = pacing.retry_after_seconds({"Retry-After": "10"}, 65.0, floor=5.0)
    assert got == 10.0


def test_stale_or_skewed_reset_header_is_ignored():
    now = 1_700_000_000.0
    got = pacing.retry_after_seconds(
        {"X-RateLimit-Reset": str(int(now - 500))}, 6.5, now=now
    )
    assert got == 6.5


def test_server_declared_wait_is_clamped():
    """An hour-long wait must not block an investigation for an hour."""
    got = pacing.retry_after_seconds({"Retry-After": "3600"}, 1.0)
    assert got == pacing.MAX_SERVER_DECLARED_WAIT


def test_exception_string_branch_matches_the_llm_client_shape():
    now = 1_700_000_000.0
    exc = Exception(
        "429 rate limit {'X-RateLimit-Reset': '%d'}" % int((now + 30) * 1000)
    )
    got = pacing.retry_after_seconds(exc, 65.0, floor=5.0, now=now)
    assert got == pytest.approx(30.0, abs=1.0)


def test_llm_retry_path_delegates_to_the_shared_parser():
    """One implementation of "the server told us how long to wait", not two."""
    import io

    source = io.open("api/routes/investigations.py", encoding="utf-8").read()
    assert "pacing.retry_after_seconds(" in source
    # The old bespoke regex must be gone.
    assert "X-RateLimit-Reset':\\s*'?(\\d{13})" not in source


@pytest.mark.asyncio
async def test_429_retry_after_beats_the_static_delay(monkeypatch):
    """
    MEASURED: a 429 carrying Retry-After makes the client wait that value, not
    the (shorter) static documented delay.
    """
    from sources import breach_lookup

    monkeypatch.setattr(breach_lookup, "_XON_MIN_INTERVAL", 0.01)
    monkeypatch.setattr(breach_lookup, "_xon_semaphore", None)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(breach_lookup.asyncio, "sleep", _record)
    monkeypatch.setattr(
        breach_lookup.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(
            [_FakeResponse(429, headers={"Retry-After": "7"})]
        ),
    )

    res = await breach_lookup.query_xposedornot("someone@example.com")
    assert res["source"] == "xposedornot_rate_limited"
    static = pacing.rate_limit_delay(0.01, breach_lookup._XON_MAX_CONCURRENCY)
    assert slept, "no delay was paid at all"
    assert slept[0] == pytest.approx(7.0), (
        f"honoured {slept[0]}s, not the server's 7s (static would be {static}s)"
    )


@pytest.mark.asyncio
async def test_429_without_headers_still_pays_the_static_delay(monkeypatch):
    from sources import breach_lookup

    monkeypatch.setattr(breach_lookup, "_LEAKCHECK_MIN_INTERVAL", 0.05)
    monkeypatch.setattr(breach_lookup, "_leakcheck_semaphore", None)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(breach_lookup.asyncio, "sleep", _record)
    monkeypatch.setattr(
        breach_lookup.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(429, headers={})]),
    )

    await breach_lookup.query_leakcheck("someone@example.com")
    expected = pacing.rate_limit_delay(0.05, breach_lookup._LEAKCHECK_MAX_CONCURRENCY)
    assert slept and slept[0] == pytest.approx(expected)


@pytest.mark.asyncio
async def test_hudson_rock_honours_retry_after(monkeypatch):
    from sources import infostealer

    monkeypatch.setattr(infostealer, "_HR_MIN_INTERVAL", 0.01)
    monkeypatch.setattr(infostealer, "_hr_semaphore", None)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(infostealer.asyncio, "sleep", _record)
    monkeypatch.setattr(
        infostealer.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(
            [_FakeResponse(429, headers={"Retry-After": "9"})]
        ),
    )

    _, status = await infostealer._get_json(
        infostealer._EMAIL_ENDPOINT, {"email": "a@example.com"}
    )
    assert status == "rate_limited"
    assert slept and slept[0] == pytest.approx(9.0)


@pytest.mark.asyncio
async def test_virustotal_429_returns_the_server_wait(monkeypatch):
    from sources import virustotal

    monkeypatch.setattr(virustotal, "VT_API_TIER", "premium")

    session = _FakeSession([_FakeResponse(429, headers={"Retry-After": "18"})])
    data, wait = await virustotal._fetch_hash("a" * 64, session)
    assert data is None
    assert wait == pytest.approx(18.0)
