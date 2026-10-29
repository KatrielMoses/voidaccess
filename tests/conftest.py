"""
tests/conftest.py — shared fixtures for the VoidAccess test suite.

The enrichment-source modules use two kinds of module-level singletons that are
sensitive to the event loop / process state:

  1. An enrichment-cache singleton (``_enrichment_cache_singleton``). Left alone
     it defaults to the SQLite backend at ``~/.voidaccess/cache.db``, which would
     persist between test runs and turn mocked HTTP responses into stale cache
     hits. We force a fresh in-memory cache per test.
  2. Lazy ``asyncio.Semaphore`` singletons bound to the loop they were created
     on. pytest-asyncio uses a fresh loop per test, so a semaphore created in a
     previous test would raise "bound to a different event loop". We reset them.

The ``reset_source_state`` fixture is autouse so every test starts clean.
"""

from __future__ import annotations

import os

# ``config.py`` raises if JWT_SECRET is unset and runs at import time. Some test
# modules import ``sources.enrichment`` (which pulls config), so set a dummy
# secret before any such import. Also ensure no DATABASE_URL so the enrichers'
# DB-write helpers no-op during unit tests.
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("DISABLE_RATE_LIMIT", "true")

# The repository's developer .env may contain a real-looking PostgreSQL URL.
# Tests that exercise the no-database degradation path must not inherit it via
# config.load_dotenv(); keep the runtime configuration unset unless an
# individual fixture explicitly supplies a database.
import config as _test_config
_test_config.DATABASE_URL = None
os.environ.pop("DATABASE_URL", None)

import pytest
from sqlalchemy import create_engine


@pytest.fixture
def db_engine(tmp_path, monkeypatch):
    """Isolated SQLite engine shared with production ``get_session()`` calls."""
    db_url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    from db.models import Base
    Base.metadata.create_all(engine)

    # db.session snapshots config.DATABASE_URL at import time. Override both
    # sources so code under test using get_session() sees this same file.
    monkeypatch.setenv("DATABASE_URL", db_url)
    import db.session as session_module
    monkeypatch.setattr(session_module, "DATABASE_URL", db_url)
    session_module._get_engine_cached.cache_clear()
    yield engine
    engine.dispose()
    session_module._get_engine_cached.cache_clear()

from utils.enrichment_cache import EnrichmentCache, reset_default_cache


@pytest.fixture(autouse=True)
async def _netpool_isolation():
    """Give each test a fresh, cleanly-closed shared clearnet session (P1.2).

    The netpool session is process-global but event-loop-bound, and each test runs
    on its own loop. Closing it here — an ASYNC autouse fixture, so under
    ``asyncio_mode = auto`` it runs in the *test's own* loop — closes the session
    and its connector in the loop that created them, avoiding both
    "attached to a different loop" errors (cross-test reuse) and
    "Unclosed client session" warnings (leaked on GC).
    """
    import netpool as _netpool

    await _netpool.close_clearnet_pool()  # drop any leftover from a prior test
    yield
    await _netpool.close_clearnet_pool()


@pytest.fixture(autouse=True)
def reset_source_state(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # An ambient allowlist in a developer shell must not change unrelated tests.
    monkeypatch.delenv("VOIDACCESS_ENRICHMENT_SOURCES", raising=False)
    # Likewise an ambient deny-list, and the process-wide cancel token / source
    # tracker (module state that must not leak from one test to the next).
    monkeypatch.delenv("VOIDACCESS_DISABLED_SOURCES", raising=False)
    from sources import source_control as _source_control
    from utils import cancel as _cancel

    _source_control.reset_for_tests()
    _cancel.reset_for_tests()
    # 22S: a GitHub rate-limit cooldown is process-wide too.
    try:
        from sources.github_scraper import reset_rate_limit_state

        reset_rate_limit_state()
    except Exception:
        pass
    """Give each test a fresh in-memory enrichment cache and reset semaphores."""
    reset_default_cache()

    # The in-process rate limiter (P2.3) is process-global; without a per-test
    # reset, requests from earlier tests that enabled rate limiting would burn
    # the per-IP budget and 429 a later test's first request.
    try:
        import ratelimit
        ratelimit.reset()
    except Exception:
        pass

    import sources.breach_lookup as breach_lookup
    import sources.infostealer as infostealer
    import sources.hash_reputation as hash_reputation
    import sources.nvd as nvd
    import sources.domain_reputation as domain_reputation
    import sources.ip_reputation as ip_reputation
    import sources.epss as epss

    fresh_cache = EnrichmentCache(backend="memory")

    # Every module holding its own cache singleton must be reset, or an entry
    # written by one test becomes a cache HIT in the next — which silently
    # suppresses the outbound request the next test is trying to observe.
    for mod in (
        breach_lookup,
        infostealer,
        hash_reputation,
        nvd,
        domain_reputation,
        ip_reputation,
        epss,
    ):
        monkeypatch.setattr(mod, "_enrichment_cache_singleton", fresh_cache, raising=False)

    # Reset lazy per-loop semaphores so they rebind to the test's event loop.
    monkeypatch.setattr(breach_lookup, "_xon_semaphore", None, raising=False)
    monkeypatch.setattr(breach_lookup, "_leakcheck_semaphore", None, raising=False)
    monkeypatch.setattr(infostealer, "_hr_semaphore", None, raising=False)

    # Neutralise the deliberate rate-limit sleeps so the suite runs fast.
    # These are the documented *intervals* the delay is derived from — zeroing
    # the interval zeroes the delay, so this keeps working now that the delay
    # is computed from (interval x concurrency) rather than stored directly.
    monkeypatch.setattr(breach_lookup, "_XON_MIN_INTERVAL", 0.0, raising=False)
    monkeypatch.setattr(breach_lookup, "_LEAKCHECK_MIN_INTERVAL", 0.0, raising=False)
    monkeypatch.setattr(infostealer, "_HR_MIN_INTERVAL", 0.0, raising=False)
    monkeypatch.setattr(nvd, "_NVD_DELAY_NO_KEY", 0.0, raising=False)
    monkeypatch.setattr(nvd, "_NVD_DELAY_WITH_KEY", 0.0, raising=False)

    # NVD's rolling window is real in-process state; a window left full by one
    # test would make the next one block on a 30 s expiry.
    nvd._reset_request_windows()

    # crt.sh is paced at 5 req/min and ransomware.live at 1 req/min — both far
    # too slow for a test suite, so zero the intervals and clear route state.
    import sources.enrichment as enrichment_mod

    monkeypatch.setattr(domain_reputation, "CRT_MIN_INTERVAL", 0.0, raising=False)
    monkeypatch.setattr(domain_reputation, "_crt_semaphore", None, raising=False)
    monkeypatch.setattr(domain_reputation, "_crt_budget_started", None, raising=False)
    monkeypatch.setattr(enrichment_mod, "_RL_MIN_INTERVAL", 0.0, raising=False)
    monkeypatch.setattr(enrichment_mod, "_rl_route_lock", None, raising=False)
    enrichment_mod.reset_ransomware_live_pacing()
    domain_reputation._crt_cache.clear()
    domain_reputation._urlscan_cache.clear()
    domain_reputation._wayback_cache.clear()

    # The Tor stream-isolation pool is process-global and shared by every
    # Tor-fetching module (scraper, crawler, search, sources).  Tests that patch
    # `aiohttp.ClientSession` would otherwise park a MagicMock in it, and the
    # next test to ask for that hostname would silently be handed the previous
    # test's mock.  Sessions are also loop-bound, so one surviving a test would
    # fail with "attached to a different loop" in the next.
    from scraper import tor_pool as _tor_pool

    _tor_pool._tor_sessions.clear()
    _tor_pool._tor_inflight.clear()

    # The shared clearnet pool (P1.2) is drained by the async `_netpool_isolation`
    # fixture above, which can close it inside the test's own event loop.

    yield

    _tor_pool._tor_sessions.clear()
    _tor_pool._tor_inflight.clear()
    reset_default_cache()


class FakeEntity:
    """Minimal stand-in for a normalized entity (only the attrs enrichers read)."""

    def __init__(self, entity_type: str, value: str, confidence: float = 1.0):
        self.entity_type = entity_type
        self.value = value
        self.confidence = confidence
        self.canonical_value = value


class FakeExtractionResult:
    """Shape: ExtractionResult — only ``.entities`` is used by the enrichers."""

    def __init__(self, entities):
        self.entities = entities


def make_results(*entities) -> list:
    """Wrap FakeEntity instances into a one-element extraction-results list."""
    return [FakeExtractionResult(list(entities))]


@pytest.fixture(autouse=True)
def _api_override_isolation():
    from api.main import app
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _isolated_ransomlook_cache(monkeypatch, tmp_path):
    """22S: RansomLook answers are cached on disk and in memory; each test
    gets its own empty cache so one test's group list never feeds another."""
    try:
        import sources.cache as _cache
        import sources.enrichment as _enrichment
    except Exception:
        yield
        return
    monkeypatch.setattr(_enrichment, "RANSOMLOOK_CACHE_DIR", str(tmp_path))
    for _url in [u for u in _cache._memory_cache if "ransomlook.io" in u]:
        _cache._memory_cache.pop(_url, None)
    yield
    for _url in [u for u in _cache._memory_cache if "ransomlook.io" in u]:
        _cache._memory_cache.pop(_url, None)
