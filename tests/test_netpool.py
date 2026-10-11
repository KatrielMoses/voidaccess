"""Tests for the shared clearnet pool (netpool) and its guarded sources handle."""
from __future__ import annotations

import asyncio
import warnings

import pytest

import netpool
from sources import http_pool


def test_get_clearnet_session_is_pooled_singleton():
    async def go():
        s1 = netpool.get_clearnet_session()
        s2 = netpool.get_clearnet_session()
        assert s1 is s2  # reused, not rebuilt per call
        return s1

    s = asyncio.run(go())
    asyncio.run(netpool.close_clearnet_pool())
    assert s.closed


def test_self_heals_after_close():
    async def go():
        s1 = netpool.get_clearnet_session()
        await netpool.close_clearnet_pool()
        s2 = netpool.get_clearnet_session()
        assert s2 is not s1
        assert not s2.closed
        await netpool.close_clearnet_pool()

    asyncio.run(go())


def test_connector_limits():
    async def go():
        conn = netpool.clearnet_connector()
        assert conn.limit == netpool.CLEARNET_CONN_LIMIT == 30
        assert conn.limit_per_host == netpool.CLEARNET_CONN_LIMIT_PER_HOST == 10
        await conn.close()

    asyncio.run(go())


def test_close_is_idempotent_and_clean():
    async def go():
        netpool.get_clearnet_session()
        await netpool.close_clearnet_pool()
        await netpool.close_clearnet_pool()  # no raise, no warning

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        asyncio.run(go())


def test_scrape_delegates_to_netpool_same_object():
    """DRY proof: scraper.scrape.get_direct_session_cached() returns the very
    session netpool owns — one pool, not two."""
    async def go():
        from scraper import scrape
        s_scrape = scrape.get_direct_session_cached()
        s_pool = netpool.get_clearnet_session()
        assert s_scrape is s_pool
        await scrape.close_cached_sessions()

    asyncio.run(go())


# --------------------------------------------------------------------------- #
# .onion refusal invariant (the guarded sources handle)
# --------------------------------------------------------------------------- #
def test_guarded_session_refuses_onion():
    session = http_pool.get_clearnet_session()
    onion = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/x"
    for call in (
        lambda: session.get(onion),
        lambda: session.post(onion),
        lambda: session.head(onion),
        lambda: session.request("GET", onion),
    ):
        with pytest.raises(ValueError):
            call()


def test_guarded_session_allows_clearnet(monkeypatch):
    # A clearnet URL passes the guard and delegates to the pool session's method.
    calls = []

    class FakeSession:
        def get(self, url, **kw):
            calls.append(("get", url, kw))
            return "CM"

    monkeypatch.setattr(netpool, "get_clearnet_session", lambda: FakeSession())
    session = http_pool.get_clearnet_session()
    result = session.get("https://example.com/api", headers={"User-Agent": "x"})
    assert result == "CM"
    assert calls == [("get", "https://example.com/api", {"headers": {"User-Agent": "x"}})]


def test_clearnet_session_contextmanager_does_not_close():
    async def go():
        async with http_pool.clearnet_session() as s:
            assert isinstance(s, http_pool._GuardedClearnetSession)
        # The shared underlying session must survive the `with` block.
        assert not netpool.get_clearnet_session().closed
        await netpool.close_clearnet_pool()

    asyncio.run(go())
