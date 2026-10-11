"""netpool — the single shared clearnet HTTP connection pool.

One cached ``aiohttp.ClientSession`` with a keep-alive ``TCPConnector``, reused by
every clearnet caller so a lookup pays the TCP+TLS handshake once and then reuses
the connection. This is the clearnet counterpart to ``scraper/tor_pool.py``.

It lives in its own top-level module ON PURPOSE: both ``scraper/`` (page scraping)
and ``sources/`` (enrichment) need the same pool, and ``sources/`` must not import
``scraper/`` (the sources/scraper firewall documented in
``sources/proxy_client.py``). A neutral module both import keeps the pool DRY *and*
the firewall intact — nobody imports across it.

Depends only on ``aiohttp`` + ``pacing`` + ``config`` — never on ``scraper`` or
``sources``. The ``.onion`` refusal invariant is enforced one layer up, in
``sources/http_pool.py`` (which owns the sources-facing guard); this module is pure
transport plumbing and stays policy-free so the scraper can use it unguarded too.
"""
from __future__ import annotations

import logging
from typing import Optional

import aiohttp

import pacing

logger = logging.getLogger(__name__)

# Connector caps — the proven values previously baked into
# ``scraper/scrape.py``. limit=30 total / limit_per_host=10. Enrichment's
# strict-quota hosts are already clamped to 1-2 concurrent by their own
# semaphores/rolling windows, and the CLI runs enrichment categories
# sequentially, so 30 is ample headroom without throttling below what the
# per-module throttles already enforce. Kept identical to the old scraper value
# so the scraper that shares this pool sees zero behavior change.
CLEARNET_CONN_LIMIT = 30
CLEARNET_CONN_LIMIT_PER_HOST = 10

# `normal` pacing baselines (seconds) for the session-level connect/read
# timeouts; scaled by the active profile at construction time.
CLEARNET_CONNECT_TIMEOUT = 5
CLEARNET_READ_TIMEOUT = 25

_clearnet_session: Optional[aiohttp.ClientSession] = None
# Tracked separately so shutdown can close it even when the session object is a
# test mock that ignores its connector (otherwise the real connector leaks).
_clearnet_connector: Optional[aiohttp.TCPConnector] = None


def clearnet_connector() -> aiohttp.TCPConnector:
    """Keep-alive TCP connector for the shared clearnet session."""
    return aiohttp.TCPConnector(
        limit=CLEARNET_CONN_LIMIT,
        limit_per_host=CLEARNET_CONN_LIMIT_PER_HOST,
    )


def get_clearnet_session() -> aiohttp.ClientSession:
    """Return the process-wide cached clearnet session.

    Lazily created, self-healing (rebuilt if never made or already closed).
    Session-level timeouts cover connect/read only (no ``total``) so a caller's
    per-request ``ClientTimeout(total=...)`` overrides cleanly — the same model
    ``sources/proxy_client.py`` already uses.
    """
    global _clearnet_session, _clearnet_connector
    # `is True` (not just truthy): a real ClientSession.closed returns an actual
    # bool, so this recreates a genuinely-closed session — but a test mock whose
    # `.closed` is a truthy MagicMock is NOT the True singleton, so the mock is
    # reused instead of spuriously rebuilt (which would orphan a real connector
    # per call and leak it on GC).
    if _clearnet_session is None or _clearnet_session.closed is True:
        _clearnet_connector = clearnet_connector()
        _clearnet_session = aiohttp.ClientSession(
            connector=_clearnet_connector,
            timeout=aiohttp.ClientTimeout(
                connect=pacing.scale_timeout(CLEARNET_CONNECT_TIMEOUT),
                sock_read=pacing.scale_timeout(CLEARNET_READ_TIMEOUT),
            ),
        )
    return _clearnet_session


async def close_clearnet_pool() -> None:
    """Close the shared clearnet session on shutdown. Idempotent.

    Mirrors ``tor_pool.close_pool``'s discipline: null the global first so nothing
    grabs a half-closed session, then await the guarded close.
    """
    global _clearnet_session, _clearnet_connector
    session = _clearnet_session
    connector = _clearnet_connector
    _clearnet_session = None
    _clearnet_connector = None
    # `getattr(..., "closed", ...)` keeps this robust to test fakes/mocks that
    # stand in for the session without implementing the full aiohttp surface.
    if session is not None and not getattr(session, "closed", False):
        try:
            await session.close()
        except Exception:  # never let a shutdown hiccup propagate
            pass
    # Close the connector explicitly too: a real session owns and closes its
    # connector, but a test mock session ignores it, so the real connector would
    # otherwise leak (and warn on GC once its loop is gone).
    if connector is not None and not getattr(connector, "closed", False):
        try:
            await connector.close()
        except Exception:
            pass
