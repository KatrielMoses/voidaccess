"""sources/http_pool.py — the sources-facing handle to the shared clearnet pool.

Every clearnet enrichment module acquires its session here instead of building a
fresh ``aiohttp.ClientSession`` per call, so lookups reuse keep-alive connections
(the P1.2 connection-pool refactor).

Layering (see netpool/README.md):

    proxy_client        decides the route (direct / api / proxy)
    netpool             IS the direct route's shared session
    sources/http_pool   guarded, sources-facing handle to it  ← this module

This module adds ONE thing on top of ``netpool``: the ``.onion`` refusal invariant.
``netpool`` is policy-free plumbing (the scraper uses it unguarded); the guard is a
``sources`` concern, so it lives here and reuses the SAME check ``proxy_client``
uses — ``sources.enrichment.is_onion_url`` — guaranteeing no onion traffic can ever
leak onto a clearnet circuit (defense in depth; enrichment only ever targets
clearnet API endpoints anyway).

The guard never bakes caller auth into the shared session (that would leak one
module's API key to every other caller): callers pass their headers per request.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import aiohttp

import netpool

# Lazily bound to sources.enrichment.is_onion_url. Lazy because enrichment.py
# itself imports this module (for the shared session), so a top-level import
# here would be circular.
_is_onion_url = None


def _refuse_onion(url: str) -> None:
    global _is_onion_url
    if _is_onion_url is None:
        from sources.enrichment import is_onion_url
        _is_onion_url = is_onion_url
    if _is_onion_url(url):
        raise ValueError(
            f"clearnet pool refuses .onion URLs — routing bug upstream: {str(url)[:60]}"
        )


class _GuardedClearnetSession:
    """A thin guard over the shared clearnet session.

    Delegates ``get``/``post``/``request``/``head`` to ``netpool``'s cached session
    after refusing any ``.onion`` URL. Each method is synchronous and returns the
    underlying request context manager, so callers keep the familiar
    ``async with session.get(...) as resp:`` shape. It re-fetches the underlying
    session on every call so ``netpool``'s self-healing (rebuild-if-closed) is
    honored, and it deliberately exposes no ``close()`` — the pool owns lifecycle.
    """

    @staticmethod
    def _session() -> aiohttp.ClientSession:
        return netpool.get_clearnet_session()

    def get(self, url, **kwargs):
        _refuse_onion(url)
        return self._session().get(url, **kwargs)

    def post(self, url, **kwargs):
        _refuse_onion(url)
        return self._session().post(url, **kwargs)

    def head(self, url, **kwargs):
        _refuse_onion(url)
        return self._session().head(url, **kwargs)

    def request(self, method, url, **kwargs):
        _refuse_onion(url)
        return self._session().request(method, url, **kwargs)


_guarded_singleton = _GuardedClearnetSession()


def get_clearnet_session() -> _GuardedClearnetSession:
    """Return the shared, ``.onion``-guarded clearnet session handle.

    Do NOT close the returned object — the pool owns its lifecycle (drained at
    shutdown via ``scraper.scrape.close_cached_sessions`` → ``netpool``).
    """
    return _guarded_singleton


@asynccontextmanager
async def clearnet_session() -> AsyncIterator[_GuardedClearnetSession]:
    """Async-context handle to the shared session that never closes it.

    Lets a module that used ``async with aiohttp.ClientSession(...) as session:``
    migrate with a one-line swap and no re-indentation — the shared session
    outlives the ``with`` block.
    """
    yield _guarded_singleton
