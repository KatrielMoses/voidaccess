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
from sources.source_control import (
    is_failure_for_url,
    record_failure_for_url,
    record_request_for_url,
)

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


class _TrackedRequest:
    """Wraps an aiohttp request context so a failed call is counted.

    Delegates everything; adds only failure accounting (an exception, or a
    401/403/429/5xx answer) so ``sources_used`` can say ``error`` when every call
    a source made failed, instead of reporting a silent zero as ``ok``.
    """

    def __init__(self, ctx, url):
        self._ctx = ctx
        self._url = url

    async def __aenter__(self):
        try:
            resp = await self._ctx.__aenter__()
        except BaseException:
            record_failure_for_url(self._url)
            raise
        if is_failure_for_url(getattr(resp, "status", 200), self._url):
            record_failure_for_url(self._url)
        return resp

    async def __aexit__(self, *exc_info):
        return await self._ctx.__aexit__(*exc_info)

    def __await__(self):
        # ``resp = await session.get(...)`` gets the same accounting as
        # ``async with session.get(...) as resp``.
        return self._awaited().__await__()

    async def _awaited(self):
        try:
            resp = await self._ctx
        except BaseException:
            record_failure_for_url(self._url)
            raise
        if is_failure_for_url(getattr(resp, "status", 200), self._url):
            record_failure_for_url(self._url)
        return resp

    def __getattr__(self, name):
        return getattr(self._ctx, name)


def _track(ctx, url):
    """Wrap *ctx* for failure accounting; pass through anything that is not an
    async request context (a test double, say) untouched."""
    return _TrackedRequest(ctx, url) if hasattr(ctx, "__aenter__") else ctx


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
        record_request_for_url(url)
        return _track(self._session().get(url, **kwargs), url)

    def post(self, url, **kwargs):
        _refuse_onion(url)
        record_request_for_url(url)
        return _track(self._session().post(url, **kwargs), url)

    def head(self, url, **kwargs):
        _refuse_onion(url)
        record_request_for_url(url)
        return _track(self._session().head(url, **kwargs), url)

    def request(self, method, url, **kwargs):
        _refuse_onion(url)
        record_request_for_url(url)
        return _track(self._session().request(method, url, **kwargs), url)


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
