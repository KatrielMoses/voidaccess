"""
api/rate_limit.py — FastAPI wiring over the in-process ``ratelimit`` substrate.

Replaces the previous slowapi setup, which constructed three independent
``Limiter`` instances (in ``api/main.py``, ``api/routes/auth.py`` and
``api/routes/investigations.py``) decoupled from ``app.state.limiter`` — the
cause of the standalone-uvicorn ``POST /auth/login`` 500 — and a global
middleware that only ``pass``ed through.

Here there is one substrate (``ratelimit.default_limiter()``):

* :func:`global_rate_limit_middleware` — a real per-IP global cap (no longer a
  no-op); a burst returns 429.
* :func:`rate_limit` — a per-route dependency for the stricter endpoint limits
  (login, create-investigation). Enforced in-process, no Redis. P4's per-API-key
  ingest limits reuse the same substrate with an api-key-based scope/key.

All honor the existing ``DISABLE_RATE_LIMIT`` switch (read live), so tests and
operators can turn enforcement off without touching code.
"""

from __future__ import annotations

import os
from typing import Callable

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

import ratelimit

# Global per-IP cap across all non-exempt routes.
GLOBAL_RATE_LIMIT = int(os.getenv("VOIDACCESS_GLOBAL_RATE_LIMIT", "120") or 120)
GLOBAL_WINDOW_SECONDS = 60.0

_EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}


def _too_many(window: float) -> dict:
    return {
        "detail": "Too many requests. Please slow down and retry shortly.",
        "retry_after": int(window),
    }


async def global_rate_limit_middleware(request: Request, call_next: Callable):
    """Enforce a global per-IP request cap. Real enforcement (429 on burst)."""
    if ratelimit.is_rate_limiting_disabled() or request.url.path in _EXEMPT_PATHS:
        return await call_next(request)

    key = f"global:{ratelimit.client_key(request)}"
    if not ratelimit.default_limiter().allow(key, GLOBAL_RATE_LIMIT, GLOBAL_WINDOW_SECONDS):
        return JSONResponse(
            status_code=429,
            content=_too_many(GLOBAL_WINDOW_SECONDS),
            headers={"Retry-After": str(int(GLOBAL_WINDOW_SECONDS))},
        )
    return await call_next(request)


def rate_limit(limit: int, window: float, *, scope: str) -> Callable:
    """Return a FastAPI dependency enforcing *limit* per *window* seconds per IP.

    Usage::

        @router.post("/login")
        async def login(..., _rl=Depends(rate_limit(5, 60, scope="login"))):
    """

    async def _dependency(request: Request) -> None:
        if ratelimit.is_rate_limiting_disabled():
            return
        key = f"{scope}:{ratelimit.client_key(request)}"
        if not ratelimit.default_limiter().allow(key, limit, window):
            raise HTTPException(
                status_code=429,
                detail=_too_many(window)["detail"],
                headers={"Retry-After": str(int(window))},
            )

    return _dependency
