"""
Token blacklist for JWT revocation — Redis OR database, zero-Redis capable.

Backends, selected at call time (so config/env changes and tests take effect):

  * REDIS_URL set  → Redis backend (unchanged behaviour). Configured-but-
    unreachable raises ``BlacklistUnavailableError`` so the caller fails closed.
  * REDIS_URL unset, DATABASE_URL set → **DB backend** (P2.3). Revocation works
    with **no Redis** on a single box: a revoked ``jti`` is stored in
    ``revoked_tokens`` with its natural expiry. A transient DB error degrades
    fail-open (returns "not revoked") rather than 503 — the service must keep
    serving JWT auth without Redis; the DB is not an opted-in external control
    the way REDIS_URL is.
  * Neither set → disabled (fail-open by design); ``is_token_revoked`` returns
    False, as before.

This closes the "boots without Redis" requirement: with only DATABASE_URL, auth
serves and revocation is enforced, and there is no 503-because-Redis-absent.
The public surface (``revoke_token`` / ``is_token_revoked`` /
``is_blacklist_configured`` / ``BlacklistUnavailableError`` / ``close``) is
unchanged, so ``api/auth.py`` and the logout route need no changes to their
call shape.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import REDIS_URL

logger = logging.getLogger(__name__)

_pool = None
_redis_client = None
_logged_disabled = False

BLACKLIST_PREFIX = "blacklist:"


class BlacklistUnavailableError(RuntimeError):
    """Raised when an opted-in blacklist store (Redis) is unreachable. Callers
    fail closed rather than silently honour a possibly-revoked token."""


def _database_configured() -> bool:
    import os

    return bool(os.getenv("DATABASE_URL"))


def is_blacklist_configured() -> bool:
    """True when revocation is available — via Redis OR the database."""
    return REDIS_URL is not None or _database_configured()


# ---------------------------------------------------------------------------
# Redis backend (lazy — importing this module must not require the redis pkg)
# ---------------------------------------------------------------------------

def _get_client():
    """Return a lazily-created Redis client. Only call when REDIS_URL is set.

    ``redis`` is imported here, not at module top, so the service boots on a box
    without the redis package installed (zero-Redis deploys).
    """
    global _pool, _redis_client
    if _redis_client is None:
        import redis.asyncio as redis  # noqa: PLC0415

        _pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
        _redis_client = redis.Redis(connection_pool=_pool)
    return _redis_client


async def _redis_revoke(jti: str, expires_in_seconds: int) -> bool:
    try:
        client = _get_client()
        await client.setex(f"{BLACKLIST_PREFIX}{jti}", expires_in_seconds, "revoked")
        return True
    except Exception as e:
        logger.error("Failed to revoke token %s (Redis unreachable?): %s", jti, e)
        return False


async def _redis_is_revoked(jti: str) -> bool:
    try:
        client = _get_client()
        return (await client.exists(f"{BLACKLIST_PREFIX}{jti}")) > 0
    except Exception as e:
        logger.error("Token revocation check failed — Redis unreachable (failing closed): %s", e)
        raise BlacklistUnavailableError(str(e)) from e


# ---------------------------------------------------------------------------
# DB backend (zero-Redis path)
# ---------------------------------------------------------------------------

def _db_revoke_sync(jti: str, expires_in_seconds: int) -> bool:
    from db.session import get_session
    from db.models import RevokedToken

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max(1, expires_in_seconds))
    try:
        with get_session() as session:
            existing = session.get(RevokedToken, jti)
            if existing is None:
                session.add(RevokedToken(jti=jti, expires_at=expires_at, revoked_at=now))
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("DB token revoke failed for %s: %s", jti, e)
        return False


def _db_is_revoked_sync(jti: str) -> bool:
    from db.session import get_session
    from db.models import RevokedToken

    try:
        with get_session() as session:
            row = session.get(RevokedToken, jti)
            if row is None:
                return False
            expires_at = row.expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at is not None and expires_at < datetime.now(timezone.utc):
                # Expired — opportunistic prune; treat as not revoked.
                session.delete(row)
                return False
            return True
    except Exception as e:  # noqa: BLE001
        # Fail-OPEN for the DB backend: a transient DB/schema error must not take
        # down JWT auth on a box whose whole point is running without Redis.
        logger.warning("DB revocation check degraded (fail-open): %s", e)
        return False


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

async def revoke_token(jti: str, expires_in_seconds: int) -> bool:
    """Revoke *jti* until *expires_in_seconds* from now. Returns success."""
    if REDIS_URL is not None:
        return await _redis_revoke(jti, expires_in_seconds)
    if _database_configured():
        return await asyncio.to_thread(_db_revoke_sync, jti, expires_in_seconds)
    return False  # disabled (no store configured)


async def is_token_revoked(jti: str) -> bool:
    """True if *jti* has been revoked.

    Redis unset + DB unset → False (disabled). Redis set + unreachable →
    BlacklistUnavailableError (fail closed). DB backend → real result, fail-open
    on transient error.
    """
    global _logged_disabled
    if REDIS_URL is not None:
        return await _redis_is_revoked(jti)
    if _database_configured():
        return await asyncio.to_thread(_db_is_revoked_sync, jti)
    if not _logged_disabled:
        logger.info(
            "No REDIS_URL or DATABASE_URL — token blacklist disabled (fail-open by design)"
        )
        _logged_disabled = True
    return False


async def close():
    """Close the Redis connection pool if one was created."""
    global _pool, _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _pool is not None:
        await _pool.disconnect()
        _pool = None
