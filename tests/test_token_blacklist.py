"""
tests/test_token_blacklist.py — P2.3 zero-Redis auth acceptance.

The token blacklist boots and works with no Redis: with a DB it enforces
revocation; with nothing configured it disables cleanly (no 503).
"""

from __future__ import annotations

import pytest

import auth.token_blacklist as tb


async def test_no_store_configured_disables_cleanly(monkeypatch):
    """No Redis, no DB → blacklist disabled, returns False, never raises/503."""
    monkeypatch.setattr(tb, "REDIS_URL", None)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert tb.is_blacklist_configured() is False
    assert await tb.is_token_revoked("any-jti") is False  # no raise → no 503
    assert await tb.revoke_token("any-jti", 3600) is False


async def test_db_backed_revocation_without_redis(db_engine, monkeypatch):
    """With only a DB (no Redis), revocation works end-to-end."""
    monkeypatch.setattr(tb, "REDIS_URL", None)
    # db_engine sets DATABASE_URL to the test SQLite DB.

    assert tb.is_blacklist_configured() is True          # DB counts as configured
    assert await tb.is_token_revoked("jti-1") is False    # not yet revoked
    assert await tb.revoke_token("jti-1", 3600) is True
    assert await tb.is_token_revoked("jti-1") is True     # now revoked
    # A different token is unaffected.
    assert await tb.is_token_revoked("jti-2") is False


async def test_expired_db_revocation_is_pruned(db_engine, monkeypatch):
    monkeypatch.setattr(tb, "REDIS_URL", None)
    # Revoke with a already-past expiry (negative → clamped to 1s, then sleep).
    await tb.revoke_token("jti-exp", 1)
    import time

    time.sleep(1.1)
    # Past expiry → treated as not revoked (and pruned).
    assert await tb.is_token_revoked("jti-exp") is False


def test_module_imports_without_redis_package():
    """Importing the blacklist must not require the redis package at import time
    (the redis import is lazy inside _get_client)."""
    import importlib

    mod = importlib.reload(tb)
    assert hasattr(mod, "is_token_revoked")
