"""
tests/test_ratelimit.py — P2.3 rate-limiting acceptance.

The limiter actually enforces (burst → 429), works per-process without Redis,
and standalone-style login no longer 500s.
"""

from __future__ import annotations

import pytest

from ratelimit import RateLimiter


def test_limiter_enforces_fixed_window():
    rl = RateLimiter()
    t = 1000.0
    # 3 per 60s window.
    assert rl.allow("k", 3, 60, now=t) is True
    assert rl.allow("k", 3, 60, now=t + 1) is True
    assert rl.allow("k", 3, 60, now=t + 2) is True
    assert rl.allow("k", 3, 60, now=t + 3) is False   # burst rejected
    # New window resets.
    assert rl.allow("k", 3, 60, now=t + 61) is True
    # Different key is independent.
    assert rl.allow("other", 3, 60, now=t + 3) is True


@pytest.fixture
def rl_client(db_engine, monkeypatch):
    """A TestClient with rate limiting ENABLED and a real user + DB."""
    monkeypatch.setenv("DISABLE_RATE_LIMIT", "false")
    import ratelimit

    ratelimit.reset()

    from sqlalchemy.orm import Session as _Session
    from db.models import User
    from api.auth import hash_password

    with _Session(db_engine) as s:
        s.add(
            User(
                id=1, email="u@example.com", hashed_password=hash_password("Password1"),
                is_active=True, must_reset_password=False,
            )
        )
        s.commit()

    from fastapi.testclient import TestClient
    from api.main import app

    return TestClient(app, raise_server_exceptions=False)


def test_login_does_not_500_and_burst_returns_429(rl_client):
    codes = [
        rl_client.post(
            "/auth/login", json={"email": "u@example.com", "password": "wrong"}
        ).status_code
        for _ in range(8)
    ]
    # Never a 500 (the standalone-uvicorn slowapi-wiring bug is gone).
    assert 500 not in codes, codes
    # Wrong password is a clean 401 while within the limit...
    assert codes[0] == 401, codes
    # ...and a burst past 5/min is rejected with 429.
    assert 429 in codes, codes


def test_login_success_within_limit(rl_client):
    resp = rl_client.post(
        "/auth/login", json={"email": "u@example.com", "password": "Password1"}
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
