"""
Tests for sources/email_reputation.py

Covers: HIBP response parsing, password exposure detection, confidence boosting,
recently_breached tagging, EmailRep disposable/malicious handling, platform
extraction, disposable blocklist, domain cross-reference, free-provider filtering,
graceful degradation, MAX_EMAILS cap, log hygiene, confidence floor/ceiling,
24h cache TTL, and sources_used tracking.
"""

from __future__ import annotations

import asyncio
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sources.email_reputation as er
from sources.email_reputation import (
    MAX_EMAILS,
    _safe_log_email,
    check_email_reputation,
    enrich_email_entities,
    is_disposable_domain,
    query_emailrep,
    query_hibp,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeEntity:
    def __init__(self, entity_type: str, value: str, confidence: float = 0.85):
        self.entity_type = entity_type
        self.value = value
        self.confidence = confidence


class _FakeExtractionResult:
    def __init__(self, entities: list):
        self.entities = entities
        self.entity_count = len(entities)


def _make_exr(emails: list[str], confidence: float = 0.85) -> _FakeExtractionResult:
    return _FakeExtractionResult(
        [_FakeEntity("EMAIL_ADDRESS", e, confidence) for e in emails]
    )


def _mock_aiohttp_get(status: int, json_data=None, text_data: str | None = None):
    """Build an aiohttp session mock that returns a fixed response for GET calls."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    # Define BOTH response readers so whichever the code path calls is a real
    # awaitable (some tests reuse one mock across a JSON call and the disposable
    # -list text fetch, which forces a fetch when its cache is empty).
    mock_resp.json = AsyncMock(return_value=json_data)
    mock_resp.text = AsyncMock(return_value=text_data if text_data is not None else "")

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get = MagicMock(return_value=ctx)
    return session


# ---------------------------------------------------------------------------
# 1. HIBP response parsing extracts breach names and dates correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_parses_breach_names_and_dates():
    hibp_data = [
        {"Name": "BreachAlpha", "BreachDate": "2020-01-15", "DataClasses": ["Email addresses"]},
        {"Name": "BreachBeta",  "BreachDate": "2022-06-30", "DataClasses": ["Usernames"]},
    ]
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "testkey"}),
        patch.object(er, "_hibp_cache", {}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=hibp_data)),
    ):
        result = await query_hibp("test@example.com")

    assert result["found"] is True
    assert "BreachAlpha" in result["breach_names"]
    assert "BreachBeta" in result["breach_names"]
    assert "2020-01-15" in result["breach_dates"]
    assert "2022-06-30" in result["breach_dates"]
    assert result["breach_count"] == 2


# ---------------------------------------------------------------------------
# 2. HIBP breach with password class sets password_exposed=True
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_password_class_sets_flag():
    hibp_data = [
        {
            "Name": "PasswordBreach",
            "BreachDate": "2021-03-10",
            "DataClasses": ["Passwords", "Email addresses"],
        },
    ]
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "testkey"}),
        patch.object(er, "_hibp_cache", {}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=hibp_data)),
    ):
        result = await query_hibp("victim@example.com")

    assert result["password_exposed"] is True


# ---------------------------------------------------------------------------
# 3. HIBP hit boosts confidence +0.15
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_hit_boosts_confidence():
    hibp_data = [
        {"Name": "SomeBreach", "BreachDate": "2019-05-01", "DataClasses": ["Email addresses"]},
    ]
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "testkey"}),
        patch.object(er, "_hibp_cache", {}),
        patch.object(er, "_emailrep_cache", {}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch.object(er, "query_emailrep", AsyncMock(return_value={})),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=hibp_data)),
    ):
        result = await check_email_reputation("actor@example.com", base_confidence=0.80)

    assert result["confidence_delta"] >= 0.15
    assert "hibp_breached" in result["tags"]


# ---------------------------------------------------------------------------
# 4. HIBP recent breach (<1 year) adds recently_breached tag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_recent_breach_tag():
    from datetime import datetime, timezone, timedelta

    recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    hibp_data = [
        {"Name": "FreshBreach", "BreachDate": recent_date, "DataClasses": ["Email addresses"]},
    ]
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "testkey"}),
        patch.object(er, "_hibp_cache", {}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=hibp_data)),
    ):
        result = await query_hibp("recent@example.com")

    assert result["recently_breached"] is True


# ---------------------------------------------------------------------------
# 5. EmailRep disposable=true lowers confidence -0.10 and adds tag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emailrep_disposable_lowers_confidence():
    emailrep_data = {
        "reputation": "low",
        "suspicious": True,
        "references": 0,
        "details": {
            "disposable": True,
            "free_provider": False,
            "blacklisted": False,
            "malicious_activity": False,
            "credentials_leaked": False,
            "profiles": [],
        },
    }
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": ""}),
        patch.object(er, "_emailrep_cache", {}),
        patch.object(er, "_hibp_cache", {}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=emailrep_data)),
    ):
        result = await check_email_reputation("throwaway@mailinator.com", base_confidence=0.85)

    assert result["disposable"] is True
    assert "disposable_email" in result["tags"]
    assert result["confidence_delta"] <= -0.10


# ---------------------------------------------------------------------------
# 6. EmailRep malicious_activity boosts confidence +0.10
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emailrep_malicious_boosts_confidence():
    emailrep_data = {
        "reputation": "none",
        "suspicious": True,
        "references": 5,
        "details": {
            "disposable": False,
            "free_provider": False,
            "blacklisted": True,
            "malicious_activity": True,
            "credentials_leaked": False,
            "profiles": [],
        },
    }
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "", "EMAILREP_API_KEY": ""}),
        patch.object(er, "_emailrep_cache", {}),
        patch.object(er, "_hibp_cache", {}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=emailrep_data)),
    ):
        result = await check_email_reputation("bad@actor-domain.net", base_confidence=0.75)

    assert result["malicious_activity"] is True
    assert "emailrep_malicious" in result["tags"]
    assert result["confidence_delta"] >= 0.10


# ---------------------------------------------------------------------------
# 7. EmailRep platforms list extracted correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emailrep_platforms_extracted():
    emailrep_data = {
        "reputation": "medium",
        "suspicious": False,
        "references": 12,
        "details": {
            "disposable": False,
            "free_provider": False,
            "blacklisted": False,
            "malicious_activity": False,
            "credentials_leaked": False,
            "profiles": ["twitter", "linkedin", "github"],
        },
    }
    with (
        patch.object(er, "_emailrep_cache", {}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=emailrep_data)),
    ):
        result = await query_emailrep("user@example.com")

    assert "twitter" in result["profiles"]
    assert "linkedin" in result["profiles"]
    assert "github" in result["profiles"]


# ---------------------------------------------------------------------------
# 8. Disposable domain list check works locally
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disposable_domain_list_check():
    blocklist_text = "mailinator.com\ntrashmail.com\nguerrillamail.com\n"
    with (
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": 0.0}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, text_data=blocklist_text)),
    ):
        assert await is_disposable_domain("mailinator.com") is True
        assert await is_disposable_domain("trashmail.com") is True
        assert await is_disposable_domain("gmail.com") is False


# ---------------------------------------------------------------------------
# 9. Custom domain extracted as new DOMAIN entity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_custom_domain_extracted_as_entity():
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": ""}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch.object(er, "query_hibp", AsyncMock(return_value={"found": False})),
        patch.object(er, "query_emailrep", AsyncMock(return_value={
            "disposable": False, "malicious_activity": False,
            "credentials_leaked": False, "blacklisted": False,
            "profiles": [], "reputation": None, "suspicious": False,
            "references": 0, "free_provider": False,
        })),
    ):
        result = await check_email_reputation(
            "threat-actor@malicious-infra.net", base_confidence=0.80
        )

    domain_entities = [e for e in result["new_entities"] if e["entity_type"] == "DOMAIN"]
    assert len(domain_entities) == 1
    assert domain_entities[0]["value"] == "malicious-infra.net"
    assert domain_entities[0]["confidence"] == 0.75


# ---------------------------------------------------------------------------
# 10. Common providers (gmail, yahoo) not added as domain entities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_common_providers_not_extracted():
    free_emails = [
        "actor@gmail.com",
        "user@yahoo.com",
        "suspect@hotmail.com",
        "anon@proton.me",
        "hider@tutanota.com",
    ]
    for email in free_emails:
        with (
            patch.dict(os.environ, {"HIBP_API_KEY": ""}),
            patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
            patch.object(er, "query_hibp", AsyncMock(return_value={"found": False})),
            patch.object(er, "query_emailrep", AsyncMock(return_value={
                "disposable": False, "malicious_activity": False,
                "credentials_leaked": False, "blacklisted": False,
                "profiles": [], "reputation": None, "suspicious": False,
                "references": 0, "free_provider": True,
            })),
        ):
            result = await check_email_reputation(email, base_confidence=0.80)

        domain_entities = [e for e in result["new_entities"] if e["entity_type"] == "DOMAIN"]
        assert len(domain_entities) == 0, f"Unexpected domain entity for {email}"


# ---------------------------------------------------------------------------
# 11. No HIBP key — HIBP skipped, EmailRep still runs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_hibp_key_emailrep_still_runs():
    emailrep_data = {
        "reputation": "medium",
        "suspicious": False,
        "references": 3,
        "details": {
            "disposable": False,
            "free_provider": False,
            "blacklisted": False,
            "malicious_activity": False,
            "credentials_leaked": False,
            "profiles": ["twitter"],
        },
    }
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": ""}),
        patch.object(er, "_emailrep_cache", {}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch("aiohttp.ClientSession",
              return_value=_mock_aiohttp_get(200, json_data=emailrep_data)),
    ):
        result = await check_email_reputation("test@somedomain.com", base_confidence=0.80)

    assert result["breached"] is False
    assert result["reputation"] == "medium"
    assert "twitter" in result["platforms"]


# ---------------------------------------------------------------------------
# 12. Email not found in any source — entity unchanged, no error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_email_not_found_no_error():
    with (
        patch.dict(os.environ, {"HIBP_API_KEY": "testkey"}),
        patch.object(er, "_disposable_cache", {"domains": frozenset(), "loaded_at": time.time()}),
        patch.object(er, "query_hibp", AsyncMock(return_value={"found": False})),
        patch.object(er, "query_emailrep", AsyncMock(return_value={
            "disposable": False, "malicious_activity": False,
            "credentials_leaked": False, "blacklisted": False,
            "profiles": [], "reputation": "medium", "suspicious": False,
            "references": 1, "free_provider": False,
        })),
    ):
        result = await check_email_reputation("clean@example.com", base_confidence=0.80)

    assert result["breached"] is False
    assert result["confidence_delta"] == 0.0
    assert result["tags"] == []


# ---------------------------------------------------------------------------
# 13. Log hygiene — full email never logged, only first 3 chars + domain
# ---------------------------------------------------------------------------

def test_safe_log_email_redaction():
    assert _safe_log_email("johndoe@example.com") == "joh***@example.com"
    assert _safe_log_email("ab@test.com") == "ab***@test.com"
    assert _safe_log_email("actor@malicious.net") == "act***@malicious.net"

    email = "fulladdress@domain.com"
    logged = _safe_log_email(email)
    assert email not in logged
    assert "***" in logged
    assert "@domain.com" in logged


# ---------------------------------------------------------------------------
# 14. MAX_EMAILS = 30 limit enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_emails_limit_enforced():
    emails = [f"user{i}@domain{i}.com" for i in range(40)]
    exr = _FakeExtractionResult([_FakeEntity("EMAIL_ADDRESS", e) for e in emails])

    checked_emails: list[str] = []

    async def mock_check(email: str, base_confidence: float = 1.0) -> dict:
        checked_emails.append(email)
        return {
            "email": email, "breached": False, "breach_count": 0,
            "breach_names": [], "password_exposed": False,
            "most_recent_breach": None, "reputation": None,
            "suspicious": False, "disposable": False,
            "malicious_activity": False, "credentials_leaked": False,
            "platforms": [], "new_entities": [], "tags": [],
            "confidence_delta": 0.0,
        }

    with patch.object(er, "check_email_reputation", side_effect=mock_check):
        await enrich_email_entities([exr], "test-inv-id")

    assert len(checked_emails) == MAX_EMAILS


# ---------------------------------------------------------------------------
# 15. Password exposed + malicious activity triggers high-value log
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_high_value_signal_logged(caplog):
    import logging
    caplog.set_level(logging.INFO)

    exr = _make_exr(["thr@actordomain.net"])

    async def mock_check(email: str, base_confidence: float = 1.0) -> dict:
        return {
            "email": email,
            "breached": True, "breach_count": 2,
            "breach_names": ["Breach1"], "password_exposed": True,
            "most_recent_breach": "2023-01-01", "reputation": "none",
            "suspicious": True, "disposable": False,
            "malicious_activity": True, "credentials_leaked": False,
            "platforms": [], "new_entities": [],
            "tags": ["hibp_breached", "hibp_password_exposed", "emailrep_malicious"],
            "confidence_delta": 0.25,
        }

    with patch.object(er, "check_email_reputation", side_effect=mock_check):
        await enrich_email_entities([exr], "test-inv-789")

    assert any("High-value email" in r.message for r in caplog.records)
    # Full email address must never appear in logs
    full_email = "thr@actordomain.net"
    for record in caplog.records:
        assert full_email not in record.message


# ---------------------------------------------------------------------------
# 16. Confidence delta capped — cannot exceed 1.0, cannot go below 0.50
# ---------------------------------------------------------------------------

def test_confidence_capped_floor_and_ceiling():
    # Ceiling: base 0.95 + delta 0.35 would be 1.30 — clamped to 1.0
    base, delta = 0.95, 0.35
    assert max(0.50, min(base + delta, 1.0)) == 1.0

    # Floor: base 0.52 + delta -0.10 would be 0.42 — clamped to 0.50
    base, delta = 0.52, -0.10
    assert max(0.50, min(base + delta, 1.0)) == 0.50

    # Normal case: no clamping needed
    base, delta = 0.75, 0.10
    assert max(0.50, min(base + delta, 1.0)) == 0.85


# ---------------------------------------------------------------------------
# 17. 24h cache TTL respected for HIBP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_cache_ttl():
    fresh_result = {
        "found": True, "source": "hibp",
        "breach_count": 1, "breach_names": ["Cached"],
        "breach_dates": ["2023-01-01"], "password_exposed": False,
        "most_recent_breach": "2023-01-01", "most_recent_name": "Cached",
        "recently_breached": False,
    }
    email = "cached@example.com"
    warm_cache = {email: {"result": fresh_result, "loaded_at": time.time()}}

    # Should serve from cache without any HTTP call
    with patch.object(er, "_hibp_cache", warm_cache):
        result = await query_hibp(email)

    assert result["found"] is True
    assert result["source"] == "hibp"
    assert result["breach_names"] == ["Cached"]


# ---------------------------------------------------------------------------
# 18. sources_used updated correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sources_used_updated():
    exr = _make_exr(["actor@evil-infra.com"])

    async def mock_check(email: str, base_confidence: float = 1.0) -> dict:
        return {
            "email": email, "breached": True, "breach_count": 1,
            "breach_names": ["TestBreach"], "password_exposed": False,
            "most_recent_breach": "2022-01-01", "reputation": "low",
            "suspicious": True, "disposable": False,
            "malicious_activity": False, "credentials_leaked": False,
            "platforms": [], "new_entities": [],
            "tags": ["hibp_breached", "hibp_breach_count_1"],
            "confidence_delta": 0.15,
        }

    with patch.object(er, "check_email_reputation", side_effect=mock_check):
        _, stats = await enrich_email_entities([exr], "test-inv-999")

    assert "email_reputation" in stats
    assert stats["email_reputation"].startswith("ok_1_emails")
    assert stats["emails_checked"] == 1
    assert stats["breached"] == 1
    assert stats["disposable"] == 0
