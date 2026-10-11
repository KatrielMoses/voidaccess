"""Offline tests for HIBP Pwned Passwords (credential_presence/).

The legally-critical proof (requirement 5.L): per attack class, the raw credential is
never stored, never logged, and never sent in full — ONLY the SHA-1 5-char prefix
leaves the process.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import credential_presence as cp


# The four raw credentials that must never leak anywhere.
_COMBO_PWS = ["Password1!", "Hunter2xxx", "Secret999z"]
_STEALER_PW = "StealerPass1"
_ALL_PWS = _COMBO_PWS + [_STEALER_PW]

_PAGE_TEXT = (
    "user1@example.com:Password1!\n"
    "user2@example.org:Hunter2xxx\n"
    "user3@example.net:Secret999z\n"
    "\nStealer dump:\n"
    "URL: http://evil.example.com/login\n"
    "LOGIN: victim@bank.example\n"
    "PASSWORD: StealerPass1\n"
)


def _recording_session(url_sink, body=""):
    """A mock aiohttp session whose .get records the requested URL."""
    resp = AsyncMock()
    resp.status = 200
    resp.text = AsyncMock(return_value=body)

    def _get(url, **kwargs):
        url_sink.append(url)
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()
    session.get = MagicMock(side_effect=_get)
    return session


# --------------------------------------------------------------------------- #
# check_password_presence: only the 5-char prefix leaves
# --------------------------------------------------------------------------- #
async def test_check_sends_only_five_char_prefix():
    pw = "correct horse battery staple"
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    urls: list[str] = []
    # Range response includes our suffix so the check reports present.
    body = f"{suffix}:1337\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n"
    with patch("aiohttp.ClientSession", return_value=_recording_session(urls, body)):
        result = await cp.check_password_presence(pw)

    assert result == {"present": True, "breach_count": 1337, "status": "ok"}
    assert len(urls) == 1
    sent = urls[0]
    assert sent.endswith("/range/" + prefix)
    # The full password and the full hash (suffix) NEVER appear in what was sent.
    assert pw not in sent
    assert suffix not in sent
    assert digest not in sent
    # Only 5 hex chars ride after /range/.
    assert re.search(r"/range/[0-9A-F]{5}$", sent)


async def test_check_empty_password_is_noop():
    assert await cp.check_password_presence("") == {"present": False, "breach_count": 0, "status": "ok"}


async def test_check_graceful_on_http_error():
    urls: list[str] = []
    sess = _recording_session(urls)
    sess.get.side_effect = None
    resp = AsyncMock(); resp.status = 503; resp.text = AsyncMock(return_value="")
    ctx = MagicMock(); ctx.__aenter__ = AsyncMock(return_value=resp); ctx.__aexit__ = AsyncMock(return_value=False)
    sess.get = MagicMock(return_value=ctx)
    with patch("aiohttp.ClientSession", return_value=sess):
        result = await cp.check_password_presence("whatever")
    assert result["status"] == "unavailable"
    assert result["present"] is False


# --------------------------------------------------------------------------- #
# scan: raw credential never sent in full, never in outputs, never logged
# --------------------------------------------------------------------------- #
async def test_scan_sends_only_prefixes_and_never_the_raw_password(caplog):
    urls: list[str] = []
    with patch("aiohttp.ClientSession", return_value=_recording_session(urls, body="")):
        with caplog.at_level(logging.DEBUG):
            page, stats = await cp.scan_pages_for_pwned_credentials([{"text": _PAGE_TEXT}])

    # Both attack classes observed (3 combo lines + 1 stealer) and checked.
    assert stats["observed"] >= 4
    assert stats["checked"] == 4  # 4 distinct passwords

    # Every network request is a bare 5-hex prefix — no raw password, no full hash.
    assert urls
    for sent in urls:
        assert re.search(r"/range/[0-9A-F]{5}$", sent)
        for pw in _ALL_PWS:
            assert pw not in sent
            assert hashlib.sha1(pw.encode()).hexdigest().upper() not in sent

    # The raw password appears nowhere in the logs.
    logtext = caplog.text
    for pw in _ALL_PWS:
        assert pw not in logtext

    # ...and nowhere in the returned artifact / stats (page is None here: no hits).
    blob = json.dumps(page) + json.dumps(stats)
    for pw in _ALL_PWS:
        assert pw not in blob


async def test_scan_flags_email_entity_with_presence_only(db_engine, monkeypatch):
    from db.models import Entity, Page, Investigation
    from db.session import get_session

    # Every observed password reports present with a count — via a spy (no network).
    async def fake_check(password):
        assert password  # transiently received (the intended use)
        return {"present": True, "breach_count": 5, "status": "ok"}

    monkeypatch.setattr(cp, "check_password_presence", fake_check)

    inv_id = uuid.uuid4()
    page_id = uuid.uuid4()
    with get_session() as s:
        s.add(Investigation(id=inv_id, query="q", status="completed"))
        s.add(Page(id=page_id, url="http://x"))
        s.add(Entity(id=uuid.uuid4(), page_id=page_id, investigation_id=inv_id,
                     entity_type="EMAIL_ADDRESS", value="user1@example.com",
                     canonical_value="user1@example.com", confidence=1.0))
        s.commit()

    page, stats = await cp.scan_pages_for_pwned_credentials([{"text": _PAGE_TEXT}])

    assert stats["pwned"] == 4
    assert page is not None and page["source"] == "hibp_pwned_passwords"
    assert page["provenance"]["license"].startswith("HIBP")
    # Presence flag + count persisted on the email entity — never the raw password.
    with get_session() as s:
        row = s.query(Entity).filter(Entity.value == "user1@example.com").first()
        tags = json.loads(row.corroborating_sources or "[]")
    assert "pwned_password" in tags
    assert "pwned_password_count_5" in tags
    assert "feed:hibp_pwned_passwords" in tags
    # The artifact carries counts only — no raw credential.
    for pw in _ALL_PWS:
        assert pw not in page["content"]


async def test_scan_no_credentials_is_noop():
    page, stats = await cp.scan_pages_for_pwned_credentials([{"text": "nothing to see here"}])
    assert page is None
    assert stats == {"status": "ok", "observed": 0, "checked": 0, "pwned": 0}
