"""credential_presence — HIBP Pwned Passwords, k-anonymity, PRESENCE-ONLY.

The operational enforcement of requirement 5.L ("presence flags/hashes only, never
raw credential corpora"). When a credential is transiently observed in collected
page text, we report *"this password appears in N known breaches"* WITHOUT ever
storing, logging, or transmitting the credential.

**The raw-credential-never-leaves contract (this module's whole reason to exist):**
  * The password is read into a loop-local variable, SHA-1'd in memory, then dropped.
  * Only the FIRST 5 HEX CHARS of the SHA-1 (`prefix`) leave the process — sent to the
    HIBP range API (k-anonymity). The remaining suffix is matched locally against the
    returned `SUFFIX:COUNT` list.
  * The password (and its full hash) are NEVER logged, NEVER stored, NEVER returned,
    and NEVER sent in full. Only a boolean presence flag + integer breach count persist
    (as tags on the associated email entity).

Free, unlimited, no key. Clearnet via ``netpool``; timeout via ``pacing`` (CC-4).
Graceful: HIBP down → nothing flagged, status ``unavailable`` — never crashes.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import Any, Optional

import aiohttp

import hygiene
import pacing
from feeds import provenance
from sources import http_pool

logger = logging.getLogger(__name__)

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_HIBP_TIMEOUT = 15          # `normal` pacing baseline (scaled per profile, CC-4)
_HIBP_DELAY = 0.05          # light politeness between range queries
MAX_CREDENTIAL_CHECKS = 100  # per-investigation cap on distinct passwords checked


def _sha1_upper(password: str) -> str:
    # UTF-8 is HIBP's canonical encoding. Computed in-memory; never persisted/logged.
    return hashlib.sha1(password.encode("utf-8", "surrogatepass")).hexdigest().upper()


async def check_password_presence(password: str) -> dict:
    """k-anonymity presence check. Returns ``{present, breach_count, status}``.

    ONLY the 5-char SHA-1 prefix is sent; the raw password/full hash never leave.
    """
    if not password:
        return {"present": False, "breach_count": 0, "status": "ok"}
    digest = _sha1_upper(password)
    prefix, suffix = digest[:5], digest[5:]
    try:
        timeout = aiohttp.ClientTimeout(total=pacing.scale_timeout(_HIBP_TIMEOUT))
        headers = {"Add-Padding": "true", "User-Agent": "VoidAccess-OSINT/1.1"}
        async with http_pool.clearnet_session() as session:
            async with session.get(_HIBP_RANGE_URL + prefix, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("HIBP range query returned HTTP %s", resp.status)
                    return {"present": False, "breach_count": 0, "status": "unavailable"}
                body = await resp.text()
    except Exception as exc:  # never leak the password via an exception message
        logger.warning("HIBP range query failed: %s", exc)
        return {"present": False, "breach_count": 0, "status": "unavailable"}

    for line in body.splitlines():
        sfx, _, count = line.strip().partition(":")
        if sfx.upper() == suffix:
            try:
                n = int(count)
            except ValueError:
                n = 0
            return {"present": n > 0, "breach_count": n, "status": "ok"}
    return {"present": False, "breach_count": 0, "status": "ok"}


def _observe_credentials(text: str) -> list[tuple[str, str]]:
    """Transiently re-observe (email, password) pairs from page text using the SAME
    extractor regexes. The passwords returned here are consumed immediately by the
    caller and never stored."""
    from extractor.regex_patterns import _COMBO_LINE_RE, _STEALER_LOG_RE

    out: list[tuple[str, str]] = []
    combos = _COMBO_LINE_RE.findall(text)
    if len(combos) >= 3:  # extractor's dump gate — avoids one-off false positives
        for email, pw in combos:
            out.append((email.strip().lower(), pw))
    for m in _STEALER_LOG_RE.finditer(text):
        login = (m.group(2) or "").strip()
        pw = m.group(3) or ""
        if "@" in login and "." in login and pw:
            out.append((login.lower(), pw))
    return out


def _write_pwned_flags(updates: list[tuple[str, str, list[str]]]) -> None:
    """Append presence tags to the associated email entity. Never touches the raw
    password. Gated on DATABASE_URL; matched by exact (entity_type, value)."""
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        import json

        from db.models import Entity
        from db.session import get_session

        with get_session() as session:
            for entity_type, value, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == entity_type,
                    Entity.value == value,
                ).first()
                if db_entity is None:
                    continue
                existing: list = json.loads(db_entity.corroborating_sources or "[]")
                for tag in tags:
                    if tag not in existing:
                        existing.append(tag)
                db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("credential_presence: flag write-back failed: %s", exc)


async def scan_pages_for_pwned_credentials(pages: list[dict]) -> tuple[Optional[dict], dict]:
    """Scan collected page text for credentials, k-anonymity-check each password's
    breach presence, and flag the associated email entity — counts only.

    Returns ``(summary_page | None, stats)``. Raw passwords exist only as loop-local
    variables and are discarded; they never reach the DB, logs, the page, or stats.
    """
    observations: list[tuple[str, str]] = []
    for page in pages or []:
        text = (
            page.get("text") or page.get("content")
            or page.get("cleaned_text") or page.get("text_content") or ""
        )
        if text:
            observations.extend(_observe_credentials(text))

    if not observations:
        return None, {"status": "ok", "observed": 0, "checked": 0, "pwned": 0}

    seen: dict[str, dict] = {}   # sha1(password) -> result (hash key, never the raw)
    updates: list[tuple[str, str, list[str]]] = []
    checked = 0
    pwned = 0

    for email, pw in observations:
        h = _sha1_upper(pw)
        result = seen.get(h)
        if result is None:
            if checked >= MAX_CREDENTIAL_CHECKS:
                pw = ""  # drop before skipping
                continue
            result = await check_password_presence(pw)
            seen[h] = result
            checked += 1
            if _HIBP_DELAY:
                await asyncio.sleep(pacing.scale_delay(_HIBP_DELAY))
        pw = ""  # discard the raw credential immediately after use
        if result.get("present"):
            pwned += 1
            tags = [
                "pwned_password",
                f"pwned_password_count_{result['breach_count']}",
                "feed:hibp_pwned_passwords",
            ]
            # Flag whichever credential entity carries this email value.
            for etype in ("EMAIL_ADDRESS", "COMBO_LIST_ENTRY"):
                updates.append((etype, email, tags))

    if updates:
        await asyncio.to_thread(_write_pwned_flags, updates)

    prov = provenance("hibp_pwned_passwords")
    # Counts only — NO raw credentials in the artifact.
    content = hygiene.strip_pii(
        f"HIBP Pwned Passwords (k-anonymity, presence-only): {pwned} of {checked} "
        f"observed credential(s) appear in known breaches.\n"
        f"Source: {prov['attribution']} ({prov['url']}) — license: {prov['license']}"
    )
    page_out = {
        "link": prov["url"],
        "url": prov["url"],
        "content": content,
        "text": content,
        "status": 200,
        "source": "hibp_pwned_passwords",
        "via": "hibp_range_kanon",
        "provenance": prov,
    } if checked else None

    return page_out, {"status": "ok", "observed": len(observations), "checked": checked, "pwned": pwned}
