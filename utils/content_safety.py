"""
utils/content_safety.py — Mandatory content safety filters for VoidAccess.

Operates at multiple layers: query intake, URL filtering, content scanning,
and post-extraction entity value filtering.
Never logs actual prohibited content — only event metadata.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Optional, Union

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

BLOCKED_TERMS = [
    # CSAM related
    "child porn", "cp porn", "lolita", "pedo",
    "pedophil", "childporn", "child sex", "minor sex",
    "underage sex", "jailbait", "preteen sex",
    "child abuse material", "csam", "child model",
    "hurtcore", "daisy's destruction",
    # Gore related
    "gore site", "gore video", "snuff film",
    "murder video", "execution video", "beheading video",
    "torture video", "bestgore", "livegore",
    "watchpeopledie", "realsnuff",
]

BLOCKED_PATTERNS = [
    r'\bcp\b.{0,20}\bonion\b',      # "cp" near "onion"
    r'\bchild.{0,10}\bnaked\b',
    r'\bminor.{0,10}\bnaked\b',
    r'\bkid.{0,10}\bporn\b',
    r'\bteen.{0,10}\bporn\b',
]

BLOCKED_URL_TERMS = [
    "pedo", "loli", "jailbait", "childporn",
    "hurtcore", "csam", "bestgore", "livegore",
    "watchpeople", "realsnuff", "daisy",
]

CONTENT_BLOCKLIST = [
    "child pornography", "child porn",
    "child sexual abuse", "csam",
    "snuff film", "murder porn",
]

# ---------------------------------------------------------------------------
# Entity value blocklist — applied after extraction, before DB storage
# Only checked against text-based entity types (not technical IOCs)
# ---------------------------------------------------------------------------

ENTITY_VALUE_BLOCKLIST: list[str] = [
    # Adult content categories
    "porn", "blowjob", "bdsm", "hardcore",
    "xxx", "nude", "nudes", "naked", "escort",
    "onlyfans", "cam girl", "sex tape",
    "adult content", "adult site",
    # Gore/violence
    "snuff", "gore", "murder video",
    "execution video", "beheading",
    # Exploitation
    "jailbait", "pedo", "csam",
    "child", "minor",
]


# Common-password substring patterns — anything matching one of these as
# a *value* (case-insensitive) is treated as a known weak password and
# must never be stored as an entity.  These are deliberately not in the
# main ENTITY_VALUE_BLOCKLIST because that list is only checked against
# text-based entity types (ORG/handle/person/malware).  Passwords can
# only appear as raw stealer-log values, which we now also filter via
# ``_looks_like_common_password`` below.
COMMON_PASSWORD_SUBSTRINGS: tuple[str, ...] = (
    "password", "passwd", "p@ssw0rd", "p@ssword",
    "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
    "letmein", "welcome", "admin", "admin123", "admin1234",
    "iloveyou", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "superman",
    "trustno1", "starwars", "passw0rd",
    "hunter2", "shadow", "master", "jordan",
    "michael", "thomas", "robert", "george",
    "charlie", "andrew", "matthew", "access",
    "hello", "secret", "love", "freedom",
)


def _looks_like_common_password(value: str) -> bool:
    """
    Return True if *value* matches any COMMON_PASSWORD_SUBSTRINGS entry.

    Used as a defensive guard for stealer-log password fields and for any
    entity value the generic API_KEY extractor surfaces.  Never logs the
    value — only the boolean outcome.
    """
    if not value:
        return False
    v = value.lower().strip()
    if not v:
        return False
    for needle in COMMON_PASSWORD_SUBSTRINGS:
        if needle in v:
            return True
    return False

# Entity types where prohibited content can appear as names/labels.
# Technical IOC types (hashes, IPs, CVEs, wallets, onion URLs) are
# intentionally omitted — they cannot contain prohibited content.
_TEXT_ENTITY_TYPES: frozenset[str] = frozenset({
    "ORGANIZATION_NAME",
    "THREAT_ACTOR_HANDLE",
    "PERSON_NAME",
    "MALWARE_FAMILY",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_blocked_query(query: str) -> tuple[bool, str]:
    """
    Check if a query should be blocked.
    Returns (is_blocked, reason).
    Never logs the actual query.
    """
    query_lower = query.lower()

    for term in BLOCKED_TERMS:
        if term in query_lower:
            return True, "Query contains prohibited content"

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, query_lower, re.IGNORECASE):
            return True, "Query contains prohibited content"

    return False, ""


def is_blocked_entity_value(entity_type: str, value: str) -> bool:
    """
    Return True if an entity value should be dropped before storage.

    Only applies to text-based entity types where prohibited content can
    appear as organisation/actor names (ORGANIZATION_NAME, THREAT_ACTOR_HANDLE,
    PERSON_NAME, MALWARE_FAMILY).

    Never applies to technical IOC types such as FILE_HASH_*, IP_ADDRESS, CVE,
    ONION_URL, or wallet addresses \u2014 these cannot contain prohibited content
    by definition and are intentionally excluded.

    Additional defensive check: any entity whose value looks like a
    common-password substring (``hunter2``, ``password123``, etc.) is
    always blocked, regardless of entity type.  This catches the case
    where the generic API_KEY extractor picks up a weak password as an
    ``api_key`` value, and the stealer-log path leaking a password into
    a downstream column.

    The check is case-insensitive substring matching against
    ENTITY_VALUE_BLOCKLIST and COMMON_PASSWORD_SUBSTRINGS.  The actual
    value is never logged.
    """
    if not value:
        return True  # empty values are blocked outright

    # Layer 1: known common-password substring filter (applies to every type).
    if _looks_like_common_password(value):
        return True

    # Layer 2: prohibited-content filter (only for text-based entity types).
    if entity_type not in _TEXT_ENTITY_TYPES:
        return False

    value_lower = value.lower()
    for term in ENTITY_VALUE_BLOCKLIST:
        if term in value_lower:
            return True

    return False


def is_blocked_url(url: str) -> tuple[bool, str]:
    """
    Check if a URL should be blocked from scraping.
    Returns (is_blocked, reason).
    """
    url_lower = url.lower()
    for term in BLOCKED_URL_TERMS:
        if term in url_lower:
            return True, "URL blocked — prohibited content"
    return False, ""


def content_hash_prefix(value: str) -> str:
    """SHA-256 hex prefix for logs and audit events (never log raw content)."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def scan_page_text(
    url: str,
    text: str,
    *,
    user_id: Optional[int] = None,
) -> tuple[str, bool]:
    """
    Layer-4 scan for one page. Returns (clean_text, dropped).

    Fail-closed: gate errors treat the page as blocked.
    """
    url_key = url or content_hash_prefix(text or "")
    try:
        clean, flagged = sanitize_content(text or "")
        if flagged:
            url_hash = content_hash_prefix(url_key)
            _logger.warning(
                "Page content blocked — prohibited content. Page hash: %s",
                url_hash,
            )
            log_content_safety_event(
                event_type="content_blocked",
                content_hash=url_hash,
                user_id=user_id,
            )
            return "", True
        return clean, False
    except Exception as exc:
        url_hash = content_hash_prefix(url_key)
        _logger.warning(
            "Content safety gate error (fail-closed). Page hash: %s: %s",
            url_hash,
            exc,
        )
        log_content_safety_event(
            event_type="content_blocked",
            content_hash=url_hash,
            user_id=user_id,
        )
        return "", True


def url_is_blocked(
    url: str,
    *,
    user_id: Optional[int] = None,
) -> bool:
    """Return True when the URL must not be fetched (fail-closed on gate errors)."""
    if not url:
        return True
    url_hash = content_hash_prefix(url)
    try:
        blocked, _reason = is_blocked_url(url)
        if blocked:
            _logger.warning(
                "URL blocked — prohibited content. URL hash: %s",
                url_hash,
            )
            log_content_safety_event(
                event_type="url_blocked",
                content_hash=url_hash,
                user_id=user_id,
            )
            return True
        return False
    except Exception as exc:
        _logger.warning(
            "URL safety gate error (fail-closed). URL hash: %s: %s",
            url_hash,
            exc,
        )
        log_content_safety_event(
            event_type="url_blocked",
            content_hash=url_hash,
            user_id=user_id,
        )
        return True


def entity_value_is_blocked(entity_type: str, value: str) -> bool:
    """Fail-closed wrapper around ``is_blocked_entity_value``."""
    try:
        return is_blocked_entity_value(entity_type, value)
    except Exception as exc:
        _logger.warning(
            "Entity safety gate error (fail-closed): type=%s err=%s",
            entity_type,
            exc,
        )
        return True


def gate_pages(
    pages: Union[dict[str, str], list[dict[str, Any]]],
    *,
    user_id: Optional[int] = None,
) -> tuple[Union[dict[str, str], list[dict[str, Any]]], int]:
    """
    Scan page text before persistence, caching, extraction, or summarization.

    Accepts either ``{url: text}`` (API scrape pool) or a list of page
    records with ``url``/``link`` and ``text``/``content`` keys (CLI/API).

    Returns (clean_pages, dropped_count).
    """
    dropped = 0
    if isinstance(pages, dict):
        clean: dict[str, str] = {}
        for page_url, page_text in pages.items():
            clean_text, was_dropped = scan_page_text(
                page_url, page_text or "", user_id=user_id
            )
            if was_dropped:
                dropped += 1
            else:
                clean[page_url] = clean_text
        return clean, dropped

    clean_records: list[dict[str, Any]] = []
    for record in pages:
        page_url = (
            record.get("url")
            or record.get("link")
            or ""
        )
        page_text = (
            record.get("text")
            or record.get("content")
            or record.get("cleaned_text")
            or record.get("text_content")
            or ""
        )
        clean_text, was_dropped = scan_page_text(
            page_url, page_text, user_id=user_id
        )
        if was_dropped:
            dropped += 1
            continue
        updated = dict(record)
        updated["text"] = clean_text
        if any(k in record for k in ("content", "text", "cleaned_text", "text_content")):
            updated["content"] = clean_text
        clean_records.append(updated)
    return clean_records, dropped


def sanitize_content(text: str) -> tuple[str, bool]:
    """
    Scan scraped text for CSAM/gore indicators.
    Returns (sanitized_text, was_flagged).
    If flagged, returns empty string — the original text is never stored.
    """
    if not text:
        return text, False

    text_lower = text.lower()
    for term in CONTENT_BLOCKLIST:
        if term in text_lower:
            return "", True

    return text, False


def log_content_safety_event(
    event_type: str,
    content_hash: Optional[str] = None,
    user_id: Optional[int] = None,
) -> None:
    """
    Persist a content safety block event to the DB for operator review.
    Fails silently — never disrupts the calling pipeline.
    event_type: one of "query_blocked", "url_blocked", "content_blocked"
    content_hash: SHA-256 hex prefix (≤16 chars) of the blocked item, for correlation only.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return
        from db.session import get_session
        from db.models import ContentSafetyEvent
        from datetime import datetime, timezone

        with get_session() as session:
            event = ContentSafetyEvent(
                event_type=event_type,
                user_id=user_id,
                content_hash=content_hash,
                timestamp=datetime.now(timezone.utc),
            )
            session.add(event)
            session.commit()
    except Exception as exc:
        _logger.debug("content_safety: DB log failed (non-critical): %s", exc)
