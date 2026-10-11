"""
sources/breach_lookup.py — Breach-exposure lookup enrichment (XposedOrNot + LeakCheck).

Enriches EMAIL_ADDRESS entities with breach-corpus exposure from two free,
key-optional sources that complement the existing (paid) HIBP integration in
``sources/email_reputation.py``. HIBP, XposedOrNot, and LeakCheck each draw
from different breach corpora, so all three run when available and each surfaces
things the others miss.

  - XposedOrNot: free breach lookup (breach names). The free tier notably
    includes stealer-log exposure, which most comparable services charge for.
    An optional XPOSEDORNOT_API_KEY unlocks richer results but is never required.
  - LeakCheck (public tier): free, unauthenticated. Returns the breach *sources*
    an email appeared in plus the categories of data exposed — not the full
    records. Treated as a lightweight corroboration signal, not a primary source.

Both sources report independently into ``sources_used`` under the keys
``xposedornot`` and ``leakcheck``. When an email surfaces in BOTH corpora, that
cross-source agreement is a stronger signal than either alone and is tagged.

Email addresses extracted from dark web content are already public — they
appeared on dark web forums/markets. Querying breach-lookup APIs about them is
legitimate security research.

Public interface
----------------
async query_xposedornot(email)                                → dict
async query_leakcheck(email)                                  → dict
async check_breach_exposure(email)                            → dict
async enrich_breach_entities(extraction_results, investigation_id) → (results, stats)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Optional

import aiohttp

import pacing
from sources import http_pool
from sources.enrichment_allowlist import (
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

MAX_EMAILS = 30

XPOSEDORNOT_BASE_URL = "https://api.xposedornot.com/v1"
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"

# Provider-dictated pacing, verified against both providers' live docs
# 2026-07-29.  The concurrency bound and the per-request delay are ONE
# mechanism, derived together by pacing.rate_limit_delay(): N workers each
# sleeping the documented interval would produce N times the documented rate,
# so the per-worker delay is (interval x concurrency) and the slot is held for
# the duration of the sleep.  Tuning either number alone reintroduces the
# multiplication bug.
#
# XposedOrNot: 2 req/s per IP on /check-email  →  0.5 s interval.  Its 25/hr
# and 100/day caps are NOT expressible as a delay (see docs/BACKLOG.md
# pattern 1).
# LeakCheck public tier: 1 RPS documented (docs.leakcheck.io).  Was 0.4 s here,
# i.e. 2.5x over the documented limit even at `normal`.
_XON_MAX_CONCURRENCY = 2
_XON_MIN_INTERVAL = 0.5           # documented: 2 req/s per IP
_LEAKCHECK_MAX_CONCURRENCY = 2
_LEAKCHECK_MIN_INTERVAL = 1.1     # documented: 1 RPS, + margin


def _xon_delay() -> float:
    """Per-worker delay holding the aggregate XposedOrNot rate at ≤ 2 req/s."""
    return pacing.rate_limit_delay(_XON_MIN_INTERVAL, _XON_MAX_CONCURRENCY)


def _leakcheck_delay() -> float:
    """Per-worker delay holding the aggregate LeakCheck rate at < 1 req/s."""
    return pacing.rate_limit_delay(
        _LEAKCHECK_MIN_INTERVAL, _LEAKCHECK_MAX_CONCURRENCY
    )

_xon_semaphore: Optional[asyncio.Semaphore] = None
_leakcheck_semaphore: Optional[asyncio.Semaphore] = None

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Breach-name substrings that indicate infostealer / combolist / stealer-log
# origin rather than a classic site breach. XposedOrNot's free tier includes
# these, which is a higher-signal category for dark web investigations.
_STEALER_LOG_MARKERS: tuple[str, ...] = (
    "stealer", "naz.api", "nazapi", "combolist", "combo list",
    "antipubliccombo", "collection-1", "collection 1", "stealer logs",
)

# TTLs (add to the shared enrichment-cache map without editing that module).
DEFAULT_TTL.setdefault("xposedornot", 172800)  # 48 h
DEFAULT_TTL.setdefault("leakcheck", 172800)     # 48 h

_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _get_xon_semaphore() -> asyncio.Semaphore:
    global _xon_semaphore
    if _xon_semaphore is None:
        _xon_semaphore = asyncio.Semaphore(_XON_MAX_CONCURRENCY)
    return _xon_semaphore


def _get_leakcheck_semaphore() -> asyncio.Semaphore:
    global _leakcheck_semaphore
    if _leakcheck_semaphore is None:
        _leakcheck_semaphore = asyncio.Semaphore(_LEAKCHECK_MAX_CONCURRENCY)
    return _leakcheck_semaphore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_email(value: str) -> bool:
    return bool(value and _EMAIL_RE.match(value.strip()))


def _safe_log_email(email: str) -> str:
    """Return privacy-safe log representation: first 3 chars + @domain."""
    try:
        local, domain = email.split("@", 1)
        return f"{local[:3]}***@{domain}"
    except Exception:
        return "***@***"


def _is_stealer_log_name(name: str) -> bool:
    low = (name or "").lower()
    return any(marker in low for marker in _STEALER_LOG_MARKERS)


# ---------------------------------------------------------------------------
# Source: XposedOrNot
# ---------------------------------------------------------------------------

async def query_xposedornot(email: str) -> dict[str, Any]:
    """
    Query XposedOrNot ``/check-email/{email}`` for breach exposure.

    No API key required for the free tier. An optional XPOSEDORNOT_API_KEY
    (sent as ``x-api-key``) unlocks richer results but is never required —
    the free tier returns breach names including stealer-log exposure.

    Returns a structured dict; ``source`` carries a sentinel on skip/error so
    the caller can distinguish "ran, nothing found" from "did not run".
    """
    empty: dict[str, Any] = {
        "found": False,
        "source": "xposedornot_not_found",
        "breach_count": 0,
        "breach_names": [],
        "stealer_log_exposure": False,
    }

    headers: dict[str, str] = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    api_key = (os.getenv("XPOSEDORNOT_API_KEY") or "").strip()
    if api_key:
        headers["x-api-key"] = api_key

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with _get_xon_semaphore():
            # The delay lives in a `finally` INSIDE the semaphore, deliberately:
            #  - `finally` so a 404/429/error return still pays it.  Returning
            #    early on non-200 used to skip the sleep entirely, which meant a
            #    run of 429s — exactly what a rate limiter produces — made
            #    VoidAccess speed up instead of back off.
            #  - inside the semaphore so the slot stays held for the delay,
            #    which is what makes rate_limit_delay()'s arithmetic hold.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(
                        f"{XPOSEDORNOT_BASE_URL}/check-email/{email}",
                        headers=headers,
                        timeout=timeout,
                    ) as resp:
                        if resp.status == 404:
                            return empty
                        if resp.status == 429:
                            # XposedOrNot's 429 carries the hourly/daily cap
                            # reset; honour whatever it names, floored by our
                            # own documented interval.
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _xon_delay()
                            )
                            logger.warning(
                                "breach_lookup: XposedOrNot — rate limited, "
                                "backing off %.1fs", server_wait,
                            )
                            return {**empty, "source": "xposedornot_rate_limited"}
                        if resp.status != 200:
                            logger.debug(
                                "breach_lookup: XposedOrNot → HTTP %s for %s",
                                resp.status, _safe_log_email(email),
                            )
                            return {**empty, "source": "xposedornot_error"}
                        data = await resp.json(content_type=None)
            finally:
                await asyncio.sleep(max(_xon_delay(), server_wait))
    except asyncio.TimeoutError:
        logger.debug("breach_lookup: XposedOrNot timed out for %s", _safe_log_email(email))
        return {**empty, "source": "xposedornot_error"}
    except Exception as exc:
        logger.debug(
            "breach_lookup: XposedOrNot failed for %s: %s", _safe_log_email(email), exc
        )
        return {**empty, "source": "xposedornot_error"}

    # Not-found shape: {"Error": "Not found", "email": null}
    if not isinstance(data, dict) or data.get("Error"):
        return empty

    # Found shape: {"breaches": [["Canva", "Adobe", ...]], "email": ..., "status": "success"}
    raw_breaches = data.get("breaches") or []
    breach_names: list[str] = []
    if isinstance(raw_breaches, list):
        for item in raw_breaches:
            if isinstance(item, list):
                breach_names.extend(str(b) for b in item if b)
            elif isinstance(item, str):
                breach_names.append(item)

    if not breach_names:
        return empty

    stealer_exposure = any(_is_stealer_log_name(n) for n in breach_names)

    return {
        "found": True,
        "source": "xposedornot",
        "breach_count": len(breach_names),
        "breach_names": breach_names,
        "stealer_log_exposure": stealer_exposure,
    }


async def _cached_query_xposedornot(email: str) -> dict[str, Any]:
    """Cached wrapper. Skip/error/rate-limited results are NOT cached (retry next run)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "xposedornot")
    if cached is not None:
        logger.debug("XposedOrNot cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_xposedornot(email)
    source_key = result.get("source") or ""
    if source_key in ("xposedornot", "xposedornot_not_found"):
        await cache.set(
            "EMAIL_ADDRESS", email, "xposedornot",
            result, DEFAULT_TTL["xposedornot"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: LeakCheck (public tier)
# ---------------------------------------------------------------------------

async def query_leakcheck(email: str) -> dict[str, Any]:
    """
    Query LeakCheck's public API for breach-source corroboration.

    Unauthenticated, free. Returns the breach *sources* an email appeared in
    and the categories of data exposed (``fields``) — not the records. Used as
    a lightweight secondary signal, not a primary source.
    """
    empty: dict[str, Any] = {
        "found": False,
        "source": "leakcheck_not_found",
        "breach_count": 0,
        "sources": [],
        "fields": [],
    }

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with _get_leakcheck_semaphore():
            # See _query_xposedornot for why the delay is in a `finally` inside
            # the semaphore rather than after a successful response.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(
                        LEAKCHECK_PUBLIC_URL, params={"check": email},
                        headers=headers, timeout=timeout,
                    ) as resp:
                        if resp.status == 429:
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _leakcheck_delay()
                            )
                            logger.warning(
                                "breach_lookup: LeakCheck — rate limited, "
                                "backing off %.1fs", server_wait,
                            )
                            return {**empty, "source": "leakcheck_rate_limited"}
                        if resp.status == 400:
                            # Public API rejects some inputs (e.g. bad format) with 400.
                            return empty
                        if resp.status != 200:
                            logger.debug(
                                "breach_lookup: LeakCheck → HTTP %s for %s",
                                resp.status, _safe_log_email(email),
                            )
                            return {**empty, "source": "leakcheck_error"}
                        data = await resp.json(content_type=None)
            finally:
                await asyncio.sleep(max(_leakcheck_delay(), server_wait))
    except asyncio.TimeoutError:
        logger.debug("breach_lookup: LeakCheck timed out for %s", _safe_log_email(email))
        return {**empty, "source": "leakcheck_error"}
    except Exception as exc:
        logger.debug(
            "breach_lookup: LeakCheck failed for %s: %s", _safe_log_email(email), exc
        )
        return {**empty, "source": "leakcheck_error"}

    if not isinstance(data, dict) or not data.get("success"):
        return empty

    raw_sources = data.get("sources") or []
    source_names: list[str] = []
    for s in raw_sources:
        if isinstance(s, dict) and s.get("name"):
            source_names.append(str(s["name"]))
        elif isinstance(s, str):
            source_names.append(s)

    found_count = int(data.get("found") or 0)
    if not source_names and found_count == 0:
        return empty

    return {
        "found": True,
        "source": "leakcheck",
        "breach_count": found_count or len(source_names),
        "sources": source_names,
        "fields": list(data.get("fields") or []),
    }


async def _cached_query_leakcheck(email: str) -> dict[str, Any]:
    """Cached wrapper. Skip/error/rate-limited results are NOT cached (retry next run)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "leakcheck")
    if cached is not None:
        logger.debug("LeakCheck cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_leakcheck(email)
    source_key = result.get("source") or ""
    if source_key in ("leakcheck", "leakcheck_not_found"):
        await cache.set(
            "EMAIL_ADDRESS", email, "leakcheck",
            result, DEFAULT_TTL["leakcheck"],
        )
    return result


# ---------------------------------------------------------------------------
# Core breach-exposure check
# ---------------------------------------------------------------------------

async def check_breach_exposure(email: str) -> dict[str, Any]:
    """
    Run XposedOrNot + LeakCheck concurrently for a single email address.

    Returns a structured dict with per-source findings, a corroboration flag
    (both corpora agree), tags, and a confidence delta.
    """
    result: dict[str, Any] = {
        "email": email,
        "xon_found": False,
        "xon_breach_count": 0,
        "xon_stealer_log": False,
        "leakcheck_found": False,
        "leakcheck_breach_count": 0,
        "corroborated": False,
        "tags": [],
        "confidence_delta": 0.0,
        "xon_status": "xposedornot_not_found",
        "leakcheck_status": "leakcheck_not_found",
    }

    if not _is_valid_email(email):
        return result

    # VOIDACCESS_ENRICHMENT_SOURCES gate: disabled sources are never called
    # and report the same neutral "not found" shape.
    async def _disabled(source: str) -> dict[str, Any]:
        return {"found": False, "source": f"{source}_not_found"}

    xon, leak = await asyncio.gather(
        _cached_query_xposedornot(email)
        if is_enrichment_source_enabled("xposedornot") else _disabled("xposedornot"),
        _cached_query_leakcheck(email)
        if is_enrichment_source_enabled("leakcheck") else _disabled("leakcheck"),
        return_exceptions=True,
    )

    if isinstance(xon, Exception):
        logger.debug("breach_lookup: XposedOrNot raised for %s: %s", _safe_log_email(email), xon)
        xon = {"found": False, "source": "xposedornot_error"}
    if isinstance(leak, Exception):
        logger.debug("breach_lookup: LeakCheck raised for %s: %s", _safe_log_email(email), leak)
        leak = {"found": False, "source": "leakcheck_error"}

    result["xon_status"] = xon.get("source", "xposedornot_error")
    result["leakcheck_status"] = leak.get("source", "leakcheck_error")

    if xon.get("found"):
        count = xon.get("breach_count", 0)
        result["xon_found"] = True
        result["xon_breach_count"] = count
        result["tags"].append("xposedornot_breached")
        result["tags"].append(f"xon_breach_count_{count}")
        result["confidence_delta"] += 0.12
        if xon.get("stealer_log_exposure"):
            result["xon_stealer_log"] = True
            result["tags"].append("stealer_log_exposure")
            result["confidence_delta"] += 0.10

    if leak.get("found"):
        result["leakcheck_found"] = True
        result["leakcheck_breach_count"] = leak.get("breach_count", 0)
        result["tags"].append("leakcheck_breached")
        result["confidence_delta"] += 0.08

    # Cross-source corroboration: strongest when both corpora agree.
    if result["xon_found"] and result["leakcheck_found"]:
        result["corroborated"] = True
        result["tags"].append("breach_corroborated")
        result["confidence_delta"] += 0.10

    return result


# ---------------------------------------------------------------------------
# DB helper (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_email_entities_in_db(
    updates: list[tuple[str, float, list[str]]],
) -> None:
    """Update confidence and corroborating_sources for enriched EMAIL_ADDRESS entities."""
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for email_val, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == "EMAIL_ADDRESS",
                    Entity.value == email_val,
                ).first()
                if db_entity is None:
                    continue
                if confidence > (db_entity.confidence or 0.0):
                    db_entity.confidence = confidence
                if tags:
                    existing: list = json.loads(db_entity.corroborating_sources or "[]")
                    for tag in tags:
                        if tag not in existing:
                            existing.append(tag)
                    db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("breach_lookup: DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

def _status_string(prefix: str, checked: int, hits: int, error_state: bool) -> str:
    """Build a sources_used status string honestly reflecting what ran."""
    if error_state and checked == 0:
        return "error"
    return f"ok_{hits}_results" if checked else "ok_0_results"


async def enrich_breach_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction breach-exposure enrichment (STEP 6.5).

    Complements HIBP (STEP 6.4) with XposedOrNot + LeakCheck. Each source
    reports its own ``sources_used`` status (keys ``xposedornot`` and
    ``leakcheck``). Caps at MAX_EMAILS unique addresses per investigation.

    Returns (extraction_results, stats_dict). ``stats_dict`` always carries
    ``xposedornot`` and ``leakcheck`` keys so the orchestrator can surface them.
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    seen: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            if getattr(entity, "entity_type", "") != "EMAIL_ADDRESS":
                continue
            email = getattr(entity, "value", "").strip()
            if not email or not _is_valid_email(email):
                continue
            if email not in seen:
                seen[email] = getattr(entity, "confidence", 1.0)

    unique_emails = list(seen.keys())
    if not unique_emails:
        return extraction_results, {
            "xposedornot": "ok_0_results",
            "leakcheck": "ok_0_results",
            "emails_checked": 0,
        }

    if len(unique_emails) > MAX_EMAILS:
        logger.info(
            "breach_lookup: capping to %d of %d unique emails",
            MAX_EMAILS, len(unique_emails),
        )
        unique_emails = unique_emails[:MAX_EMAILS]

    logger.info("breach_lookup: checking %d unique email(s)", len(unique_emails))

    rep_list = await asyncio.gather(
        *[check_breach_exposure(e) for e in unique_emails],
        return_exceptions=True,
    )

    db_updates: list[tuple[str, float, list[str]]] = []
    stats: dict[str, Any] = {
        "emails_checked": len(unique_emails),
        "xon_breached": 0,
        "leakcheck_breached": 0,
        "stealer_log_exposed": 0,
        "corroborated": 0,
    }
    xon_error = False
    leakcheck_error = False

    for email, rep in zip(unique_emails, rep_list):
        if isinstance(rep, Exception):
            logger.debug(
                "breach_lookup: check raised for %s: %s", _safe_log_email(email), rep
            )
            xon_error = True
            leakcheck_error = True
            continue

        if rep.get("xon_status") == "xposedornot_error":
            xon_error = True
        if rep.get("leakcheck_status") == "leakcheck_error":
            leakcheck_error = True

        if rep.get("xon_found"):
            stats["xon_breached"] += 1
        if rep.get("leakcheck_found"):
            stats["leakcheck_breached"] += 1
        if rep.get("xon_stealer_log"):
            stats["stealer_log_exposed"] += 1
        if rep.get("corroborated"):
            stats["corroborated"] += 1

        tags = rep.get("tags", [])
        delta = rep.get("confidence_delta", 0.0)
        if tags or delta:
            base_conf = seen.get(email, 1.0)
            new_conf = max(0.50, min(base_conf + delta, 1.0))
            db_updates.append((email, new_conf, tags))

    if db_updates:
        await asyncio.to_thread(_update_email_entities_in_db, db_updates)

    checked = stats["emails_checked"]
    stats["xposedornot"] = _status_string(
        "xposedornot", checked, stats["xon_breached"], xon_error
    )
    stats["leakcheck"] = _status_string(
        "leakcheck", checked, stats["leakcheck_breached"], leakcheck_error
    )

    # Report honestly when the allowlist switched a source off.
    if not is_enrichment_source_enabled("xposedornot"):
        stats["xposedornot"] = "disabled"
    if not is_enrichment_source_enabled("leakcheck"):
        stats["leakcheck"] = "disabled"

    logger.info(
        "breach_lookup: done — %d checked, XposedOrNot %d breached (%d stealer-log), "
        "LeakCheck %d breached, %d corroborated by both",
        checked, stats["xon_breached"], stats["stealer_log_exposed"],
        stats["leakcheck_breached"], stats["corroborated"],
    )

    return extraction_results, stats
