"""
sources/email_reputation.py — Email reputation enrichment.

Enriches EMAIL_ADDRESS entities with identity attribution data from four sources:
  - HaveIBeenPwned (HIBP): breach history and password exposure (requires HIBP_API_KEY)
  - EmailRep.io: reputation scoring, disposable detection, platform presence
  - Disposable domain blocklist: fast local check against known throwaway domains
  - Domain cross-reference: email domain added as DOMAIN entity (custom domains only)

Email addresses extracted from dark web content are already public — they appeared
on dark web forums/markets. Querying HIBP and EmailRep is legitimate security research.

Public interface
----------------
async is_disposable_domain(domain)                          → bool
async query_hibp(email)                                     → dict
async query_emailrep(email)                                 → dict
async check_email_reputation(email, base_confidence)        → dict
async enrich_email_entities(extraction_results, investigation_id) → (results, stats)
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

from sources import http_pool
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

MAX_EMAILS = 30

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
EMAILREP_BASE_URL = "https://emailrep.io"
DISPOSABLE_LIST_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)

HIBP_CACHE_TTL = 86400.0      # 24 h
EMAILREP_CACHE_TTL = 43200.0  # 12 h
DISPOSABLE_LIST_CACHE_TTL = 86400.0  # 24 h

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Common free/privacy providers — domain cross-reference reveals no attribution signal
_FREE_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com",
    "proton.me", "protonmail.com", "protonmail.ch",
    "tutanota.com", "tutanota.de", "tuta.io",
    "icloud.com", "me.com",
    "aol.com",
    "mail.com",
})

# In-memory per-email caches
_hibp_cache: dict[str, dict] = {}
_emailrep_cache: dict[str, dict] = {}

# Disposable domain set cache (module-level singleton)
_disposable_cache: dict[str, Any] = {"domains": frozenset(), "loaded_at": 0.0}

# Module-level enrichment cache singleton (lazy-init on first lookup).
_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_email(value: str) -> bool:
    return bool(value and _EMAIL_RE.match(value.strip()))


def _extract_domain(email: str) -> str:
    """Return the domain portion of an email address."""
    try:
        return email.strip().split("@", 1)[1].lower()
    except IndexError:
        return ""


def _safe_log_email(email: str) -> str:
    """Return privacy-safe log representation: first 3 chars + @domain."""
    try:
        local, domain = email.split("@", 1)
        return f"{local[:3]}***@{domain}"
    except Exception:
        return "***@***"


# ---------------------------------------------------------------------------
# Source: Disposable domain blocklist
# ---------------------------------------------------------------------------

async def _load_disposable_list() -> frozenset[str]:
    """Fetch and cache the disposable email domain blocklist (24 h TTL)."""
    cache = _disposable_cache
    if time.time() - cache["loaded_at"] < DISPOSABLE_LIST_CACHE_TTL and cache["domains"]:
        return cache["domains"]  # type: ignore[return-value]

    logger.info("email_reputation: Refreshing disposable domain blocklist")
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        headers = {"User-Agent": "VoidAccess-OSINT/1.1 (security research)"}
        async with http_pool.clearnet_session() as session:
            async with session.get(DISPOSABLE_LIST_URL, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning(
                        "email_reputation: Disposable list returned HTTP %s", resp.status
                    )
                    return frozenset(cache["domains"])
                text = await resp.text()
    except Exception as exc:
        logger.warning("email_reputation: Disposable list fetch failed: %s", exc)
        return frozenset(cache["domains"])

    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)

    frozen = frozenset(domains)
    cache["domains"] = frozen
    cache["loaded_at"] = time.time()
    logger.info("email_reputation: Disposable blocklist: %d domains loaded", len(frozen))
    return frozen


async def is_disposable_domain(domain: str) -> bool:
    """Return True if *domain* appears in the disposable email domain blocklist."""
    blocklist = await _load_disposable_list()
    return domain.lower() in blocklist


# ---------------------------------------------------------------------------
# Source: HaveIBeenPwned
# ---------------------------------------------------------------------------

async def query_hibp(email: str) -> dict[str, Any]:
    """
    Query HIBP v3 breachedaccount/{email} for breach history.

    Requires HIBP_API_KEY. Without a key the check is skipped gracefully.
    HIBP is a paid API ($3.50/month individual) — the most authoritative
    source for email breach data.
    Cached for 24 h.
    """
    cached = _hibp_cache.get(email)
    if cached and (time.time() - cached["loaded_at"]) < HIBP_CACHE_TTL:
        return cached["result"]

    api_key = (os.getenv("HIBP_API_KEY") or "").strip()
    if not api_key:
        logger.debug("email_reputation: HIBP skipped — no API key")
        return {"found": False, "source": "hibp_skipped"}

    try:
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "VoidAccess-OSINT",
        }
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.get(
                f"{HIBP_BASE_URL}/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=timeout,
            ) as resp:
                if resp.status == 404:
                    result: dict[str, Any] = {"found": False, "source": "hibp_not_found"}
                    _hibp_cache[email] = {"result": result, "loaded_at": time.time()}
                    return result
                if resp.status == 401:
                    logger.warning("email_reputation: HIBP — invalid API key")
                    return {"found": False, "source": "hibp_auth_error"}
                if resp.status == 429:
                    logger.warning("email_reputation: HIBP — rate limited")
                    return {"found": False, "source": "hibp_rate_limited"}
                if resp.status != 200:
                    logger.debug(
                        "email_reputation: HIBP → HTTP %s for %s",
                        resp.status, _safe_log_email(email),
                    )
                    return {"found": False, "source": "hibp_error"}
                data = await resp.json()
    except Exception as exc:
        logger.debug(
            "email_reputation: HIBP failed for %s: %s", _safe_log_email(email), exc
        )
        return {"found": False, "source": "hibp_error"}

    if not data or not isinstance(data, list):
        return {"found": False, "source": "hibp_not_found"}

    breach_names: list[str] = []
    breach_dates: list[str] = []
    password_exposed = False

    for breach in data:
        name = breach.get("Name") or breach.get("Title") or ""
        date = breach.get("BreachDate") or ""
        data_classes = breach.get("DataClasses") or []
        if name:
            breach_names.append(name)
        if date:
            breach_dates.append(date)
        if any("password" in dc.lower() for dc in data_classes):
            password_exposed = True

    # YYYY-MM-DD sorts lexicographically — max gives most recent
    most_recent_breach = max(breach_dates) if breach_dates else None
    most_recent_name: str | None = None
    if most_recent_breach and breach_dates:
        idx = breach_dates.index(most_recent_breach)
        most_recent_name = breach_names[idx] if idx < len(breach_names) else (breach_names[-1] if breach_names else None)

    recently_breached = False
    if most_recent_breach:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(most_recent_breach)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            recently_breached = (datetime.now(timezone.utc) - dt).days < 365
        except Exception:
            pass

    result = {
        "found": True,
        "source": "hibp",
        "breach_count": len(breach_names),
        "breach_names": breach_names,
        "breach_dates": breach_dates,
        "password_exposed": password_exposed,
        "most_recent_breach": most_recent_breach,
        "most_recent_name": most_recent_name,
        "recently_breached": recently_breached,
    }

    _hibp_cache[email] = {"result": result, "loaded_at": time.time()}
    return result


async def _cached_query_hibp(email: str) -> dict[str, Any]:
    """Cached wrapper around query_hibp (48h TTL via DEFAULT_TTL).

    Skipped / auth-error / rate-limited results are NOT cached — the next run
    should retry. Both 404 (``hibp_not_found``) and found results ARE cached
    so repeat lookups for the same email don't hit HIBP.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "hibp")
    if cached is not None:
        logger.debug("HIBP cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_hibp(email)
    source_key = result.get("source") or ""
    if source_key and source_key not in (
        "hibp_skipped",
        "hibp_auth_error",
        "hibp_rate_limited",
        "hibp_error",
    ):
        await cache.set(
            "EMAIL_ADDRESS", email, "hibp",
            result, DEFAULT_TTL["hibp"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: EmailRep.io
# ---------------------------------------------------------------------------

async def query_emailrep(email: str) -> dict[str, Any]:
    """
    Query EmailRep.io for reputation data.

    Optional EMAILREP_API_KEY increases rate limits — works without key.
    Cached for 12 h.
    """
    cached = _emailrep_cache.get(email)
    if cached and (time.time() - cached["loaded_at"]) < EMAILREP_CACHE_TTL:
        return cached["result"]

    api_key = (os.getenv("EMAILREP_API_KEY") or "").strip()
    headers: dict[str, str] = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    if api_key:
        headers["Key"] = api_key

    empty: dict[str, Any] = {
        "reputation": None,
        "suspicious": False,
        "references": 0,
        "profiles": [],
        "disposable": False,
        "free_provider": False,
        "blacklisted": False,
        "malicious_activity": False,
        "credentials_leaked": False,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.get(f"{EMAILREP_BASE_URL}/{email}", headers=headers, timeout=timeout) as resp:
                if resp.status == 400:
                    logger.debug(
                        "email_reputation: EmailRep → HTTP 400 for %s (invalid email)",
                        _safe_log_email(email),
                    )
                    return empty
                if resp.status == 429:
                    logger.warning("email_reputation: EmailRep — rate limited")
                    return empty
                if resp.status != 200:
                    logger.debug(
                        "email_reputation: EmailRep → HTTP %s for %s",
                        resp.status, _safe_log_email(email),
                    )
                    return empty
                data = await resp.json()
    except Exception as exc:
        logger.debug(
            "email_reputation: EmailRep failed for %s: %s", _safe_log_email(email), exc
        )
        return empty

    attributes = data.get("details") or {}
    result: dict[str, Any] = {
        "reputation": data.get("reputation"),
        "suspicious": bool(data.get("suspicious", False)),
        "references": data.get("references", 0),
        "profiles": list(attributes.get("profiles") or []),
        "disposable": bool(attributes.get("disposable", False)),
        "free_provider": bool(attributes.get("free_provider", False)),
        "blacklisted": bool(attributes.get("blacklisted", False)),
        "malicious_activity": bool(attributes.get("malicious_activity", False)),
        "credentials_leaked": bool(attributes.get("credentials_leaked", False)),
    }

    _emailrep_cache[email] = {"result": result, "loaded_at": time.time()}
    return result


async def _cached_query_emailrep(email: str) -> dict[str, Any]:
    """Cached wrapper around query_emailrep (24h TTL via DEFAULT_TTL)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "emailrep")
    if cached is not None:
        logger.debug("EmailRep cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_emailrep(email)
    # EmailRep returns the "empty" dict (reputation=None etc.) for 400/429.
    # We cache it because the empty result IS the cached fact: that the email
    # has no EmailRep data. This protects the rate-limited path.
    await cache.set(
        "EMAIL_ADDRESS", email, "emailrep",
        result, DEFAULT_TTL["emailrep"],
    )
    return result


# ---------------------------------------------------------------------------
# Core reputation check
# ---------------------------------------------------------------------------

async def check_email_reputation(
    email: str,
    base_confidence: float = 1.0,
) -> dict[str, Any]:
    """
    Run all four enrichment sources concurrently for a single email address.

    Returns a structured result dict with keys:
        email, breached, breach_count, breach_names, password_exposed,
        most_recent_breach, reputation, suspicious, disposable,
        malicious_activity, credentials_leaked, platforms,
        new_entities, tags, confidence_delta
    """
    result: dict[str, Any] = {
        "email": email,
        "breached": False,
        "breach_count": 0,
        "breach_names": [],
        "password_exposed": False,
        "most_recent_breach": None,
        "reputation": None,
        "suspicious": False,
        "disposable": False,
        "malicious_activity": False,
        "credentials_leaked": False,
        "platforms": [],
        "new_entities": [],
        "tags": [],
        "confidence_delta": 0.0,
    }

    if not _is_valid_email(email):
        return result

    domain = _extract_domain(email)
    if not domain:
        return result

    disposable_check, hibp_result, emailrep_result = await asyncio.gather(
        is_disposable_domain(domain),
        _cached_query_hibp(email),
        _cached_query_emailrep(email),
        return_exceptions=True,
    )

    if isinstance(disposable_check, Exception):
        logger.debug(
            "email_reputation: disposable check raised for %s: %s",
            _safe_log_email(email), disposable_check,
        )
        disposable_check = False

    if isinstance(hibp_result, Exception):
        logger.debug(
            "email_reputation: HIBP raised for %s: %s",
            _safe_log_email(email), hibp_result,
        )
        hibp_result = {"found": False}

    if isinstance(emailrep_result, Exception):
        logger.debug(
            "email_reputation: EmailRep raised for %s: %s",
            _safe_log_email(email), emailrep_result,
        )
        emailrep_result = {}

    # ── Disposable domain check ────────────────────────────────────────────────
    if disposable_check:
        result["disposable"] = True
        result["tags"].append("disposable_email")

    # ── HIBP ──────────────────────────────────────────────────────────────────
    if hibp_result.get("found"):
        count = hibp_result.get("breach_count", 0)
        result["breached"] = True
        result["breach_count"] = count
        result["breach_names"] = hibp_result.get("breach_names", [])
        result["password_exposed"] = hibp_result.get("password_exposed", False)
        result["most_recent_breach"] = hibp_result.get("most_recent_breach")

        result["tags"].append("hibp_breached")
        result["tags"].append(f"hibp_breach_count_{count}")
        result["confidence_delta"] += 0.15

        if hibp_result.get("password_exposed"):
            result["tags"].append("hibp_password_exposed")

        if hibp_result.get("recently_breached"):
            result["tags"].append("recently_breached")
            name = hibp_result.get("most_recent_name") or ""
            if name:
                slug = re.sub(r"[^a-z0-9]+", "_", name.lower())[:40]
                result["tags"].append(f"recent_breach_{slug}")

    # ── EmailRep.io ───────────────────────────────────────────────────────────
    if emailrep_result:
        result["reputation"] = emailrep_result.get("reputation")
        result["suspicious"] = emailrep_result.get("suspicious", False)
        result["platforms"] = emailrep_result.get("profiles", [])

        if emailrep_result.get("disposable"):
            result["disposable"] = True
            if "disposable_email" not in result["tags"]:
                result["tags"].append("disposable_email")

        if emailrep_result.get("malicious_activity"):
            result["malicious_activity"] = True
            result["tags"].append("emailrep_malicious")
            result["confidence_delta"] += 0.10

        if emailrep_result.get("credentials_leaked"):
            result["credentials_leaked"] = True
            result["tags"].append("credentials_leaked")

        if emailrep_result.get("blacklisted"):
            result["tags"].append("email_blacklisted")

    # Apply disposable confidence penalty once regardless of which source flagged it
    if result["disposable"]:
        result["confidence_delta"] -= 0.10

    # ── Domain cross-reference (custom domains only) ───────────────────────────
    if domain and domain not in _FREE_PROVIDERS and not result["disposable"]:
        result["new_entities"].append({
            "entity_type": "DOMAIN",
            "value": domain,
            "canonical_value": domain,
            "confidence": 0.75,
            "source": "email_domain",
            "extraction_method": "enrich",
            "context_snippet": (
                f"Domain extracted from email entity {_safe_log_email(email)}"
            ),
        })

    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread)
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
    except Exception:
        # Do not log the raw SQLAlchemy exception: its parameter dump can
        # contain the full email address being enriched.
        logger.warning("email_reputation: DB update failed")


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

async def enrich_email_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction email reputation enrichment step (STEP 6.4).

    Email addresses extracted from dark web content are already public —
    they appeared on dark web forums/markets. Querying HIBP and EmailRep
    constitutes legitimate security research.

    Collects EMAIL_ADDRESS entities from *extraction_results*.
    Caps at MAX_EMAILS = 30 per investigation.
    Confidence floor: 0.50 (disposable addresses may still be real threat actor emails).
    Confidence ceiling: 1.0.

    Returns (extraction_results, stats_dict).
    """
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
        return extraction_results, {"email_reputation": "ok_0_emails"}

    if len(unique_emails) > MAX_EMAILS:
        logger.info(
            "email_reputation: capping to %d of %d unique emails",
            MAX_EMAILS, len(unique_emails),
        )
        unique_emails = unique_emails[:MAX_EMAILS]

    logger.info("email_reputation: checking %d unique email(s)", len(unique_emails))

    rep_list = await asyncio.gather(
        *[
            check_email_reputation(e, base_confidence=seen[e])
            for e in unique_emails
        ],
        return_exceptions=True,
    )

    db_updates: list[tuple[str, float, list[str]]] = []
    all_new_entities: list[dict] = []
    stats: dict[str, Any] = {
        "emails_checked": len(unique_emails),
        "breached": 0,
        "password_exposed": 0,
        "disposable": 0,
        "malicious": 0,
        "new_entities_discovered": 0,
    }

    for email, rep in zip(unique_emails, rep_list):
        if isinstance(rep, Exception):
            logger.debug(
                "email_reputation: check raised for %s: %s",
                _safe_log_email(email), rep,
            )
            continue

        base_conf = seen[email]
        delta = rep.get("confidence_delta", 0.0)
        new_conf = max(0.50, min(base_conf + delta, 1.0))
        tags = rep.get("tags", [])

        if rep.get("breached"):
            stats["breached"] += 1
        if rep.get("password_exposed"):
            stats["password_exposed"] += 1
        if rep.get("disposable"):
            stats["disposable"] += 1
        if rep.get("malicious_activity"):
            stats["malicious"] += 1

            # High-value identity signal: breach history + malicious activity
            if rep.get("password_exposed"):
                logger.info(
                    "[%s] High-value email entity: %s — "
                    "breach history + malicious activity confirmed",
                    investigation_id,
                    _safe_log_email(email),
                )

        new_entities = rep.get("new_entities", [])
        all_new_entities.extend(new_entities)
        stats["new_entities_discovered"] += len(new_entities)

        if tags or delta != 0.0:
            db_updates.append((email, new_conf, tags))

    if db_updates:
        await asyncio.to_thread(_update_email_entities_in_db, db_updates)

    if all_new_entities:
        logger.info(
            "email_reputation: %d new entities discovered (custom domains)",
            len(all_new_entities),
        )

    checked = stats["emails_checked"]
    status = (
        f"ok_{checked}_emails"
        f"_{stats['breached']}_breached"
        f"_{stats['disposable']}_disposable"
    )

    logger.info(
        "email_reputation: done — %d checked, %d breached, %d passwords exposed, "
        "%d disposable, %d malicious",
        checked,
        stats["breached"],
        stats["password_exposed"],
        stats["disposable"],
        stats["malicious"],
    )

    return extraction_results, {"email_reputation": status, **stats}
