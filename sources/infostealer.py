"""
sources/infostealer.py — Infostealer intelligence enrichment (Hudson Rock Cavalier).

Queries Hudson Rock's free Cavalier API — a database of 30M+ machines
compromised by infostealer malware — for both EMAIL_ADDRESS and DOMAIN
entities. This is a meaningfully different (and higher-signal) category than
the breach-corpus lookups in ``breach_lookup.py``/``email_reputation.py``:
rather than "this account appeared in an old breach dump", it reports that a
real machine was actively infected and had credentials / session data
exfiltrated by malware — more current intelligence for dark web work.

  - search-by-email: does an email appear in stealer logs, and on how many
    distinct compromised machines?
  - search-by-domain: how many corporate employees / users of a domain appear
    in stealer logs? One of the few sources in the pipeline giving
    domain-level infostealer exposure, valuable for org-centred investigations.

No API key required (confirmed via existing real-world usage by other OSINT
platforms). Reports into ``sources_used`` under the key ``hudsonrock``.

Public interface
----------------
async query_hudsonrock_email(email)                                  → dict
async query_hudsonrock_domain(domain)                                → dict
async enrich_infostealer_entities(extraction_results, investigation_id) → (results, stats)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Optional

import aiohttp

import pacing
from sources import http_pool
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

MAX_EMAILS = 30
MAX_DOMAINS = 20

_CAVALIER_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_EMAIL_ENDPOINT = f"{_CAVALIER_BASE}/search-by-email"
_DOMAIN_ENDPOINT = f"{_CAVALIER_BASE}/search-by-domain"

# Courtesy pacing for a free source.  Hudson Rock publishes NO rate limit for
# the free osint-tools endpoints (checked against docs.hudsonrock.com
# 2026-07-29: getting-started, permissions and the API reference are all
# silent), so 2 req/s is VoidAccess's own chosen ceiling rather than a quota we
# are obliged to respect — see the courtesy classification in docs/BACKLOG.md.
#
# It still goes through pacing.rate_limit_delay() so the concurrency bound and
# the delay stay one derived mechanism instead of two independently-tuned
# numbers that multiply against each other.
_HR_MAX_CONCURRENCY = 2
_HR_MIN_INTERVAL = 0.5            # self-imposed: 2 req/s aggregate


def _hr_delay() -> float:
    """Per-worker delay holding the aggregate Hudson Rock rate at ≤ 2 req/s."""
    return pacing.rate_limit_delay(_HR_MIN_INTERVAL, _HR_MAX_CONCURRENCY)

_hr_semaphore: Optional[asyncio.Semaphore] = None

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

# Free/privacy providers — domain-level infostealer lookup is meaningless for them.
_FREE_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "proton.me", "protonmail.com", "icloud.com", "me.com",
    "aol.com", "mail.com", "gmx.com", "yandex.com", "example.com",
})

DEFAULT_TTL.setdefault("hudsonrock", 86400)  # 24 h — infostealer data updates frequently

_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _get_hr_semaphore() -> asyncio.Semaphore:
    global _hr_semaphore
    if _hr_semaphore is None:
        _hr_semaphore = asyncio.Semaphore(_HR_MAX_CONCURRENCY)
    return _hr_semaphore


def _is_valid_email(value: str) -> bool:
    return bool(value and _EMAIL_RE.match(value.strip()))


def _is_valid_domain(value: str) -> bool:
    return bool(value and _DOMAIN_RE.match(value.strip()))


def _safe_log_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        return f"{local[:3]}***@{domain}"
    except Exception:
        return "***@***"


async def _get_json(url: str, params: dict) -> tuple[Optional[Any], str]:
    """
    GET *url* with *params*. Returns (data_or_None, status_sentinel).

    status_sentinel is one of: "ok", "not_found", "rate_limited", "error".
    """
    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with _get_hr_semaphore():
            # `finally` inside the semaphore: a 404/429/error return must still
            # pay the delay (otherwise a run of 429s speeds us up rather than
            # backing off), and the slot must stay held while we sleep so the
            # concurrency arithmetic in rate_limit_delay() holds.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(url, params=params, headers=headers, timeout=timeout) as resp:
                        if resp.status == 404:
                            return None, "not_found"
                        if resp.status == 429:
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _hr_delay()
                            )
                            logger.warning(
                                "infostealer: Hudson Rock — rate limited, "
                                "backing off %.1fs", server_wait,
                            )
                            return None, "rate_limited"
                        if resp.status != 200:
                            logger.debug("infostealer: Hudson Rock → HTTP %s", resp.status)
                            return None, "error"
                        text = await resp.text()
            finally:
                await asyncio.sleep(max(_hr_delay(), server_wait))
    except asyncio.TimeoutError:
        logger.debug("infostealer: Hudson Rock timed out")
        return None, "error"
    except Exception as exc:
        logger.debug("infostealer: Hudson Rock request failed: %s", exc)
        return None, "error"

    if not text or not text.strip():
        # Empty body is Hudson Rock's "no data" response for some inputs.
        return None, "not_found"
    try:
        return json.loads(text), "ok"
    except Exception:
        return None, "error"


# ---------------------------------------------------------------------------
# Source: Hudson Rock — search by email
# ---------------------------------------------------------------------------

async def query_hudsonrock_email(email: str) -> dict[str, Any]:
    """Query Cavalier search-by-email. Returns a structured exposure dict."""
    empty: dict[str, Any] = {
        "found": False,
        "source": "hudsonrock_not_found",
        "kind": "email",
        "value": email,
        "machine_count": 0,
        "most_recent_compromise": None,
    }

    data, status = await _get_json(_EMAIL_ENDPOINT, {"email": email})
    if status != "ok" or not isinstance(data, dict):
        if status in ("not_found",):
            return empty
        return {**empty, "source": f"hudsonrock_{status}"}

    stealers = data.get("stealers") or []
    if not isinstance(stealers, list) or not stealers:
        # Message present but no stealers → not infected.
        return empty

    dates = [
        s.get("date_compromised") for s in stealers
        if isinstance(s, dict) and s.get("date_compromised")
    ]
    most_recent = max(dates) if dates else None  # ISO 8601 sorts lexicographically

    total_corporate = sum(
        int(s.get("total_corporate_services") or 0)
        for s in stealers if isinstance(s, dict)
    )

    return {
        "found": True,
        "source": "hudsonrock",
        "kind": "email",
        "value": email,
        "machine_count": len(stealers),
        "most_recent_compromise": most_recent,
        "corporate_services_exposed": total_corporate,
    }


async def _cached_query_email(email: str) -> dict[str, Any]:
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "hudsonrock")
    if cached is not None:
        return cached
    result = await query_hudsonrock_email(email)
    if result.get("source") in ("hudsonrock", "hudsonrock_not_found"):
        await cache.set("EMAIL_ADDRESS", email, "hudsonrock", result, DEFAULT_TTL["hudsonrock"])
    return result


# ---------------------------------------------------------------------------
# Source: Hudson Rock — search by domain
# ---------------------------------------------------------------------------

async def query_hudsonrock_domain(domain: str) -> dict[str, Any]:
    """Query Cavalier search-by-domain. Returns a structured exposure dict."""
    empty: dict[str, Any] = {
        "found": False,
        "source": "hudsonrock_not_found",
        "kind": "domain",
        "value": domain,
        "employees": 0,
        "users": 0,
        "third_parties": 0,
        "total": 0,
    }

    data, status = await _get_json(_DOMAIN_ENDPOINT, {"domain": domain})
    if status != "ok" or not isinstance(data, dict):
        if status == "not_found":
            return empty
        return {**empty, "source": f"hudsonrock_{status}"}

    employees = int(data.get("employees") or 0)
    users = int(data.get("users") or 0)
    third_parties = int(data.get("third_parties") or 0)
    total = int(data.get("total") or 0)

    if employees == 0 and users == 0 and total == 0:
        return empty

    return {
        "found": True,
        "source": "hudsonrock",
        "kind": "domain",
        "value": domain,
        "employees": employees,
        "users": users,
        "third_parties": third_parties,
        "total": total,
        "total_stealers": int(data.get("totalStealers") or 0),
    }


async def _cached_query_domain(domain: str) -> dict[str, Any]:
    cache = await _get_enrichment_cache()
    cached = await cache.get("DOMAIN", domain, "hudsonrock")
    if cached is not None:
        return cached
    result = await query_hudsonrock_domain(domain)
    if result.get("source") in ("hudsonrock", "hudsonrock_not_found"):
        await cache.set("DOMAIN", domain, "hudsonrock", result, DEFAULT_TTL["hudsonrock"])
    return result


# ---------------------------------------------------------------------------
# DB helper (sync — via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_entities_in_db(
    updates: list[tuple[str, str, float, list[str]]],
) -> None:
    """Update confidence + corroborating_sources. updates: (entity_type, value, conf, tags)."""
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for entity_type, value, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == entity_type,
                    Entity.value == value,
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
        logger.warning("infostealer: DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

def _collect_entities(extraction_results: list) -> tuple[dict[str, float], dict[str, float]]:
    """Return ({email: conf}, {domain: conf}) unique across extraction results."""
    emails: dict[str, float] = {}
    domains: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            etype = getattr(entity, "entity_type", "")
            value = (getattr(entity, "value", "") or "").strip()
            conf = getattr(entity, "confidence", 1.0)
            if etype == "EMAIL_ADDRESS" and _is_valid_email(value):
                emails.setdefault(value, conf)
            elif etype == "DOMAIN" and _is_valid_domain(value):
                dv = value.lower()
                if dv not in _FREE_PROVIDERS:
                    domains.setdefault(dv, conf)
    return emails, domains


async def enrich_infostealer_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction infostealer enrichment (STEP 6.6) via Hudson Rock Cavalier.

    Runs for both EMAIL_ADDRESS (search-by-email) and DOMAIN (search-by-domain)
    entities. Reports into ``sources_used`` under the key ``hudsonrock``.

    Returns (extraction_results, stats_dict) — ``stats_dict`` always carries a
    ``hudsonrock`` status key.
    """
    emails, domains = _collect_entities(extraction_results)

    if not emails and not domains:
        return extraction_results, {"hudsonrock": "ok_0_results", "emails_checked": 0, "domains_checked": 0}

    email_list = list(emails.keys())[:MAX_EMAILS]
    domain_list = list(domains.keys())[:MAX_DOMAINS]

    logger.info(
        "infostealer: checking %d email(s), %d domain(s)",
        len(email_list), len(domain_list),
    )

    email_results, domain_results = await asyncio.gather(
        asyncio.gather(*[_cached_query_email(e) for e in email_list], return_exceptions=True),
        asyncio.gather(*[_cached_query_domain(d) for d in domain_list], return_exceptions=True),
    )

    db_updates: list[tuple[str, str, float, list[str]]] = []
    stats: dict[str, Any] = {
        "emails_checked": len(email_list),
        "domains_checked": len(domain_list),
        "emails_infected": 0,
        "domains_exposed": 0,
        "total_machines": 0,
    }
    any_error = False
    any_hit = 0

    for email, rep in zip(email_list, email_results):
        if isinstance(rep, Exception):
            any_error = True
            continue
        if rep.get("source", "").startswith("hudsonrock_") and rep["source"] not in (
            "hudsonrock_not_found",
        ):
            any_error = True
        if rep.get("found"):
            any_hit += 1
            stats["emails_infected"] += 1
            machines = rep.get("machine_count", 0)
            stats["total_machines"] += machines
            tags = ["hudsonrock_infostealer", f"infostealer_machines_{machines}"]
            base_conf = emails.get(email, 1.0)
            new_conf = max(0.50, min(base_conf + 0.15, 1.0))
            db_updates.append(("EMAIL_ADDRESS", email, new_conf, tags))
            logger.info(
                "[%s] Infostealer exposure: %s on %d machine(s)",
                investigation_id, _safe_log_email(email), machines,
            )

    for domain, rep in zip(domain_list, domain_results):
        if isinstance(rep, Exception):
            any_error = True
            continue
        if rep.get("source", "").startswith("hudsonrock_") and rep["source"] not in (
            "hudsonrock_not_found",
        ):
            any_error = True
        if rep.get("found"):
            any_hit += 1
            stats["domains_exposed"] += 1
            emp = rep.get("employees", 0)
            usr = rep.get("users", 0)
            tags = [
                "hudsonrock_infostealer",
                f"infostealer_employees_{emp}",
                f"infostealer_users_{usr}",
            ]
            base_conf = domains.get(domain, 1.0)
            new_conf = max(0.50, min(base_conf + 0.12, 1.0))
            db_updates.append(("DOMAIN", domain, new_conf, tags))
            logger.info(
                "[%s] Domain infostealer exposure: %s — %d employees, %d users",
                investigation_id, domain, emp, usr,
            )

    if db_updates:
        await asyncio.to_thread(_update_entities_in_db, db_updates)

    checked = stats["emails_checked"] + stats["domains_checked"]
    if any_error and any_hit == 0:
        stats["hudsonrock"] = "error"
    else:
        stats["hudsonrock"] = f"ok_{any_hit}_results" if checked else "ok_0_results"

    logger.info(
        "infostealer: done — %d emails infected, %d domains exposed, %d machines total",
        stats["emails_infected"], stats["domains_exposed"], stats["total_machines"],
    )

    return extraction_results, stats
