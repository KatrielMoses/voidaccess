"""
sources/domain_reputation.py — Domain reputation enrichment.

Enriches extracted DOMAIN entities with infrastructure profiles from three sources:
  - crt.sh (Certificate Transparency): subdomain enumeration — free, no auth
  - URLScan.io: live scan data, malicious indicators, communicating IPs
  - Wayback Machine (Internet Archive): historical snapshots for taken-down domains

All three sources queried concurrently per domain. Results are cached.
New subdomain/IP entities are returned in the result for pipeline reporting.
Existing DOMAIN entities get confidence and tag updates written to the DB.

Public interface
----------------
async query_crt_sh(domain)                         → list[dict]
async query_urlscan(domain)                        → dict
async query_wayback(domain)                        → dict
async check_domain_reputation(domain, confidence)  → dict
async enrich_domain_entities(extraction_results, investigation_id) → (results, stats)
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

MAX_DOMAINS = 30
MAX_SUBDOMAINS_PER_DOMAIN = 20
MAX_IPS_PER_DOMAIN = 5

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
WAYBACK_CDX_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&limit=5&fl=timestamp,statuscode,mimetype"
)

# In-memory per-domain caches (module-level singletons, keyed by domain)
_crt_cache: dict[str, dict] = {}
_urlscan_cache: dict[str, dict] = {}
_wayback_cache: dict[str, dict] = {}

# crt.sh pacing — Class B, quota-driven.  The operator states a per-IP limit of
# **5 requests per minute** (crtsh mailing list, June 2023; reduced from the
# 60/min announced in January 2020).  Verified 2026-07-29.
#
# Before this, up to MAX_DOMAINS (30) crt.sh requests were fired concurrently
# with no delay and no 429 handling, against a 5/min limit — the highest real
# throttling risk in the tree.
#
# Concurrency 1 rather than a wider semaphore: at 5 req/min the derived
# per-worker delay for N workers is N x 12 s, so extra concurrency buys nothing
# and only makes the arithmetic harder to read.
#
# A correctly paced crt.sh cannot cover 30 domains inside an investigation
# (30 x 12 s = 6 minutes), so a soft budget bounds it the same way nvd.py bounds
# its CVE loop.  That is a real coverage reduction and it is the correct
# trade: firing 30 concurrent requests at a 5/min endpoint gets us throttled,
# so most of those 30 were returning nothing anyway.  The 24 h in-memory cache
# plus the cross-process enrichment cache are what actually recover coverage
# across runs.
CRT_MIN_INTERVAL = 12.5      # documented: 5 req/min = 12.0 s, + margin
CRT_MAX_CONCURRENCY = 1
CRT_SOFT_BUDGET = 45.0       # stop issuing new crt.sh requests after this long

_crt_semaphore: Optional[asyncio.Semaphore] = None
_crt_budget_started: Optional[float] = None

CRT_CACHE_TTL = 86400.0      # 24 h
URLSCAN_CACHE_TTL = 21600.0  # 6 h
WAYBACK_CACHE_TTL = 86400.0  # 24 h

# Module-level enrichment cache singleton (lazy-init on first lookup).
# Kept separate from the in-memory dicts above — those protect a single
# investigation run, this one spans runs / processes.
_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)

_PRIVATE_SUFFIXES = (".local", ".internal", ".test", ".example", ".invalid", ".localhost")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_onion(domain: str) -> bool:
    return domain.lower().strip().endswith(".onion")


def _is_private_domain(domain: str) -> bool:
    d = domain.lower().strip()
    if d == "localhost":
        return True
    return any(d.endswith(s) for s in _PRIVATE_SUFFIXES)


def _is_valid_domain(value: str) -> bool:
    if not value or len(value) < 4 or "." not in value:
        return False
    if value.endswith(".onion"):
        return False
    return bool(_DOMAIN_RE.match(value))


def _parse_wayback_timestamp(ts: str) -> str | None:
    """Convert 14-char Wayback timestamp (YYYYMMDDHHmmss) to ISO date (YYYY-MM-DD)."""
    try:
        ts = ts.strip()
        if len(ts) >= 8:
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        return None
    except Exception:
        return None


def _is_established_domain(first_seen: str | None) -> bool:
    """True if first Wayback snapshot is older than 5 years."""
    if not first_seen:
        return False
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(first_seen)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days > 1825
    except Exception:
        return False


def _is_newly_observed(first_seen: str | None) -> bool:
    """True if first Wayback snapshot is younger than 90 days."""
    if not first_seen:
        return False
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(first_seen)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days < 90
    except Exception:
        return False


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency
# ---------------------------------------------------------------------------

def _get_crt_semaphore() -> asyncio.Semaphore:
    global _crt_semaphore
    if _crt_semaphore is None:
        _crt_semaphore = asyncio.Semaphore(CRT_MAX_CONCURRENCY)
    return _crt_semaphore


def _crt_delay() -> float:
    """Per-worker delay holding the aggregate crt.sh rate at ≤ 5 req/min."""
    return pacing.rate_limit_delay(CRT_MIN_INTERVAL, CRT_MAX_CONCURRENCY)


def start_crt_budget() -> None:
    """Open a fresh crt.sh soft-budget window for one investigation."""
    global _crt_budget_started
    _crt_budget_started = time.monotonic()


def _crt_budget_exhausted() -> bool:
    if _crt_budget_started is None:
        return False
    return (time.monotonic() - _crt_budget_started) > CRT_SOFT_BUDGET


async def query_crt_sh(domain: str) -> list[dict]:
    """
    Query crt.sh for subdomains found in certificate transparency logs.

    Returns list of dicts with keys: name, first_seen, last_seen, issuer.
    Wildcards (*.example.com) and the parent domain itself are filtered out.
    Results capped at MAX_SUBDOMAINS_PER_DOMAIN. Cached for 24 h.

    Paced to crt.sh's documented 5 requests/minute per IP, and bounded by
    CRT_SOFT_BUDGET so a 30-domain investigation degrades to fewer CT lookups
    instead of running for six minutes or getting the IP throttled.
    """
    cached = _crt_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < CRT_CACHE_TTL:
        return cached["subdomains"]

    if _crt_budget_exhausted():
        logger.info(
            "domain_reputation: crt.sh skipped for %s — soft budget (%.0fs) "
            "reached at 5 req/min", domain, CRT_SOFT_BUDGET,
        )
        return []

    url = CRT_SH_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(connect=10, sock_read=120)
        headers = {"User-Agent": "VoidAccess-OSINT/1.1 (security research)"}
        async with _get_crt_semaphore():
            # Delay in a `finally` inside the semaphore: paid on 429s and errors
            # too (a 429 storm must slow us down, not speed us up), and the slot
            # stays held so rate_limit_delay()'s arithmetic holds.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(url, headers=headers, timeout=timeout) as resp:
                        if resp.status == 429:
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _crt_delay()
                            )
                            logger.warning(
                                "domain_reputation: crt.sh rate limited for %s "
                                "— backing off %.1fs", domain, server_wait,
                            )
                            return []
                        if resp.status != 200:
                            logger.debug(
                                "domain_reputation: crt.sh %s → HTTP %s",
                                domain, resp.status,
                            )
                            return []
                        data = await resp.json(content_type=None)
            finally:
                await asyncio.sleep(max(_crt_delay(), server_wait))
    except Exception as exc:
        logger.debug("domain_reputation: crt.sh failed for %s: %s", domain, exc)
        return []

    seen: set[str] = set()
    results: list[dict] = []
    for entry in data or []:
        raw = (entry.get("name_value") or "").strip().lower()
        # name_value may contain newline-separated entries
        for name in raw.split("\n"):
            name = name.strip()
            if not name:
                continue
            if name.startswith("*"):
                continue
            if name == domain:
                continue
            if not name.endswith(f".{domain}"):
                continue
            if not _is_valid_domain(name):
                continue
            if name in seen:
                continue
            seen.add(name)
            results.append({
                "name": name,
                "first_seen": entry.get("not_before", ""),
                "last_seen": entry.get("not_after", ""),
                "issuer": entry.get("issuer_name", ""),
            })
            if len(results) >= MAX_SUBDOMAINS_PER_DOMAIN:
                break
        if len(results) >= MAX_SUBDOMAINS_PER_DOMAIN:
            break

    _crt_cache[domain] = {"subdomains": results, "loaded_at": time.time()}
    logger.debug("domain_reputation: crt.sh %s → %d subdomains", domain, len(results))
    return results


async def _cached_query_crt_sh(domain: str) -> list[dict]:
    """Cached wrapper around query_crt_sh (72h TTL via DEFAULT_TTL).

    Cache order: enrichment cache (cross-process) → in-memory dict (within
    process) → live API. Stores an empty list as a sentinel for known-no-records
    domains to avoid hammering crt.sh for uninteresting targets.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("DOMAIN", domain, "crt_sh")
    if cached is not None:
        logger.debug("crt.sh cache hit: %s", domain)
        return cached
    result = await query_crt_sh(domain)
    # Cache both empty and populated lists — repeat lookups for empty domains
    # shouldn't refire.
    await cache.set("DOMAIN", domain, "crt_sh", result, DEFAULT_TTL["crt_sh"])
    return result


# ---------------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------------

async def query_urlscan(domain: str) -> dict[str, Any]:
    """
    Query URLScan.io search API for the most recent scans of a domain.

    Returns dict: malicious, tags, categories, ips, technologies, screenshot_url.
    Uses URLSCAN_API_KEY env var if present (higher rate limits).
    Cached for 6 h.
    """
    cached = _urlscan_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < URLSCAN_CACHE_TTL:
        return cached["result"]

    empty: dict[str, Any] = {
        "malicious": False,
        "tags": [],
        "categories": [],
        "ips": [],
        "technologies": [],
        "screenshot_url": None,
    }

    api_key = (os.getenv("URLSCAN_API_KEY") or "").strip()
    headers: dict[str, str] = {"User-Agent": "VoidAccess-OSINT/1.1 (security research)"}
    if api_key:
        headers["API-Key"] = api_key

    url = URLSCAN_SEARCH_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.get(url, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug("domain_reputation: URLScan %s → HTTP %s", domain, resp.status)
                    _urlscan_cache[domain] = {"result": empty, "loaded_at": time.time()}
                    return empty
                data = await resp.json()
    except Exception as exc:
        logger.debug("domain_reputation: URLScan failed for %s: %s", domain, exc)
        return empty

    scan_list = data.get("results") or []
    if not scan_list:
        _urlscan_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    malicious = False
    all_tags: list[str] = []
    all_categories: list[str] = []
    seen_ips: list[str] = []
    all_tech: list[str] = []
    screenshot_url: str | None = None

    for scan in scan_list[:5]:
        verdicts = scan.get("verdicts", {})
        overall = verdicts.get("overall", {})
        if overall.get("malicious"):
            malicious = True
        all_tags.extend(overall.get("tags") or [])
        all_categories.extend(overall.get("categories") or [])

        for ip in (scan.get("lists") or {}).get("ips") or []:
            if isinstance(ip, str) and ip not in seen_ips:
                seen_ips.append(ip)
            if len(seen_ips) >= MAX_IPS_PER_DOMAIN:
                break

        wappa = (scan.get("meta") or {}).get("processors", {}).get("wappa", {})
        for tech in wappa.get("data") or []:
            name = tech.get("app") or tech.get("name") or ""
            if name and name not in all_tech:
                all_tech.append(name)

        if screenshot_url is None:
            screenshot_url = (scan.get("task") or {}).get("screenshotURL")

    result: dict[str, Any] = {
        "malicious": malicious,
        "tags": list(dict.fromkeys(all_tags))[:10],
        "categories": list(dict.fromkeys(all_categories))[:5],
        "ips": seen_ips[:MAX_IPS_PER_DOMAIN],
        "technologies": all_tech[:10],
        "screenshot_url": screenshot_url,
    }

    _urlscan_cache[domain] = {"result": result, "loaded_at": time.time()}
    logger.debug(
        "domain_reputation: URLScan %s → malicious=%s, %d IPs",
        domain, malicious, len(result["ips"]),
    )
    return result


async def _cached_query_urlscan(domain: str) -> dict[str, Any]:
    """Cached wrapper around query_urlscan (12h TTL via DEFAULT_TTL).

    Cache order: enrichment cache (cross-process) → in-memory dict (within
    process) → live API.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("DOMAIN", domain, "urlscan")
    if cached is not None:
        logger.debug("URLScan cache hit: %s", domain)
        return cached
    result = await query_urlscan(domain)
    await cache.set("DOMAIN", domain, "urlscan", result, DEFAULT_TTL["urlscan"])
    return result


async def _submit_urlscan(domain: str, api_key: str) -> None:
    """Submit a new public scan to URLScan.io — only when URLSCAN_SUBMIT=true."""
    if (os.getenv("URLSCAN_SUBMIT") or "false").lower().strip() != "true":
        return
    if not api_key:
        return
    try:
        payload = {"url": f"https://{domain}", "visibility": "public"}
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.post(URLSCAN_SUBMIT_URL, json=payload, headers=headers, timeout=timeout) as resp:
                if resp.status in (200, 201):
                    logger.debug("domain_reputation: URLScan scan submitted for %s", domain)
                else:
                    logger.debug(
                        "domain_reputation: URLScan submit %s → HTTP %s", domain, resp.status
                    )
    except Exception as exc:
        logger.debug("domain_reputation: URLScan submit failed for %s: %s", domain, exc)


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

async def query_wayback(domain: str) -> dict[str, Any]:
    """
    Query the Wayback Machine CDX API for historical snapshots of a domain.

    Returns dict: exists, first_seen, last_seen, snapshot_url, likely_taken_down.
    A domain shows "likely_taken_down" when earlier snapshots returned 2xx
    and the most recent snapshot returned a 4xx status.
    Cached for 24 h.
    """
    cached = _wayback_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < WAYBACK_CACHE_TTL:
        return cached["result"]

    empty: dict[str, Any] = {
        "exists": False,
        "first_seen": None,
        "last_seen": None,
        "snapshot_url": None,
        "likely_taken_down": False,
    }

    url = WAYBACK_CDX_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {"User-Agent": "VoidAccess-OSINT/1.1 (security research)"}
        async with http_pool.clearnet_session() as session:
            async with session.get(url, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug("domain_reputation: Wayback %s → HTTP %s", domain, resp.status)
                    _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
                    return empty
                rows = await resp.json(content_type=None)
    except Exception as exc:
        logger.debug("domain_reputation: Wayback failed for %s: %s", domain, exc)
        return empty

    # CDX returns list-of-lists; first row is the header
    if not rows or len(rows) <= 1:
        _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    data_rows = rows[1:]
    timestamps: list[str] = []
    status_codes: list[str] = []
    for row in data_rows:
        if isinstance(row, list) and len(row) >= 2:
            timestamps.append(str(row[0]))
            status_codes.append(str(row[1]))

    if not timestamps:
        _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    timestamps_sorted = sorted(timestamps)
    first_seen = _parse_wayback_timestamp(timestamps_sorted[0])
    last_seen = _parse_wayback_timestamp(timestamps_sorted[-1])
    snapshot_url = f"https://web.archive.org/web/{timestamps_sorted[-1]}/{domain}"

    has_200 = any(sc.startswith("2") for sc in status_codes)
    last_status = status_codes[-1] if status_codes else ""
    likely_taken_down = has_200 and last_status.startswith("4")

    result: dict[str, Any] = {
        "exists": True,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "snapshot_url": snapshot_url,
        "likely_taken_down": likely_taken_down,
    }

    _wayback_cache[domain] = {"result": result, "loaded_at": time.time()}
    logger.debug(
        "domain_reputation: Wayback %s → archived, taken_down=%s", domain, likely_taken_down
    )
    return result


async def _cached_query_wayback(domain: str) -> dict[str, Any]:
    """Cached wrapper around query_wayback (7d TTL via DEFAULT_TTL).

    Archive snapshots are immutable — long TTL is safe and worthwhile.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("DOMAIN", domain, "wayback")
    if cached is not None:
        logger.debug("Wayback cache hit: %s", domain)
        return cached
    result = await query_wayback(domain)
    await cache.set("DOMAIN", domain, "wayback", result, DEFAULT_TTL["wayback"])
    return result


# ---------------------------------------------------------------------------
# Core enrichment check
# ---------------------------------------------------------------------------

async def check_domain_reputation(
    domain: str,
    base_confidence: float = 1.0,
) -> dict[str, Any]:
    """
    Run all three enrichment sources for a single domain concurrently.

    Returns:
        domain, crt_subdomains, urlscan_malicious, urlscan_tags, urlscan_ips,
        wayback_exists, wayback_first_seen, wayback_last_seen, likely_taken_down,
        new_entities, tags, confidence_delta
    """
    result: dict[str, Any] = {
        "domain": domain,
        "crt_subdomains": [],
        "urlscan_malicious": False,
        "urlscan_tags": [],
        "urlscan_ips": [],
        "wayback_exists": False,
        "wayback_first_seen": None,
        "wayback_last_seen": None,
        "likely_taken_down": False,
        "new_entities": [],
        "tags": [],
        "confidence_delta": 0.0,
    }

    if _is_onion(domain) or _is_private_domain(domain):
        return result

    # VOIDACCESS_ENRICHMENT_SOURCES gate: a disabled source is never called
    # (no coroutine is created) and contributes nothing.
    async def _disabled() -> None:
        return None

    crt_data, urlscan_data, wayback_data = await asyncio.gather(
        _cached_query_crt_sh(domain) if is_enrichment_source_enabled("crtsh") else _disabled(),
        _cached_query_urlscan(domain) if is_enrichment_source_enabled("urlscan") else _disabled(),
        _cached_query_wayback(domain) if is_enrichment_source_enabled("wayback") else _disabled(),
        return_exceptions=True,
    )

    # --- crt.sh ---
    if isinstance(crt_data, list) and crt_data:
        result["crt_subdomains"] = crt_data
        result["tags"].append("has_ct_history")
        n = len(crt_data)
        result["tags"].append(f"subdomain_count_{n}")
        for sub in crt_data:
            name = sub.get("name", "")
            if name:
                result["new_entities"].append({
                    "entity_type": "DOMAIN",
                    "value": name,
                    "canonical_value": name,
                    "confidence": 0.70,
                    "source": "crt_sh",
                    "extraction_method": "domain_enrichment",
                    "context_snippet": f"Subdomain of {domain} (certificate transparency logs)",
                })
    elif isinstance(crt_data, Exception):
        logger.debug("domain_reputation: crt.sh error for %s: %s", domain, crt_data)

    # --- URLScan.io ---
    if isinstance(urlscan_data, dict):
        result["urlscan_malicious"] = urlscan_data.get("malicious", False)
        result["urlscan_tags"] = urlscan_data.get("tags", [])
        result["urlscan_ips"] = urlscan_data.get("ips", [])

        if urlscan_data.get("malicious"):
            result["tags"].append("urlscan_malicious")
            result["confidence_delta"] += 0.10

        for ip in urlscan_data.get("ips", [])[:MAX_IPS_PER_DOMAIN]:
            result["new_entities"].append({
                "entity_type": "IP_ADDRESS",
                "value": ip,
                "canonical_value": ip,
                "confidence": 0.72,
                "source": "urlscan",
                "extraction_method": "domain_enrichment",
                "context_snippet": f"IP communicating with {domain} (URLScan.io)",
            })

        for tech in urlscan_data.get("technologies", []):
            slug = re.sub(r"[^a-z0-9]+", "_", tech.lower())[:40]
            result["tags"].append(f"tech_{slug}")
    elif isinstance(urlscan_data, Exception):
        logger.debug("domain_reputation: URLScan error for %s: %s", domain, urlscan_data)

    # --- Wayback Machine ---
    if isinstance(wayback_data, dict):
        result["wayback_exists"] = wayback_data.get("exists", False)
        result["wayback_first_seen"] = wayback_data.get("first_seen")
        result["wayback_last_seen"] = wayback_data.get("last_seen")
        result["likely_taken_down"] = wayback_data.get("likely_taken_down", False)

        if wayback_data.get("exists"):
            result["tags"].append("wayback_archived")
            first_seen = wayback_data.get("first_seen")
            if wayback_data.get("likely_taken_down"):
                result["tags"].append("likely_taken_down")
            if _is_established_domain(first_seen):
                result["tags"].append("established_domain")
            elif _is_newly_observed(first_seen):
                result["tags"].append("newly_observed_domain")
    elif isinstance(wayback_data, Exception):
        logger.debug("domain_reputation: Wayback error for %s: %s", domain, wayback_data)

    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_domain_entities_in_db(
    updates: list[tuple[str, float, list[str]]],
) -> None:
    """Update confidence and corroborating_sources for enriched DOMAIN entities."""
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for domain_val, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == "DOMAIN",
                    Entity.value == domain_val,
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
        logger.warning("domain_reputation: DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

async def enrich_domain_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction domain reputation enrichment step.

    Collects DOMAIN entities from *extraction_results*, skipping ONION_URL and
    private/internal domains. Queries crt.sh, URLScan.io, and Wayback Machine
    concurrently per domain (capped at MAX_DOMAINS).

    Updates confidence and tags for existing DOMAIN entities in the DB.
    New entities (subdomains, communicating IPs) are returned in stats for logging.

    Returns (extraction_results, stats_dict).
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    seen: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            if getattr(entity, "entity_type", "") != "DOMAIN":
                continue
            domain = entity.value
            if _is_onion(domain) or _is_private_domain(domain):
                continue
            if domain not in seen:
                seen[domain] = getattr(entity, "confidence", 1.0)

    unique_domains = list(seen.keys())
    if not unique_domains:
        return extraction_results, {"domain_reputation": "ok_0_domains"}

    if len(unique_domains) > MAX_DOMAINS:
        logger.info(
            "domain_reputation: capping to %d of %d unique domains",
            MAX_DOMAINS, len(unique_domains),
        )
        unique_domains = unique_domains[:MAX_DOMAINS]

    logger.info("domain_reputation: enriching %d unique domain(s)", len(unique_domains))

    # Open the crt.sh soft-budget window for this investigation.  crt.sh allows
    # 5 req/min, so the fan-out below cannot cover every domain; the budget makes
    # that degradation bounded and visible instead of open-ended.
    start_crt_budget()

    rep_list = await asyncio.gather(
        *[check_domain_reputation(d, base_confidence=seen[d]) for d in unique_domains],
        return_exceptions=True,
    )

    db_updates: list[tuple[str, float, list[str]]] = []
    all_new_entities: list[dict] = []
    stats = {
        "domains_checked": len(unique_domains),
        "ct_records": 0,
        "urlscan_malicious": 0,
        "wayback_archived": 0,
        "new_entities_discovered": 0,
    }

    for domain, rep in zip(unique_domains, rep_list):
        if isinstance(rep, Exception):
            logger.debug("domain_reputation: check raised for %s: %s", domain, rep)
            continue

        base_conf = seen[domain]
        new_conf = min(base_conf + rep["confidence_delta"], 1.0)
        tags = rep.get("tags", [])

        stats["ct_records"] += len(rep.get("crt_subdomains", []))
        if rep.get("urlscan_malicious"):
            stats["urlscan_malicious"] += 1
        if rep.get("wayback_exists"):
            stats["wayback_archived"] += 1

        new_entities = rep.get("new_entities", [])
        all_new_entities.extend(new_entities)
        stats["new_entities_discovered"] += len(new_entities)

        if tags or rep["confidence_delta"] > 0:
            db_updates.append((domain, new_conf, tags))

    if db_updates:
        await asyncio.to_thread(_update_domain_entities_in_db, db_updates)

    checked = stats["domains_checked"]
    status = (
        f"ok_{checked}_domains"
        f"_{stats['ct_records']}_ct"
        f"_{stats['urlscan_malicious']}_malicious"
        f"_{stats['wayback_archived']}_archived"
    )

    if all_new_entities:
        logger.info(
            "domain_reputation: %d new entities discovered (subdomains + IPs)",
            len(all_new_entities),
        )

    logger.info(
        "domain_reputation: done — %d domains, %d CT records, %d malicious, %d archived",
        checked,
        stats["ct_records"],
        stats["urlscan_malicious"],
        stats["wayback_archived"],
    )

    return extraction_results, {"domain_reputation": status, **stats}
