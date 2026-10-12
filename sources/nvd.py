"""
sources/nvd.py — NVD 2.0 (National Vulnerability Database) CVE enrichment.

Fills a real gap in the pipeline. Today, when a CVE is extracted as an entity,
the only enrichment is checking whether it appears in CISA's Known Exploited
Vulnerabilities list (``sources/cisa.py``) — a small subset of all CVEs. NVD
2.0 is NIST's authoritative, complete CVE dataset, so ANY extracted CVE can be
enriched with its severity score, description, weaknesses (CWE), and publication
date, regardless of KEV membership.

Runs alongside CISA (both surface complementary facts) inside the Phase-A
``_enrich_new_sources`` fan-out. Reports into ``sources_used`` under ``nvd``.

Auth: works without a key. An optional free NVD_API_KEY raises the rate limit
(NVD documents 5 requests / 30s without a key, 50 / 30s with one), following the
same optional-key pattern as every other source in this project.

Public interface
----------------
async fetch_nvd_cve(cve_id)          → dict | None
async enrich_nvd(entities)           → list[dict]
"""

from __future__ import annotations

import asyncio
import logging
import os
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

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# Per-investigation cap and pacing.  Verified against NIST's own developer
# docs 2026-07-29: 5 requests per rolling 30 s window without an API key,
# 50 with one, and NIST explicitly recommends scripts "sleep for six seconds
# between requests" on the unauthenticated tier.  Both constants below are
# therefore the documented interval plus a small margin, and both are routed
# through pacing.scale_delay_floor() so no profile can shorten them.
#
MAX_CVES_PER_INVESTIGATION = 15
_NVD_DELAY_NO_KEY = 6.5    # documented: 5 per 30 s = 6.0 s, + margin
_NVD_DELAY_WITH_KEY = 0.7  # documented: 50 per 30 s = 0.6 s, + margin
_NVD_SOFT_BUDGET = 45.0    # stop issuing new requests after this many seconds

# NVD's window is *rolling*, and a flat delay only approximates that: it
# enforces the right mean rate but has no memory of when earlier requests went
# out, so a caller that bursts and then idles can still land >5 requests inside
# some 30-second span without ever violating the mean.  The window below closes
# that gap by tracking actual request timestamps.
#
# Deliberately NVD-local rather than a general framework: NVD is the only
# provider in the tree that documents a rolling window, and a shared abstraction
# with one consumer is the dead-generality problem pacing/ exists to avoid.
# The reusable part (timestamp bookkeeping) lives in pacing.RollingWindow; the
# provider-specific limits stay here.
_NVD_WINDOW_SECONDS = 30.0
_NVD_WINDOW_LIMIT_NO_KEY = 5      # documented: 5 requests / rolling 30 s
_NVD_WINDOW_LIMIT_WITH_KEY = 50   # documented: 50 requests / rolling 30 s
# One margin slot held back, so a clock difference between us and NIST cannot
# put us exactly on the boundary.
_NVD_WINDOW_MARGIN = 1

_nvd_window_no_key: Optional["pacing.RollingWindow"] = None
_nvd_window_with_key: Optional["pacing.RollingWindow"] = None


def _request_window() -> "pacing.RollingWindow":
    """
    The rolling window for the active key tier.

    Two separate windows because the tiers have different limits, and a run that
    gains or loses a key mid-flight should not inherit the other tier's history.
    """
    global _nvd_window_no_key, _nvd_window_with_key
    if _api_key():
        if _nvd_window_with_key is None:
            _nvd_window_with_key = pacing.RollingWindow(
                limit=_NVD_WINDOW_LIMIT_WITH_KEY - _NVD_WINDOW_MARGIN,
                window=_NVD_WINDOW_SECONDS,
            )
        return _nvd_window_with_key
    if _nvd_window_no_key is None:
        _nvd_window_no_key = pacing.RollingWindow(
            limit=_NVD_WINDOW_LIMIT_NO_KEY - _NVD_WINDOW_MARGIN,
            window=_NVD_WINDOW_SECONDS,
        )
    return _nvd_window_no_key


def _reset_request_windows() -> None:
    """Drop accumulated window state (used by tests)."""
    global _nvd_window_no_key, _nvd_window_with_key
    _nvd_window_no_key = None
    _nvd_window_with_key = None

DEFAULT_TTL.setdefault("nvd", 259200)  # 72 h — CVE metadata is fairly stable
DEFAULT_TTL.setdefault("nvd_cpe", 604800)

_enrichment_cache_singleton: Optional[Any] = None

# Loose CVE-id shape guard; the extractor emits canonical CVE-YYYY-NNNN+ strings.
import re as _re
_CVE_RE = _re.compile(r"^CVE-\d{4}-\d{4,}$", _re.I)


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _api_key() -> str:
    return (os.getenv("NVD_API_KEY") or "").strip()


def _request_delay() -> float:
    """
    Documented NVD interval for the active key tier, as a pacing floor.

    This is the reference implementation of the key-tier pattern: a configured
    NVD_API_KEY genuinely raises the quota, so the delay drops.  That does NOT
    generalise — GitLab's /search cap is per-IP and a token does not lift it.
    Check each provider's docs before assuming "key present == go faster".
    """
    baseline = _NVD_DELAY_WITH_KEY if _api_key() else _NVD_DELAY_NO_KEY
    return pacing.scale_delay_floor(baseline)


def _parse_cve(cve: dict) -> dict[str, Any]:
    """Extract the fields we care about from an NVD 2.0 ``cve`` object."""
    cve_id = cve.get("id", "")

    # Description — prefer English.
    description = ""
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS — prefer v3.1, then v3.0, then v2.
    base_score: Optional[float] = None
    base_severity = ""
    vector = ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr and isinstance(arr, list):
            cdata = (arr[0] or {}).get("cvssData") or {}
            base_score = cdata.get("baseScore")
            base_severity = cdata.get("baseSeverity", "") or ""
            vector = cdata.get("vectorString", "") or ""
            break
    if base_score is None:
        arr = metrics.get("cvssMetricV2") or []
        if arr and isinstance(arr, list):
            entry = arr[0] or {}
            cdata = entry.get("cvssData") or {}
            base_score = cdata.get("baseScore")
            base_severity = entry.get("baseSeverity", "") or ""
            vector = cdata.get("vectorString", "") or ""

    # Weaknesses (CWE).
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in (w.get("description") or []):
            val = d.get("value", "")
            if val and val not in cwes:
                cwes.append(val)

    return {
        "source": "nvd",
        "entity_type": "CVE_NUMBER",
        "entity_value": cve_id,
        "description": description,
        "base_score": base_score,
        "base_severity": base_severity,
        "vector": vector,
        "cwes": cwes,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
    }


async def fetch_nvd_cve(cve_id: str, session: Optional[aiohttp.ClientSession] = None) -> Optional[dict]:
    """
    Fetch a single CVE from NVD 2.0. Returns a parsed result dict, or None on
    error / not-found. Cached by (CVE_NUMBER, cve_id, "nvd").
    """
    if not _CVE_RE.match(cve_id or ""):
        return None
    if not is_enrichment_source_enabled("nvd"):
        return None  # VOIDACCESS_ENRICHMENT_SOURCES: no cache read, no network
    cve_id = cve_id.upper()

    cache = await _get_enrichment_cache()
    cached = await cache.get("CVE_NUMBER", cve_id, "nvd")
    if cached is not None:
        logger.debug("NVD cache hit: %s", cve_id)
        return cached

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    key = _api_key()
    if key:
        headers["apiKey"] = key

    owns_session = session is None
    # Reserve a slot in the rolling window BEFORE issuing the request.  This is
    # the difference from a flat delay: if the window is already full this blocks
    # until the oldest request ages out, so a burst followed by an idle gap
    # cannot slip past the limit the way a mean-rate delay allows.  Passing the
    # documented interval as min_spacing keeps NIST's "sleep six seconds between
    # requests" recommendation as well, so the window governs both constraints
    # instead of one being enforced here and the other in the caller's loop.
    await _request_window().acquire(min_spacing=_request_delay())
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        if owns_session:
            # Shared clearnet pool (P1.2): borrow, never close. Per-request headers
            # + timeout since the shared session carries no caller-specific ones.
            session = http_pool.get_clearnet_session()
        assert session is not None
        async with session.get(
            _NVD_BASE_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout,
        ) as resp:
            if resp.status == 404:
                return None
            if resp.status == 403 or resp.status == 429:
                # NVD did throttle us despite the window — honour whatever wait
                # it names, floored by our own documented interval.
                wait = pacing.retry_after_seconds(resp.headers, _request_delay())
                logger.warning(
                    "NVD: rate limited (HTTP %s) for %s — backing off %.1fs",
                    resp.status, cve_id, wait,
                )
                await asyncio.sleep(wait)
                return None
            if resp.status != 200:
                logger.debug("NVD: HTTP %s for %s", resp.status, cve_id)
                return None
            data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        logger.warning("NVD: timed out for %s", cve_id)
        return None
    except Exception as exc:
        logger.debug("NVD: error for %s: %s", cve_id, exc)
        return None

    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve_obj = (vulns[0] or {}).get("cve") or {}
    if not cve_obj:
        return None

    result = _parse_cve(cve_obj)
    # Cache successful lookups only.
    await cache.set("CVE_NUMBER", cve_id, "nvd", result, DEFAULT_TTL["nvd"])
    return result


def _cpe_key(value: str) -> str:
    """Normalize a product phrase for a conservative CPE comparison."""
    value = (value or "").casefold().replace("_", " ").replace("-", " ")
    return " ".join(value.split())


def _cpe_match(product_name: str, cpe_record: dict[str, Any]) -> bool:
    """Require an exact product-component or title phrase match."""
    wanted = _cpe_key(product_name)
    if not wanted:
        return False

    titles: list[str] = []
    for title in cpe_record.get("titles") or []:
        text = title.get("title", "") if isinstance(title, dict) else str(title or "")
        if text:
            titles.append(_cpe_key(text))
    if any(title == wanted or f" {wanted} " in f" {title} " for title in titles):
        return True

    for cpe_name in cpe_record.get("cpeName") or []:
        cpe_uri = (
            cpe_name.get("cpeName", "")
            if isinstance(cpe_name, dict)
            else str(cpe_name or "")
        )
        fields = cpe_uri.split(":")
        if len(fields) > 4 and _cpe_key(fields[4]) == wanted:
            return True
    return False


async def fetch_nvd_cpe(
    product_name: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[dict]:
    """Look up a product phrase in NVD's CPE catalog.

    This is a suppression lookup, not a positive classifier. A match is
    returned only when NVD gives an exact product component or title phrase;
    a miss or unavailable service leaves the caller's candidate unchanged.
    """
    product_name = (product_name or "").strip()
    if len(product_name) < 4:
        return None
    if not is_enrichment_source_enabled("nvd"):
        return None  # VOIDACCESS_ENRICHMENT_SOURCES: no cache read, no network

    cache = await _get_enrichment_cache()
    cached = await cache.get("CPE_PRODUCT_LOOKUP", product_name, "nvd_cpe")
    if cached is not None:
        logger.debug("NVD CPE cache hit: %s", product_name)
        return cached

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    key = _api_key()
    if key:
        headers["apiKey"] = key

    owns_session = session is None
    await _request_window().acquire(min_spacing=_request_delay())
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        if owns_session:
            # Shared clearnet pool (P1.2): borrow, never close.
            session = http_pool.get_clearnet_session()
        assert session is not None
        async with session.get(
            _CPE_BASE_URL,
            params={
                "keywordSearch": product_name,
                "resultsPerPage": 20,
            },
            headers=headers,
            timeout=timeout,
        ) as resp:
            if resp.status in (403, 404, 429):
                if resp.status in (403, 429):
                    logger.warning("NVD CPE: HTTP %s for %s", resp.status, product_name)
                return None
            if resp.status != 200:
                logger.debug("NVD CPE: HTTP %s for %s", resp.status, product_name)
                return None
            data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        logger.warning("NVD CPE: timed out for %s", product_name)
        return None
    except Exception as exc:
        logger.debug("NVD CPE: error for %s: %s", product_name, exc)
        return None

    products = (data or {}).get("products") or []
    matched = any(
        isinstance(product, dict)
        and _cpe_match(product_name, product.get("cpe") or {})
        for product in products
    )
    result = {
        "source": "nvd_cpe",
        "entity_value": product_name,
        "matched": matched,
        "result_count": len(products),
    }
    await cache.set(
        "CPE_PRODUCT_LOOKUP",
        product_name,
        "nvd_cpe",
        result,
        DEFAULT_TTL["nvd_cpe"],
    )
    return result


async def enrich_nvd(entities: list[dict]) -> list[dict]:
    """
    For each CVE_NUMBER entity, fetch NVD 2.0 metadata.

    Rate-limited (key-aware) and capped at MAX_CVES_PER_INVESTIGATION, with a
    soft time budget so a CVE-heavy investigation returns partial results rather
    than blowing the enclosing Phase-A deadline.
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently
    if not is_enrichment_source_enabled("nvd"):
        return []
    cve_ids: list[str] = []
    seen: set[str] = set()
    for e in entities:
        et = e.get("type") or e.get("entity_type", "")
        ev = (e.get("value") or e.get("entity_value", "") or "").upper()
        if et == "CVE_NUMBER" and ev and _CVE_RE.match(ev) and ev not in seen:
            seen.add(ev)
            cve_ids.append(ev)

    if not cve_ids:
        return []

    cve_ids = cve_ids[:MAX_CVES_PER_INVESTIGATION]
    window = _request_window()
    logger.info(
        "NVD: enriching %d CVE(s) (key=%s, spacing=%.1fs, window=%d/%.0fs)",
        len(cve_ids), "yes" if _api_key() else "no",
        _request_delay(), window.limit, window.window,
    )

    results: list[dict] = []
    started = time.monotonic()

    # One shared clearnet session reused across the whole CVE batch (injected into
    # each fetch_nvd_cve, which applies its own per-request headers + timeout).
    async with http_pool.clearnet_session() as session:
        for cve_id in cve_ids:
            if time.monotonic() - started > _NVD_SOFT_BUDGET:
                logger.warning(
                    "NVD: soft time budget (%.0fs) reached — enriched %d of %d CVEs",
                    _NVD_SOFT_BUDGET, len(results), len(cve_ids),
                )
                break
            # No inter-request sleep here: fetch_nvd_cve() reserves its slot in
            # the rolling window, which enforces BOTH the 30 s window limit and
            # the documented inter-request spacing.  Pacing in this loop as well
            # would double-count — the same two-mechanisms-multiplying mistake
            # that the semaphore/delay derivation fixed for the breach sources.
            result = await fetch_nvd_cve(cve_id, session=session)
            if result is not None:
                results.append(result)

    logger.info("NVD: %d CVE(s) enriched", len(results))
    return results
