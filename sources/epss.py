"""sources/epss.py — FIRST EPSS (Exploit Prediction Scoring System) enrichment.

EPSS gives, per CVE, the probability it will be exploited in the wild in the next 30
days (``epss_score``, 0..1) and its ``epss_percentile`` among all CVEs. Free, no auth.

API: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...  (comma-separated batch)
Response: {"status":"OK","data":[{"cve","epss","percentile","date"}, ...]}

Clearnet via the shared ``netpool`` session (P1.2); timeout via ``pacing`` (CC-4);
per-investigation bounded (``MAX_EPSS_PER_INVESTIGATION``); per-CVE results cached
across runs in the shared enrichment cache (24 h, EPSS refreshes daily). Graceful:
if EPSS is unreachable the map is simply missing those CVEs — the CVE view degrades
by omitting the EPSS signal, never crashing.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import aiohttp

import pacing
from sources import http_pool
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"

# Mirror sources/nvd.py's MAX_CVES_PER_INVESTIGATION (15). Kept local to the source,
# like NVD's, rather than in config.py.
MAX_EPSS_PER_INVESTIGATION = 15

# `normal` pacing baseline; scaled by the active profile at call time (CC-4).
_EPSS_TIMEOUT = 20

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# EPSS scores refresh once daily, so a 24 h TTL matches the feed cadence. Registered
# at import (like nvd.py does for "nvd"/"nvd_cpe") so DEFAULT_TTL["epss"] resolves.
DEFAULT_TTL.setdefault("epss", 86400)

_CACHE_ENTITY_TYPE = "CVE_NUMBER"  # same namespace nvd/cisa use for CVE cache keys
_CACHE_SOURCE = "epss"

# Module-level cache singleton (mirrors sources/nvd.py) so tests can swap in a
# fresh in-memory cache per test via conftest, instead of writing EPSS entries to
# the persistent SQLite enrichment cache.
_enrichment_cache_singleton = None


async def _get_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _normalize_cves(cve_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for cid in cve_ids:
        c = (cid or "").strip().upper()
        if _CVE_RE.match(c) and c not in seen:
            seen.add(c)
            out.append(c)
    return out[:MAX_EPSS_PER_INVESTIGATION]


async def enrich_epss(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Return ``{CVE: {"epss_score": float, "epss_percentile": float}}``.

    Deduped/validated/capped. Cached per-CVE; only the cache-miss CVEs are fetched,
    in a single batched request. Never raises — returns whatever it has on error.
    """
    cves = _normalize_cves(cve_ids)
    if not cves:
        return {}

    cache = await _get_cache()
    results: dict[str, dict[str, Any]] = {}
    to_fetch: list[str] = []

    for cve in cves:
        try:
            cached = await cache.get(_CACHE_ENTITY_TYPE, cve, _CACHE_SOURCE)
        except Exception:
            cached = None
        if cached is not None:
            results[cve] = cached
        else:
            to_fetch.append(cve)

    if not to_fetch:
        return results

    try:
        timeout = aiohttp.ClientTimeout(total=pacing.scale_timeout(_EPSS_TIMEOUT))
        params = {"cve": ",".join(to_fetch)}
        async with http_pool.clearnet_session() as session:
            async with session.get(_EPSS_API, params=params, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("EPSS: HTTP %s", resp.status)
                    return results
                payload = await resp.json(content_type=None)
    except Exception as exc:
        logger.warning("EPSS: fetch failed: %s", exc)
        return results

    for row in (payload or {}).get("data") or []:
        cve = (row.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            record = {
                "epss_score": float(row.get("epss")),
                "epss_percentile": float(row.get("percentile")),
            }
        except (TypeError, ValueError):
            continue
        results[cve] = record
        try:
            await cache.set(_CACHE_ENTITY_TYPE, cve, _CACHE_SOURCE, record, DEFAULT_TTL["epss"])
        except Exception:
            pass

    return results
