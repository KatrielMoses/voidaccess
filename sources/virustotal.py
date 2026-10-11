"""
sources/virustotal.py — VirusTotal hash enrichment (file hash lookup).

Requires VT_API_KEY in config. Public tier: 4 requests/minute (15 s apart).
Set VT_API_TIER=premium if the key carries a paid subscription — premium keys
have no per-minute limit, and pacing them at the free-tier rate makes a paying
subscriber 25x slower than their entitlement.
Max 20 hashes per investigation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

import pacing
from sources import http_pool
from config import VT_API_KEY, VT_API_TIER

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_HASH_LIMIT = 20
# Provider-dictated: VirusTotal's public API allows 4 requests/minute, i.e.
# exactly 15.0 s between requests (verified against docs.virustotal.com
# 2026-07-29).  Routed through pacing.scale_delay_floor() so no profile can
# shorten it — `aggressive` would otherwise make this 3.75 s, a 4x overrun.
#
# The public tier also has a hard 500 requests/DAY quota, which no per-request
# delay can express — that is an hourly/daily budget (pattern 1 in
# docs/BACKLOG.md) and remains deferred.
_VT_RATE_LIMIT_DELAY = 15.0

# Premium keys have no per-minute limit, and a key string does not reveal its
# tier, so the tier is declared in config (VT_API_TIER).  Premium still gets a
# small courtesy gap rather than zero: unbounded concurrency against any API is
# a good way to get an account flagged, and 0.25 s is invisible next to the 15 s
# the free tier pays.
_VT_PREMIUM_COURTESY_DELAY = 0.25
_VT_PREMIUM_TIERS: frozenset[str] = frozenset({"premium", "paid", "enterprise"})


def _is_premium_tier() -> bool:
    """True when the operator has declared a paid VirusTotal subscription."""
    tier = getattr(VT_API_TIER, "strip", lambda: "")().lower()
    return tier in _VT_PREMIUM_TIERS


def _vt_delay() -> float:
    """
    Inter-request interval for the configured VirusTotal tier.

    Public is the documented 4 req/min floor.  Premium is courtesy pacing only —
    it is VoidAccess's own choice, not a quota, so it takes the symmetric
    scale_delay() and an `aggressive` run may genuinely shorten it.  This is the
    one place in the enrichment clients where `aggressive` buys something, and it
    is correct precisely because there is no published limit to protect.
    """
    if _is_premium_tier():
        return pacing.scale_delay(_VT_PREMIUM_COURTESY_DELAY)
    return pacing.scale_delay_floor(_VT_RATE_LIMIT_DELAY)


def _is_enabled() -> bool:
    key = getattr(VT_API_KEY, "strip", lambda: "")()
    return bool(key)


async def _fetch_hash(
    hash_value: str, session: aiohttp.ClientSession
) -> tuple[Optional[dict], float]:
    """
    Fetch one hash.  Returns ``(payload_or_None, server_declared_wait)``.

    The second element exists so a 429's ``Retry-After`` / ``X-RateLimit-Reset``
    can reach the caller's sleep.  Previously a 429 was logged and dropped with
    no effect on subsequent request timing, which meant VirusTotal telling us
    exactly how long to wait was information we threw away.
    """
    try:
        headers = {"x-apikey": VT_API_KEY.strip()}
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(
            f"{_VT_BASE}/files/{hash_value}", headers=headers, timeout=timeout
        ) as resp:
            if resp.status == 404:
                return None, 0.0
            if resp.status == 401:
                logger.warning("VirusTotal: invalid API key")
                return None, 0.0
            if resp.status == 429:
                wait = pacing.retry_after_seconds(resp.headers, _vt_delay())
                logger.warning(
                    "VirusTotal: rate limited — backing off %.1fs", wait
                )
                return None, wait
            if resp.status != 200:
                return None, 0.0
            return await resp.json(), 0.0
    except asyncio.TimeoutError:
        logger.warning("VirusTotal: timeout for hash %s", hash_value[:16])
        return None, 0.0
    except Exception as e:
        logger.warning("VirusTotal: error for hash %s: %s", hash_value[:16], e)
        return None, 0.0


async def enrich_virustotal(entities: list[dict]) -> list[dict]:
    """
    For each FILE_HASH_MD5 / FILE_HASH_SHA1 / FILE_HASH_SHA256 entity,
    query VirusTotal and return detection stats.
    """
    if not _is_enabled():
        logger.debug("VirusTotal skipped — no API key configured")
        return []

    hash_type_map = {
        "FILE_HASH_MD5": "md5",
        "FILE_HASH_SHA1": "sha1",
        "FILE_HASH_SHA256": "sha256",
    }

    hash_entities = [
        e for e in entities
        if (e.get("type") or e.get("entity_type", "")) in hash_type_map
        and (e.get("value") or e.get("entity_value", ""))
    ]

    hashes_to_query = [
        (e.get("value") or e.get("entity_value", ""), (e.get("type") or e.get("entity_type", "")))
        for e in hash_entities
    ][:_VT_HASH_LIMIT]

    results: list[dict] = []
    async with http_pool.clearnet_session() as session:
        for hash_val, hash_type in hashes_to_query:
            data, server_wait = await _fetch_hash(hash_val, session)
            if data is None:
                # server_wait already includes _vt_delay() as its floor.
                await asyncio.sleep(max(_vt_delay(), server_wait))
                continue

            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values())
            detection_ratio = mal / total if total > 0 else 0.0

            results.append({
                "source": "virustotal",
                "entity_type": hash_type_map.get(hash_type, "FILE_HASH"),
                "entity_value": hash_val,
                "malicious_count": mal,
                "total_engines": total,
                "detection_ratio": detection_ratio,
                "suggested_threat_label": attr.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "first_seen": attr.get("creation_date", ""),
                "last_seen": attr.get("last_analysis_date", ""),
                "confirmed_malicious": detection_ratio > 0.5,
            })

            await asyncio.sleep(_vt_delay())

    if results:
        logger.info("VirusTotal: %d results", len(results))
    return results
