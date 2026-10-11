"""
sources/hash_reputation.py — File hash behavioral enrichment.

Enriches FILE_HASH_MD5, FILE_HASH_SHA1, FILE_HASH_SHA256 entities with
malware profiles from four sources:
  - Hybrid Analysis: full behavioral sandbox (requires HYBRID_ANALYSIS_API_KEY)
  - MalwareBazaar (abuse.ch): family classification — free, no auth
  - ThreatFox (abuse.ch): IOC database and associated IOCs — free, no auth
  - VirusTotal: AV detection data and sandbox network IOCs (requires VT_API_KEY)

Hashes are never suppressed — even a clean hash is a useful data point.
Cache TTL: 48 h (hashes are immutable).
Limit: MAX_HASHES = 50 per investigation (SHA256 → SHA1 → MD5 priority).

Public interface
----------------
async query_hybrid_analysis(hash_value)                        → dict
async query_malwarebazaar(hash_value)                          → dict
async query_threatfox(hash_value)                              → dict
async query_virustotal_hash(hash_value)                        → dict
async check_hash_reputation(hash_value, hash_type, base_conf)  → dict
async enrich_hash_entities(extraction_results, investigation_id) → (results, stats)
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
from sources.enrichment_allowlist import (
    get_enrichment_allowlist,
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

MAX_HASHES = 50
MAX_IPS_PER_HASH = 10
MAX_DOMAINS_PER_HASH = 10

HASH_CACHE_TTL = 172800.0  # 48 hours

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
HA_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# In-memory per-hash cache: {hash_value: {"result": dict, "loaded_at": float}}
_hash_cache: dict[str, dict] = {}

# Module-level enrichment cache singleton (lazy-init on first lookup).
_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


# Processing priority: lower number = higher priority
HASH_TYPES = {
    "FILE_HASH_SHA256": 1,
    "FILE_HASH_SHA1": 2,
    "FILE_HASH_MD5": 3,
}

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_hash(value: str) -> bool:
    return bool(value and _HASH_RE.match(value.strip()))


def _normalize_family(name: str) -> str:
    """Return a lowercase slug for a malware family name."""
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")[:50]


# ---------------------------------------------------------------------------
# Source: Hybrid Analysis
# ---------------------------------------------------------------------------

async def query_hybrid_analysis(hash_value: str) -> dict[str, Any]:
    """
    POST /search/hash to Hybrid Analysis. Returns behavioral analysis or {"found": False}.

    Requires HYBRID_ANALYSIS_API_KEY. Free tier available at hybrid-analysis.com.
    """
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    if not api_key:
        logger.debug("hash_reputation: Hybrid Analysis skipped — no API key")
        return {"found": False, "source": "hybrid_analysis_skipped"}

    try:
        headers = {
            "api-key": api_key,
            "user-agent": "Falcon Sandbox",
        }
        timeout = aiohttp.ClientTimeout(total=20)
        async with http_pool.clearnet_session() as session:
            async with session.post(
                f"{HA_BASE_URL}/search/hash",
                data={"hash": hash_value},
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status == 401:
                    logger.warning("hash_reputation: Hybrid Analysis — invalid API key")
                    return {"found": False, "source": "hybrid_analysis_auth_error"}
                if resp.status == 429:
                    logger.warning("hash_reputation: Hybrid Analysis — rate limited")
                    return {"found": False, "source": "hybrid_analysis_rate_limited"}
                if resp.status != 200:
                    logger.debug(
                        "hash_reputation: Hybrid Analysis → HTTP %s for %s",
                        resp.status, hash_value[:16],
                    )
                    return {"found": False, "source": "hybrid_analysis_error"}
                data = await resp.json()
    except Exception as exc:
        logger.debug("hash_reputation: Hybrid Analysis failed for %s: %s", hash_value[:16], exc)
        return {"found": False, "source": "hybrid_analysis_error"}

    if not data or not isinstance(data, list):
        return {"found": False, "source": "hybrid_analysis_not_found"}

    report = data[0]

    network = report.get("network") or {}

    contacted_ips: list[str] = []
    for host in (network.get("hosts") or []):
        ip = host.get("ip") if isinstance(host, dict) else (host if isinstance(host, str) else "")
        if ip and _IP_RE.match(ip):
            contacted_ips.append(ip)

    contacted_domains: list[str] = []
    for d in (network.get("domains") or []):
        if isinstance(d, str) and d:
            contacted_domains.append(d)
    for http_entry in (network.get("http") or [])[:20]:
        if isinstance(http_entry, dict):
            host = http_entry.get("host") or ""
            if host and not _IP_RE.match(host) and host not in contacted_domains:
                contacted_domains.append(host)

    return {
        "found": True,
        "source": "hybrid_analysis",
        "verdict": (report.get("verdict") or "").lower(),
        "malware_family": report.get("vx_family") or "",
        "threat_score": report.get("threat_score"),
        "av_detections": report.get("total_av_detections"),
        "av_total": report.get("av_detect"),
        "file_type": report.get("type_short") or report.get("type") or "",
        "tags": list(report.get("tags") or []),
        "contacted_ips": contacted_ips[:MAX_IPS_PER_HASH],
        "contacted_domains": contacted_domains[:MAX_DOMAINS_PER_HASH],
    }


async def _cached_query_hybrid_analysis(hash_value: str) -> dict[str, Any]:
    """Cached wrapper around query_hybrid_analysis (7d TTL via DEFAULT_TTL).

    Sandbox reports are immutable — long TTL is safe. Auth errors, rate
    limits, and skipped (no-key) results are NOT cached so retries aren't
    blocked.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("FILE_HASH_SHA256", hash_value, "hybrid_analysis")
    if cached is not None:
        logger.debug("HybridAnalysis cache hit: %s", hash_value[:16])
        return cached
    result = await query_hybrid_analysis(hash_value)
    # Only cache results that look like real API responses — must have a
    # populated ``source`` field and NOT be a transient error / skip marker.
    source_key = result.get("source") or ""
    if source_key and source_key not in (
        "hybrid_analysis_auth_error",
        "hybrid_analysis_rate_limited",
        "hybrid_analysis_error",
        "hybrid_analysis_skipped",
    ):
        await cache.set(
            "FILE_HASH_SHA256", hash_value, "hybrid_analysis",
            result, DEFAULT_TTL["hybrid_analysis"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: MalwareBazaar
# ---------------------------------------------------------------------------

async def query_malwarebazaar(hash_value: str) -> dict[str, Any]:
    """
    POST get_info to MalwareBazaar for a file hash.

    Requires ABUSECH_API_KEY (abuse.ch made auth-key mandatory in 2024).
    Returns malware family, file type, first seen date.
    """
    api_key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    if not api_key:
        return {"found": False, "source": "malwarebazaar_no_key"}
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {
            "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
            "Auth-Key": api_key,
        }
        async with http_pool.clearnet_session() as session:
            async with session.post(
                MALWAREBAZAAR_URL,
                data={"query": "get_info", "hash": hash_value},
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    logger.debug(
                        "hash_reputation: MalwareBazaar → HTTP %s for %s",
                        resp.status, hash_value[:16],
                    )
                    return {"found": False, "source": "malwarebazaar_error"}
                data = await resp.json()
    except Exception as exc:
        logger.debug("hash_reputation: MalwareBazaar failed for %s: %s", hash_value[:16], exc)
        return {"found": False, "source": "malwarebazaar_error"}

    if data.get("query_status") != "ok":
        return {"found": False, "source": "malwarebazaar_not_found"}

    samples = data.get("data") or []
    if not samples:
        return {"found": False, "source": "malwarebazaar_not_found"}

    sample = samples[0]
    return {
        "found": True,
        "source": "malwarebazaar",
        "malware_family": sample.get("signature") or "",
        "file_type": sample.get("file_type") or "",
        "first_seen": sample.get("first_seen") or "",
        "tags": list(sample.get("tags") or []),
        "sha256": sample.get("sha256_hash") or "",
    }


async def _cached_query_malwarebazaar(hash_value: str) -> dict[str, Any]:
    """Cached wrapper around query_malwarebazaar (48h TTL via DEFAULT_TTL)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("FILE_HASH_SHA256", hash_value, "malwarebazaar")
    if cached is not None:
        logger.debug("MalwareBazaar cache hit: %s", hash_value[:16])
        return cached
    result = await query_malwarebazaar(hash_value)
    source_key = result.get("source") or ""
    # Cache any real API response (found / not_found / error) but skip the
    # no-key skip marker so re-checks happen once a key is configured.
    if source_key and source_key != "malwarebazaar_no_key":
        await cache.set(
            "FILE_HASH_SHA256", hash_value, "malwarebazaar",
            result, DEFAULT_TTL["malwarebazaar"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: ThreatFox
# ---------------------------------------------------------------------------

async def query_threatfox(hash_value: str) -> dict[str, Any]:
    """
    POST search_ioc to ThreatFox for a file hash.

    Requires ABUSECH_API_KEY (abuse.ch made auth-key mandatory in 2024).
    Returns malware family and associated IOCs.
    """
    api_key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    if not api_key:
        return {"found": False, "source": "threatfox_no_key"}
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {
            "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
            "Auth-Key": api_key,
        }
        async with http_pool.clearnet_session() as session:
            async with session.post(
                THREATFOX_URL,
                json={"query": "search_ioc", "search_term": hash_value},
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    logger.debug(
                        "hash_reputation: ThreatFox → HTTP %s for %s",
                        resp.status, hash_value[:16],
                    )
                    return {"found": False, "source": "threatfox_error"}
                data = await resp.json()
    except Exception as exc:
        logger.debug("hash_reputation: ThreatFox failed for %s: %s", hash_value[:16], exc)
        return {"found": False, "source": "threatfox_error"}

    if data.get("query_status") != "ok":
        return {"found": False, "source": "threatfox_not_found"}

    iocs = data.get("data") or []
    if not iocs:
        return {"found": False, "source": "threatfox_not_found"}

    primary = iocs[0]

    # Collect associated IOCs from the same submission (exclude the queried hash)
    associated_iocs: list[dict] = []
    for item in iocs[:20]:
        ioc_type = item.get("ioc_type") or ""
        ioc_value = item.get("ioc") or ""
        if ioc_type and ioc_value and ioc_value.lower() != hash_value.lower():
            associated_iocs.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "malware": item.get("malware_printable") or item.get("malware") or "",
            })

    return {
        "found": True,
        "source": "threatfox",
        "malware_family": primary.get("malware_printable") or primary.get("malware") or "",
        "confidence_level": primary.get("confidence_level"),
        "first_seen": primary.get("first_seen") or "",
        "tags": list(primary.get("tags") or []),
        "associated_iocs": associated_iocs,
    }


async def _cached_query_threatfox(hash_value: str) -> dict[str, Any]:
    """Cached wrapper around query_threatfox (24h TTL via DEFAULT_TTL)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("FILE_HASH_SHA256", hash_value, "threatfox")
    if cached is not None:
        logger.debug("ThreatFox cache hit: %s", hash_value[:16])
        return cached
    result = await query_threatfox(hash_value)
    source_key = result.get("source") or ""
    if source_key and source_key != "threatfox_no_key":
        await cache.set(
            "FILE_HASH_SHA256", hash_value, "threatfox",
            result, DEFAULT_TTL["threatfox"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: VirusTotal (extended)
# ---------------------------------------------------------------------------

async def query_virustotal_hash(hash_value: str) -> dict[str, Any]:
    """
    Extended VirusTotal lookup: detection stats + optional behaviour network IOCs.

    GET /files/{hash} for core data.
    GET /files/{hash}/behaviours for sandbox network contacts (premium feature;
    gracefully skipped if unavailable or on free tier).

    Requires VT_API_KEY.
    """
    vt_key = os.getenv("VT_API_KEY", "").strip()
    if not vt_key:
        logger.debug("hash_reputation: VirusTotal skipped — no API key")
        return {"found": False, "source": "virustotal_skipped"}

    headers = {"x-apikey": vt_key}
    timeout = aiohttp.ClientTimeout(total=20)

    try:
        async with http_pool.clearnet_session() as session:
            async with session.get(f"{VT_BASE_URL}/files/{hash_value}", headers=headers, timeout=timeout) as resp:
                if resp.status == 404:
                    return {"found": False, "source": "virustotal_not_found"}
                if resp.status in (401, 403):
                    logger.warning("hash_reputation: VirusTotal — auth error")
                    return {"found": False, "source": "virustotal_auth_error"}
                if resp.status == 429:
                    logger.warning("hash_reputation: VirusTotal — rate limited")
                    return {"found": False, "source": "virustotal_rate_limited"}
                if resp.status != 200:
                    logger.debug(
                        "hash_reputation: VirusTotal → HTTP %s for %s",
                        resp.status, hash_value[:16],
                    )
                    return {"found": False, "source": "virustotal_error"}
                file_data = await resp.json()

            attr = file_data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            # Extract malware family: prefer popular threat classification;
            # fall back to reliable AV vendor names (Kaspersky > Microsoft > Symantec)
            family = ""
            threat_cls = attr.get("popular_threat_classification") or {}
            family = threat_cls.get("suggested_threat_label") or ""
            if not family:
                reliable_vendors = [
                    "Kaspersky", "Microsoft", "Symantec", "Norton", "Bitdefender", "ESET-NOD32",
                ]
                engine_results = attr.get("last_analysis_results") or {}
                for vendor in reliable_vendors:
                    vr = engine_results.get(vendor) or {}
                    if vr.get("result"):
                        family = vr["result"]
                        break

            result: dict[str, Any] = {
                "found": True,
                "source": "virustotal",
                "malicious": malicious,
                "total": total,
                "malware_family": family,
                "file_type": attr.get("type_description") or attr.get("type_tag") or "",
                "first_seen": str(attr.get("first_submission_date") or ""),
                "last_seen": str(attr.get("last_analysis_date") or ""),
                "contacted_ips": [],
                "contacted_domains": [],
                "dropped_hashes": [],
            }

            # Try behaviour sandbox data (premium / enterprise; gracefully skip)
            try:
                async with session.get(
                    f"{VT_BASE_URL}/files/{hash_value}/behaviours"
                ) as behav_resp:
                    if behav_resp.status == 200:
                        behav_data = await behav_resp.json()
                        all_ips: set[str] = set()
                        all_domains: set[str] = set()
                        all_hashes: list[str] = []

                        for behav in (behav_data.get("data") or [])[:3]:
                            ba = behav.get("attributes") or {}

                            for entry in (ba.get("ip_traffic") or [])[:30]:
                                ip = (
                                    entry.get("destination_ip")
                                    if isinstance(entry, dict) else str(entry)
                                )
                                if ip and _IP_RE.match(ip):
                                    all_ips.add(ip)

                            for entry in (ba.get("dns_lookups") or [])[:30]:
                                d = (
                                    entry.get("hostname")
                                    if isinstance(entry, dict) else str(entry)
                                )
                                if d and not d.endswith(".onion"):
                                    all_domains.add(d)

                            for dropped in (ba.get("files_dropped") or [])[:10]:
                                if isinstance(dropped, dict):
                                    sha = dropped.get("sha256") or ""
                                    if sha and sha.lower() != hash_value.lower():
                                        all_hashes.append(sha)

                        result["contacted_ips"] = list(all_ips)[:MAX_IPS_PER_HASH]
                        result["contacted_domains"] = list(all_domains)[:MAX_DOMAINS_PER_HASH]
                        result["dropped_hashes"] = list(dict.fromkeys(all_hashes))[:5]
            except Exception as behav_exc:
                logger.debug(
                    "hash_reputation: VT behaviours unavailable for %s: %s",
                    hash_value[:16], behav_exc,
                )

            return result

    except asyncio.TimeoutError:
        logger.warning("hash_reputation: VirusTotal timeout for %s", hash_value[:16])
        return {"found": False, "source": "virustotal_timeout"}
    except Exception as exc:
        logger.debug("hash_reputation: VirusTotal failed for %s: %s", hash_value[:16], exc)
        return {"found": False, "source": "virustotal_error"}


async def _cached_query_virustotal(hash_value: str) -> dict[str, Any]:
    """Cached wrapper around query_virustotal_hash (24h TTL via DEFAULT_TTL).

    Auth / rate-limit / error responses are NOT cached so the next investigation
    can retry once keys or quotas recover.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("FILE_HASH_SHA256", hash_value, "virustotal")
    if cached is not None:
        logger.debug("VirusTotal cache hit: %s", hash_value[:16])
        return cached
    result = await query_virustotal_hash(hash_value)
    source_key = result.get("source") or ""
    if source_key and source_key not in (
        "virustotal_auth_error",
        "virustotal_rate_limited",
        "virustotal_error",
        "virustotal_timeout",
        "virustotal_skipped",
    ):
        await cache.set(
            "FILE_HASH_SHA256", hash_value, "virustotal",
            result, DEFAULT_TTL["virustotal"],
        )
    return result


# ---------------------------------------------------------------------------
# Core reputation check
# ---------------------------------------------------------------------------

async def check_hash_reputation(
    hash_value: str,
    hash_type: str = "FILE_HASH_SHA256",
    base_confidence: float = 1.0,
) -> dict[str, Any]:
    """
    Run all four reputation checks for a single file hash concurrently.

    Returns a dict with keys:
        hash, hash_type, verdict, malware_families, threat_score,
        av_detections, av_total, file_type, first_seen, new_entities,
        tags, confidence_delta, suppress (always False for hashes)
    """
    # The in-process result cache is bypassed (read and write) while a
    # VOIDACCESS_ENRICHMENT_SOURCES allowlist is active, so a restricted
    # result never leaks into an unrestricted run and vice versa.
    _use_cache = get_enrichment_allowlist() is None

    # Serve from cache when fresh
    cached = _hash_cache.get(hash_value) if _use_cache else None
    if cached and (time.time() - cached["loaded_at"]) < HASH_CACHE_TTL:
        return cached["result"]

    result: dict[str, Any] = {
        "hash": hash_value,
        "hash_type": hash_type,
        "verdict": None,
        "malware_families": [],
        "threat_score": None,
        "av_detections": None,
        "av_total": None,
        "file_type": None,
        "first_seen": None,
        "new_entities": [],
        "tags": [],
        "confidence_delta": 0.0,
        "suppress": False,
    }

    if not _is_valid_hash(hash_value):
        return result

    # Disabled sources are never called and report "not found".
    async def _disabled() -> dict[str, Any]:
        return {"found": False}

    ha_result, mb_result, tf_result, vt_result = await asyncio.gather(
        _cached_query_hybrid_analysis(hash_value)
        if is_enrichment_source_enabled("hybrid_analysis") else _disabled(),
        _cached_query_malwarebazaar(hash_value)
        if is_enrichment_source_enabled("malwarebazaar") else _disabled(),
        _cached_query_threatfox(hash_value)
        if is_enrichment_source_enabled("threatfox") else _disabled(),
        _cached_query_virustotal(hash_value)
        if is_enrichment_source_enabled("virustotal") else _disabled(),
        return_exceptions=True,
    )

    if isinstance(ha_result, Exception):
        logger.debug("hash_reputation: HA exception for %s: %s", hash_value[:16], ha_result)
        ha_result = {"found": False}
    if isinstance(mb_result, Exception):
        logger.debug("hash_reputation: MB exception for %s: %s", hash_value[:16], mb_result)
        mb_result = {"found": False}
    if isinstance(tf_result, Exception):
        logger.debug("hash_reputation: TF exception for %s: %s", hash_value[:16], tf_result)
        tf_result = {"found": False}
    if isinstance(vt_result, Exception):
        logger.debug("hash_reputation: VT exception for %s: %s", hash_value[:16], vt_result)
        vt_result = {"found": False}

    # Track malware family agreement across sources {slug: count}
    family_count: dict[str, int] = {}
    family_names: dict[str, str] = {}

    def _add_family(name: str) -> None:
        if not name:
            return
        slug = _normalize_family(name)
        if not slug:
            return
        family_count[slug] = family_count.get(slug, 0) + 1
        if slug not in family_names:
            family_names[slug] = name

    # ── Hybrid Analysis ───────────────────────────────────────────────────────
    if ha_result.get("found"):
        verdict = ha_result.get("verdict") or ""
        if "malicious" in verdict:
            result["verdict"] = "malicious"
            result["tags"].append("hybrid_analysis_malicious")
            result["confidence_delta"] += 0.15
        elif "suspicious" in verdict:
            result["verdict"] = result["verdict"] or "suspicious"
            result["tags"].append("hybrid_analysis_suspicious")
        elif "no" in verdict and "threat" in verdict:
            result["verdict"] = result["verdict"] or "no_specific_threat"
            result["tags"].append("hybrid_analysis_clean")

        if ha_result.get("malware_family"):
            slug = _normalize_family(ha_result["malware_family"])
            _add_family(ha_result["malware_family"])
            if slug:
                result["tags"].append(f"malware_family_{slug}")

        if ha_result.get("threat_score") is not None:
            result["threat_score"] = ha_result["threat_score"]
            result["tags"].append(f"threat_score_{ha_result['threat_score']}")

        if ha_result.get("av_detections") is not None:
            result["av_detections"] = ha_result["av_detections"]
        if ha_result.get("av_total") is not None:
            result["av_total"] = ha_result["av_total"]

        if ha_result.get("file_type"):
            result["file_type"] = ha_result["file_type"]

        short_hash = hash_value[:16]
        for ip in (ha_result.get("contacted_ips") or [])[:MAX_IPS_PER_HASH]:
            result["new_entities"].append({
                "entity_type": "IP_ADDRESS",
                "value": ip,
                "canonical_value": ip,
                "confidence": 0.82,
                "source": "hybrid_analysis",
                "extraction_method": "enrich",
                "context_snippet": f"Contacted by {short_hash}... (Hybrid Analysis sandbox)",
            })

        for domain in (ha_result.get("contacted_domains") or [])[:MAX_DOMAINS_PER_HASH]:
            result["new_entities"].append({
                "entity_type": "DOMAIN",
                "value": domain,
                "canonical_value": domain,
                "confidence": 0.80,
                "source": "hybrid_analysis",
                "extraction_method": "enrich",
                "context_snippet": f"Contacted by {short_hash}... (Hybrid Analysis sandbox)",
            })

    # ── MalwareBazaar ─────────────────────────────────────────────────────────
    if mb_result.get("found"):
        result["confidence_delta"] += 0.10
        result["tags"].append("malwarebazaar_confirmed")

        if mb_result.get("malware_family"):
            _add_family(mb_result["malware_family"])

        if mb_result.get("file_type") and not result["file_type"]:
            result["file_type"] = mb_result["file_type"]
        if mb_result.get("first_seen") and not result["first_seen"]:
            result["first_seen"] = mb_result["first_seen"]

    # ── ThreatFox ─────────────────────────────────────────────────────────────
    if tf_result.get("found"):
        result["confidence_delta"] += 0.10
        result["tags"].append("threatfox_confirmed")

        if tf_result.get("malware_family"):
            _add_family(tf_result["malware_family"])
        if tf_result.get("first_seen") and not result["first_seen"]:
            result["first_seen"] = tf_result["first_seen"]

        # Associated IOCs as new entities
        short_hash = hash_value[:16]
        for ioc in (tf_result.get("associated_iocs") or [])[:5]:
            ioc_type = ioc.get("ioc_type") or ""
            ioc_value = ioc.get("ioc_value") or ""
            if not ioc_type or not ioc_value:
                continue
            entity_type = None
            if "ip" in ioc_type:
                entity_type = "IP_ADDRESS"
            elif "domain" in ioc_type:
                entity_type = "DOMAIN"
            elif "sha256" in ioc_type:
                entity_type = "FILE_HASH_SHA256"
            elif "sha1" in ioc_type:
                entity_type = "FILE_HASH_SHA1"
            elif "md5" in ioc_type:
                entity_type = "FILE_HASH_MD5"
            if entity_type:
                result["new_entities"].append({
                    "entity_type": entity_type,
                    "value": ioc_value,
                    "canonical_value": ioc_value,
                    "confidence": 0.78,
                    "source": "threatfox",
                    "extraction_method": "enrich",
                    "context_snippet": (
                        f"Associated IOC from ThreatFox with {short_hash}..."
                    ),
                })

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if vt_result.get("found"):
        if vt_result.get("malware_family"):
            _add_family(vt_result["malware_family"])

        if result["av_detections"] is None and vt_result.get("malicious") is not None:
            result["av_detections"] = vt_result["malicious"]
        if result["av_total"] is None and vt_result.get("total"):
            result["av_total"] = vt_result["total"]
        if vt_result.get("file_type") and not result["file_type"]:
            result["file_type"] = vt_result["file_type"]
        if vt_result.get("first_seen") and not result["first_seen"]:
            result["first_seen"] = vt_result["first_seen"]

        # Fallback verdict from VT when HA is unavailable
        if result["verdict"] is None:
            mal = vt_result.get("malicious", 0) or 0
            tot = vt_result.get("total", 0) or 0
            if tot > 0:
                ratio = mal / tot
                if ratio > 0.5:
                    result["verdict"] = "malicious"
                    result["tags"].append("hybrid_analysis_malicious")
                elif ratio > 0.1:
                    result["verdict"] = "suspicious"
                    result["tags"].append("hybrid_analysis_suspicious")
                else:
                    result["verdict"] = "no_specific_threat"
                    result["tags"].append("hybrid_analysis_clean")

        # Network IOCs from sandbox behaviours (premium tier)
        short_hash = hash_value[:16]
        existing_ips = {e["value"] for e in result["new_entities"] if e["entity_type"] == "IP_ADDRESS"}
        for ip in (vt_result.get("contacted_ips") or [])[:MAX_IPS_PER_HASH]:
            if ip not in existing_ips:
                result["new_entities"].append({
                    "entity_type": "IP_ADDRESS",
                    "value": ip,
                    "canonical_value": ip,
                    "confidence": 0.82,
                    "source": "virustotal",
                    "extraction_method": "enrich",
                    "context_snippet": f"Contacted by {short_hash}... (VirusTotal sandbox)",
                })

        existing_domains = {e["value"] for e in result["new_entities"] if e["entity_type"] == "DOMAIN"}
        for domain in (vt_result.get("contacted_domains") or [])[:MAX_DOMAINS_PER_HASH]:
            if domain not in existing_domains:
                result["new_entities"].append({
                    "entity_type": "DOMAIN",
                    "value": domain,
                    "canonical_value": domain,
                    "confidence": 0.80,
                    "source": "virustotal",
                    "extraction_method": "enrich",
                    "context_snippet": f"Contacted by {short_hash}... (VirusTotal sandbox)",
                })

        for sha256 in (vt_result.get("dropped_hashes") or []):
            result["new_entities"].append({
                "entity_type": "FILE_HASH_SHA256",
                "value": sha256,
                "canonical_value": sha256,
                "confidence": 0.75,
                "source": "virustotal",
                "extraction_method": "enrich",
                "context_snippet": f"File dropped by {short_hash}... (VirusTotal sandbox)",
            })

    # ── AV detection tag ──────────────────────────────────────────────────────
    if result["av_detections"] is not None and result["av_total"]:
        n = result["av_detections"]
        t = result["av_total"]
        result["tags"].append(f"av_detections_{n}_of_{t}")

    # ── Aggregate confirmed malware families ───────────────────────────────────
    result["malware_families"] = [
        family_names[slug]
        for slug, _ in sorted(family_count.items(), key=lambda x: -x[1])
    ]

    # ── MALWARE_FAMILY entity when confirmed by 2+ sources ────────────────────
    for slug, count in family_count.items():
        if count >= 2:
            display_name = family_names[slug]
            result["new_entities"].append({
                "entity_type": "MALWARE_FAMILY",
                "value": display_name,
                "canonical_value": display_name,
                "confidence": 0.90,
                "source": "hash_enrichment",
                "extraction_method": "enrich",
                "context_snippet": (
                    f"Identified as {display_name} by {count} source(s) "
                    f"for hash {hash_value[:20]}"
                ),
            })
            break  # one MALWARE_FAMILY entity per hash is enough

    result["confidence_delta"] = min(result["confidence_delta"], 0.35)

    if _use_cache:
        _hash_cache[hash_value] = {"result": result, "loaded_at": time.time()}
    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_hash_entities_in_db(
    updates: list[tuple[str, str, float, list[str]]],
) -> None:
    """
    Update confidence and corroborating_sources for enriched hash entities.

    *updates* is a list of (entity_type, hash_value, new_confidence, tags).
    """
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for entity_type, hash_val, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == entity_type,
                    Entity.value == hash_val,
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
        logger.warning("hash_reputation: DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

async def enrich_hash_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction hash reputation enrichment step.

    Collects FILE_HASH_SHA256 / SHA1 / MD5 entities from *extraction_results*.
    Processes SHA256 first, then SHA1, then MD5 (HASH_TYPES priority).
    Caps at MAX_HASHES = 50 per investigation.

    Updates confidence and corroborating_sources for existing hash entities in DB.
    New entities discovered (IPs, domains, malware families) are returned in
    stats for logging — same pattern as domain_reputation.

    Returns (extraction_results, stats_dict).
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    seen: dict[str, tuple[str, float]] = {}  # hash_value → (entity_type, confidence)

    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            et = getattr(entity, "entity_type", "")
            if et not in HASH_TYPES:
                continue
            hv = getattr(entity, "value", "").strip()
            if not hv or not _is_valid_hash(hv):
                continue
            if hv not in seen:
                seen[hv] = (et, getattr(entity, "confidence", 1.0))
            else:
                existing_type, existing_conf = seen[hv]
                if HASH_TYPES.get(et, 99) < HASH_TYPES.get(existing_type, 99):
                    seen[hv] = (et, getattr(entity, "confidence", 1.0))

    if not seen:
        return extraction_results, {"hash_reputation": "ok_0_hashes"}

    # Sort SHA256 first, SHA1 second, MD5 last
    sorted_hashes = sorted(
        seen.items(),
        key=lambda x: HASH_TYPES.get(x[1][0], 99),
    )

    if len(sorted_hashes) > MAX_HASHES:
        logger.info(
            "hash_reputation: capping to %d of %d unique hashes",
            MAX_HASHES, len(sorted_hashes),
        )
        sorted_hashes = sorted_hashes[:MAX_HASHES]

    logger.info("hash_reputation: checking %d unique hash(es)", len(sorted_hashes))

    rep_list = await asyncio.gather(
        *[
            check_hash_reputation(hv, ht, base_confidence=conf)
            for hv, (ht, conf) in sorted_hashes
        ],
        return_exceptions=True,
    )

    db_updates: list[tuple[str, str, float, list[str]]] = []
    all_new_entities: list[dict] = []
    stats = {
        "hashes_checked": len(sorted_hashes),
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "malware_families_found": 0,
        "new_entities_discovered": 0,
    }

    for (hv, (ht, base_conf)), rep in zip(sorted_hashes, rep_list):
        if isinstance(rep, Exception):
            logger.debug("hash_reputation: check raised for %s: %s", hv[:16], rep)
            continue

        verdict = rep.get("verdict")
        if verdict == "malicious":
            stats["malicious"] += 1
        elif verdict == "suspicious":
            stats["suspicious"] += 1
        elif verdict == "no_specific_threat":
            stats["clean"] += 1

        if rep.get("malware_families"):
            stats["malware_families_found"] += 1

        tags = rep.get("tags", [])
        new_conf = min(base_conf + rep.get("confidence_delta", 0.0), 1.0)

        new_entities = rep.get("new_entities", [])
        all_new_entities.extend(new_entities)
        stats["new_entities_discovered"] += len(new_entities)

        if tags or rep.get("confidence_delta", 0) > 0:
            db_updates.append((ht, hv, new_conf, tags))

    if db_updates:
        await asyncio.to_thread(_update_hash_entities_in_db, db_updates)

    if all_new_entities:
        logger.info(
            "hash_reputation: %d new entities discovered (IPs, domains, families)",
            len(all_new_entities),
        )

    checked = stats["hashes_checked"]
    status = (
        f"ok_{checked}_hashes"
        f"_{stats['malicious']}_malicious"
        f"_{stats['suspicious']}_suspicious"
    )

    logger.info(
        "hash_reputation: done — %d checked, %d malicious, %d suspicious, "
        "%d clean, %d families, %d new entities",
        checked,
        stats["malicious"],
        stats["suspicious"],
        stats["clean"],
        stats["malware_families_found"],
        stats["new_entities_discovered"],
    )

    return extraction_results, {"hash_reputation": status, **stats}
