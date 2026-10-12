"""
sources/ip_reputation.py — IP reputation enrichment.

Checks extracted IP addresses against four sources:
  - Feodo Tracker (abuse.ch): confirmed C2 IPs for banking trojans/ransomware loaders
  - C2IntelFeeds (montysecurity/C2-Tracker): framework-specific C2 IPs
  - AbuseIPDB: community abuse reports (requires ABUSEIPDB_API_KEY)
  - GreyNoise: scanner classification (requires GREYNOISE_API_KEY)

GreyNoise "benign" IPs (known legitimate scanners) are SUPPRESSED from results.
All other sources run without API keys — Feodo and C2IntelFeeds are fully public.

Public interface
----------------
async load_feodo_feed()                    → dict[ip, malware_family]
async load_c2_feeds()                      → dict[framework, set[ip]]
async check_ip_reputation(ip, base_conf)   → dict with suppress/tags/threat_confidence
async enrich_ip_entities(extraction_results, investigation_id) → (results, stats)
"""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
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

MAX_IPS = 50

# GreyNoise free tier: 50 lookups per WEEK (10/day unauthenticated), shared with
# the GreyNoise Visualizer.  MAX_IPS is 50, so without this cap one real
# investigation can burn a whole week's access.  Set well below 50 so several
# investigations can share a week without tracking actual weekly usage — that
# would need cross-process persistence, deliberately deferred.  See
# GreyNoiseBudget.
MAX_GREYNOISE_LOOKUPS = 12

FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

C2_FEED_URLS: dict[str, str] = {
    "cobalt_strike": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike%20C2%20IPs.txt",
    "sliver":        "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver%20C2%20IPs.txt",
    "metasploit":    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit%20Framework%20C2%20IPs.txt",
    "brute_ratel":   "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4%20IPs.txt",
    "posh_c2":       "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Posh%20C2%20IPs.txt",
    "havoc":         "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc%20C2%20IPs.txt",
}

# In-memory feed caches (module-level singletons, refreshed on TTL expiry)
_feed_cache: dict[str, dict] = {
    "feodo":   {"ips": {}, "loaded_at": 0.0},
    "c2feeds": {"ips": {}, "loaded_at": 0.0},
}

# Module-level enrichment cache singleton (lazy-init on first lookup).
# Feodo and C2IntelFeeds use the in-memory feed cache above — skip those.
_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    """Lazy-init accessor for the cross-investigation enrichment cache."""
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _feed_ttl_seconds() -> float:
    try:
        hours = float(os.getenv("C2_FEED_CACHE_TTL", "24"))
    except ValueError:
        hours = 24.0
    return hours * 3600.0


def is_private_ip(ip: str) -> bool:
    """Return True if *ip* is private, loopback, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def _parse_feodo_csv(csv_text: str) -> dict[str, str]:
    """Parse Feodo Tracker ipblocklist.csv → {ip: malware_family}."""
    result: dict[str, str] = {}
    # Strip comment lines; the first non-comment line is the CSV header
    lines = [
        line for line in csv_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        return result
    try:
        reader = csv.DictReader(lines)
        for row in reader:
            ip = (row.get("dst_ip") or row.get("ip_address") or "").strip()
            malware = (row.get("malware") or row.get("malware_family") or "").strip()
            if ip:
                result[ip] = malware or "unknown"
    except Exception as exc:
        logger.warning("ip_reputation: Feodo CSV parse error: %s", exc)
    return result


def _parse_c2_txt(text: str) -> set[str]:
    """Parse a plain-text C2 IP list (one entry per line, optional comments)."""
    ips: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip port suffix (1.2.3.4:8080 → 1.2.3.4) and CIDR (/32)
        ip = line.split(":")[0].split("/")[0].strip()
        if ip:
            ips.add(ip)
    return ips


# ---------------------------------------------------------------------------
# Feed loaders (cached, refreshed on TTL expiry)
# ---------------------------------------------------------------------------

async def load_feodo_feed() -> dict[str, str]:
    """Fetch and cache Feodo Tracker blocklist. Returns {ip: malware_family}."""
    cache = _feed_cache["feodo"]
    if time.time() - cache["loaded_at"] < _feed_ttl_seconds() and cache["ips"]:
        return cache["ips"]  # type: ignore[return-value]

    logger.info("ip_reputation: Refreshing Feodo Tracker feed")
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with http_pool.clearnet_session() as session:
            async with session.get(FEODO_CSV_URL, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("ip_reputation: Feodo returned HTTP %s", resp.status)
                    return dict(cache["ips"])
                text = await resp.text()

        parsed = _parse_feodo_csv(text)
        cache["ips"] = parsed
        cache["loaded_at"] = time.time()
        logger.info("ip_reputation: Feodo Tracker: %d C2 IPs loaded", len(parsed))
        return parsed
    except Exception as exc:
        logger.warning("ip_reputation: Feodo fetch failed: %s", exc)
        return dict(cache["ips"])


async def load_c2_feeds() -> dict[str, set[str]]:
    """Fetch and cache all C2IntelFeeds. Returns {framework: set_of_ips}."""
    cache = _feed_cache["c2feeds"]
    if time.time() - cache["loaded_at"] < _feed_ttl_seconds() and cache["ips"]:
        return cache["ips"]  # type: ignore[return-value]

    logger.info("ip_reputation: Refreshing C2IntelFeeds")

    async def _fetch_one(framework: str, url: str) -> tuple[str, set[str]]:
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with http_pool.clearnet_session() as session:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status != 200:
                        logger.debug("ip_reputation: C2Feed %s → HTTP %s", framework, resp.status)
                        return framework, set()
                    text = await resp.text()
            return framework, _parse_c2_txt(text)
        except Exception as exc:
            logger.debug("ip_reputation: C2Feed %s fetch failed: %s", framework, exc)
            return framework, set()

    fetched = await asyncio.gather(*[_fetch_one(fw, url) for fw, url in C2_FEED_URLS.items()])

    results: dict[str, set[str]] = {}
    for framework, ips in fetched:
        results[framework] = ips
        logger.info("ip_reputation: C2Feed %-14s %d IPs", framework, len(ips))

    cache["ips"] = results
    cache["loaded_at"] = time.time()
    return results


# ---------------------------------------------------------------------------
# External API checks
# ---------------------------------------------------------------------------

async def _check_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB v2 /check. Returns parsed response or {}."""
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    logger.debug("ip_reputation: AbuseIPDB → HTTP %s for %s", resp.status, ip)
                    return {}
                return await resp.json()
    except Exception as exc:
        logger.debug("ip_reputation: AbuseIPDB check failed for %s: %s", ip, exc)
        return {}


async def _cached_check_abuseipdb(ip: str, api_key: str) -> dict:
    """Cached wrapper around _check_abuseipdb (24h TTL).

    Wraps the live AbuseIPDB call in the cross-investigation enrichment cache.
    Successful responses (containing a ``data`` key) are stored; transient
    errors (empty ``{}``) fall through uncached so retries aren't blocked.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("IP_ADDRESS", ip, "abuseipdb")
    if cached is not None:
        logger.debug("AbuseIPDB cache hit: %s", ip)
        return cached
    result = await _check_abuseipdb(ip, api_key)
    if result and isinstance(result, dict) and result.get("data"):
        await cache.set(
            "IP_ADDRESS", ip, "abuseipdb", result, DEFAULT_TTL["abuseipdb"]
        )
    return result


class GreyNoiseBudget:
    """
    Per-investigation safety cap on GreyNoise lookups.

    GreyNoise's free tier allows **50 lookups per week** (10/day
    unauthenticated), and that allowance is shared with the GreyNoise Visualizer.
    MAX_IPS is 50, so a single investigation could consume an entire week's
    access in one run.

    This is deliberately a *safety cap*, not a budget tracker: it bounds one
    investigation and keeps no state between runs. Tracking real weekly usage
    needs cross-process persistence, which is a separate deferred design
    question (pattern 1 in docs/BACKLOG.md). The cap is set well below 50 so
    several investigations can share a week without any tracking at all.

    ``try_consume`` has no await, so the check-then-increment is atomic with
    respect to the concurrent ``asyncio.gather`` fan-out in
    ``enrich_ip_entities``.
    """

    __slots__ = ("limit", "used", "capped")

    def __init__(self, limit: int = 0) -> None:
        self.limit = MAX_GREYNOISE_LOOKUPS if limit <= 0 else int(limit)
        self.used = 0
        self.capped = False

    def try_consume(self) -> bool:
        """Claim one lookup. False once the cap is reached."""
        if self.used >= self.limit:
            self.capped = True
            return False
        self.used += 1
        return True


async def _check_greynoise(ip: str, api_key: str) -> dict:
    """Query GreyNoise community API. Returns parsed response or {}."""
    try:
        headers = {"key": api_key}
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            async with session.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status == 404:
                    return {"classification": "unknown"}
                if resp.status == 429:
                    # GreyNoise 429s mean the weekly allowance is gone; it tells
                    # us when it resets, but that is days away, so honour the
                    # header only up to the cap and let the run continue without
                    # GreyNoise rather than blocking on it.
                    wait = pacing.retry_after_seconds(resp.headers, 0.0)
                    logger.warning(
                        "ip_reputation: GreyNoise quota exhausted for %s "
                        "(server suggests %.0fs)", ip, wait,
                    )
                    return {}
                if resp.status != 200:
                    logger.debug("ip_reputation: GreyNoise → HTTP %s for %s", resp.status, ip)
                    return {}
                return await resp.json()
    except Exception as exc:
        logger.debug("ip_reputation: GreyNoise check failed for %s: %s", ip, exc)
        return {}


async def _cached_check_greynoise(
    ip: str,
    api_key: str,
    budget: Optional[GreyNoiseBudget] = None,
) -> dict:
    """Cached wrapper around _check_greynoise (6h TTL).

    Caches both real responses and 404 ``{"classification": "unknown"}`` results
    so we don't hammer GreyNoise repeatedly for known-unknown IPs. Empty error
    responses (``{}``) are NOT cached.

    *budget* is consumed only on a cache MISS — a cache hit issues no request,
    so charging it against the weekly allowance would under-use a quota this
    tight for no reason.
    """
    cache = await _get_enrichment_cache()
    cached = await cache.get("IP_ADDRESS", ip, "greynoise")
    if cached is not None:
        logger.debug("GreyNoise cache hit: %s", ip)
        return cached

    if budget is not None and not budget.try_consume():
        logger.info(
            "ip_reputation: GreyNoise skipped for %s — per-investigation cap "
            "of %d reached (free tier is 50/week)", ip, budget.limit,
        )
        return {}

    result = await _check_greynoise(ip, api_key)
    if result:
        await cache.set(
            "IP_ADDRESS", ip, "greynoise", result, DEFAULT_TTL["greynoise"]
        )
    return result


# ---------------------------------------------------------------------------
# Core reputation check
# ---------------------------------------------------------------------------

async def check_ip_reputation(
    ip: str,
    base_confidence: float = 1.0,
    greynoise_budget: Optional[GreyNoiseBudget] = None,
) -> dict[str, Any]:
    """
    Run all four reputation checks for a single IP address.

    Returns a dict with keys:
        ip, feodo_hit, feodo_malware, c2feed_hit, c2feed_framework,
        abuseipdb_score, abuseipdb_categories, greynoise_classification,
        suppress, tags, threat_confidence
    """
    result: dict[str, Any] = {
        "ip": ip,
        "feodo_hit": False,
        "feodo_malware": None,
        "c2feed_hit": False,
        "c2feed_framework": None,
        "abuseipdb_score": None,
        "abuseipdb_categories": [],
        "greynoise_classification": None,
        "suppress": False,
        "tags": [],
        "threat_confidence": base_confidence,
    }

    if is_private_ip(ip):
        return result

    abuseipdb_key = (os.getenv("ABUSEIPDB_API_KEY") or "").strip()
    greynoise_key = (os.getenv("GREYNOISE_API_KEY") or "").strip()

    # VOIDACCESS_ENRICHMENT_SOURCES gate: a disabled source makes no call and
    # behaves exactly like a missing key / empty feed.
    if not is_enrichment_source_enabled("abuseipdb"):
        abuseipdb_key = ""
    if not is_enrichment_source_enabled("greynoise"):
        greynoise_key = ""

    # Load local feeds (both are cached — near-instant after first load)
    async def _no_feed() -> dict:
        return {}

    feodo_data, c2feeds_data = await asyncio.gather(
        load_feodo_feed() if is_enrichment_source_enabled("feodo_tracker") else _no_feed(),
        load_c2_feeds() if is_enrichment_source_enabled("c2_tracker") else _no_feed(),
    )

    # --- Feodo Tracker check ---
    if ip in feodo_data:
        malware = feodo_data[ip]
        result["feodo_hit"] = True
        result["feodo_malware"] = malware
        result["tags"].append("confirmed_c2")
        if malware and malware.lower() != "unknown":
            slug = malware.lower().replace(" ", "_").replace("-", "_")
            result["tags"].append(f"confirmed_c2_{slug}")

    # --- C2IntelFeeds check ---
    for framework, ips in c2feeds_data.items():
        if ip in ips:
            result["c2feed_hit"] = True
            result["c2feed_framework"] = framework
            if "confirmed_c2" not in result["tags"]:
                result["tags"].append("confirmed_c2")
            result["tags"].append(f"confirmed_c2_{framework}")
            break

    # --- AbuseIPDB check ---
    if abuseipdb_key:
        abuse_resp = await _cached_check_abuseipdb(ip, abuseipdb_key)
        if abuse_resp:
            data = abuse_resp.get("data", {})
            score = data.get("abuseConfidenceScore")
            result["abuseipdb_score"] = score
            # usageType is a string; categories come from individual reports
            usage = data.get("usageType")
            result["abuseipdb_categories"] = [usage] if usage else []
            if score is not None and score > 50:
                result["tags"].append("abuse_confirmed")
    else:
        logger.debug("ip_reputation: AbuseIPDB skipped — no API key")

    # --- GreyNoise check ---
    if greynoise_key:
        gn_resp = await _cached_check_greynoise(ip, greynoise_key, greynoise_budget)
        if gn_resp:
            classification = gn_resp.get("classification", "unknown")
            result["greynoise_classification"] = classification

            if classification == "benign":
                result["suppress"] = True
                logger.info("IP %s suppressed — GreyNoise benign scanner", ip)
                return result

            if classification == "malicious":
                result["tags"].append("greynoise_malicious")
                for gn_tag in gn_resp.get("tags") or []:
                    slug = str(gn_tag).lower().replace(" ", "_")
                    result["tags"].append(f"greynoise_{slug}")
    else:
        logger.debug("ip_reputation: GreyNoise skipped — no API key")

    # --- Threat confidence calculation ---
    conf = base_confidence
    if result["feodo_hit"]:
        conf += 0.15
    if result["c2feed_hit"]:
        conf += 0.15
    score = result["abuseipdb_score"]
    if score is not None:
        if score > 80:
            conf += 0.10
        elif score >= 50:
            conf += 0.05
    if "greynoise_malicious" in result["tags"]:
        conf += 0.10
    result["threat_confidence"] = min(conf, 1.0)

    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread or direct from sync context)
# ---------------------------------------------------------------------------

def _suppress_entities_in_db(suppressed_ips: set[str], investigation_id: Any) -> None:
    """Remove suppressed IPs from an investigation's entity pool in the DB."""
    if not os.getenv("DATABASE_URL") or not suppressed_ips:
        return
    try:
        from db.session import get_session
        from db.models import Entity, InvestigationEntityLink

        with get_session() as session:
            entity_ids = [
                row[0]
                for row in session.query(Entity.id).filter(
                    Entity.entity_type == "IP_ADDRESS",
                    Entity.value.in_(suppressed_ips),
                ).all()
            ]
            if not entity_ids:
                return

            session.query(InvestigationEntityLink).filter(
                InvestigationEntityLink.investigation_id == investigation_id,
                InvestigationEntityLink.entity_id.in_(entity_ids),
            ).delete(synchronize_session=False)

            session.query(Entity).filter(
                Entity.investigation_id == investigation_id,
                Entity.id.in_(entity_ids),
            ).update({"investigation_id": None}, synchronize_session=False)

            session.commit()
            logger.info(
                "ip_reputation: Suppressed %d IP(s) from investigation %s",
                len(entity_ids),
                investigation_id,
            )
    except Exception as exc:
        logger.warning("ip_reputation: DB suppression failed: %s", exc)


def _update_entity_reputations(
    updates: list[tuple[str, float, list[str]]],
) -> None:
    """
    Update confidence and corroborating_sources for non-suppressed IP entities.

    *updates* is a list of (ip_value, new_confidence, tags).
    """
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for ip_val, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == "IP_ADDRESS",
                    Entity.value == ip_val,
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
        logger.warning("ip_reputation: DB reputation update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

async def enrich_ip_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction IP reputation enrichment step.

    - Collects IP_ADDRESS entities from *extraction_results*
    - Limits to MAX_IPS unique IPs per investigation
    - Runs all four checks concurrently
    - Suppresses benign scanner IPs (GreyNoise benign): removes from results + DB
    - Updates confidence and corroborating_sources for remaining IPs

    Returns (filtered_extraction_results, stats_dict).
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    # Collect unique IPs → (first_entity, confidence)
    seen: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            if getattr(entity, "entity_type", "") == "IP_ADDRESS":
                ip = entity.value
                if ip not in seen:
                    seen[ip] = getattr(entity, "confidence", 1.0)

    unique_ips = list(seen.keys())
    if not unique_ips:
        return extraction_results, {"ip_reputation": "ok_0_ips"}

    if len(unique_ips) > MAX_IPS:
        logger.info(
            "ip_reputation: capping to %d of %d unique IPs",
            MAX_IPS, len(unique_ips),
        )
        unique_ips = unique_ips[:MAX_IPS]

    logger.info("ip_reputation: checking %d unique IP(s)", len(unique_ips))

    # One budget shared by the whole fan-out, so the cap is per investigation
    # rather than per IP.
    greynoise_budget = GreyNoiseBudget()

    # Run all checks concurrently
    rep_list = await asyncio.gather(
        *[
            check_ip_reputation(
                ip,
                base_confidence=seen[ip],
                greynoise_budget=greynoise_budget,
            )
            for ip in unique_ips
        ],
        return_exceptions=True,
    )

    suppressed_ips: set[str] = set()
    db_updates: list[tuple[str, float, list[str]]] = []
    stats = {
        "checked": len(unique_ips),
        "suppressed": 0,
        "c2_confirmed": 0,
        "abuse_confirmed": 0,
        "greynoise_lookups": greynoise_budget.used,
        "greynoise_capped": greynoise_budget.capped,
    }

    for ip, rep in zip(unique_ips, rep_list):
        if isinstance(rep, Exception):
            logger.debug("ip_reputation: check raised for %s: %s", ip, rep)
            continue
        if rep["suppress"]:
            suppressed_ips.add(ip)
            stats["suppressed"] += 1
            continue
        if rep["c2feed_hit"] or rep["feodo_hit"]:
            stats["c2_confirmed"] += 1
        if (rep["abuseipdb_score"] or 0) > 50:
            stats["abuse_confirmed"] += 1
        if rep["tags"] or rep["threat_confidence"] > seen[ip]:
            db_updates.append((ip, rep["threat_confidence"], rep["tags"]))

    # Apply suppression to in-memory extraction results
    if suppressed_ips:
        for exr in extraction_results:
            exr.entities = [
                e for e in getattr(exr, "entities", [])
                if not (
                    getattr(e, "entity_type", "") == "IP_ADDRESS"
                    and e.value in suppressed_ips
                )
            ]
            exr.entity_count = len(exr.entities)
        await asyncio.to_thread(_suppress_entities_in_db, suppressed_ips, investigation_id)

    # Update DB for non-suppressed IPs
    if db_updates:
        await asyncio.to_thread(_update_entity_reputations, db_updates)

    checked = stats["checked"]
    sup = stats["suppressed"]
    status = f"ok_{checked}_ips" + (f"_{sup}_suppressed" if sup else "")
    # Surface the cap honestly in sources_used rather than silently returning
    # fewer GreyNoise classifications than the IP count implies.
    if greynoise_budget.capped:
        status += f"_greynoise_capped_at_{greynoise_budget.limit}"

    logger.info(
        "ip_reputation: done — %d checked, %d suppressed, %d C2, %d abuse, "
        "%d GreyNoise lookup(s)%s",
        checked, sup, stats["c2_confirmed"], stats["abuse_confirmed"],
        greynoise_budget.used,
        " (cap reached)" if greynoise_budget.capped else "",
    )

    return extraction_results, {"ip_reputation": status, **stats}
