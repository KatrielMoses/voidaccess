"""
Threat intelligence enrichment — OTX (AlienVault) and abuse.ch (MalwareBazaar,
ThreatFox, URLhaus).

Returns page-shaped dicts compatible with ``extract_entities_from_pages`` (``url``,
``text`` / ``content``, plus ``link``, ``status``, ``source`` for traceability).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

import pacing
import json

from sources import http_pool, source_control
from sources.cache import CachedFeed
from utils import cancel
from sources.enrichment_allowlist import (
    ENRICHMENT_SOURCE_IDS,
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


def is_onion_url(url: str) -> bool:
    """Return True if *url* points to a .onion hidden service."""
    if not url:
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# All HTTP calls use at most 30s client timeout (enforced per request).


_ABUSECH_WARNED = False


def _abusech_headers() -> dict[str, str]:
    key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    return {"Auth-Key": key} if key else {}


def _abusech_enabled() -> bool:
    """abuse.ch APIs (MalwareBazaar/ThreatFox/URLhaus) require an Auth-Key
    since 2024. Return False (and log once) when the key is missing so we
    skip the request entirely instead of spamming HTTP 401."""
    global _ABUSECH_WARNED
    if (os.environ.get("ABUSECH_API_KEY") or "").strip():
        return True
    if not _ABUSECH_WARNED:
        logger.info(
            "abuse.ch enrichment skipped — set ABUSECH_API_KEY "
            "(free at https://auth.abuse.ch) to enable MalwareBazaar/ThreatFox/URLhaus."
        )
        _ABUSECH_WARNED = True
    return False


def is_onion_url(url: str) -> bool:
    """
    Return True if *url* looks like a Tor hidden service URL (.onion).
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        return host.endswith(".onion")
    except Exception:
        return ".onion" in url.lower()


async def fetch_otx_pulses(query: str, api_key: str, limit: int = 20) -> list[dict]:
    """
    Search OTX for threat pulses related to the query.

    Returns list of dicts with pulse metadata and optional ``indicators``.
    """
    if not is_enrichment_source_enabled("otx"):
        return []
    if not (api_key or "").strip():
        logger.debug("OTX skipped — no API key configured")
        return []

    headers = {"X-OTX-API-KEY": api_key.strip()}
    results: list[dict] = []

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with http_pool.clearnet_session() as session:
            url = f"{OTX_BASE_URL}/search/pulses"
            params = {"q": query, "limit": limit, "page": 1}

            async with session.get(url, params=params, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("OTX pulse search returned HTTP %s", resp.status)
                    return []

                data = await resp.json()
                pulses = data.get("results", [])
                logger.info("OTX: %d results", len(pulses))

                for pulse in pulses:
                    mf = pulse.get("malware_families") or []
                    if mf and isinstance(mf[0], str):
                        malware_families_fmt: list[Any] = mf
                    else:
                        malware_families_fmt = mf

                    result = {
                        "source": "otx_pulse",
                        "pulse_id": pulse.get("id"),
                        "title": pulse.get("name", ""),
                        "description": pulse.get("description", ""),
                        "tags": pulse.get("tags", []),
                        "created": pulse.get("created"),
                        "modified": pulse.get("modified"),
                        "tlp": pulse.get("tlp", "white"),
                        "indicator_count": pulse.get("indicator_count", 0),
                        "malware_families": malware_families_fmt,
                        "attack_ids": [
                            a.get("display_name")
                            for a in (pulse.get("attack_ids") or [])
                            if isinstance(a, dict)
                        ],
                        "indicators": [],
                    }
                    results.append(result)

                for pulse_result in results[:5]:
                    indicators = await fetch_otx_pulse_indicators(
                        str(pulse_result["pulse_id"]), api_key, session
                    )
                    pulse_result["indicators"] = indicators

    except asyncio.TimeoutError:
        logger.warning("OTX: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("OTX: Client error: %s", e)
    except Exception as e:
        logger.warning("OTX: Error fetching pulses: %s", e)

    return results


async def fetch_otx_pulse_indicators(
    pulse_id: str, api_key: str, session: aiohttp.ClientSession
) -> list[dict]:
    """Fetch IOCs for a pulse."""
    try:
        url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
        headers = {"X-OTX-API-KEY": api_key}

        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return []

            data = await resp.json()
            indicators = data.get("results", [])

            return [
                {
                    "type": ind.get("type"),
                    "value": ind.get("indicator"),
                    "description": ind.get("description", ""),
                    "created": ind.get("created"),
                }
                for ind in indicators
                if ind.get("indicator")
            ]

    except Exception as e:
        logger.debug("OTX: Error fetching indicators for pulse %s: %s", pulse_id, e)
        return []


def otx_pulse_to_page(pulse: dict) -> dict:
    """Convert an OTX pulse to page-shaped dict for the entity extractor."""
    lines: list[str] = []

    if pulse.get("title"):
        lines.append(f"Threat Report: {pulse['title']}")

    if pulse.get("description"):
        lines.append(f"\nDescription: {pulse['description']}")

    if pulse.get("tags"):
        lines.append(f"\nTags: {', '.join(pulse['tags'])}")

    mf = pulse.get("malware_families") or []
    if mf:
        families: list[str] = []
        for m in mf:
            if isinstance(m, dict):
                families.append(m.get("display_name") or m.get("name") or "")
            elif isinstance(m, str):
                families.append(m)
        families = [f for f in families if f]
        if families:
            lines.append(f"\nMalware Families: {', '.join(families)}")

    if pulse.get("attack_ids"):
        lines.append(f"\nMITRE ATT&CK: {', '.join(pulse['attack_ids'])}")

    indicators = pulse.get("indicators", [])
    if indicators:
        lines.append("\nIndicators of Compromise:")
        for ind in indicators:
            ind_type = ind.get("type", "")
            ind_value = ind.get("value", "")
            ind_desc = ind.get("description", "")
            if ind_value:
                extra = f" ({ind_desc})" if ind_desc else ""
                lines.append(f"  {ind_type}: {ind_value}{extra}")

    content = "\n".join(lines)
    pid = pulse.get("pulse_id") or ""
    link = f"https://otx.alienvault.com/pulse/{pid}"

    return {
        "link": link,
        "url": link,
        "content": content,
        "text": content,
        "status": 200,
        "source": "alienvault_otx",
        "title": pulse.get("title", "OTX Threat Report"),
        "via": "otx_api",
    }


async def fetch_malwarebazaar(query: str, limit: int = 20) -> list[dict]:
    """Query MalwareBazaar by tag then by signature."""
    if not is_enrichment_source_enabled("malwarebazaar"):
        return []
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        # Fetch most recent samples (last 100)
        try:
            headers = _abusech_headers()
            timeout = aiohttp.ClientTimeout(total=30)
            async with http_pool.clearnet_session() as session:
                payload = {"query": "get_recent", "selector": "time"}
                async with session.post(MALWAREBAZAAR_URL, data=payload, headers=headers, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            samples = data.get("data") or []
                            for sample in samples:
                                results.append({
                                    "source": "malwarebazaar",
                                    "sha256": sample.get("sha256_hash"),
                                    "signature": sample.get("signature"),
                                    "malware_family": sample.get("signature", ""),
                                    "tags": sample.get("tags", []),
                                    "first_seen": sample.get("first_seen"),
                                })
                            return results
        except Exception as e:
            logger.warning("MalwareBazaar recent fetch failed: %s", e)
            return []
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)

    def _map_sample(sample: dict) -> dict:
        return {
            "source": "malwarebazaar",
            "sha256": sample.get("sha256_hash"),
            "md5": sample.get("md5_hash"),
            "file_name": sample.get("file_name"),
            "file_type": sample.get("file_type"),
            "signature": sample.get("signature"),
            "tags": sample.get("tags", []),
            "malware_family": sample.get("signature", ""),
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "reporter": sample.get("reporter", ""),
            "comment": sample.get("comment", ""),
        }

    try:
        async with http_pool.clearnet_session() as session:
            tag_payload = {"query": "get_taginfo", "tag": q, "limit": limit}
            async with session.post(MALWAREBAZAAR_URL, data=tag_payload, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("MalwareBazaar: HTTP %s (tag)", resp.status)
                else:
                    data = await resp.json()
                    if data.get("query_status") == "no_api_key":
                        logger.warning(
                            "MalwareBazaar: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                        )
                        return []
                    if data.get("query_status") == "ok":
                        samples = data.get("data") or []
                        logger.info("MalwareBazaar: %d samples (tag)", len(samples))
                        for sample in samples:
                            results.append(_map_sample(sample))
                        if results:
                            return results

            sig_payload = {"query": "get_siginfo", "signature": q, "limit": limit}
            async with session.post(MALWAREBAZAAR_URL, data=sig_payload, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("MalwareBazaar: HTTP %s (signature)", resp.status)
                    return []
                data = await resp.json()
                if data.get("query_status") != "ok":
                    return []
                samples = data.get("data") or []
                logger.info("MalwareBazaar: %d samples (signature)", len(samples))
                for sample in samples:
                    results.append(_map_sample(sample))

    except asyncio.TimeoutError:
        logger.warning("MalwareBazaar: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("MalwareBazaar: Client error: %s", e)
    except Exception as e:
        logger.warning("MalwareBazaar: Error: %s", e)

    return results


async def fetch_threatfox(query: str, limit: int = 50) -> list[dict]:
    """Search ThreatFox IOCs by search term."""
    if not is_enrichment_source_enabled("threatfox"):
        return []
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        # Fetch most recent IOCs (last 24 hours)
        payload = {"query": "get_iocs", "days": 1}
        try:
            headers = _abusech_headers()
            timeout = aiohttp.ClientTimeout(total=30)
            async with http_pool.clearnet_session() as session:
                async with session.post(THREATFOX_URL, json=payload, headers=headers, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            iocs = data.get("data") or []
                            for ioc in iocs[:limit]:
                                conf = ioc.get("confidence_level")
                                conf_f = float(conf) / 100.0 if conf is not None else 0.0
                                results.append({
                                    "source": "threatfox",
                                    "ioc_type": ioc.get("ioc_type"),
                                    "ioc_value": ioc.get("ioc"),
                                    "malware": ioc.get("malware_printable"),
                                    "confidence": conf_f,
                                    "tags": ioc.get("tags", []),
                                })
                            return results
        except Exception as e:
            logger.warning("ThreatFox recent fetch failed: %s", e)
            return []
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)
    payload = {"query": "search_ioc", "search_term": q}

    try:
        async with http_pool.clearnet_session() as session:
            async with session.post(THREATFOX_URL, json=payload, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("ThreatFox: HTTP %s", resp.status)
                    return []

                data = await resp.json()
                if data.get("query_status") == "no_api_key":
                    logger.warning(
                        "ThreatFox: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                    )
                    return []
                if data.get("query_status") != "ok":
                    return []

                iocs = data.get("data") or []
                logger.info("ThreatFox: %d results", len(iocs))

                for ioc in iocs[:limit]:
                    conf = ioc.get("confidence_level")
                    conf_f = float(conf) / 100.0 if conf is not None else 0.0
                    results.append(
                        {
                            "source": "threatfox",
                            "ioc_type": ioc.get("ioc_type"),
                            "ioc_value": ioc.get("ioc"),
                            "malware": ioc.get("malware"),
                            "malware_printable": ioc.get("malware_printable"),
                            "confidence": conf_f,
                            "first_seen": ioc.get("first_seen"),
                            "last_seen": ioc.get("last_seen"),
                            "tags": ioc.get("tags", []),
                            "comment": ioc.get("comment", ""),
                            "reporter": ioc.get("reporter", ""),
                        }
                    )

    except asyncio.TimeoutError:
        logger.warning("ThreatFox: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("ThreatFox: Client error: %s", e)
    except Exception as e:
        logger.warning("ThreatFox: Error: %s", e)

    return results


async def fetch_urlhaus(query: str, limit: int = 20) -> list[dict]:
    """Search URLhaus by tag."""
    if not is_enrichment_source_enabled("urlhaus"):
        return []
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)
    payload = {"tag": q}

    try:
        async with http_pool.clearnet_session() as session:
            async with session.post(f"{URLHAUS_URL}tag/", data=payload, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("URLhaus: HTTP %s", resp.status)
                    return []

                data = await resp.json()
                if data.get("query_status") == "no_api_key":
                    logger.warning(
                        "URLhaus: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                    )
                    return []
                if data.get("query_status") != "ok":
                    return []

                urls = (data.get("urls") or [])[:limit]
                logger.info("URLhaus: %d results", len(urls))

                for url_entry in urls:
                    results.append(
                        {
                            "source": "urlhaus",
                            "url": url_entry.get("url"),
                            "url_status": url_entry.get("url_status"),
                            "tags": url_entry.get("tags", []),
                            "threat": url_entry.get("threat"),
                            "date_added": url_entry.get("date_added"),
                            "reporter": url_entry.get("reporter", ""),
                        }
                    )

    except asyncio.TimeoutError:
        logger.warning("URLhaus: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("URLhaus: Client error: %s", e)
    except Exception as e:
        logger.warning("URLhaus: Error: %s", e)

    return results


def abusech_to_pages(
    malwarebazaar_results: list[dict],
    threatfox_results: list[dict],
    urlhaus_results: list[dict],
) -> list[dict]:
    """Group Abuse.ch results into page-shaped dicts."""
    pages: list[dict] = []

    if malwarebazaar_results:
        lines = ["MalwareBazaar Threat Intelligence Report\n"]
        for sample in malwarebazaar_results[:20]:
            lines.append(f"Malware Family: {sample.get('malware_family', 'Unknown')}")
            if sample.get("sha256"):
                lines.append(f"SHA256: {sample['sha256']}")
            if sample.get("tags"):
                lines.append(f"Tags: {', '.join(sample['tags'])}")
            if sample.get("reporter"):
                lines.append(f"Reporter: {sample['reporter']}")
            if sample.get("first_seen"):
                lines.append(f"First seen: {sample['first_seen']}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://bazaar.abuse.ch/browse/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "malwarebazaar",
                "via": "abusech_api",
            }
        )

    if threatfox_results:
        lines = ["ThreatFox IOC Intelligence Report\n"]
        for ioc in threatfox_results[:30]:
            lines.append(f"IOC Type: {ioc.get('ioc_type', 'Unknown')}")
            lines.append(f"IOC Value: {ioc.get('ioc_value', '')}")
            if ioc.get("malware_printable"):
                lines.append(f"Malware: {ioc['malware_printable']}")
            if ioc.get("confidence"):
                lines.append(f"Confidence: {ioc['confidence']:.0%}")
            if ioc.get("tags"):
                lines.append(f"Tags: {', '.join(ioc['tags'])}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://threatfox.abuse.ch/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "threatfox",
                "via": "abusech_api",
            }
        )

    if urlhaus_results:
        lines = ["URLhaus Malicious URL Intelligence Report\n"]
        for url_entry in urlhaus_results[:20]:
            lines.append(f"URL: {url_entry.get('url', '')}")
            lines.append(f"Threat: {url_entry.get('threat', 'Unknown')}")
            if url_entry.get("tags"):
                lines.append(f"Tags: {', '.join(url_entry['tags'])}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://urlhaus.abuse.ch/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "urlhaus",
                "via": "abusech_api",
            }
        )

    return pages


_RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2"
_RANSOMWARE_LIVE_HEADERS = {"User-Agent": "VoidAccess-OSINT/1.0", "Accept": "application/json"}

# ransomware.live pacing — Class B, quota-driven, and the strictest limit
# anywhere in the tree.  Its own API page states: "Rate limited: 1 req/min per
# endpoint", "No authentication", "Personal use only" (verified 2026-07-29).
#
# **Per endpoint** is the load-bearing detail.  /groups, /group/{name},
# /v2/recentvictims and /v2/recentcyberattacks are four distinct routes, so one
# request to each may go out immediately without violating anything.  What did
# violate was the group-detail fan-out: five concurrent /group/{name} calls all
# hit the SAME route, so they shared one 1-req/min allowance.
#
# Hence a per-route gate rather than one global delay — a single flat delay
# would either be wrong (global, so it needlessly serialises unrelated routes)
# or unsafe (per-call, so it misses that the five details share a route).
_RL_MIN_INTERVAL = 62.0          # documented: 1 req/min = 60 s, + margin
# At 1 req/min, fetching N group details costs N minutes.  Cap the fan-out and
# bound it with a soft budget, the same shape nvd.py and crt.sh use, rather than
# stalling the pipeline for five minutes.  Was `[:5]`.
_RL_MAX_GROUP_DETAILS = 2
_RL_SOFT_BUDGET = 70.0

_rl_route_last: dict[str, float] = {}
_rl_route_lock: Optional[asyncio.Lock] = None


def _rl_route_key(path: str) -> str:
    """
    Collapse a concrete path to the route it shares a quota with.

    ``/group/lockbit`` and ``/group/alphv`` are the same endpoint for
    rate-limiting purposes, so the trailing path parameter is dropped.
    """
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) >= 2 and parts[0] in {"group", "groupvictims", "victims"}:
        return f"/{parts[0]}/*"
    return "/" + "/".join(parts)


async def _rl_route_gate(path: str) -> float:
    """
    Hold until *path*'s route is allowed another request. Returns seconds slept.

    Serialised through one lock so two coroutines cannot both read a stale
    last-request timestamp and decide they are clear to send.
    """
    global _rl_route_lock
    if _rl_route_lock is None:
        _rl_route_lock = asyncio.Lock()

    key = _rl_route_key(path)
    interval = pacing.scale_delay_floor(_RL_MIN_INTERVAL)
    slept = 0.0
    async with _rl_route_lock:
        last = _rl_route_last.get(key)
        now = time.monotonic()
        if last is not None:
            wait = last + interval - now
            if wait > 0:
                await asyncio.sleep(wait)
                slept = wait
        _rl_route_last[key] = time.monotonic()
    return slept


def reset_ransomware_live_pacing() -> None:
    """Clear per-route pacing state (used by tests)."""
    _rl_route_last.clear()

# Generic words that carry no group-identity signal in a realistic analyst
# query ("LockBit ransomware leak site").  Stripped before matching so the
# meaningful token(s) — e.g. "lockbit" — are what we match on, rather than
# requiring the whole query string to appear literally in a group name.
_GROUP_QUERY_STOPWORDS: frozenset[str] = frozenset({
    "ransomware", "ransom", "group", "gang", "crew", "team",
    "leak", "leaks", "leaksite", "site", "blog", "portal",
    "data", "the", "and", "actor", "threat", "malware",
})


def _significant_group_tokens(query: str) -> list[str]:
    """Meaningful lowercase tokens from a group query, stopwords removed.

    Falls back to all tokens if every token was a stopword, so a query made
    entirely of generic words still matches on something rather than nothing.
    """
    tokens = re.findall(r"[a-z0-9.]+", (query or "").lower())
    tokens = [t.strip(".") for t in tokens if t.strip(".")]
    significant = [t for t in tokens if t not in _GROUP_QUERY_STOPWORDS and len(t) >= 3]
    return significant or tokens


def _group_name_matches_query(name: str, tokens: list[str]) -> bool:
    """Token-based match of a tracked group name against query tokens.

    A token matches if it is a substring of the group name (so ``lockbit``
    matches ``lockbit``, ``lockbit2``, ``lockbit3``) or the group name is a
    substring of the token.  This is how an analyst actually phrases a query,
    versus the old "entire query string must appear in the name" rule.
    """
    n = (name or "").lower()
    if not n:
        return False
    return any(t and (t in n or n in t) for t in tokens)


def _rl_extract_onion_urls(group: dict) -> list[str]:
    """Extract .onion leak-site URLs from a group dict (available sites first)."""
    locations = group.get("locations") or []
    if not isinstance(locations, list):
        return []
    # available=True sites first, then the rest
    locations = sorted(locations, key=lambda l: not l.get("available", False))
    urls: list[str] = []
    for loc in locations:
        fqdn = (loc.get("fqdn") or "").strip()
        if fqdn and ".onion" in fqdn:
            urls.append(fqdn if fqdn.startswith("http") else f"http://{fqdn}")
    return urls


# The free data feed: the full group list with descriptions and leak-site
# locations in one static file (verified 2026-10-17). It replaces the API's
# /groups (now an HTML page) and the per-group /group/{name} detail calls, so a
# run makes one request instead of one per minute per group.
RANSOMWARE_LIVE_GROUPS_URL = "https://data.ransomware.live/groups.json"
_rl_groups_feed = CachedFeed(
    RANSOMWARE_LIVE_GROUPS_URL,
    "/tmp/voidaccess_ransomware_live_groups.json",
    ttl_seconds=21600,
    headers=_RANSOMWARE_LIVE_HEADERS,
)


async def fetch_ransomware_live(query: str) -> list[dict]:
    """
    Search ransomware.live for threat group profiles, leak-site .onion addresses,
    and recent victim claim URLs.

    Produces three kinds of intelligence:
    1. Group profile (text for entity extraction)
    2. Leak-site .onion addresses (scrape seeds — bypass search engine discovery)
    3. Individual victim claim URLs (specific .onion post pages to scrape)

    Groups come from the data feed (RANSOMWARE_LIVE_GROUPS_URL); recent attacks
    from the API's /v2/recentcyberattacks. Free, no key; personal-use terms, so
    it is off in the hosted profile.
    """
    if not is_enrichment_source_enabled("ransomware_live"):
        return []
    q = (query or "").strip().lower()
    if not q:
        return []

    results: list[dict] = []

    try:
        all_groups = await _rl_groups_feed.fetch()
        if all_groups is None:
            return []  # the failed request is already counted against the source
        if not isinstance(all_groups, list):
            logger.warning("ransomware.live: group feed was not a list")
            source_control.record_source_failure("ransomware_live")
            return []

        _tokens = _significant_group_tokens(query)
        matched_summary: list[dict] = []
        for g in all_groups:
            if not isinstance(g, dict):
                continue
            name = (g.get("name") or "").lower()
            if _group_name_matches_query(name, _tokens):
                matched_summary.append(g)

        if not matched_summary:
            logger.info("ransomware.live: no groups matched %r", query)
            return []

        logger.info("ransomware.live: %d groups matched %r", len(matched_summary), query)

        # ── Recent attacks, filtered to the matched groups ────────────────────
        recent_victims: list[dict] = []
        matched_names = {g.get("name", "").lower() for g in matched_summary}
        endpoint = "/v2/recentcyberattacks"
        try:
            await _rl_route_gate(endpoint)
            async with http_pool.clearnet_session() as session:
                async with session.get(
                    f"https://api.ransomware.live{endpoint}",
                    headers=_RANSOMWARE_LIVE_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=25),
                ) as r:
                    if r.status == 200:
                        text = await r.text()
                        if text.strip()[:1] == "[":
                            for v in json.loads(text):
                                if (v.get("group") or "").lower() in matched_names:
                                    recent_victims.append(v)
                        else:
                            source_control.record_source_failure("ransomware_live")
        except Exception as exc:
            logger.warning("ransomware.live %s failed: %s", endpoint, exc)

        logger.info("ransomware.live: %d recent victims for matched groups", len(recent_victims))

        # ── Assemble results ────────────────────────────────────────────────
        for gdata in matched_summary:
            gname = gdata.get("name", "")
            if not gname:
                continue
            group_victims = [
                v for v in recent_victims
                if (v.get("group") or "").lower() == gname.lower()
            ]
            # Claim URLs are individual victim post pages on the leak site
            claim_urls = [
                v.get("claim_url") for v in group_victims
                if v.get("claim_url") and ".onion" in (v.get("claim_url") or "")
            ]
            results.append({
                "group":        gname,
                "description":  gdata.get("description") or "",
                "onion_urls":   _rl_extract_onion_urls(gdata),
                "claim_urls":   claim_urls[:30],
                "victims":      group_victims[:50],
                "ttps":         gdata.get("ttps") or [],
                "tools":        gdata.get("tools") or [],
                "victim_count": gdata.get("_victim_count", 0),
            })

    except asyncio.TimeoutError:
        logger.warning("ransomware.live: request timed out")
    except aiohttp.ClientError as exc:
        logger.warning("ransomware.live: client error: %s", exc)
    except Exception as exc:
        logger.warning("ransomware.live: unexpected error: %s", exc)
        source_control.record_source_failure("ransomware_live")

    return results


def ransomwarelive_to_pages(groups: list[dict]) -> list[dict]:
    """Convert ransomware.live group data into page-shaped dicts.

    Produces two kinds of pages:
    1. A rich text summary page (for entity extraction)
    2. One stub page per discovered .onion URL (so the scraper will visit them)
    """
    pages: list[dict] = []

    for gd in groups:
        gname = gd.get("group", "Unknown")
        lines: list[str] = [f"Ransomware Group Intelligence Report: {gname}"]

        if gd.get("description"):
            lines.append(f"\nDescription: {gd['description']}")

        onion_urls = gd.get("onion_urls", [])
        if onion_urls:
            lines.append(f"\nLeak Site URLs: {', '.join(onion_urls)}")

        victims = gd.get("victims", [])
        if victims:
            lines.append(f"\nKnown Victims ({len(victims)} total):")
            for v in victims[:40]:
                title  = v.get("victim") or v.get("post_title") or v.get("website") or ""
                domain = v.get("domain") or v.get("website") or ""
                date   = v.get("attackdate") or v.get("published") or v.get("date") or ""
                country = v.get("country") or ""
                activity = v.get("activity") or ""
                victim_line = f"  - {title}"
                if domain and domain != title:
                    victim_line += f" ({domain})"
                if country:
                    victim_line += f" [{country}]"
                if date:
                    victim_line += f" {date}"
                if activity:
                    victim_line += f" — {activity}"
                lines.append(victim_line)

        claim_urls = gd.get("claim_urls", [])

        content = "\n".join(lines)
        base_link = f"https://www.ransomware.live/group/{gname}"

        pages.append({
            "link":    base_link,
            "url":     base_link,
            "content": content,
            "text":    content,
            "status":  200,
            "source":  "ransomware_live",
            "title":   f"ransomware.live — {gname}",
            "via":     "ransomware_live_api",
        })

        # Stub pages for each .onion leak site so the scraper will visit them
        for onion_url in onion_urls:
            if onion_url and ".onion" in onion_url:
                stub = f"{gname} ransomware group leak site: {onion_url}"
                pages.append({
                    "link":    onion_url,
                    "url":     onion_url,
                    "content": stub,
                    "text":    stub,
                    "status":  200,
                    "source":  "ransomware_live",
                    "title":   f"{gname} leak site",
                    "via":     "ransomware_live_onion_seed",
                    "_scrape_seed": True,
                })

        # Stub pages for individual victim claim URLs (specific post pages on leak sites)
        for claim_url in claim_urls[:20]:
            if claim_url and ".onion" in claim_url:
                stub = f"{gname} ransomware victim post: {claim_url}"
                pages.append({
                    "link":    claim_url,
                    "url":     claim_url,
                    "content": stub,
                    "text":    stub,
                    "status":  200,
                    "source":  "ransomware_live",
                    "title":   f"{gname} victim claim",
                    "via":     "ransomware_live_claim_seed",
                    "_scrape_seed": True,
                })

    return pages


async def _gather_with_partial_results(
    named_coros: list[tuple[str, Any]],
    timeout: float,
    phase_label: str,
    unfinished: Optional[set[str]] = None,
) -> dict[str, Any]:
    """
    Run named coroutines concurrently with a deadline, PRESERVING the results
    of any that finished before the deadline hit.

    Unlike ``asyncio.wait_for(asyncio.gather(...))`` — which cancels the whole
    group on timeout and loses everything — this schedules each coroutine as a
    task, waits up to *timeout*, then returns whatever completed. Sources still
    running at the deadline are cancelled and reported as ``[]`` (an unfinished
    source contributes nothing, but a *finished* sibling's results survive).

    Returns a dict mapping name → result. On a per-task exception the value is
    the Exception instance (callers already guard with ``isinstance(x, Exception)``).
    Names whose task did not finish map to ``[]``; when *unfinished* is given,
    those names are also added to it (a cut-off and an empty result differ).
    """
    if not named_coros:  # every source gated off by VOIDACCESS_ENRICHMENT_SOURCES
        return {}
    tasks: dict[str, asyncio.Task] = {
        name: asyncio.ensure_future(coro) for name, coro in named_coros
    }
    done, pending = await cancel.wait_cancellable(set(tasks.values()), timeout=timeout)

    if pending and cancel.is_cancelled():
        # Cancel checkpoint between sources: keep what finished, drop the rest.
        logger.info(
            "%s: cancelled — keeping %d finished source(s), stopping %d",
            phase_label, len(done), len(pending),
        )
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    elif pending:
        late = [name for name, t in tasks.items() if t in pending]
        logger.warning(
            "%s: deadline (%.0fs) hit — preserving %d finished source(s), "
            "dropping unfinished: %s",
            phase_label, timeout, len(done), ", ".join(late),
        )
        for t in pending:
            t.cancel()
        # Let cancellations settle so no "Task was destroyed but pending" warnings.
        await asyncio.gather(*pending, return_exceptions=True)

    results: dict[str, Any] = {}
    for name, t in tasks.items():
        if t in done and not t.cancelled():
            exc = t.exception()
            results[name] = exc if exc is not None else t.result()
        else:
            results[name] = []
            if unfinished is not None:
                unfinished.add(name)
    return results


# ---------------------------------------------------------------------------
# ransomlook.io — second ransomware-group tracker for cross-validation
# ---------------------------------------------------------------------------
# Draws from a different aggregation pipeline than ransomware.live (different
# upstream scrapers / community contributions), so the two have partial but not
# complete overlap. Runs ALONGSIDE ransomware.live — the value is corroboration
# when the same group/victim appears in both, and genuinely new coverage when
# only one has it. Leak-site .onion seed URLs are formatted IDENTICALLY to
# ``ransomwarelive_to_pages`` (``http://{fqdn}``) so the enrichment page URL
# dedup collapses a leak site discovered by both trackers into a single scrape
# seed; the summary pages stay distinct (that is the corroboration signal). If
# the same leak site is nonetheless reached twice, the scrape-layer
# ``raw_content_hash`` dedup is the backstop. Free, no key required.

_RANSOMLOOK_BASE = "https://www.ransomlook.io/api"
_RANSOMLOOK_HEADERS = {"User-Agent": "VoidAccess-OSINT/1.1 (security research)", "Accept": "application/json"}


def _ransomlook_onion_from_locations(locations: list) -> list[str]:
    """Extract .onion leak-site URLs from a ransomlook group's locations list.

    Available sites first. Formatted as ``http://{fqdn}`` to match
    ``_rl_extract_onion_urls`` (ransomware.live) so cross-source dedup works.
    """
    if not isinstance(locations, list):
        return []
    ordered = sorted(locations, key=lambda l: not (isinstance(l, dict) and l.get("available", False)))
    urls: list[str] = []
    seen: set[str] = set()
    for loc in ordered:
        if not isinstance(loc, dict):
            continue
        fqdn = (loc.get("fqdn") or "").strip().lower()
        # Normalize to bare host (strip scheme + trailing slash), then re-add http://
        fqdn = fqdn.replace("https://", "").replace("http://", "").rstrip("/")
        if fqdn and ".onion" in fqdn:
            url = f"http://{fqdn}"
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


async def fetch_ransomlook(query: str) -> list[dict]:
    """
    Search ransomlook.io for ransomware-group profiles, leak-site .onion
    addresses, and recent victim posts. Free public API — no key required.

    Cross-validates the existing ransomware.live source (different corpus).
    """
    if not is_enrichment_source_enabled("ransomlook"):
        return []
    q = (query or "").strip().lower()
    if not q:
        return []

    results: list[dict] = []
    timeout = aiohttp.ClientTimeout(total=25)

    try:
        async with http_pool.clearnet_session() as session:
            # ── 1. Match groups from the full group name index ─────────────────
            async with session.get(
                f"{_RANSOMLOOK_BASE}/groups",
                headers=_RANSOMLOOK_HEADERS, timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    logger.warning("ransomlook.io /groups HTTP %s", resp.status)
                    return []
                all_groups = await resp.json(content_type=None)

            group_names = [g for g in all_groups if isinstance(g, str)] if isinstance(all_groups, list) else []
            _tokens = _significant_group_tokens(query)
            matched = [name for name in group_names if _group_name_matches_query(name, _tokens)]

            if not matched:
                logger.info("ransomlook.io: no groups matched %r", query)
                return []

            matched = matched[:5]
            logger.info("ransomlook.io: %d group(s) matched %r", len(matched), query)

            # ── 2. Fetch detail for each matched group ─────────────────────────
            async def _fetch_group_detail(gname: str) -> tuple[str, Optional[dict]]:
                try:
                    async with session.get(
                        f"{_RANSOMLOOK_BASE}/group/{gname}",
                        headers=_RANSOMLOOK_HEADERS, timeout=timeout,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if isinstance(data, list) and data and isinstance(data[0], dict):
                                return gname, data[0]
                            if isinstance(data, dict):
                                return gname, data
                except Exception:
                    pass
                return gname, None

            detail_pairs = await asyncio.gather(
                *[_fetch_group_detail(g) for g in matched],
                return_exceptions=True,
            )
            group_details: dict[str, dict] = {}
            for pair in detail_pairs:
                if isinstance(pair, Exception):
                    continue
                gname, detail = pair
                group_details[gname] = detail if isinstance(detail, dict) else {}

            # ── 3. Pull recent posts and filter by matched group names ─────────
            recent_by_group: dict[str, list[dict]] = {name.lower(): [] for name in matched}
            try:
                async with session.get(
                    f"{_RANSOMLOOK_BASE}/recent",
                    headers=_RANSOMLOOK_HEADERS, timeout=timeout,
                ) as r:
                    if r.status == 200:
                        recent = await r.json(content_type=None)
                        for post in (recent if isinstance(recent, list) else []):
                            if not isinstance(post, dict):
                                continue
                            gname = (post.get("group_name") or "").lower()
                            if gname in recent_by_group:
                                recent_by_group[gname].append(post)
            except Exception:
                pass

            # ── 4. Assemble results ────────────────────────────────────────────
            for gname in matched:
                detail = group_details.get(gname, {})
                onion_urls = _ransomlook_onion_from_locations(detail.get("locations") or [])
                profile_refs = detail.get("profile") if isinstance(detail.get("profile"), list) else []
                meta = detail.get("meta")
                description = meta if isinstance(meta, str) else ""
                victims = recent_by_group.get(gname.lower(), [])
                results.append({
                    "group": gname,
                    "description": description,
                    "onion_urls": onion_urls,
                    "references": [r for r in (profile_refs or []) if isinstance(r, str)][:20],
                    "victims": victims[:50],
                })

    except asyncio.TimeoutError:
        logger.warning("ransomlook.io: request timed out")
    except aiohttp.ClientError as exc:
        logger.warning("ransomlook.io: client error: %s", exc)
    except Exception as exc:
        logger.warning("ransomlook.io: unexpected error: %s", exc)

    return results


def ransomlook_to_pages(groups: list[dict]) -> list[dict]:
    """Convert ransomlook.io group data into page-shaped dicts.

    Mirrors ``ransomwarelive_to_pages``: a rich text summary page per group
    (source ``ransomlook``) plus one .onion scrape-seed stub per leak site.
    Onion URLs match ransomware.live's format so cross-source dedup collapses
    shared leak sites.
    """
    from feeds import provenance as _feed_provenance
    _rl_prov = _feed_provenance("ransomlook")  # CC BY 4.0 — attribution required

    pages: list[dict] = []

    for gd in groups:
        gname = gd.get("group", "Unknown")
        lines: list[str] = [f"Ransomware Group Intelligence (ransomlook.io): {gname}"]

        if gd.get("description"):
            lines.append(f"\nDescription: {gd['description']}")

        onion_urls = gd.get("onion_urls", [])
        if onion_urls:
            lines.append(f"\nLeak Site URLs: {', '.join(onion_urls)}")

        refs = gd.get("references", [])
        if refs:
            lines.append(f"\nReferences: {', '.join(refs)}")

        victims = gd.get("victims", [])
        if victims:
            lines.append(f"\nRecent Victims ({len(victims)} total):")
            for v in victims[:40]:
                title = v.get("post_title") or v.get("victim") or ""
                date = v.get("discovered") or v.get("date") or ""
                victim_line = f"  - {title}"
                if date:
                    victim_line += f" {date}"
                lines.append(victim_line)

        # CC BY 4.0 attribution — RansomLook requires visible credit.
        lines.append(
            f"\nSource: {_rl_prov['attribution']} ({_rl_prov['url']}) — "
            f"license: {_rl_prov['license']}"
        )
        content = "\n".join(lines)
        base_link = f"https://www.ransomlook.io/group/{gname}"

        pages.append({
            "link": base_link,
            "url": base_link,
            "content": content,
            "text": content,
            "status": 200,
            "source": "ransomlook",
            "title": f"ransomlook.io — {gname}",
            "via": "ransomlook_api",
            "provenance": _rl_prov,
        })

        for onion_url in onion_urls:
            if onion_url and ".onion" in onion_url:
                stub = f"{gname} ransomware group leak site: {onion_url}"
                pages.append({
                    "link": onion_url,
                    "url": onion_url,
                    "content": stub,
                    "text": stub,
                    "status": 200,
                    "source": "ransomlook",
                    "title": f"{gname} leak site",
                    "via": "ransomlook_onion_seed",
                    "_scrape_seed": True,
                    "provenance": _rl_prov,
                })

    return pages


# ---------------------------------------------------------------------------
# Enrichment deadlines (E4). One wall-clock budget for the whole phase; every
# other bound below is derived from it or caps one source inside it.
# ---------------------------------------------------------------------------
# The enrichment phase ends this many seconds after enrich_investigation starts.
ENRICHMENT_DEADLINE_S = 59.0
# _enrich_new_sources returns this long before the phase deadline, so its
# partial results and per-source statuses are assembled instead of cancelled.
NEW_SOURCES_MARGIN_S = 2.0
# NVD starts no new CVE lookup after this many seconds (keeps what returned).
# Without a key NVD allows 4 requests per 30 s here, so a CVE-heavy run used to
# spend its whole window on NVD and leave nothing for KEV fusion and MITRE.
NVD_BUDGET_S = 35.0
# Bound on the CVE fusion (EPSS + Exploit-DB lookups). On expiry the legacy
# NVD/KEV pages are used, exactly as when the fusion raises.
CVE_FUSION_TIMEOUT_S = 8.0
# Historical intel (MITRE / justice.gov / CISA advisories; R1 measured 5-8 s)
# starts no later than this long before the group deadline, even if one of its
# inputs (CISA, Shodan, VirusTotal) is still running; a late input then simply
# does not narrow its entity list.
HISTORICAL_RESERVE_S = 10.0

# Named parts of the new-sources group -> the source ids they report under.
_NEW_SOURCE_IDS: dict[str, tuple[str, ...]] = {
    "cisa": ("cisa_kev",),
    "nvd": ("nvd",),
    "shodan": ("shodan_internetdb",),
    "virustotal": ("virustotal",),
    "historical": ("mitre_attack", "fbi_doj_press"),
    "cve_fusion": ("cve_intel", "epss", "exploitdb"),
    "mitre_overlay": ("mitre_attack",),
    "blocklists": ("sslbl", "openphish", "phishtank", "ransomwhere"),
}
# Outer-gather task names -> source ids.
_OUTER_SOURCE_IDS: dict[str, tuple[str, ...]] = {
    "otx": ("otx",),
    "malwarebazaar": ("malwarebazaar",),
    "threatfox": ("threatfox",),
    "urlhaus": ("urlhaus",),
    "ransomware_live": ("ransomware_live",),
    "ransomlook": ("ransomlook",),
}


def _record_source_state(source_ids, state: str) -> None:
    """Record a cut-off (``timed_out``) or failure (``error``) for *source_ids*
    so ``sources_used`` and the trace events never read ``ok`` for them.
    Ids the allowlist/deny-list switched off keep their gate status."""
    from sources import source_control

    tracker = source_control.get_tracker()
    for sid in source_ids:
        try:
            if sid in ENRICHMENT_SOURCE_IDS and not is_enrichment_source_enabled(sid):
                continue
        except Exception:
            continue
        if tracker.states.get(sid) == source_control.STATUS_TIMED_OUT:
            continue  # a cut-off is never downgraded to an error
        tracker.set_state(sid, state)


# Entity types that name an actor whose ATT&CK techniques the overlay may add.
OVERLAY_ACTOR_TYPES = frozenset({
    "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "RANSOMWARE_GROUP", "MALWARE_FAMILY",
})


async def _mitre_overlay_page(actor_name: str, seen_groups: set[str]) -> Optional[dict]:
    """The MITRE overlay page for *actor_name*, or None.

    Only a group the name resolves to exactly (sources.historical_intel) is used,
    once per group; every technique line names that group, so each T-code
    carries its provenance into extraction."""
    from sources.historical_intel import get_group_techniques

    try:
        found = await get_group_techniques(actor_name)
    except Exception as exc:
        logger.warning("MITRE overlay: failed for '%s': %s", actor_name, exc)
        return None
    if not found or not found[2] or found[1] in seen_groups:
        return None
    group_name, gid, techniques = found
    seen_groups.add(gid)
    logger.info("MITRE overlay: %d techniques for actor '%s' (group %s %s)",
                len(techniques), actor_name, gid, group_name)
    content = (
        f"MITRE ATT&CK Overlay: Techniques associated with {actor_name} "
        f"(source: mitre_attack_overlay; matched group: {group_name} {gid})\n"
        + "\n".join(f"{t} [group: {group_name} {gid}]" for t in techniques)
    )
    url = f"https://attack.mitre.org/groups/{gid}/"
    return {
        "link": url,
        "url": url,
        "content": content,
        "text": content,
        "status": 200,
        "source": "mitre_attack_overlay",
        "via": "mitre_overlay",
        "mitre_group": gid,
    }


def _assemble_new_source_pages(parts: dict[str, Any], query: str) -> list[dict]:
    """Pages from the group's finished parts, in the order the group always used."""
    pages: list[dict] = []
    if parts.get("advisories"):
        pages.extend(_cisa_results_to_pages(parts["advisories"], query))
    pages.extend(parts.get("cve") or [])
    if parts.get("shodan"):
        pages.extend(_shodan_results_to_pages(parts["shodan"]))
    if parts.get("virustotal"):
        pages.extend(_vt_results_to_pages(parts["virustotal"]))
    pages.extend(parts.get("historical") or [])
    pages.extend(parts.get("mitre_overlay") or [])
    pages.extend(parts.get("blocklists") or [])
    return pages


async def _enrich_new_sources(
    query: str,
    entities: list[dict],
    *,
    budget_s: Optional[float] = None,
    parts: Optional[dict[str, Any]] = None,
) -> list[dict]:
    """
    Run the new entity-driven enrichment sources and return page-shaped dicts.

    Sources:
    - CISA KEV + advisories   (cisa.py)
    - NVD 2.0 full CVE data   (nvd.py), capped at NVD_BUDGET_S
    - Shodan InternetDB       (shodan.py)
    - VirusTotal              (virustotal.py)
    - Historical intel        (historical_intel.py)
    - CVE fusion              (cve_intel.py: EPSS + Exploit-DB), bounded
    - Entity MITRE overlay and abuse/phishing blocklists

    Nothing waits behind NVD: historical intel starts as soon as CISA, Shodan
    and VirusTotal (its only inputs) are done, the CVE fusion as soon as NVD
    and KEV are, and the overlay and blocklists at once. The group returns by
    *budget_s* (default: the phase deadline minus NEW_SOURCES_MARGIN_S) with
    whatever finished; a part still running then is stopped and its sources
    are recorded ``timed_out``. Finished parts are published into *parts* as
    they complete, so a caller that has to cancel the group keeps them.
    """
    from sources.cisa import enrich_cisa
    from sources.nvd import enrich_nvd
    from sources.shodan import enrich_shodan
    from sources.virustotal import enrich_virustotal
    from sources.historical_intel import enrich_historical

    loop = asyncio.get_running_loop()
    if budget_s is None:
        budget_s = ENRICHMENT_DEADLINE_S - NEW_SOURCES_MARGIN_S
    deadline = loop.time() + max(0.0, budget_s)
    parts = parts if parts is not None else {}

    def remaining() -> float:
        return max(0.0, deadline - loop.time())

    # VOIDACCESS_ENRICHMENT_SOURCES: build coroutines only for enabled sources
    # (no never-awaited coroutine objects for disabled ones).
    validate_enrichment_allowlist()
    nvd_collected: list[dict] = []
    _factories = [
        ("cisa", "cisa_kev", lambda: enrich_cisa(query, entities)),
        ("nvd", "nvd", lambda: enrich_nvd(entities, budget_s=NVD_BUDGET_S, collected=nvd_collected)),
        ("shodan", "shodan_internetdb", lambda: enrich_shodan(entities)),
        ("virustotal", "virustotal", lambda: enrich_virustotal(entities)),
    ]
    fetch: dict[str, asyncio.Task] = {
        name: asyncio.ensure_future(factory())
        for name, sid, factory in _factories
        if is_enrichment_source_enabled(sid)
    }

    async def _wait_for(names: list[str], until: float) -> None:
        tasks = [fetch[n] for n in names if n in fetch and not fetch[n].done()]
        if tasks:
            # asyncio.wait never cancels what it waits on.
            await asyncio.wait(tasks, timeout=max(0.0, until - loop.time()))

    def _result(name: str) -> list:
        """A finished fetch's results; ``[]`` if it failed or is not done."""
        task = fetch.get(name)
        if task is None or not task.done() or task.cancelled():
            return []
        exc = task.exception()
        if exc is not None:
            logger.warning("%s enrichment failed: %s", name, exc)
            _record_source_state(_NEW_SOURCE_IDS[name], "error")
            return []
        return task.result() or []

    def _publish_fetches() -> None:
        """Expose finished CISA advisories / Shodan / VT results in *parts*."""
        if fetch.get("cisa") is not None and fetch["cisa"].done():
            parts["advisories"] = [r for r in _result("cisa") if r.get("source") != "cisa_kev"]
        for name in ("shodan", "virustotal"):
            if fetch.get(name) is not None and fetch[name].done():
                parts[name] = _result(name)

    async def _historical_part() -> None:
        await _wait_for(["cisa", "shodan", "virustotal"], deadline - HISTORICAL_RESERVE_S)
        _publish_fetches()
        cisa_results, shodan_results, vt_results = (
            _result("cisa"), _result("shodan"), _result("virustotal")
        )
        if cisa_results or shodan_results or vt_results:
            unenriched = _group_unenriched_entities(entities, cisa_results, shodan_results, vt_results)
            if unenriched:
                hist = await enrich_historical(unenriched)
                parts["historical"] = _historical_results_to_pages(hist)

    async def _fusion_part() -> None:
        # Leave the fusion its own window: NVD gets until then, and keeps what
        # it had fetched if it is still running.
        await _wait_for(["nvd", "cisa"], deadline - CVE_FUSION_TIMEOUT_S)
        nvd_task = fetch.get("nvd")
        if nvd_task is not None and not nvd_task.done():
            nvd_task.cancel()
            await asyncio.gather(nvd_task, return_exceptions=True)
            logger.warning(
                "_enrich_new_sources: NVD still running at the fusion cut-off — "
                "keeping %d CVE(s) it had enriched", len(nvd_collected),
            )
            _record_source_state(("nvd",), "timed_out")
            nvd_results = list(nvd_collected)
        else:
            nvd_results = _result("nvd")
        await _wait_for(["cisa"], deadline)
        cisa_results = _result("cisa")
        kev_results = [r for r in cisa_results if r.get("source") == "cisa_kev"]
        # P1.3: fuse NVD + CISA KEV (already fetched — no re-fetch) with EPSS +
        # Exploit-DB into ONE unified CVE view, replacing the separate NVD page
        # + KEV-CVE pages. CISA advisories still render on their own.
        try:
            from sources.cve_intel import fuse_cve_intelligence
            parts["cve"] = await asyncio.wait_for(
                fuse_cve_intelligence(query, entities, nvd_results, kev_results),
                timeout=min(CVE_FUSION_TIMEOUT_S, remaining()),
            )
        except Exception as exc:
            if isinstance(exc, asyncio.TimeoutError):
                logger.warning("cve_intel fusion timed out, falling back to legacy CVE pages")
                _record_source_state(_NEW_SOURCE_IDS["cve_fusion"], "timed_out")
            else:
                logger.warning("cve_intel fusion failed, falling back to legacy CVE pages: %s", exc)
            legacy: list[dict] = []
            if kev_results:
                legacy.extend(_cisa_results_to_pages(kev_results, query))
            if nvd_results:
                legacy.extend(_nvd_results_to_pages(nvd_results))
            parts["cve"] = legacy

    async def _overlay_part() -> None:
        # Entity-based MITRE overlay: fires when the run found actors but no
        # MITRE_TECHNIQUE entities yet.
        _actor_ents = [
            e for e in entities
            if (e.get("type") or e.get("entity_type", "")) in OVERLAY_ACTOR_TYPES
        ]
        _has_mitre = any(
            (e.get("type") or e.get("entity_type", "")) == "MITRE_TECHNIQUE"
            for e in entities
        )
        if not (_actor_ents and not _has_mitre and is_enrichment_source_enabled("mitre_attack")):
            return

        overlay: list[dict] = []
        parts["mitre_overlay"] = overlay  # published as it grows
        seen_groups: set[str] = set()
        for _actor_ent in _actor_ents:
            if cancel.is_cancelled():
                break
            _actor_name = (
                _actor_ent.get("value")
                or _actor_ent.get("canonical_value")
                or _actor_ent.get("entity_value", "")
            )
            if not _actor_name:
                continue
            page = await _mitre_overlay_page(_actor_name, seen_groups)
            if page is not None:
                overlay.append(page)

    async def _blocklists_part() -> None:
        # P1.4 — abuse/phishing blocklist matching (SSLBL / OpenPhish / PhishTank).
        # Bulk feeds matched in memory against the investigation's entities; matched
        # entities are flagged in the DB and a provenance-stamped page is emitted.
        try:
            from feeds import enrich_blocklists
            _bl_pages, _bl_stats = await enrich_blocklists(entities)
            parts["blocklists"] = _bl_pages
        except Exception as exc:
            logger.warning("blocklist enrichment failed: %s", exc)

    branches = {
        "historical": asyncio.ensure_future(_historical_part()),
        "cve_fusion": asyncio.ensure_future(_fusion_part()),
        "mitre_overlay": asyncio.ensure_future(_overlay_part()),
        "blocklists": asyncio.ensure_future(_blocklists_part()),
    }
    try:
        _, pending = await cancel.wait_cancellable(set(branches.values()), timeout=remaining())
    except asyncio.CancelledError:
        # The caller gave up on the group: stop everything, report the cut,
        # and leave the finished parts in *parts* for the caller.
        _stop_and_record(fetch, branches)
        raise
    if pending:
        _stop_and_record(fetch, branches, budget_s=budget_s)
        await asyncio.gather(*fetch.values(), *branches.values(), return_exceptions=True)
    else:
        # Every branch is done; a fetch nothing waited on (none today) must not leak.
        _stop_and_record(fetch, {}, budget_s=budget_s)
        await asyncio.gather(*fetch.values(), return_exceptions=True)

    for name, task in branches.items():
        if task.done() and not task.cancelled() and task.exception() is not None:
            logger.warning("%s part failed: %s", name, task.exception())
            _record_source_state(_NEW_SOURCE_IDS[name], "error")

    _publish_fetches()  # inputs that finished after historical intel started
    return _assemble_new_source_pages(parts, query)


def _stop_and_record(
    fetch: dict[str, asyncio.Task],
    branches: dict[str, asyncio.Task],
    budget_s: Optional[float] = None,
) -> None:
    """Cancel unfinished fetches/parts and record their sources ``timed_out``.

    Logs in the same form as ``_gather_with_partial_results`` so run logs show
    every source a deadline cut off."""
    unfinished = [n for n, t in {**fetch, **branches}.items() if not t.done()]
    if not unfinished:
        return
    if not cancel.is_cancelled():
        logger.warning(
            "_enrich_new_sources: deadline (%.0fs) hit — preserving finished parts, "
            "dropping unfinished: %s",
            budget_s or 0.0, ", ".join(unfinished),
        )
    for name in unfinished:
        if not cancel.is_cancelled():
            _record_source_state(_NEW_SOURCE_IDS[name], "timed_out")
        ({**fetch, **branches})[name].cancel()


def _cisa_results_to_pages(results: list[dict], query: str) -> list[dict]:
    pages: list[dict] = []
    kev_entries = [r for r in results if r.get("source") == "cisa_kev"]
    adv_entries = [r for r in results if r.get("source") == "cisa_advisory"]

    if kev_entries:
        lines = ["CISA Known Exploited Vulnerabilities (KEV) Catalog\n"]
        for r in kev_entries:
            lines.append(f"CVE: {r.get('entity_value', '')}")
            if r.get("vendor_project"):
                lines.append(f"  Vendor/Project: {r['vendor_project']}")
            if r.get("product"):
                lines.append(f"  Product: {r['product']}")
            if r.get("vulnerability_name"):
                lines.append(f"  Vulnerability: {r['vulnerability_name']}")
            if r.get("date_added"):
                lines.append(f"  Date Added to KEV: {r['date_added']}")
            if r.get("short_description"):
                lines.append(f"  Description: {r['short_description']}")
            lines.append("")
        pages.append({
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "cisa_kev",
            "via": "cisa_feed",
        })

    if adv_entries:
        lines = ["CISA Cybersecurity Advisories\n"]
        for r in adv_entries:
            lines.append(f"Title: {r.get('advisory_title', '')}")
            if r.get("advisory_url"):
                lines.append(f"  URL: {r['advisory_url']}")
            if r.get("advisory_date"):
                lines.append(f"  Date: {r['advisory_date']}")
            lines.append("")
        pages.append({
            "link": "https://www.cisa.gov/cybersecurity-advisories",
            "url": "https://www.cisa.gov/cybersecurity-advisories",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "cisa_advisory",
            "via": "cisa_feed",
        })

    return pages


def _nvd_results_to_pages(results: list[dict]) -> list[dict]:
    """Convert NVD 2.0 CVE results into page-shaped dicts for entity extraction."""
    if not results:
        return []
    lines = ["NVD 2.0 — National Vulnerability Database\n"]
    for r in results:
        lines.append(f"CVE: {r.get('entity_value', '')}")
        score = r.get("base_score")
        sev = r.get("base_severity") or ""
        if score is not None:
            lines.append(f"  CVSS Base Score: {score} {sev}".rstrip())
        if r.get("vector"):
            lines.append(f"  CVSS Vector: {r['vector']}")
        if r.get("cwes"):
            lines.append(f"  Weaknesses: {', '.join(r['cwes'])}")
        if r.get("vuln_status"):
            lines.append(f"  Status: {r['vuln_status']}")
        if r.get("published"):
            lines.append(f"  Published: {r['published']}")
        if r.get("last_modified"):
            lines.append(f"  Last Modified: {r['last_modified']}")
        if r.get("description"):
            lines.append(f"  Description: {r['description']}")
        lines.append("")
    content = "\n".join(lines)
    return [{
        "link": "https://nvd.nist.gov/vuln",
        "url": "https://nvd.nist.gov/vuln",
        "content": content,
        "text": content,
        "status": 200,
        "source": "nvd",
        "via": "nvd_api",
    }]


def _shodan_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        lines = [f"Shodan InternetDB: {r.get('entity_value', '')}\n"]
        if r.get("open_ports"):
            lines.append(f"Open Ports: {', '.join(str(p) for p in r['open_ports'])}")
        if r.get("hostnames"):
            lines.append(f"Hostnames: {', '.join(r['hostnames'])}")
        if r.get("tags"):
            lines.append(f"Tags: {', '.join(r['tags'])}")
        if r.get("vulns"):
            lines.append(f"Vulnerabilities: {', '.join(r['vulns'])}")
        if r.get("correlated_cves"):
            lines.append(f"Correlated CVEs (also extracted): {', '.join(r['correlated_cves'])}")
        if r.get("high_confidence_c2"):
            lines.append("** HIGH CONFIDENCE C2 **")
        pages.append({
            "link": f"https://internetdb.shodan.io/{r.get('entity_value', '')}",
            "url": f"https://internetdb.shodan.io/{r.get('entity_value', '')}",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "shodan_internetdb",
            "via": "shodan_api",
        })
    return pages


def _vt_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        lines = [f"VirusTotal: {r.get('entity_value', '')}\n"]
        lines.append(f"Detection: {r.get('malicious_count', 0)}/{r.get('total_engines', 0)} ({r.get('detection_ratio', 0):.0%})")
        if r.get("suggested_threat_label"):
            lines.append(f"Threat Label: {r['suggested_threat_label']}")
        if r.get("first_seen"):
            lines.append(f"First Seen: {r['first_seen']}")
        if r.get("last_seen"):
            lines.append(f"Last Seen: {r['last_seen']}")
        if r.get("confirmed_malicious"):
            lines.append("** CONFIRMED MALICIOUS **")
        pages.append({
            "link": f"https://www.virustotal.com/gui/file/{r.get('entity_value', '')}",
            "url": f"https://www.virustotal.com/gui/file/{r.get('entity_value', '')}",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "virustotal",
            "via": "virustotal_api",
        })
    return pages


def _group_unenriched_entities(
    entities: list[dict],
    cisa_results: list[dict],
    shodan_results: list[dict],
    vt_results: list[dict],
) -> dict[str, list[dict]]:
    """
    Determine which THREAT_ACTOR / RANSOMWARE_GROUP / MALWARE_FAMILY entities
    received zero enrichment results from CISA, Shodan, and VT.
    Returns a dict mapping entity type -> list of entities with no enrichment.
    """
    fallback_types = {"THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"}
    ent_by_type: dict[str, list[dict]] = {t: [] for t in fallback_types}

    for e in entities:
        et = e.get("type") or e.get("entity_type", "")
        if et in fallback_types:
            ent_by_type[et].append(e)

    enriched_values: set[str] = set()
    for r in cisa_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())
    for r in shodan_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())
    for r in vt_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())

    result: dict[str, list[dict]] = {}
    for et, ent_list in ent_by_type.items():
        unenriched = [
            ent for ent in ent_list
            if (ent.get("value") or ent.get("entity_value", "")).lower() not in enriched_values
        ]
        if unenriched:
            result[et] = unenriched

    return result


def _historical_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        src = r.get("source", "")
        lines = [f"Historical Intel: {r.get('entity_value', '')}\n"]
        if src == "mitre_attack":
            lines.append(f"MITRE ATT&CK ID: {r.get('mitre_id', '')}")
            lines.append(f"Name: {r.get('mitre_name', '')}")
            if r.get("aliases"):
                lines.append(f"Aliases: {', '.join(r['aliases'])}")
            if r.get("techniques"):
                lines.append(f"Techniques: {', '.join(r['techniques'])}")
            if r.get("description"):
                lines.append(f"Description: {r['description']}")
            pages.append({
                "link": f"https://attack.mitre.org/groups/{r.get('mitre_id', '')}",
                "url": f"https://attack.mitre.org/groups/{r.get('mitre_id', '')}",
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "mitre_attack",
                "via": "mitre_cti",
            })
        elif src == "fbi_doj_press":
            lines.append(f"Title: {r.get('press_title', '')}")
            lines.append(f"Date: {r.get('press_date', '')}")
            pages.append({
                "link": r.get("press_url", ""),
                "url": r.get("press_url", ""),
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "fbi_doj_press",
                "via": "fbi_rss",
            })
        elif src == "cisa_advisory_historical":
            lines.append(f"Title: {r.get('advisory_title', '')}")
            lines.append(f"URL: {r.get('advisory_url', '')}")
            lines.append(f"Date: {r.get('advisory_date', '')}")
            pages.append({
                "link": r.get("advisory_url", ""),
                "url": r.get("advisory_url", ""),
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "cisa_advisory",
                "via": "cisa_feed",
            })
    return pages


async def run_dns_enrichment(extracted_entities: list[dict]) -> dict:
    """
    Run DNS/WHOIS enrichment on extracted IP and domain entities.
    Returns ip_enrichments, domain_enrichments, new_entities, infrastructure_clusters.
    """
    # Validate OUTSIDE the try so an unknown id is never swallowed below.
    validate_enrichment_allowlist()
    try:
        from sources.dns_enrichment import enrich_with_dns
        return await enrich_with_dns(extracted_entities)
    except Exception as e:
        logger.error("DNS enrichment error: %s", e)
        return {
            "ip_enrichments": {},
            "domain_enrichments": {},
            "new_entities": [],
            "infrastructure_clusters": [],
        }


async def enrich_investigation(
    query: str,
    otx_api_key: Optional[str] = None,
    entities: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Run all threat intel sources in parallel; return page dicts for extraction.

    Sources:
    - OTX (AlienVault)      — requires OTX_API_KEY
    - MalwareBazaar          — free (ABUSECH_API_KEY improves rate limits)
    - ThreatFox              — free
    - URLhaus                — free
    - ransomware.live        — free, no key required
    - CISA KEV + advisories  — free, no key required (clearnet)
    - Shodan InternetDB      — free, no key required (clearnet)
    - VirusTotal             — requires VT_API_KEY (clearnet)

    Completes within ENRICHMENT_DEADLINE_S (59 s), wall clock: a source still
    running then contributes nothing and is reported ``timed_out``; everything
    that finished is kept (see ``_enrich_new_sources`` for the CVE/MITRE group).
    """
    # Fail loudly (outside the gather) on an unknown VOIDACCESS_ENRICHMENT_SOURCES id.
    validate_enrichment_allowlist()

    if cancel.is_cancelled():
        return []

    logger.info("Starting threat intel enrichment for: %s", query)
    loop = asyncio.get_running_loop()
    phase_deadline = loop.time() + ENRICHMENT_DEADLINE_S

    _entities = entities if entities is not None else []

    # Partial-results-preserving fan-out: if the 59s deadline hits while some
    # sources are still running, the results of sources that ALREADY finished
    # are kept (unfinished ones contribute nothing) rather than discarding the
    # entire batch.
    # VOIDACCESS_ENRICHMENT_SOURCES: coroutines are created only for enabled
    # sources. "new_sources" fans out to cisa_kev/nvd/shodan_internetdb/
    # virustotal/mitre_attack/blocklists, each gated again inside; it is skipped
    # outright only when none of those is enabled.
    _factories = [
        ("otx", "otx", lambda: fetch_otx_pulses(query, otx_api_key or "", limit=20)),
        ("malwarebazaar", "malwarebazaar", lambda: fetch_malwarebazaar(query, limit=20)),
        ("threatfox", "threatfox", lambda: fetch_threatfox(query, limit=50)),
        ("urlhaus", "urlhaus", lambda: fetch_urlhaus(query, limit=20)),
        ("ransomware_live", "ransomware_live", lambda: fetch_ransomware_live(query)),
        ("ransomlook", "ransomlook", lambda: fetch_ransomlook(query)),
    ]
    _new_source_ids = (
        "cisa_kev", "nvd", "shodan_internetdb", "virustotal", "mitre_attack",
        "fbi_doj_press", "blocklists", "sslbl", "openphish", "phishtank", "ransomwhere",
        "epss", "exploitdb",
    )
    _named: list[tuple[str, Any]] = [
        (name, factory())
        for name, sid, factory in _factories
        if is_enrichment_source_enabled(sid)
    ]
    # The group gets the phase budget minus a margin, so it returns its own
    # partial results before this gather's deadline; *new_parts* is the
    # backstop if it is cancelled anyway.
    new_parts: dict[str, Any] = {}
    if any(is_enrichment_source_enabled(sid) for sid in _new_source_ids):
        _named.append(("new_sources", _enrich_new_sources(
            query, _entities,
            budget_s=ENRICHMENT_DEADLINE_S - NEW_SOURCES_MARGIN_S,
            parts=new_parts,
        )))
    packed: dict[str, Any] = {name: [] for name, _sid, _f in _factories}
    packed["new_sources"] = []
    cut: set[str] = set()
    packed.update(await _gather_with_partial_results(
        _named,
        timeout=ENRICHMENT_DEADLINE_S,
        phase_label="Enrichment",
        unfinished=cut,
    ))
    if not cancel.is_cancelled():
        for name in cut - {"new_sources"}:
            _record_source_state(_OUTER_SOURCE_IDS[name], "timed_out")
        for name, value in packed.items():
            if isinstance(value, Exception) and name in _OUTER_SOURCE_IDS:
                _record_source_state(_OUTER_SOURCE_IDS[name], "error")
    if "new_sources" in cut:
        packed["new_sources"] = _assemble_new_source_pages(new_parts, query)

    otx_pulses = packed["otx"]
    mb_results = packed["malwarebazaar"]
    tf_results = packed["threatfox"]
    uh_results = packed["urlhaus"]
    rl_groups = packed["ransomware_live"]
    rlook_groups = packed["ransomlook"]
    new_pages = packed["new_sources"]

    if isinstance(otx_pulses, Exception):
        logger.warning("OTX failed: %s", otx_pulses)
        otx_pulses = []
    if isinstance(mb_results, Exception):
        logger.warning("MalwareBazaar failed: %s", mb_results)
        mb_results = []
    if isinstance(tf_results, Exception):
        logger.warning("ThreatFox failed: %s", tf_results)
        tf_results = []
    if isinstance(uh_results, Exception):
        logger.warning("URLhaus failed: %s", uh_results)
        uh_results = []
    if isinstance(rl_groups, Exception):
        logger.warning("ransomware.live failed: %s", rl_groups)
        rl_groups = []
    if isinstance(rlook_groups, Exception):
        logger.warning("ransomlook.io failed: %s", rlook_groups)
        rlook_groups = []
    if isinstance(new_pages, Exception):
        logger.warning("New enrichment sources failed: %s", new_pages)
        new_pages = []

    pages: list[dict] = []

    for pulse in otx_pulses:
        page = otx_pulse_to_page(pulse)
        if page.get("content"):
            pages.append(page)

    pages.extend(abusech_to_pages(mb_results, tf_results, uh_results))
    pages.extend(ransomwarelive_to_pages(rl_groups))
    pages.extend(ransomlook_to_pages(rlook_groups))
    pages.extend(new_pages or [])

    # Page-scan MITRE overlay: extract actor names from ransomware.live / OTX results
    # and inject T-codes when no MITRE techniques appear in any enrichment page.
    # This fires without a pre-extracted entity list, covering the current pipeline.
    _overlay_actor_names: list[str] = []
    for _g in (rl_groups if isinstance(rl_groups, list) else []):
        _gname = _g.get("group", "")
        if _gname and _gname not in _overlay_actor_names:
            _overlay_actor_names.append(_gname)
    for _pulse in (otx_pulses if isinstance(otx_pulses, list) else []):
        for _mf in (_pulse.get("malware_families") or []):
            _mfname = _mf if isinstance(_mf, str) else (_mf.get("display_name") or _mf.get("name", ""))
            if _mfname and _mfname not in _overlay_actor_names:
                _overlay_actor_names.append(_mfname)

    if _overlay_actor_names and is_enrichment_source_enabled("mitre_attack"):
        _t_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        _t_found = any(
            _t_pattern.search(p.get("content", "") or p.get("text", ""))
            for p in pages
        )
        if not _t_found:
            # Bounded by what is left of the phase deadline as well.
            OVERLAY_TIMEOUT = 20
            overlay_timeout = min(OVERLAY_TIMEOUT, max(0.0, phase_deadline - loop.time()))

            _q_lower = query.lower()
            _capped = _overlay_actor_names[:10]
            _prioritized = sorted(
                _capped,
                key=lambda a: 0 if a.lower() in _q_lower else 1,
            )

            async def _run_overlay():
                _results = []
                _seen: set[str] = set()
                for _aname in _prioritized:
                    if cancel.is_cancelled():
                        break
                    page = await _mitre_overlay_page(_aname, _seen)
                    if page is not None:
                        _results.append(page)
                return _results

            try:
                _overlay_pages = await asyncio.wait_for(
                    _run_overlay(),
                    timeout=overlay_timeout,
                )
                pages.extend(_overlay_pages)
            except asyncio.TimeoutError:
                logger.warning(
                    "MITRE overlay timed out after %.0fs — skipping",
                    overlay_timeout,
                )

    total_onion_seeds = sum(1 for p in pages if p.get("_scrape_seed"))
    logger.info(
        "Enrichment complete: %s OTX pulses, %s MalwareBazaar, "
        "%s ThreatFox IOCs, %s URLhaus, %s ransomware.live groups, "
        "%s ransomlook.io groups (%s .onion seeds) → %s enrichment pages total",
        len(otx_pulses), len(mb_results), len(tf_results),
        len(uh_results), len(rl_groups), len(rlook_groups),
        total_onion_seeds, len(pages),
    )

    return pages
