"""
sources/shodan.py — Shodan InternetDB integration for C2 infrastructure.

No API key required. Queries https://internetdb.shodan.io/{ip} for each
extracted IP_ADDRESS entity and returns open ports, vulnerabilities,
tags, and hostnames. Tags are used to flag high-confidence C2.

Rate-limited: max 1 request/second, max 50 IPs per investigation.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

import pacing
from sources import http_pool
from sources.enrichment_allowlist import (
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from config import MAX_IPS_PER_INVESTIGATION, SHODAN_RATE_LIMIT_DELAY

logger = logging.getLogger(__name__)

_SHODAN_INTERNETDB = "https://internetdb.shodan.io"

_C2_TAGS = {"c2", "cobalt-strike", "metasploit", "malware"}


async def enrich_shodan_ip(ip_address: str, extracted_cves: set[str]) -> dict | None:
    """
    Query Shodan InternetDB for *ip_address*.

    Returns a dict with open_ports, vulns, tags, hostnames, and
    high_confidence_c2 flag, or None on error / no data (or when
    ``shodan_internetdb`` is not in VOIDACCESS_ENRICHMENT_SOURCES).
    """
    if not is_enrichment_source_enabled("shodan_internetdb"):
        return None
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with http_pool.clearnet_session() as session:
            async with session.get(f"{_SHODAN_INTERNETDB}/{ip_address}", timeout=timeout) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    logger.warning("Shodan InternetDB: HTTP %s for %s", resp.status, ip_address)
                    return None
                data = await resp.json()
    except asyncio.TimeoutError:
        logger.warning("Shodan InternetDB: timeout for %s", ip_address)
        return None
    except Exception as e:
        logger.warning("Shodan InternetDB: error for %s: %s", ip_address, e)
        return None

    raw_tags = [t.lower() for t in data.get("tags") or []]
    high_confidence_c2 = bool(raw_tags and set(raw_tags) & _C2_TAGS)

    vulns = data.get("vulns") or {}
    cve_set = set(vulns.keys())
    correlated_cves = cve_set & extracted_cves if extracted_cves else set()

    return {
        "source": "shodan_internetdb",
        "entity_type": "IP_ADDRESS",
        "entity_value": ip_address,
        "open_ports": data.get("ports") or [],
        "vulns": list(cve_set),
        "correlated_cves": list(correlated_cves),
        "tags": raw_tags,
        "hostnames": data.get("hostnames") or [],
        "high_confidence_c2": high_confidence_c2,
    }


async def enrich_shodan(entities: list[dict]) -> list[dict]:
    """
    For each IP_ADDRESS entity in *entities*, query Shodan InternetDB.

    Rate-limited to SHODAN_RATE_LIMIT_DELAY between requests.
    Capped at MAX_IPS_PER_INVESTIGATION IPs.
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently
    if not is_enrichment_source_enabled("shodan_internetdb"):
        return []
    ip_entities = [
        e for e in entities
        if (e.get("type") or e.get("entity_type", "")) == "IP_ADDRESS"
        and (e.get("value") or e.get("entity_value", ""))
    ]

    extracted_cves: set[str] = {
        e.get("value") or e.get("entity_value", "")
        for e in entities
        if (e.get("type") or e.get("entity_type", "")) == "CVE_NUMBER"
        and (e.get("value") or e.get("entity_value", ""))
    }

    ips_to_query = [
        ip_ent.get("value") or ip_ent.get("entity_value", "")
        for ip_ent in ip_entities
    ][:MAX_IPS_PER_INVESTIGATION]

    results: list[dict] = []
    for ip in ips_to_query:
        result = await enrich_shodan_ip(ip, extracted_cves)
        if result is not None:
            results.append(result)
        await asyncio.sleep(pacing.scale_delay_floor(SHODAN_RATE_LIMIT_DELAY))

    return results
