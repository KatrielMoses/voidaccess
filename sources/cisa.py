"""
sources/cisa.py — CISA KEV catalog + CISA advisories feed enrichment.

Fetches two CISA feeds (clearnet, not through Tor):
  1. Known Exploited Vulnerabilities (KEV) catalog — 24-hour TTL cache
  2. Cybersecurity advisories index — 6-hour TTL cache

For CVE entities: checks if they appear in the KEV catalog and marks them
as actively exploited.
For THREAT_ACTOR / RANSOMWARE_GROUP / MALWARE_FAMILY entities: searches
advisory titles and tags for name matches.
"""

from __future__ import annotations

import logging

from sources.cache import CachedFeed

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.json"

_KEV_CACHE = "/tmp/voidaccess_cisa_kev.json"
_ADVISORIES_CACHE = "/tmp/voidaccess_cisa_advisories.json"

_kev_feed = CachedFeed(CISA_KEV_URL, _KEV_CACHE, ttl_seconds=86400)
_adv_feed = CachedFeed(CISA_ADVISORIES_URL, _ADVISORIES_CACHE, ttl_seconds=21600)


async def enrich_cisa_cve(cve_id: str) -> list[dict]:
    """
    Check if *cve_id* appears in the CISA KEV catalog.

    Returns a list with one EnrichmentResult dict if found, empty list otherwise.
    """
    data = await _kev_feed.fetch()
    if data is None:
        return []

    kev_list = data if isinstance(data, list) else data.get("vulnerabilities", [])
    for entry in kev_list:
        if (entry.get("cveID") or "").upper() == cve_id.upper():
            return [{
                "source": "cisa_kev",
                "entity_type": "CVE_NUMBER",
                "entity_value": cve_id,
                "is_actively_exploited": True,
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "date_added": entry.get("dateAdded", ""),
                "short_description": entry.get("shortDescription", ""),
                # Added P1.3 (additive): remediation due date + whether the CVE is
                # known to be used in ransomware campaigns — both feed the fused
                # CVE-priority signal in sources/cve_intel.py.
                "due_date": entry.get("dueDate", ""),
                "ransomware_use": (entry.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            }]
    return []


async def enrich_cisa_advisories(entity_value: str, entity_type: str) -> list[dict]:
    """
    Search CISA advisories for *entity_value* matching THREAT_ACTOR,
    RANSOMWARE_GROUP, or MALWARE_FAMILY.
    """
    if entity_type not in ("THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"):
        return []

    data = await _adv_feed.fetch()
    if data is None:
        return []

    advisories = data if isinstance(data, list) else data.get("items", [])
    results = []
    q = entity_value.lower()

    for adv in advisories:
        title = (adv.get("title") or "").lower()
        tags = " ".join(adv.get("tags") or []).lower()
        if q in title or q in tags:
            results.append({
                "source": "cisa_advisory",
                "entity_type": entity_type,
                "entity_value": entity_value,
                "advisory_title": adv.get("title", ""),
                "advisory_url": adv.get("url", ""),
                "advisory_date": adv.get("datePublished", ""),
            })
    return results


async def enrich_cisa(query: str, entities: list[dict]) -> list[dict]:
    """
    Main entry point for CISA enrichment.

    For each CVE entity, checks KEV.
    For each THREAT_ACTOR / RANSOMWARE_GROUP / MALWARE_FAMILY entity, searches advisories.
    """
    results: list[dict] = []
    for ent in entities:
        et = ent.get("type") or ent.get("entity_type", "")
        ev = ent.get("value") or ent.get("entity_value", "")

        if et == "CVE_NUMBER" and ev:
            results.extend(await enrich_cisa_cve(ev))
        elif et in ("THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY") and ev:
            results.extend(await enrich_cisa_advisories(ev, et))

    return results
