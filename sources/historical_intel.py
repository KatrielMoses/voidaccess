"""
sources/historical_intel.py — Historical threat-actor fallback enrichment.

Activated ONLY when:
  a) entity type is THREAT_ACTOR, RANSOMWARE_GROUP, or MALWARE_FAMILY
  b) all other enrichment sources returned 0 results for this entity

Queries:
  A. CISA advisories (cache already populated by sources/cisa.py)
  B. MITRE ATT&CK STIX data (7-day cache, ~50MB)
  C. FBI/DOJ press releases RSS (12-hour cache)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional


import pacing
from sources.cache import CachedFeed

logger = logging.getLogger(__name__)

_MITRE_CACHE = "/tmp/voidaccess_mitre_attack.json"
_FBI_CACHE = "/tmp/voidaccess_fbi_press.json"

ACTOR_ALIASES = {
    "revil": "Wizard Spider",
    "sodinokibi": "Wizard Spider",
    "gandcrab": "Wizard Spider",
    "lockbit": None,
    "conti": "Wizard Spider",
    "ryuk": "Wizard Spider",
    "trickbot": "Wizard Spider",
    "darkside": "FIN7",
    "blackmatter": "FIN7",
    "alphv": None,
    "blackcat": None,
    "hive": None,
    "cl0p": "TA505",
    "ta505": "TA505",
    "cobalt strike": "Cobalt Group",
    "apt28": "APT28",
    "fancy bear": "APT28",
    "lazarus": "Lazarus Group",
    "apt38": "Lazarus Group",
    "fin7": "FIN7",
    "carbanak": "FIN7",
}

_mitre_feed = CachedFeed(
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    _MITRE_CACHE,
    ttl_seconds=604800,
)
# /news/press-releases/rss 404s (verified 2026-10-09). sources/rss_scraper.py
# reads the all-news replacement /news/rss and filters downstream; here the
# lookup is on press-release titles only, so restrict the feed with ?type=.
_fbi_feed = CachedFeed(
    "https://www.justice.gov/news/rss?type=press_release",
    _FBI_CACHE,
    ttl_seconds=43200)

# Per-entity pacing across the MITRE / DOJ / CISA fan-out (verified 2026-07-29):
#
#   raw.githubusercontent.com (MITRE CTI) — 60 req/HOUR unauthenticated since
#     GitHub's May 2025 change.  A real quota, but an hourly one.
#   justice.gov RSS, cisa.gov feeds       — no published limit; courtesy only.
#
# Routed through pacing.scale_delay_floor() on the strength of the GitHub side.
# The long feed TTLs above (7 days for MITRE, 12 h for DOJ) are what actually
# keeps us clear of the hourly cap; this delay only smooths the per-entity loop.
ENTITY_REQUEST_DELAY = 0.5


async def _fetch_mitre_index() -> dict:
    data = await _mitre_feed.fetch()
    if data is None:
        return {}

    index: dict = {}
    objects = data if isinstance(data, list) else data.get("objects", [])
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        name = (obj.get("name") or "").lower()
        aliases = [a.lower() for a in obj.get("aliases") or []]
        for key in [name] + aliases:
            if key:
                index[key] = obj
    return index


async def _fetch_fbi_results(entity_value: str) -> list[dict]:
    data = await _fbi_feed.fetch()
    if data is None:
        return []

    entries = data if isinstance(data, list) else []
    q = entity_value.lower()
    results = []

    for entry in entries:
        title = (entry.get("title") or "").lower()
        if q in title:
            results.append({
                "source": "fbi_doj_press",
                "entity_value": entity_value,
                "press_title": entry.get("title", ""),
                "press_url": entry.get("link", ""),
                "press_date": entry.get("published", ""),
            })
    return results


async def get_techniques_for_actor(actor_name: str) -> list[str]:
    """Return MITRE ATT&CK T-codes used by a threat group (case-insensitive partial match).

    Searches group names and aliases in the local STIX cache, then follows
    ``uses`` relationships to attack-pattern objects to collect T-codes.
    Returns [] when the actor is not found or the cache is unavailable.
    """
    data = await _mitre_feed.fetch()
    if data is None:
        return []

    objects = data if isinstance(data, list) else data.get("objects", [])
    q = actor_name.lower()

    alias_result = ACTOR_ALIASES.get(q)
    if alias_result is None and q in ACTOR_ALIASES:
        return []
    if alias_result is not None:
        q = alias_result.lower()

    # Locate intrusion-set STIX ID by name / alias (partial match)
    group_stix_id: Optional[str] = None
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        name = (obj.get("name") or "").lower()
        aliases = [a.lower() for a in (obj.get("aliases") or [])]
        if q in name or any(q in alias for alias in aliases):
            group_stix_id = obj.get("id")
            break

    if not group_stix_id:
        return []

    # Build attack-pattern stix_id → T-code lookup
    technique_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in (obj.get("external_references") or []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id.startswith("T"):
                    technique_map[obj.get("id", "")] = ext_id
                    break

    # Collect T-codes via "uses" relationships from this group
    t_codes: list[str] = []
    seen: set[str] = set()
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == group_stix_id
        ):
            t_code = technique_map.get(obj.get("target_ref", ""))
            if t_code and t_code not in seen:
                seen.add(t_code)
                t_codes.append(t_code)

    return t_codes


async def enrich_historical(entities_by_type: dict[str, list[dict]]) -> list[dict]:
    """
    Historical fallback enrichment.

    *entities_by_type* is a dict mapping entity type string ->
    list of entity dicts that had no enrichment results.

    Only processes THREAT_ACTOR, RANSOMWARE_GROUP, MALWARE_FAMILY.
    """
    fallback_types = {"THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"}
    relevant_entities = []
    for et in fallback_types:
        relevant_entities.extend(entities_by_type.get(et, []))

    if not relevant_entities:
        return []

    results: list[dict] = []
    mitre_index: dict = {}

    for ent in relevant_entities:
        ev = ent.get("value") or ent.get("entity_value", "")
        if not ev:
            continue

        q = ev.lower()

        if not mitre_index:
            mitre_index = await _fetch_mitre_index()

        mitre_match = mitre_index.get(q)
        if mitre_match:
            results.append({
                "source": "mitre_attack",
                "entity_type": ent.get("type") or ent.get("entity_type", ""),
                "entity_value": ev,
                "mitre_id": mitre_match.get("external_references", [{}])[0].get("external_id", ""),
                "mitre_name": mitre_match.get("name", ""),
                "aliases": mitre_match.get("aliases", []),
                "description": mitre_match.get("description", ""),
                "techniques": [
                    ref.get("external_id", "")
                    for ref in mitre_match.get("external_references") or []
                    if ref.get("source_name") == "mitre-attack"
                ],
            })

        fbi_results = await _fetch_fbi_results(ev)
        results.extend(fbi_results)

        cisa_adv = await _cisa_advisory_for_entity(ev, ent.get("type") or ent.get("entity_type", ""))
        if cisa_adv:
            results.append(cisa_adv)

        await asyncio.sleep(pacing.scale_delay_floor(ENTITY_REQUEST_DELAY))

    return results


async def _cisa_advisory_for_entity(entity_value: str, entity_type: str) -> Optional[dict]:
    try:
        from sources.cisa import _adv_feed
    except Exception:
        return None

    data = await _adv_feed.fetch()
    if data is None:
        return None

    advisories = data if isinstance(data, list) else data.get("items", [])
    q = entity_value.lower()

    for adv in advisories:
        title = (adv.get("title") or "").lower()
        tags = " ".join(adv.get("tags") or []).lower()
        if q in title or q in tags:
            return {
                "source": "cisa_advisory_historical",
                "entity_type": entity_type,
                "entity_value": entity_value,
                "advisory_title": adv.get("title", ""),
                "advisory_url": adv.get("url", ""),
                "advisory_date": adv.get("datePublished", ""),
            }
    return None
