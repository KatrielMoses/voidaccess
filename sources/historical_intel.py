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
from utils import cancel
from sources.enrichment_allowlist import (
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)

logger = logging.getLogger(__name__)

_MITRE_CACHE = "/tmp/voidaccess_mitre_attack.json"
_FBI_CACHE = "/tmp/voidaccess_fbi_press.xml"

# Common names that ATT&CK lists as a name or alias of the same intrusion set,
# applied before exact resolution. Only names ATT&CK itself attributes belong
# here: a ransomware or malware brand is not an alias of the group that ATT&CK
# says used it (tests/test_e5_sources.py checks every entry against ATT&CK).
ACTOR_ALIASES = {
    "ta505": "TA505",
    "apt28": "APT28",
    "fancy bear": "APT28",
    "fin7": "FIN7",
}

_mitre_feed = CachedFeed(
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    _MITRE_CACHE,
    ttl_seconds=604800,
)
# justice.gov retired /news/press-releases/rss; /news/rss is the live feed (the
# same one rss_scraper reads; verified 2026-10-17). It is RSS, not JSON.
_fbi_feed = CachedFeed(
    "https://www.justice.gov/news/rss",
    _FBI_CACHE,
    ttl_seconds=43200,
    parse="rss")

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


class _AttackIndex:
    """Exact-match lookups over one ATT&CK STIX bundle (built once per bundle).

    A name resolves to an intrusion set only by exact, case-insensitive match
    on the set's name or one of its aliases, after ACTOR_ALIASES; never by
    substring. A term that is only an *alias* of a set and is also an ATT&CK
    software name or alias ("Snake": a Turla alias and the Uroburos implant) is
    ambiguous and resolves to nothing; a set's own name wins ("Play" is the
    group G1040 even though Playcrypt lists it as an alias). Revoked and
    deprecated objects are ignored.
    """

    def __init__(self, objects: list) -> None:
        live = [o for o in objects if isinstance(o, dict)
                and not o.get("revoked") and not o.get("x_mitre_deprecated")]
        self.by_name: dict[str, dict] = {}
        self.by_alias: dict[str, dict] = {}
        self.software: set[str] = set()
        technique_ids: dict[str, str] = {}
        for obj in live:
            kind = obj.get("type")
            if kind == "intrusion-set":
                name = (obj.get("name") or "").strip().lower()
                if name:
                    self.by_name.setdefault(name, obj)
                for alias in obj.get("aliases") or []:
                    self.by_alias.setdefault(str(alias).strip().lower(), obj)
            elif kind in ("tool", "malware"):
                for term in [obj.get("name")] + list(obj.get("x_mitre_aliases") or []):
                    if term:
                        self.software.add(str(term).strip().lower())
            elif kind == "attack-pattern":
                for ref in obj.get("external_references") or []:
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        if ext_id.startswith("T"):
                            technique_ids[obj.get("id", "")] = ext_id
                        break
        self.techniques: dict[str, list[str]] = {}
        for obj in live:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                t_code = technique_ids.get(obj.get("target_ref", ""))
                if t_code:
                    codes = self.techniques.setdefault(obj.get("source_ref", ""), [])
                    if t_code not in codes:
                        codes.append(t_code)

    def resolve(self, actor_name: str) -> Optional[dict]:
        q = (actor_name or "").strip().lower()
        if not q:
            return None
        q = ACTOR_ALIASES.get(q, q).lower()
        if q in self.by_name:
            return self.by_name[q]
        if q in self.by_alias and q not in self.software:
            return self.by_alias[q]
        return None


_attack_index_cache: dict[int, _AttackIndex] = {}


def _attack_index(data) -> _AttackIndex:
    key = id(data)
    index = _attack_index_cache.get(key)
    if index is None:
        objects = data if isinstance(data, list) else data.get("objects", [])
        index = _AttackIndex(objects)
        _attack_index_cache.clear()  # one bundle per process
        _attack_index_cache[key] = index
    return index


def group_id(group: dict) -> str:
    for ref in group.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


async def _fetch_mitre_index() -> Optional[_AttackIndex]:
    if not is_enrichment_source_enabled("mitre_attack"):
        return None
    data = await _mitre_feed.fetch()
    if data is None:
        return None
    return _attack_index(data)


async def _fetch_fbi_results(entity_value: str) -> list[dict]:
    if not is_enrichment_source_enabled("fbi_doj_press"):
        return []
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


async def get_group_techniques(actor_name: str) -> Optional[tuple[str, str, list[str]]]:
    """``(group name, group id, T-codes)`` for the ATT&CK group *actor_name*
    names exactly (see :class:`_AttackIndex`), or ``None``."""
    index = await _fetch_mitre_index()
    if index is None:
        return None
    group = index.resolve(actor_name)
    if group is None:
        return None
    return group.get("name", ""), group_id(group), list(index.techniques.get(group.get("id", ""), []))


async def get_techniques_for_actor(actor_name: str) -> list[str]:
    """Return MITRE ATT&CK T-codes used by the threat group *actor_name* names.

    Exact, case-insensitive match on an intrusion set's name or alias (after
    ACTOR_ALIASES), never a substring, and never an ATT&CK software name. Returns
    [] when there is no such group, the cache is unavailable, or ``mitre_attack``
    is not enabled.
    """
    found = await get_group_techniques(actor_name)
    return found[2] if found else []


async def enrich_historical(entities_by_type: dict[str, list[dict]]) -> list[dict]:
    """
    Historical fallback enrichment.

    *entities_by_type* is a dict mapping entity type string ->
    list of entity dicts that had no enrichment results.

    Only processes THREAT_ACTOR, RANSOMWARE_GROUP, MALWARE_FAMILY.

    Gated per sub-source by VOIDACCESS_ENRICHMENT_SOURCES: ``mitre_attack``
    (STIX index), ``fbi_doj_press`` (justice.gov RSS) and ``cisa_kev`` (CISA
    advisories feed). A disabled one contributes nothing.
    """
    validate_enrichment_allowlist()
    fallback_types = {"THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"}
    relevant_entities = []
    for et in fallback_types:
        relevant_entities.extend(entities_by_type.get(et, []))

    if not relevant_entities:
        return []

    results: list[dict] = []
    mitre_index: Optional[_AttackIndex] = None
    mitre_loaded = False

    for ent in relevant_entities:
        if cancel.is_cancelled():
            break  # cancel checkpoint between entities
        ev = ent.get("value") or ent.get("entity_value", "")
        if not ev:
            continue

        q = ev.lower()

        if not mitre_loaded:
            mitre_index = await _fetch_mitre_index()
            mitre_loaded = True

        mitre_match = mitre_index.resolve(q) if mitre_index is not None else None
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

        if any(
            is_enrichment_source_enabled(_sid)
            for _sid in ("mitre_attack", "fbi_doj_press", "cisa_kev")
        ):
            await asyncio.sleep(pacing.scale_delay_floor(ENTITY_REQUEST_DELAY))

    return results


async def _cisa_advisory_for_entity(entity_value: str, entity_type: str) -> Optional[dict]:
    if not is_enrichment_source_enabled("cisa_kev"):
        return None
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
                "advisory_url": adv.get("url") or adv.get("link", ""),
                "advisory_date": adv.get("datePublished") or adv.get("published", ""),
            }
    return None
