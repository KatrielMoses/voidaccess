"""
export/stix.py — Converts VoidAccess entities and investigations into STIX 2.1 bundles.

Uses the stix2 Python library throughout; no manual JSON construction.

Public interface
----------------
entity_to_stix_indicator(entity)                                    → stix2.Indicator | None
entity_to_stix_malware(entity)                                      → stix2.Malware | None
entity_to_stix_threat_actor(entity)                                 → stix2.ThreatActor | None
investigation_to_stix_bundle(investigation_id, include_relationships) → stix2.Bundle
bundle_to_json(bundle)                                              → str
bundle_to_dict(bundle)                                              → dict
"""

from __future__ import annotations

import json
import logging
import os
import re
import warnings
from typing import Any, Optional
import uuid

from extractor.confidence import get_entity_confidence

logger = logging.getLogger(__name__)

# MED-9: suppress SQLAlchemy SAWarning from ORM IN-clause coercion internals.
# This is a belt-and-suspenders guard — the actual fix for this warning is
# replacing the subquery-IN pattern with a JOIN (Phase 0).  Keeping this filter
# here prevents any residual SAWarnings from leaking to stderr on every export.
try:
    import sqlalchemy
    warnings.filterwarnings(
        "ignore",
        message=r".*IN expression list.*",
        category=sqlalchemy.exc.SAWarning,
    )
except Exception:
    pass  # Non-fatal if sqlalchemy is not installed
_LAST_RELATIONSHIP_WARNING: Optional[str] = None

# ---------------------------------------------------------------------------
# Graceful import of stix2
# ---------------------------------------------------------------------------

try:
    import stix2  # type: ignore
    _STIX2_AVAILABLE = True
except ImportError:
    stix2 = None  # type: ignore
    _STIX2_AVAILABLE = False
    logger.warning(
        "stix2 not installed — export/stix.py functions will return None / empty Bundle"
    )


# ---------------------------------------------------------------------------
# STIX pattern templates per entity type
# ---------------------------------------------------------------------------

_STIX_PATTERNS: dict[str, str] = {
    "BITCOIN_ADDRESS":   "[cryptocurrency-wallet:address = '{value}']",
    "ETHEREUM_ADDRESS":  "[cryptocurrency-wallet:address = '{value}']",
    "MONERO_ADDRESS":    "[cryptocurrency-wallet:address = '{value}']",
    "EMAIL_ADDRESS":     "[email-message:from_ref.value = '{value}']",
    "FILE_HASH_MD5":     "[file:hashes.MD5 = '{value}']",
    "FILE_HASH_SHA1":    "[file:hashes.'SHA-1' = '{value}']",
    "FILE_HASH_SHA256":  "[file:hashes.'SHA-256' = '{value}']",
    "ONION_URL":         "[url:value = '{value}']",
    "IP_ADDRESS":        "[ipv4-addr:value = '{value}']",
    "CVE_NUMBER":        "[vulnerability:name = '{value}']",
    "MALWARE_FAMILY":    "[malware:name = '{value}']",
    "RANSOMWARE_GROUP":  "[malware:name = '{value}']",
}

# Entity types that map to STIX Malware objects
_MALWARE_TYPES = frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP"})

# STIX 2.1's malware-type vocabulary is intentionally small.  Keep the
# mapping here instead of treating every MALWARE_FAMILY as the generic
# ``malware`` type: family names and enrichment metadata often carry enough
# information for SIEM consumers to filter useful categories.
_STIX_MALWARE_TYPE_ALIASES = {
    "infostealer": "spyware",
    "stealer": "spyware",
    "remote_access_trojan": "remote-access-trojan",
    "remote access trojan": "remote-access-trojan",
    "rat": "remote-access-trojan",
    "coinminer": "resource-exploitation",
    "cryptominer": "resource-exploitation",
    "crypto-miner": "resource-exploitation",
    "miner": "resource-exploitation",
}
_STIX_MALWARE_TYPES = frozenset({
    "adware",
    "backdoor",
    "bot",
    "ddos",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rootkit",
    "screen-capture",
    "spyware",
    "wiper",
    "malware",
})

# These are conservative, high-signal family/name hints.  Unknown families
# retain the valid generic STIX type rather than being assigned a speculative
# category.
_MALWARE_NAME_PATTERNS = (
    ("ransomware", re.compile(
        r"\b(?:ransomware|lockbit|blackcat|alphv|clop|conti|ryuk|hive|revil|darkside|wannacry)\b",
        re.IGNORECASE,
    )),
    ("remote-access-trojan", re.compile(
        r"\b(?:remote\s+access\s+trojan|remcos|njrat|nanocore|quasar|darkcomet|xrat)\b",
        re.IGNORECASE,
    )),
    ("spyware", re.compile(
        r"\b(?:spyware|infostealer|stealer|redline|vidar|lumma|raccoon|agent\s+tesla|formbook)\b",
        re.IGNORECASE,
    )),
    ("bot", re.compile(
        r"\b(?:botnet|emotet|qakbot|qbot|trickbot|mirai|zeus|mozi)\b",
        re.IGNORECASE,
    )),
    ("keylogger", re.compile(r"\bkeylogger\b", re.IGNORECASE)),
    ("exploit-kit", re.compile(r"\bexploit[\s-]+kit\b", re.IGNORECASE)),
    ("rootkit", re.compile(r"\brootkit\b", re.IGNORECASE)),
    ("screen-capture", re.compile(r"\bscreen[\s-]+capture\b", re.IGNORECASE)),
    ("dropper", re.compile(r"\bdropper\b", re.IGNORECASE)),
    ("wiper", re.compile(r"\bwiper\b", re.IGNORECASE)),
    ("adware", re.compile(r"\badware\b", re.IGNORECASE)),
    ("resource-exploitation", re.compile(
        r"\b(?:cryptominer|crypto[\s-]+miner|coinminer|cryptojacking)\b",
        re.IGNORECASE,
    )),
    ("backdoor", re.compile(r"\bbackdoor\b", re.IGNORECASE)),
)


def _entity_attribute(entity: Any, name: str) -> Any:
    """Read optional classification metadata from dicts and ORM-like rows."""
    if isinstance(entity, dict):
        return entity.get(name)
    return getattr(entity, name, None)


def _normalise_malware_type(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("_", " ")
    key = _STIX_MALWARE_TYPE_ALIASES.get(key, key)
    key = key.replace(" ", "-")
    return key if key in _STIX_MALWARE_TYPES else None


def _classify_malware(entity: Any) -> list[str]:
    """Return evidence-backed STIX malware types for an entity."""
    entity_type = str(getattr(entity, "entity_type", "") or "").upper()
    if isinstance(entity, dict):
        entity_type = str(entity.get("entity_type") or "").upper()
    if entity_type == "RANSOMWARE_GROUP":
        return ["ransomware"]

    for field_name in ("malware_types", "malware_type", "malware_category", "category", "family_type"):
        raw = _entity_attribute(entity, field_name)
        values = raw if isinstance(raw, (list, tuple, set)) else [raw]
        classified = [item for item in (_normalise_malware_type(v) for v in values) if item]
        if classified:
            return list(dict.fromkeys(classified))

    evidence = " ".join(
        str(_entity_attribute(entity, field) or "")
        for field in ("value", "context_snippet")
    )
    for malware_type, pattern in _MALWARE_NAME_PATTERNS:
        if pattern.search(evidence):
            return [malware_type]
    return ["malware"]

# ---------------------------------------------------------------------------
# Confidence mapping: VoidAccess float → STIX integer (0-100)
# ---------------------------------------------------------------------------


def _to_stix_confidence(confidence: float) -> int:
    return min(100, max(0, int(round(confidence * 100))))


# ---------------------------------------------------------------------------
# Public conversion functions
# ---------------------------------------------------------------------------


def entity_to_stix_indicator(entity: Any) -> Optional[Any]:
    """
    Convert a single NormalizedEntity to a STIX 2.1 Indicator object.

    Returns None for entity types without a clear STIX pattern mapping,
    and returns None (with a warning) if stix2 is not installed.
    """
    if not _STIX2_AVAILABLE:
        return None

    pattern_template = _STIX_PATTERNS.get(entity.entity_type)
    if pattern_template is None:
        return None

    safe_value = entity.value.replace("'", "\\'")
    pattern = pattern_template.format(value=safe_value)

    # Determine indicator_types from entity_type
    indicator_types = ["unknown"]
    etype = entity.entity_type
    if etype in ("MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        indicator_types = ["malicious-activity"]
    elif etype in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS"):
        indicator_types = ["malicious-activity"]
    elif etype in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
        indicator_types = ["malicious-activity"]
    elif etype in ("IP_ADDRESS", "ONION_URL"):
        indicator_types = ["malicious-activity"]
    elif etype == "CVE_NUMBER":
        indicator_types = ["compromised"]

    try:
        indicator = stix2.Indicator(
            name=f"{entity.entity_type}: {entity.value[:80]}",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
            confidence=_to_stix_confidence(get_entity_confidence(entity)),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return indicator
    except Exception as exc:
        logger.warning("entity_to_stix_indicator failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_malware(entity: Any) -> Optional[Any]:
    """
    Convert a MALWARE_FAMILY or RANSOMWARE_GROUP entity to a STIX 2.1 Malware object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type not in _MALWARE_TYPES:
        return None

    try:
        malware = stix2.Malware(
            name=entity.value,
            is_family=True,
            malware_types=_classify_malware(entity),
            confidence=_to_stix_confidence(get_entity_confidence(entity)),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return malware
    except Exception as exc:
        logger.warning("entity_to_stix_malware failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_identity(entity: Any) -> Optional[Any]:
    """Convert an organization entity to a STIX Identity object."""
    if not _STIX2_AVAILABLE or entity.entity_type != "ORGANIZATION_NAME":
        return None
    try:
        return stix2.Identity(
            name=entity.value,
            identity_class="organization",
            confidence=_to_stix_confidence(get_entity_confidence(entity)),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
    except Exception as exc:
        logger.warning("entity_to_stix_identity failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_threat_actor(entity: Any) -> Optional[Any]:
    """
    Convert a THREAT_ACTOR_HANDLE entity to a STIX 2.1 ThreatActor object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type != "THREAT_ACTOR_HANDLE":
        return None

    try:
        threat_actor = stix2.ThreatActor(
            name=entity.value,
            aliases=[entity.value],
            confidence=_to_stix_confidence(get_entity_confidence(entity)),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return threat_actor
    except Exception as exc:
        logger.warning(
            "entity_to_stix_threat_actor failed for %r: %s", entity.value, exc
        )
        return None


def investigation_to_stix_bundle(
    investigation_id: Any,
    include_relationships: bool = True,
    entity_ids: Optional[list[str]] = None,
) -> Any:
    """
    Load all entities for an investigation and return a STIX 2.1 Bundle.

    If include_relationships=True, adds STIX Relationship objects for entity pairs
    that have edges in the graph (loaded via graph.build_graph_from_db).

    Returns an empty Bundle if:
    - stix2 is not installed
    - DATABASE_URL is not set
    - investigation not found
    """
    if not _STIX2_AVAILABLE:
        _set_relationship_warning("stix2 is not installed")
        return _empty_bundle()

    filter_uuids: Optional[list[uuid.UUID]] = None
    if entity_ids:
        filter_uuids = []
        for raw in entity_ids:
            try:
                filter_uuids.append(uuid.UUID(str(raw)))
            except (ValueError, AttributeError):
                continue
        if not filter_uuids:
            return _empty_bundle()

    entities = _load_entities_for_investigation(investigation_id, entity_ids=filter_uuids)
    if not entities:
        return _empty_bundle()

    from extractor.identity import entity_canonical_id, entity_graph_id  # noqa: PLC0415

    stix_objects: list[Any] = []
    # Maps BOTH the graph node id AND the bare canonical value → stix_object.id.
    # Graph edges are keyed by the graph node id (which for THREAT_ACTOR_HANDLE
    # is "<canonical>@domain", not the bare value); registering only the bare
    # value silently dropped every threat-actor relationship — the exact
    # "silently dropped relationships" failure the CHANGELOG keeps re-fixing.
    #
    # Both keys are now derived through extractor.identity, the *same* module
    # the graph builder uses to generate node ids.  The two sides can no longer
    # diverge (e.g. "LockBit" vs "lockbit") because they are literally the same
    # function call, not two functions that happen to agree today.
    stix_id_map: dict[str, str] = {}

    def _register(entity: Any, stix_id: str) -> None:
        try:
            stix_id_map.setdefault(entity_canonical_id(entity), stix_id)
        except Exception:
            stix_id_map.setdefault(entity.value, stix_id)
        try:
            node_id = entity_graph_id(entity)
        except Exception:
            node_id = entity.value
        if node_id:
            stix_id_map.setdefault(node_id, stix_id)

    for entity in entities:
        indicator = entity_to_stix_indicator(entity)
        if indicator:
            stix_objects.append(indicator)
            _register(entity, indicator.id)

        malware = entity_to_stix_malware(entity)
        if malware:
            stix_objects.append(malware)
            _register(entity, malware.id)

        actor = entity_to_stix_threat_actor(entity)
        if actor:
            stix_objects.append(actor)
            _register(entity, actor.id)

        identity = entity_to_stix_identity(entity)
        if identity:
            stix_objects.append(identity)
            _register(entity, identity.id)

    if include_relationships and stix_objects:
        relationships, relationship_warning = _build_stix_relationships(
            investigation_id, stix_id_map
        )
        stix_objects.extend(relationships)
        _set_relationship_warning(relationship_warning)
    else:
        _set_relationship_warning(None)

    try:
        return stix2.Bundle(*stix_objects, allow_custom=True)
    except Exception as exc:
        logger.warning("investigation_to_stix_bundle: Bundle construction failed: %s", exc)
        return _empty_bundle()


def bundle_to_json(bundle: Any) -> str:
    """Return JSON string of a STIX bundle (pretty-printed, 2-space indent)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return "{}"
    try:
        return bundle.serialize(pretty=True, indent=2)
    except Exception as exc:
        logger.warning("bundle_to_json failed: %s", exc)
        return "{}"


def bundle_to_dict(bundle: Any) -> dict:
    """Return a plain Python dict representation of the bundle (no stix2 objects)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return {}
    try:
        raw = bundle_to_json(bundle)
        return json.loads(raw)
    except Exception as exc:
        logger.warning("bundle_to_dict failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _empty_bundle() -> Any:
    """Return an empty STIX Bundle, or a plain dict sentinel if stix2 absent."""
    if not _STIX2_AVAILABLE:
        return None
    try:
        return stix2.Bundle(allow_custom=True)
    except Exception:
        return stix2.Bundle()


def _set_relationship_warning(message: Optional[str]) -> None:
    global _LAST_RELATIONSHIP_WARNING
    _LAST_RELATIONSHIP_WARNING = message


def get_last_relationship_warning() -> Optional[str]:
    """Return the last relationship-build warning, if any."""
    return _LAST_RELATIONSHIP_WARNING


def _load_entities_for_investigation(
    investigation_id: Any,
    entity_ids: Optional[list[uuid.UUID]] = None,
    session: Optional[Any] = None,
) -> list[Any]:
    """
    Load entities from DB for the given investigation_id.

    Includes entities owned directly by the investigation AND entities linked
    via InvestigationEntityLink (canonical dedup junction table).

    Parameters
    ----------
    investigation_id: UUID or string UUID of the investigation.
    entity_ids: Optional list of entity UUIDs to filter to.
    session: Optional existing SQLAlchemy Session. When provided, the caller
        controls the session boundary (commits, rollbacks). When None (the
        default), this function opens its own session via get_session() and
        commits on exit. Exposing session enables test injection of the
        fixture's session so the function sees uncommitted data.

    Returns [] if DATABASE_URL is not set, investigation not found, or any error.
    """
    if session is None and not os.getenv("DATABASE_URL"):
        return []

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
        from db.models import Entity, InvestigationEntityLink  # noqa: PLC0415
        from extractor.normalizer import NormalizedEntity  # noqa: PLC0415
        from export._entity_loading import normalized_entity_from_db_row  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return []

        def _do_query(sess: Any) -> list[Any]:
            nonlocal inv_uuid
            inv = get_investigation_by_id_or_run(sess, inv_uuid)
            if inv is None:
                return []

            direct_q = sess.query(Entity).filter(Entity.investigation_id == inv.id)
            linked_q = (
                sess.query(Entity)
                .join(
                    InvestigationEntityLink,
                    InvestigationEntityLink.entity_id == Entity.id,
                )
                .filter(InvestigationEntityLink.investigation_id == inv.id)
            )
            from db.entity_views import entity_views
            db_entities = entity_views(sess, direct_q.union(linked_q).all(), investigation_id=inv.id)

            if entity_ids is not None:
                want = frozenset(entity_ids)
                db_entities = [e for e in db_entities if e.id in want]

            result: list[NormalizedEntity] = [
                normalized_entity_from_db_row(e) for e in db_entities
            ]
            return result

        if session is not None:
            return _do_query(session)
        with get_session() as sess:
            return _do_query(sess)

    except Exception as exc:
        logger.warning("_load_entities_for_investigation failed: %s", exc)
        return []


def _build_stix_relationships(
    investigation_id: Any,
    stix_id_map: dict[str, str],
) -> tuple[list[Any], Optional[str]]:
    """
    Build STIX Relationship objects from graph edges for the investigation.

    Returns [] on any error.
    """
    if not _STIX2_AVAILABLE:
        return [], "stix2 is not installed"
    try:
        from export.relationships import load_export_relationships  # noqa: PLC0415

        graph_relationships, warning = load_export_relationships(
            investigation_id, stix_id_map
        )
        if warning:
            return [], warning
        relationships: list[Any] = []
        for data in graph_relationships:
            # Carry the edge's own confidence onto the SRO.  Typed relationships
            # have a claim-specific confidence distinct from co-occurrence's
            # flat value; STIX 2.1 confidence is an int 0-100.
            rel_kwargs: dict[str, Any] = {
                "relationship_type": data["stix_relationship_type"],
                "source_ref": data["source_ref"],
                "target_ref": data["target_ref"],
                "allow_custom": True,
            }
            try:
                edge_conf = data.get("confidence")
                if edge_conf is not None:
                    rel_kwargs["confidence"] = _to_stix_confidence(float(edge_conf))
            except (TypeError, ValueError):
                pass
            try:
                rel = stix2.Relationship(**rel_kwargs)
                relationships.append(rel)
            except Exception:
                # Retry without confidence in case the value tripped validation.
                try:
                    rel_kwargs.pop("confidence", None)
                    relationships.append(stix2.Relationship(**rel_kwargs))
                except Exception:
                    continue
        return relationships, None
    except Exception as exc:
        logger.warning("_build_stix_relationships failed: %s", exc)
        return [], f"_build_stix_relationships failed: {exc}"


def _edge_type_to_stix(edge_type: str) -> str:
    """Map VoidAccess graph edge types to STIX relationship type strings."""
    from export.relationships import _normalise_edge_type  # noqa: PLC0415
    from graph.model import RELATIONSHIP_TYPE_STIX  # noqa: PLC0415
    return RELATIONSHIP_TYPE_STIX.get(_normalise_edge_type(edge_type), "related-to")


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Try to coerce an arbitrary value to uuid.UUID. Returns None on failure."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
