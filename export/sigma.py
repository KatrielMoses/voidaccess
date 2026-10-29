"""
export/sigma.py — Generates draft Sigma detection rules from investigation entities.

Sigma rules are YAML-formatted SIEM-agnostic detection rules.
LLM assistance is optional; if provided, enriches description, tags, and falsepositives.

Public interface
----------------
entities_to_sigma_rules(entities, llm)     → list[dict]
sigma_rule_to_yaml(rule)                   → str
export_sigma_rules(investigation_id, output_dir, llm) → list[str]
"""

from __future__ import annotations

import json
import logging
import os
import uuid as _uuid_module
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity types that produce Sigma rules
# ---------------------------------------------------------------------------

_SIGMA_ENTITY_TYPES = frozenset({"IP_ADDRESS", "ONION_URL", "CVE_NUMBER", "MALWARE_FAMILY", "RANSOMWARE_GROUP"})

# ---------------------------------------------------------------------------
# Base rule builders per entity type
# ---------------------------------------------------------------------------


def _base_rule_for_ip(entity: Any) -> dict:
    return {
        "title": f"Network connection to suspicious IP: {entity.value}",
        "id": str(_uuid_module.uuid4()),
        "status": "experimental",
        "description": f"Detects outbound network connection to IP address {entity.value} "
                       "associated with dark web activity.",
        "references": [entity.source_url] if entity.source_url else [],
        "tags": ["attack.initial_access"],
        "logsource": {"category": "network", "product": "any"},
        "detection": {
            "selection": {"DestinationIp": entity.value},
            "condition": "selection",
        },
        "falsepositives": ["Unknown"],
        "level": "medium",
    }


def _base_rule_for_onion(entity: Any) -> dict:
    return {
        "title": f"DNS query or connection to .onion address: {entity.value[:60]}",
        "id": str(_uuid_module.uuid4()),
        "status": "experimental",
        "description": f"Detects connection attempt to Tor hidden service {entity.value}.",
        "references": [entity.source_url] if entity.source_url else [],
        "tags": ["attack.command_and_control"],
        "logsource": {"category": "network", "product": "any"},
        "detection": {
            "selection": {"DestinationHostname|contains": ".onion"},
            "condition": "selection",
        },
        "falsepositives": ["Legitimate Tor browser usage"],
        "level": "medium",
    }


def _base_rule_for_cve(entity: Any) -> dict:
    return {
        "title": f"Exploitation attempt for {entity.value}",
        "id": str(_uuid_module.uuid4()),
        "status": "experimental",
        "description": f"Detects activity patterns related to exploitation of {entity.value} "
                       "observed in dark web intelligence.",
        "references": [entity.source_url] if entity.source_url else [],
        "tags": ["attack.initial_access", "attack.exploitation"],
        "logsource": {"category": "network", "product": "any"},
        "detection": {
            "selection": {"CommandLine|contains": entity.value},
            "condition": "selection",
        },
        "falsepositives": ["Security scanners", "Penetration testing tools"],
        "level": "high",
    }


def _base_rule_for_malware(entity: Any) -> dict:
    name = entity.value
    return {
        "title": f"Malware family activity: {name}",
        "id": str(_uuid_module.uuid4()),
        "status": "experimental",
        "description": f"Detects activity associated with {name} malware family "
                       "as observed in dark web intelligence.",
        "references": [entity.source_url] if entity.source_url else [],
        "tags": ["attack.execution"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"CommandLine|contains": name},
            "condition": "selection",
        },
        "falsepositives": ["Unknown"],
        "level": "high",
    }


def _build_base_rule(entity: Any) -> Optional[dict]:
    """Return a base Sigma rule dict for the entity, or None if unsupported type."""
    etype = entity.entity_type
    if etype == "IP_ADDRESS":
        return _base_rule_for_ip(entity)
    if etype == "ONION_URL":
        return _base_rule_for_onion(entity)
    if etype == "CVE_NUMBER":
        return _base_rule_for_cve(entity)
    if etype in ("MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        return _base_rule_for_malware(entity)
    return None


# ---------------------------------------------------------------------------
# LLM enrichment
# ---------------------------------------------------------------------------

_LLM_PROMPT_TEMPLATE = """You are a threat intelligence analyst writing Sigma detection rules.
Given the following base Sigma rule as JSON, enrich three fields:
1. "description" — make it more precise and actionable
2. "tags" — use MITRE ATT&CK tactic/technique tags (e.g. attack.t1071)
3. "falsepositives" — list realistic false positive scenarios

Return ONLY a JSON object with exactly these three keys: description, tags, falsepositives.
Do not include any other text.

Base rule:
{base_rule_json}
"""


def _enrich_with_llm(rule: dict, llm: Any) -> dict:
    """
    Send base rule to LLM to enrich description, tags, and falsepositives.

    Returns the original rule unchanged if LLM fails or returns invalid JSON.
    """
    try:
        base_json = json.dumps(rule, indent=2)
        # The rule carries entity values taken from scraped pages.
        from voidaccess.fence import format_prompt
        prompt = format_prompt(_LLM_PROMPT_TEMPLATE, base_rule_json=base_json)

        # Support both LangChain-style (invoke) and simple (predict/call) interfaces
        if hasattr(llm, "invoke"):
            response = llm.invoke(prompt)
            # LangChain returns an AIMessage; get .content
            content = getattr(response, "content", str(response))
        elif callable(llm):
            content = str(llm(prompt))
        else:
            return rule

        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            lines = [l for l in lines if not l.startswith("```")]
            content = "\n".join(lines).strip()

        enriched = json.loads(content)
        if not isinstance(enriched, dict):
            return rule

        updated = dict(rule)
        if "description" in enriched and isinstance(enriched["description"], str):
            updated["description"] = enriched["description"]
        if "tags" in enriched and isinstance(enriched["tags"], list):
            updated["tags"] = enriched["tags"]
        if "falsepositives" in enriched and isinstance(enriched["falsepositives"], list):
            updated["falsepositives"] = enriched["falsepositives"]
        return updated

    except Exception as exc:
        logger.warning("LLM enrichment failed for Sigma rule %r: %s", rule.get("id"), exc)
        return rule


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def entities_to_sigma_rules(
    entities: list[Any],
    llm: Optional[Any] = None,
) -> list[dict]:
    """
    Generate Sigma rule dicts for relevant entities.

    Entity types that produce rules: IP_ADDRESS, ONION_URL, CVE_NUMBER,
    MALWARE_FAMILY, RANSOMWARE_GROUP.

    If llm is provided, enriches description, tags, and falsepositives via LLM.
    Falls back to base rule if LLM fails.
    """
    rules: list[dict] = []
    for raw_entity in entities:
        entity = _adapt_entity(raw_entity)
        if entity.entity_type not in _SIGMA_ENTITY_TYPES:
            continue
        base = _build_base_rule(entity)
        if base is None:
            continue
        if llm is not None:
            base = _enrich_with_llm(base, llm)
        rules.append(base)
    return rules


def sigma_rule_to_yaml(rule: dict) -> str:
    """Convert a Sigma rule dict to a valid YAML string."""
    try:
        return yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception as exc:
        logger.warning("sigma_rule_to_yaml failed: %s", exc)
        return ""


def render_sigma_rules(
    entities: list[Any],
    llm: Optional[Any] = None,
) -> str:
    """Render the shared Sigma artifact used by every export surface.

    The CLI export and the IOC package both receive the same export payload,
    whose entities are normally dictionaries.  Keeping adaptation, rule
    generation, and YAML assembly here prevents one surface from growing a
    second DB-loading implementation with different failure semantics.
    """
    rules = entities_to_sigma_rules(list(entities or []), llm=llm)
    return "\n---\n".join(
        sigma_rule_to_yaml(rule) for rule in rules if rule
    )


def export_sigma_rules(
    investigation_id: Any,
    output_dir: str,
    llm: Optional[Any] = None,
) -> list[str]:
    """
    Load entities for an investigation, generate Sigma rules, and write each to
    {output_dir}/{uuid}.yml.

    Returns list of file paths written. Creates output_dir if it doesn't exist.
    Returns [] if investigation not found or DATABASE_URL not set.
    """
    entities = _load_entities_for_investigation(investigation_id)
    if not entities:
        return []

    rules = entities_to_sigma_rules(entities, llm=llm)
    if not rules:
        return []

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for rule in rules:
        rule_id = rule.get("id") or str(_uuid_module.uuid4())
        filename = out_path / f"{rule_id}.yml"
        try:
            yaml_content = sigma_rule_to_yaml(rule)
            filename.write_text(yaml_content, encoding="utf-8")
            written.append(str(filename))
        except Exception as exc:
            logger.warning("Failed to write Sigma rule %r: %s", rule_id, exc)

    return written


# ---------------------------------------------------------------------------
# Internal DB helper
# ---------------------------------------------------------------------------


def _load_entities_for_investigation(investigation_id: Any) -> list[Any]:
    """Load NormalizedEntity list from DB for this investigation.

    Includes entities owned directly AND entities linked via InvestigationEntityLink.
    Returns [] on error.
    """
    if not os.getenv("DATABASE_URL"):
        return []

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
        from db.models import Entity, InvestigationEntityLink  # noqa: PLC0415
        from extractor.normalizer import NormalizedEntity  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return []

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                return []

            linked_ids_select = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
            )
            db_entities = (
                session.query(Entity)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_select)
                )
                .all()
            )

            from export._entity_loading import normalized_entity_from_db_row  # noqa: PLC0415

            # Shared row→NormalizedEntity mapping (same one STIX/MISP use).
            result: list[NormalizedEntity] = [
                normalized_entity_from_db_row(e) for e in db_entities
            ]
            return result

    except Exception as exc:
        logger.warning("sigma _load_entities_for_investigation failed: %s", exc)
        return []


class _DictEntityAdapter:
    """Expose dictionary-shaped export entities through Sigma's object API."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @property
    def entity_type(self) -> str:
        return str(self._data.get("entity_type") or "")

    @property
    def value(self) -> str:
        return str(
            self._data.get("canonical_value")
            or self._data.get("value")
            or ""
        )

    @property
    def confidence(self) -> float:
        try:
            return float(self._data.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @property
    def source_url(self) -> str:
        return str(self._data.get("source_url") or "")


def _adapt_entity(entity: Any) -> Any:
    """Accept both ORM/normalized entities and export dictionaries."""
    if isinstance(entity, dict):
        return _DictEntityAdapter(entity)
    return entity


def _coerce_uuid(value: Any):
    """Coerce value to uuid.UUID. Returns None on failure."""
    import uuid as _uuid
    if isinstance(value, _uuid.UUID):
        return value
    try:
        return _uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
