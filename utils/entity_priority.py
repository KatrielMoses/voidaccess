"""Signal-based prioritization for investigation entities.

The prioritization score is intentionally independent of graph density.  The
confidence, corroboration, and freshness signals are always available; typed
relationship degree is an optional, low-weight hint when the investigation has
enough variation for it to be meaningful.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from datetime import datetime
from math import isfinite, log1p
from typing import Any

from utils.ioc_freshness import FreshnessTag, get_freshness_tag

# Keep the score shape explicit and easy to audit.  Centrality is opportunistic
# by design: one sparse edge cannot outweigh strong evidence from the other
# three signals.
PRIORITY_WEIGHTS = {
    "confidence": 0.45,
    "corroboration": 0.30,
    "freshness": 0.20,
    "centrality": 0.05,
}

_SOURCE_COUNT_CAP = 10
_INVESTIGATION_COUNT_CAP = 5
_CENTRALITY_DEGREE_CAP = 10
_CO_OCCURRENCE_EDGE = "CO_APPEARED_ON"

_FRESHNESS_SCORES = {
    FreshnessTag.FRESH.value: 1.0,
    FreshnessTag.AGING.value: 0.67,
    FreshnessTag.STALE.value: 0.33,
    FreshnessTag.EXPIRED.value: 0.0,
    # Missing timestamps are not evidence of staleness.  Keep this neutral so
    # legacy rows do not receive an arbitrary hard penalty.
    FreshnessTag.UNKNOWN.value: 0.5,
}


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, _number(value)))


def _log_capped(value: Any, cap: int) -> float:
    """Normalize a non-negative count with a fixed logarithmic cap."""
    count = max(0.0, _number(value, 1.0))
    if cap <= 1:
        return 1.0 if count >= cap else 0.0
    return min(1.0, log1p(max(0.0, count - 1.0)) / log1p(cap - 1.0))


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _freshness_score(item: Any) -> tuple[str, float]:
    tag = _value(item, "freshness_tag")
    tag_value = getattr(tag, "value", tag)
    if tag_value:
        normalized = str(tag_value).lower()
        return normalized, _FRESHNESS_SCORES.get(normalized, 0.5)

    entity_type = str(_value(item, "entity_type", "") or "")
    last_seen = _parse_datetime(
        _value(item, "last_seen_at") or _value(item, "last_seen")
    )
    first_seen = _parse_datetime(
        _value(item, "first_seen_at") or _value(item, "first_seen")
    )
    freshness = get_freshness_tag(entity_type, last_seen, first_seen)
    return freshness.value, _FRESHNESS_SCORES[freshness.value]


def _entity_id(item: Any) -> str:
    return str(_value(item, "id", ""))


def _typed_degrees(
    entities: Iterable[Any], relationships: Iterable[Any],
) -> dict[str, int]:
    """Return undirected degree counts for typed edges only."""
    entity_ids = {_entity_id(entity) for entity in entities if _entity_id(entity)}
    degrees = {entity_id: 0 for entity_id in entity_ids}
    for relationship in relationships or ():
        relationship_type = str(
            _value(relationship, "relationship_type", "") or ""
        ).upper()
        if not relationship_type or relationship_type == _CO_OCCURRENCE_EDGE:
            continue
        entity_a_id = str(_value(relationship, "entity_a_id", "") or "")
        entity_b_id = str(_value(relationship, "entity_b_id", "") or "")
        if entity_a_id in degrees and entity_b_id in degrees:
            degrees[entity_a_id] += 1
            degrees[entity_b_id] += 1
    return degrees


def score_entities(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
) -> list[dict[str, Any]]:
    """Return per-entity prioritization fields in a normalized ``[0, 1]`` range.

    The returned list has one mapping per input item and does not mutate ORM
    rows.  Centrality is zero when there are no typed edges or when every
    entity has the same typed degree (including the all-tied sparse case).
    """
    entity_list = list(entities or ())
    degree_by_id = _typed_degrees(entity_list, relationships)
    degree_values = list(degree_by_id.values())
    has_centrality_variation = bool(degree_values) and max(degree_values) > min(degree_values)

    result: list[dict[str, Any]] = []
    for entity in entity_list:
        confidence = _clamp(_value(entity, "confidence", 0.0))
        source_count = max(1.0, _number(_value(entity, "source_count", 1), 1.0))
        investigation_count = max(
            1.0, _number(_value(entity, "investigation_count", 1), 1.0)
        )
        source_signal = _log_capped(source_count, _SOURCE_COUNT_CAP)
        investigation_signal = _log_capped(
            investigation_count, _INVESTIGATION_COUNT_CAP
        )
        corroboration = (source_signal + investigation_signal) / 2.0
        freshness_tag, freshness = _freshness_score(entity)

        degree = degree_by_id.get(_entity_id(entity), 0)
        centrality = 0.0
        if has_centrality_variation:
            centrality = _log_capped(degree + 1, _CENTRALITY_DEGREE_CAP)

        score = (
            PRIORITY_WEIGHTS["confidence"] * confidence
            + PRIORITY_WEIGHTS["corroboration"] * corroboration
            + PRIORITY_WEIGHTS["freshness"] * freshness
            + PRIORITY_WEIGHTS["centrality"] * centrality
        )
        centrality_contribution = PRIORITY_WEIGHTS["centrality"] * centrality
        result.append(
            {
                "id": _entity_id(entity),
                "priority_score": round(max(0.0, min(1.0, score)), 6),
                "freshness_tag": freshness_tag,
                "priority_score_components": {
                    "confidence": round(confidence, 6),
                    "corroboration": round(corroboration, 6),
                    "freshness": round(freshness, 6),
                    "centrality": round(centrality, 6),
                },
                "priority_score_centrality_contribution": round(
                    centrality_contribution, 6
                ),
                "typed_relationship_degree": degree,
            }
        )
    return result


def score_map(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
) -> dict[str, dict[str, Any]]:
    """Convenience lookup keyed by the entity id used by both surfaces."""
    return {item["id"]: item for item in score_entities(entities, relationships)}


# --------------------------------------------------------------------------- #
# Low-noise-by-default ranking + non-destructive suppression (P1.6)
# --------------------------------------------------------------------------- #
#
# ``score_entities`` produces the per-entity ``priority_score``.  Ranking and
# suppression are layered on top *here* — in the one shared module every surface
# already calls — so the ordering and the ``suppressed`` flag are identical for
# the same investigation across the API, the CLI export, and the summary feed
# (the parity the audit called out).  Suppression is deprioritise-and-mark, never
# delete: every input entity appears in the output, suppressed ones ranked last
# and flagged with a reason, so an analyst can always drill in (a surface toggle
# re-includes them).  All levers are the existing signals — the blended
# ``priority_score`` (confidence + corroboration + freshness) and a per-type
# display cap — plus a deterministic high-signal exemption.  No ML, no corpus.

# Deterministic P1.3–P1.5 relevance flags (stored as ``corroborating_sources``
# tags).  Presence exempts an entity from suppression and, among entities with an
# equal ``priority_score``, surfaces it first.  These are a *display-time*
# surfacing hint only — they never enter ``priority_score`` (that would break the
# P1.3 ranking invariant that derived tags do not inflate corroboration).
HIGH_SIGNAL_TAGS = frozenset(
    {"kev", "exploit_public", "ransom_wallet", "phishing", "malicious_cert",
     "pwned_password"}
)
_HIGH_SIGNAL_PREFIXES = (
    "ransom_wallet_", "phishing_", "malicious_cert_", "pwned_password_count_",
)

# Default priority floor: entities scoring below this are suppressed (unless
# high-signal).  Tunable via env so the P1-end live-Tor run can sweep it against
# the committed junk-ratio baseline without a code change.
DEFAULT_PRIORITY_FLOOR = 0.25

# Per-type *display* caps — within a noisy type only the top-N by priority stay
# visible; the tail is suppressed (still reachable).  Distinct from the
# extraction-time ``extractor.pipeline.PER_TYPE_CAPS`` (which bounds what is
# *stored*); this bounds what is *shown* by default.
PER_TYPE_DISPLAY_CAPS = {
    "DATE": 10,
    "LOCATION": 10,
    "PERSON_NAME": 15,
    "ORGANIZATION_NAME": 25,
}


def _priority_floor() -> float:
    raw = os.getenv("VOIDACCESS_PRIORITY_FLOOR")
    if raw:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return DEFAULT_PRIORITY_FLOOR
        if 0.0 <= value <= 1.0:
            return value
    return DEFAULT_PRIORITY_FLOOR


def _coerce_tags(raw: Any) -> tuple[str, ...]:
    """Normalize ``corroborating_sources`` (a JSON string on ORM rows, a list on
    API/CLI dicts) into a tuple of tag strings.  Never raises."""
    if not raw:
        return ()
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(item) for item in raw)
    return ()


def _has_high_signal_tag(item: Any) -> bool:
    for tag in _coerce_tags(_value(item, "corroborating_sources")):
        if tag in HIGH_SIGNAL_TAGS or tag.startswith(_HIGH_SIGNAL_PREFIXES):
            return True
    return False


def rank_entities(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
    *,
    priority_floor: float | None = None,
    per_type_display_caps: Mapping[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Return the scored records ordered high-signal-first with suppression flags.

    Each record carries every field ``score_entities`` produces plus:

    * ``index`` — the entity's original position in *entities* (lets callers map
      a ranked record back to the input object even when ids are absent).
    * ``entity_type`` — echoed for the per-type cap and for callers.
    * ``high_signal`` — carries a deterministic P1.3–P1.5 relevance flag.
    * ``rank`` — 1-based position after ordering by ``priority_score`` desc
      (high-signal breaking ties, then id for full determinism).
    * ``suppressed`` / ``suppression_reason`` — non-destructive: the entity stays
      in the list, ranked last, marked ``"below_priority_floor"`` or
      ``"per_type_display_cap"``.  High-signal entities are never suppressed.

    Deterministic and surface-independent: the same input set yields the same
    ordering and flags on every surface.
    """
    entity_list = list(entities or ())
    scored = score_entities(entity_list, relationships)
    floor = _priority_floor() if priority_floor is None else priority_floor
    caps = PER_TYPE_DISPLAY_CAPS if per_type_display_caps is None else per_type_display_caps

    for index, (record, entity) in enumerate(zip(scored, entity_list)):
        record["index"] = index
        record["entity_type"] = str(_value(entity, "entity_type", "") or "")
        record["high_signal"] = _has_high_signal_tag(entity)

    scored.sort(
        key=lambda r: (-r["priority_score"], 0 if r["high_signal"] else 1, r["id"])
    )

    per_type_seen: dict[str, int] = {}
    for position, record in enumerate(scored, start=1):
        record["rank"] = position
        reason: str | None = None
        if not record["high_signal"]:
            entity_type = record["entity_type"].upper()
            cap = caps.get(entity_type)
            if cap is not None:
                seen = per_type_seen.get(entity_type, 0) + 1
                per_type_seen[entity_type] = seen
                if seen > cap:
                    reason = "per_type_display_cap"
            if reason is None and record["priority_score"] < floor:
                reason = "below_priority_floor"
        record["suppressed"] = reason is not None
        record["suppression_reason"] = reason
    return scored


def rank_map(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
) -> dict[str, dict[str, Any]]:
    """``rank_entities`` keyed by entity id (for the DB-backed surfaces)."""
    return {record["id"]: record for record in rank_entities(entities, relationships)}


def order_and_filter_for_summary(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
    *,
    limit: int | None = None,
    include_suppressed: bool = False,
) -> list[Any]:
    """Return the input entity *objects* ordered high-signal-first with suppressed
    ones dropped — the low-noise, prioritized set to feed the LLM report.

    Non-destructive with respect to storage: this only shapes what the summary
    sees.  Ordering matches every other surface because it reuses
    ``rank_entities``.
    """
    entity_list = list(entities or ())
    ordered: list[Any] = []
    for record in rank_entities(entity_list, relationships):
        if not include_suppressed and record["suppressed"]:
            continue
        ordered.append(entity_list[record["index"]])
        if limit is not None and len(ordered) >= limit:
            break
    return ordered
