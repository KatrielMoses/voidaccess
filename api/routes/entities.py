"""
api/routes/entities.py — Entity query endpoints.

GET /entities                       — paginated entity list with filters
GET /entities/{entity_id}           — single entity full profile
GET /entities/{entity_id}/neighbors — graph neighbors (sigma.js graph page)
GET /entities/{entity_id}/related   — DB-based related entities for profile page
GET /entities/{entity_id}/export/stix — export single entity as STIX 2.1
GET /entities/{entity_id}/export/json — export single entity as JSON
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from api.auth import CurrentUser, get_current_user
from api.errors import GENERIC_ERROR_MESSAGE, log_exception
from extractor.identity import entity_canonical_id

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_entities(
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type"),
    value_contains: Optional[str] = Query(default=None, description="Filter by value substring"),
    since: Optional[str] = Query(default=None, description="ISO datetime lower bound for created_at"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return paginated entities matching optional filters."""
    if not os.getenv("DATABASE_URL"):
        return {"items": [], "total": 0, "skip": 0, "limit": 20}
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity, Investigation, InvestigationEntityLink  # noqa: PLC0415
        import sqlalchemy as sa  # noqa: PLC0415

        since_dt: Optional[datetime] = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                raise HTTPException(status_code=422, detail="Invalid 'since' datetime format")

        with get_session() as session:
            user_inv_ids = (
                sa.select(Investigation.id)
                .where(Investigation.user_id == current_user.user.id)
            )
            linked_entity_ids = (
                sa.select(InvestigationEntityLink.entity_id)
                .where(InvestigationEntityLink.investigation_id.in_(user_inv_ids))
            )
            q = session.query(Entity).filter(
                sa.or_(
                    Entity.investigation_id.in_(user_inv_ids),
                    Entity.id.in_(linked_entity_ids),
                )
            ).distinct()
            if entity_type:
                q = q.filter(Entity.entity_type == entity_type)
            if value_contains:
                q = q.filter(Entity.value.contains(value_contains))
            if since_dt:
                q = q.filter(Entity.created_at >= since_dt)
            total = q.count()
            entities = (
                q.order_by(Entity.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            # Score each row against its own investigation (cached per
            # investigation id so a page of same-investigation entities builds
            # the map once), matching the CLI export and /entities/{id} exactly.
            priority_cache: dict = {}
            return {
                "items": [
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "canonical_value": e.canonical_value,
                        "value": e.canonical_value or e.value,
                        "confidence": e.confidence,
                        "context_snippet": e.context_snippet,
                        "context": e.context,
                        "investigation_id": str(e.investigation_id) if e.investigation_id else None,
                        "investigation_count": getattr(e, "investigation_count", 1) or 1,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                        **_entity_priority_fields(session, e, priority_cache),
                    }
                    for e in entities
                ],
                "total": total,
                "skip": offset,
                "limit": limit,
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("list_entities failed: %s", exc)
        return []


@router.get("/{entity_id}/export/stix")
async def export_entity_stix(
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """Export single entity as a STIX 2.1 bundle."""
    eid = _parse_uuid(entity_id)
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")
            _assert_entity_accessible(session, eid, current_user.user.id)

            try:
                from export.stix import entity_to_stix_indicator, entity_to_stix_threat_actor, entity_to_stix_malware, bundle_to_json  # noqa: PLC0415
                import stix2  # noqa: PLC0415

                stix_obj = (
                    entity_to_stix_threat_actor(entity)
                    or entity_to_stix_malware(entity)
                    or entity_to_stix_indicator(entity)
                )
                if stix_obj:
                    bundle = stix2.Bundle(objects=[stix_obj], spec_version="2.1")
                    json_str = bundle_to_json(bundle)
                else:
                    json_str = json.dumps({
                        "type": "bundle",
                        "spec_version": "2.1",
                        "id": f"bundle--{uuid.uuid4()}",
                        "objects": [],
                    })
            except Exception as exc:
                logger.warning("STIX export for entity %s failed, falling back to raw JSON: %s", entity_id, exc)
                json_str = json.dumps(
                    _entity_to_dict(entity, _entity_priority_fields(session, entity)),
                    indent=2,
                )

            filename = f"voidaccess_entity_{entity_id}_stix.json"
            return Response(
                content=json_str,
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_entity_stix failed: %s", exc)
        raise HTTPException(status_code=500, detail="Export failed")


@router.get("/{entity_id}/export/json")
async def export_entity_json(
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """Export single entity as JSON."""
    eid = _parse_uuid(entity_id)
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415
        from db.queries import get_entity_appearances  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")
            _assert_entity_accessible(session, eid, current_user.user.id)

            appearances = get_entity_appearances(session, eid, current_user.user.id)
            data = _entity_to_dict(entity, _entity_priority_fields(session, entity))
            data["appearances"] = appearances
            json_str = json.dumps(data, indent=2, default=str)

            filename = f"voidaccess_entity_{entity_id}.json"
            return Response(
                content=json_str,
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_entity_json failed: %s", exc)
        raise HTTPException(status_code=500, detail="Export failed")


@router.get("/{entity_id}/related")
async def get_entity_related(
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Return DB-based related entities for the profile page mini-graph.
    Uses EntityRelationship table directly — returns DB UUIDs for navigation.
    """
    eid = _parse_uuid(entity_id)
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity, EntityRelationship  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")
            _assert_entity_accessible(session, eid, current_user.user.id)

            rels = (
                session.query(EntityRelationship)
                .filter(
                    (EntityRelationship.entity_a_id == eid)
                    | (EntityRelationship.entity_b_id == eid)
                )
                .all()
            )

            neighbor_ids = set()
            for rel in rels:
                if rel.entity_a_id == eid:
                    neighbor_ids.add(rel.entity_b_id)
                else:
                    neighbor_ids.add(rel.entity_a_id)

            neighbors_map: dict[str, Entity] = {}
            if neighbor_ids:
                neighbor_entities = (
                    session.query(Entity)
                    .filter(Entity.id.in_(neighbor_ids))
                    .all()
                )
                neighbors_map = {ne.id: ne for ne in neighbor_entities}

            neighbors: dict[str, dict] = {}
            for rel in rels:
                other_id = rel.entity_b_id if rel.entity_a_id == eid else rel.entity_a_id
                other = neighbors_map.get(other_id)
                if other is None:
                    continue
                key = str(other.id)
                if key not in neighbors or rel.confidence > neighbors[key]["strength"]:
                    neighbors[key] = {
                        "id": str(other.id),
                        "entity_type": other.entity_type,
                        "value": other.value,
                        "confidence": other.confidence,
                        "relationship_type": rel.relationship_type,
                        "strength": rel.confidence,
                    }

            return {
                "entity": {
                    "id": str(entity.id),
                    "entity_type": entity.entity_type,
                    "value": entity.value,
                    "confidence": entity.confidence,
                },
                "neighbors": list(neighbors.values()),
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_entity_related failed: %s", exc)
        return {"entity": {"id": entity_id}, "neighbors": []}


@router.get("/{entity_id}/analysis/stylometry")
async def get_stylometry_analysis(
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Run stylometric analysis on all text attributed to this entity.

    Collects context_snippets for this entity's canonical alias group,
    builds a writing-style fingerprint via fingerprint/stylometry.py,
    and returns 6 scalar features + notable traits.

    Returns {"error": "insufficient_data"} (not 500) when text < 3 samples.
    """
    eid = _parse_uuid(entity_id)
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from sqlalchemy.orm import joinedload  # noqa: PLC0415

        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415
        from fingerprint.profiler import build_actor_profile  # noqa: PLC0415
        from fingerprint.calibration import calibration_summary  # noqa: PLC0415

        BASELINE = {
            "avg_word_length": 4.8,
            "avg_sentence_length": 12.1,
            "punctuation_density": 0.12,
            "uppercase_ratio": 0.09,
            "vocabulary_richness": 0.52,
            "digit_ratio": 0.04,
            "avg_paragraph_length": 3.5,
            "exclamation_ratio": 0.05,
            "question_ratio": 0.08,
        }

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")

            # Canonical dedup key via the shared identity module (was an inline
            # `entity.canonical_value or entity.value.lower()` re-derivation).
            canonical = entity_canonical_id(entity)

            related = (
                session.query(Entity)
                .filter(
                    (Entity.canonical_value == canonical)
                    | (Entity.value == entity.value)
                )
                .options(joinedload(Entity.page))
                .all()
            )

            texts: list[str] = []
            for e in related:
                if e.page and e.page.cleaned_text and len((e.page.cleaned_text or "").strip()) >= 100:
                    texts.append(e.page.cleaned_text[:3000].strip())
                elif e.context_snippet and len((e.context_snippet or "").strip()) >= 50:
                    texts.append(e.context_snippet.strip())

            text_samples = len(texts)
            total_chars = sum(len(t) for t in texts)
            logger.warning(
                "Stylometry: %s samples, %s total chars (min 3 samples and 500 chars for MEDIUM confidence)",
                text_samples,
                total_chars,
            )

            if text_samples < 3 or total_chars < 500:
                return {
                    "entity_id": entity_id,
                    "error": "insufficient_data",
                    "text_samples": text_samples,
                    "total_chars": total_chars,
                    "chars": total_chars,
                    "message": (
                        f"Insufficient text volume for stylometry "
                        f"({text_samples} samples, {total_chars} chars)"
                    ),
                }

            profile = build_actor_profile(texts)
            if profile is None:
                return {
                    "entity_id": entity_id,
                    "error": "insufficient_data",
                    "text_samples": text_samples,
                    "total_chars": 0,
                    "message": "Text samples too short for analysis (minimum 100 characters each)",
                }

            scalar_features = {
                k: round(float(v), 4)
                for k, v in profile.items()
                if not k.startswith("_") and isinstance(v, (int, float))
            }

            sample_count = int(profile.get("_sample_count", text_samples))
            confidence = "low"
            if sample_count >= 5 and total_chars >= 2000:
                confidence = "medium"
            if sample_count >= 10 and total_chars >= 5000:
                confidence = "high"

            notable_traits: list[str] = []
            for feat, baseline in BASELINE.items():
                val = scalar_features.get(feat)
                if val is None or baseline == 0:
                    continue
                deviation = (val - baseline) / baseline
                if abs(deviation) >= 0.5:
                    direction = "above" if deviation > 0 else "below"
                    pct = abs(round(deviation * 100))
                    feat_label = feat.replace("_", " ").title()
                    notable_traits.append(
                        f"{feat_label}: {pct}% {direction} baseline ({val:.2f} vs {baseline})"
                    )

            # === NEW: Cross-actor matching ===
            similar_actors = []
            try:
                import asyncio  # noqa: PLC0415
                if profile and text_samples >= 3:
                    similar_actors = await asyncio.to_thread(
                        _find_similar_actors,
                        profile=profile,
                        canonical_value=entity_canonical_id(entity),
                        entity_type=entity.entity_type,
                    )
            except Exception as e:
                logger.warning(f"Similar actor matching failed: {e}")

            return {
                "entity_id": entity_id,
                "text_samples": sample_count,
                "total_chars": total_chars,
                "profile": scalar_features,
                "confidence": confidence,
                "notable_traits": notable_traits,
                "similar_actors": similar_actors,
                "similarity_method": "burrows_delta_zscore",
                "calibration": calibration_summary(),
                "reliability": {
                    "text_samples": sample_count,
                    "total_chars": total_chars,
                    "minimum_recommended_chars": 2000,
                    "warning": (
                        "Short texts produce less reliable stylometric estimates."
                        if total_chars < 2000 or sample_count < 5
                        else None
                    ),
                },
            }
    except HTTPException:
        raise
    except Exception as exc:
        correlation_id = log_exception(exc, context="get_stylometry_analysis")
        return {
            "error": "analysis_failed",
            "message": GENERIC_ERROR_MESSAGE,
            "correlation_id": correlation_id,
        }


@router.get("/{entity_id}/analysis/opsec")
async def get_opsec_analysis(
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Run OPSEC failure analysis for this entity across all their appearances.

    Collects texts + timestamps, runs analysis/opsec.py checks,
    and returns structured findings with an opsec_score (0-100, lower = worse).

    Returns {"error": "insufficient_data"} (not 500) when no text is available.
    """
    eid = _parse_uuid(entity_id)
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from urllib.parse import urlparse  # noqa: PLC0415

        from sqlalchemy.orm import joinedload  # noqa: PLC0415

        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415
        from analysis.opsec import run_full_opsec_analysis  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")

            # Canonical dedup key via the shared identity module (was an inline
            # `entity.canonical_value or entity.value.lower()` re-derivation).
            canonical = entity_canonical_id(entity)
            related = (
                session.query(Entity)
                .filter(
                    (Entity.canonical_value == canonical)
                    | (Entity.value == entity.value)
                )
                .options(joinedload(Entity.page))
                .all()
            )

            texts_with_timestamps: list[dict] = []
            for e in related:
                text = ""
                if e.page and e.page.cleaned_text and len((e.page.cleaned_text or "").strip()) >= 20:
                    text = (e.page.cleaned_text or "")[:8000].strip()
                elif e.context_snippet and len((e.context_snippet or "").strip()) >= 20:
                    text = (e.context_snippet or "").strip()
                if len(text) < 20:
                    continue
                ts = e.created_at
                if e.page:
                    if e.page.posted_at:
                        ts = e.page.posted_at
                    elif e.page.scrape_timestamp:
                        ts = e.page.scrape_timestamp
                texts_with_timestamps.append({"text": text, "timestamp": ts})

            inv_ids = list({e.investigation_id for e in related if e.investigation_id})
            pgp_fingerprints: list[str] = []
            pgp_sources: list[str] = []
            if inv_ids:
                pgp_rows = (
                    session.query(Entity)
                    .filter(
                        Entity.entity_type.in_(("PGP_KEY_BLOCK", "pgp_key")),
                        Entity.investigation_id.in_(inv_ids),
                    )
                    .options(joinedload(Entity.page))
                    .all()
                )
                for row in pgp_rows:
                    v = (row.value or "").strip()
                    if not v:
                        continue
                    pgp_fingerprints.append(v)
                    dom = ""
                    if row.page and row.page.url:
                        dom = urlparse(row.page.url).hostname or ""
                    pgp_sources.append(dom)

            if not texts_with_timestamps:
                return {
                    "entity_id": entity_id,
                    "error": "insufficient_data",
                    "message": "No text data available for OPSEC analysis",
                    "opsec_score": None,
                    "risk_level": None,
                    "findings": [],
                    "pages_analyzed": 0,
                }

            src_ok = len(pgp_sources) == len(pgp_fingerprints) and bool(pgp_fingerprints)
            result = run_full_opsec_analysis(
                entity.value,
                texts_with_timestamps,
                pgp_fingerprints=pgp_fingerprints or None,
                pgp_sources=pgp_sources if src_ok else None,
            )

            findings = list(result.get("findings", []))
            opsec_score = int(result.get("opsec_score", 100))
            risk_raw = str(result.get("risk_level", "LOW")).upper()

            return {
                "entity_id": entity_id,
                "opsec_score": opsec_score,
                "risk_level": risk_raw,
                "findings": findings,
                "pages_analyzed": len(texts_with_timestamps),
            }
    except HTTPException:
        raise
    except Exception as exc:
        correlation_id = log_exception(exc, context="get_opsec_analysis")
        return {
            "error": "analysis_failed",
            "message": GENERIC_ERROR_MESSAGE,
            "correlation_id": correlation_id,
        }


@router.get("/{entity_id}")
async def get_entity(
    entity_id: str,
    defang: bool = True,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return full entity profile including appearances."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    eid = _parse_uuid(entity_id)

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415
        from db.queries import get_entity_appearances  # noqa: PLC0415
        from utils.ioc_freshness import get_freshness_tag, get_freshness_display  # noqa: PLC0415
        from utils.defang import defang_value, defang_value_checked, defang_text  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")
            _assert_entity_accessible(session, eid, current_user.user.id)

            source_url = ""
            try:
                if entity.page:
                    source_url = entity.page.url or ""
            except Exception:
                pass

            is_seed = False
            try:
                if entity.investigation:
                    is_seed = bool(entity.investigation.is_seed)
            except Exception:
                pass

            appearances = get_entity_appearances(session, eid, current_user.user.id)

            freshness_tag = get_freshness_tag(
                entity.entity_type,
                entity.last_seen_at,
                entity.first_seen_at,
            )
            freshness_display = get_freshness_display(freshness_tag)

            display_value = entity.value
            display_canonical = entity.canonical_value
            display_context = entity.context
            value_defanged = False
            if defang:
                display_value, value_defanged = defang_value_checked(
                    entity.entity_type, entity.value or ""
                )
                if entity.canonical_value:
                    display_canonical = defang_value(entity.entity_type, entity.canonical_value)
                if entity.context:
                    display_context = defang_text(entity.context)

            priority = _entity_priority_fields(session, entity)

            return {
                **_entity_to_dict(entity, priority),
                "value": display_value,
                "canonical_value": display_canonical,
                "context": display_context,
                "source_url": source_url,
                "is_seed": is_seed,
                "appearances": appearances,
                "appearance_count": len(appearances),
                "first_seen_at": entity.first_seen_at.isoformat() if entity.first_seen_at else None,
                "last_seen_at": entity.last_seen_at.isoformat() if entity.last_seen_at else None,
                "freshness_tag": freshness_tag.value,
                "freshness_label": freshness_display["label"],
                "freshness_color": freshness_display["color"],
                "source_count": entity.source_count or 1,
                "investigation_count": getattr(entity, "investigation_count", 1) or 1,
                "corroborating_sources": json.loads(entity.corroborating_sources or '["dark_web_scrape"]'),
                "cross_referenced": (getattr(entity, "investigation_count", 1) or 1) > 1,
                "defanged": value_defanged,
                "blockchain_data": {
                    "wallet_type": entity.entity_type if entity.entity_type in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS") else None,
                    "historical_context": entity.historical_context,
                    "first_seen_blockchain": entity.first_seen.isoformat() if entity.first_seen else None,
                }
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_entity failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/{entity_id}/neighbors")
async def get_entity_neighbors(
    entity_id: str,
    hops: int = Query(default=1, ge=1, le=5),
    edge_types: Optional[str] = Query(
        default=None,
        description="Comma-separated list of edge types to filter",
    ),
    investigation_id: Optional[str] = Query(
        default=None,
        description="Scope to a specific investigation",
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Return direct neighbors of an entity using targeted SQL queries.
    Uses get_entity_neighbors_db for O(1) neighbor lookup instead of building the full graph.
    """
    try:
        entity_uuid = uuid.UUID(entity_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entity ID format")

    inv_uuid: Optional[uuid.UUID] = None
    if investigation_id:
        try:
            inv_uuid = uuid.UUID(investigation_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid investigation_id format")

    edge_type_list: Optional[list[str]] = None
    if edge_types:
        edge_type_list = [t.strip() for t in edge_types.split(",") if t.strip()]

    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415
        from db.queries import get_entity_neighbors_db  # noqa: PLC0415

        with get_session() as session:
            entity = session.query(Entity).filter_by(id=entity_uuid).first()
            if entity is None:
                raise HTTPException(status_code=404, detail="Entity not found")

            neighbors = get_entity_neighbors_db(
                entity_id=entity_uuid,
                investigation_id=inv_uuid,
                session=session,
            )

            if edge_type_list:
                neighbors = [
                    n for n in neighbors
                    if n.get("relationship_type") in edge_type_list
                ]

            if hops > 1:
                neighbor_ids = [uuid.UUID(n["neighbor_id"]) for n in neighbors]
                visited = {entity_uuid}
                visited.update(neighbor_ids)

                current_level = neighbor_ids
                for _ in range(1, hops):
                    next_level = []
                    for nid in current_level:
                        if nid in visited:
                            continue
                        visited.add(nid)
                        nxt = get_entity_neighbors_db(
                            entity_id=nid,
                            investigation_id=inv_uuid,
                            session=session,
                        )
                        for n in nxt:
                            nid2 = uuid.UUID(n["neighbor_id"])
                            if nid2 not in visited:
                                next_level.append(nid2)
                                neighbors.append(n)
                    if not next_level:
                        break
                    current_level = next_level

            return {
                "entity_id": entity_id,
                "hops": hops,
                "neighbors": neighbors,
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_entity_neighbors failed: %s", exc)
        return {"entity_id": entity_id, "hops": hops, "neighbors": []}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_uuid(entity_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(entity_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entity ID format")


def _assert_entity_accessible(session, entity_id: uuid.UUID, user_id: int) -> None:
    """Raise HTTP 404 if this entity is not reachable by the given user."""
    import sqlalchemy as sa  # noqa: PLC0415
    from db.models import Entity, Investigation, InvestigationEntityLink  # noqa: PLC0415

    user_inv_ids = (
        sa.select(Investigation.id)
        .where(Investigation.user_id == user_id)
    )
    linked_entity_ids = (
        sa.select(InvestigationEntityLink.entity_id)
        .where(InvestigationEntityLink.investigation_id.in_(user_inv_ids))
    )
    accessible = (
        session.query(Entity.id)
        .filter(
            sa.or_(
                Entity.investigation_id.in_(user_inv_ids),
                Entity.id.in_(linked_entity_ids),
            ),
            Entity.id == entity_id,
        )
        .first()
    )
    if accessible is None:
        raise HTTPException(status_code=404, detail="Entity not found")


# Default priority fields for an entity we could not (or chose not to) score.
# Mirrors the zero-defaults the investigation entities endpoint uses so the two
# API surfaces are shape-identical.
_EMPTY_PRIORITY: dict = {
    "priority_score": 0.0,
    "priority_score_components": {},
    "priority_score_centrality_contribution": 0.0,
}


def _investigation_priority_map(session, investigation_id) -> dict:
    """Return ``score_map`` for a whole investigation, scoped identically to the
    investigation entities endpoint and the CLI export.

    Prioritization is normalized against the *complete* investigation (direct +
    linked entities, all relationships), never a single entity or a filtered
    page — that is what makes the value returned here byte-for-byte comparable
    to ``GET /investigations/{id}/entities`` and to the CLI JSON/CSV/MD export
    for the same entity (see ``api/routes/investigations.py`` and
    ``voidaccess_cli/commands/export.py``).
    """
    from db.models import Entity, EntityRelationship, InvestigationEntityLink  # noqa: PLC0415
    import sqlalchemy as sa  # noqa: PLC0415
    from utils.entity_priority import score_map  # noqa: PLC0415

    linked_ids = (
        sa.select(InvestigationEntityLink.entity_id)
        .where(InvestigationEntityLink.investigation_id == investigation_id)
    )
    scoped = (
        session.query(Entity)
        .filter(
            (Entity.investigation_id == investigation_id)
            | Entity.id.in_(linked_ids)
        )
        .all()
    )
    relationships = (
        session.query(EntityRelationship)
        .filter(EntityRelationship.investigation_id == investigation_id)
        .all()
    )
    return score_map(scoped, relationships)


def _entity_priority_fields(session, entity, cache: Optional[dict] = None) -> dict:
    """Return the three ``priority_score`` fields for *entity*, computed with the
    same function and the same investigation-wide input set the CLI export uses.

    ``cache`` (an optional ``dict`` keyed by investigation id) lets a list
    endpoint score many entities from the same investigation without rebuilding
    the score map per row.  Any failure degrades to zero defaults rather than
    breaking the response.
    """
    inv_id = getattr(entity, "investigation_id", None)
    if inv_id is None:
        return dict(_EMPTY_PRIORITY)
    try:
        if cache is not None and inv_id in cache:
            pmap = cache[inv_id]
        else:
            pmap = _investigation_priority_map(session, inv_id)
            if cache is not None:
                cache[inv_id] = pmap
        entry = pmap.get(str(entity.id), {})
        return {
            "priority_score": entry.get("priority_score", 0.0),
            "priority_score_components": entry.get("priority_score_components", {}),
            "priority_score_centrality_contribution": entry.get(
                "priority_score_centrality_contribution", 0.0
            ),
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("entity priority computation failed: %s", exc)
        return dict(_EMPTY_PRIORITY)


def _entity_to_dict(entity, priority: Optional[dict] = None) -> dict:  # type: ignore[type-arg]
    # ``priority`` carries the three prioritization fields (see
    # ``_entity_priority_fields``).  It is passed in by callers that hold an open
    # session so the score matches the CLI export exactly; when absent we emit
    # the same zero defaults as the investigation entities endpoint so the field
    # is always present on the ``/entities`` surface.
    priority = priority or _EMPTY_PRIORITY
    return {
        "id": str(entity.id),
        "entity_type": entity.entity_type,
        "value": entity.value,
        "canonical_value": entity.canonical_value,
        "confidence": entity.confidence,
        "context": entity.context,
        "context_snippet": entity.context_snippet,
        "historical_context": entity.historical_context,
        "first_seen": entity.first_seen.isoformat() if entity.first_seen else None,
        "last_seen": entity.last_seen.isoformat() if entity.last_seen else None,
        "investigation_id": str(entity.investigation_id) if entity.investigation_id else None,
        "created_at": entity.created_at.isoformat() if entity.created_at else None,
        "extraction_method": getattr(entity, "extraction_method", None),
        "source_count": getattr(entity, "source_count", 1) or 1,
        "investigation_count": getattr(entity, "investigation_count", 1) or 1,
        "corroborating_sources": getattr(entity, "corroborating_sources", None),
        "priority_score": priority.get("priority_score", 0.0),
        "priority_score_components": priority.get("priority_score_components", {}),
        "priority_score_centrality_contribution": priority.get(
            "priority_score_centrality_contribution", 0.0
        ),
    }


def _get_entity_value(entity_id: str) -> Optional[str]:
    """Look up entity.value by UUID from DB."""
    if not os.getenv("DATABASE_URL"):
        return None
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity  # noqa: PLC0415

        eid = uuid.UUID(entity_id)
        with get_session() as session:
            entity = session.query(Entity).filter_by(id=eid).first()
            if entity:
                return entity.value
        return None
    except Exception:
        return None


def _resolve_graph_node_id(
    graph, entity_value: str, entity_type: Optional[str] = None
) -> Optional[str]:
    """Resolve a graph node id for an entity value.

    The graph is keyed by canonical identity (extractor.identity.entity_graph_id).
    When ``entity_type`` is known, the lookup value is canonicalised through the
    same shared module so it matches the node regardless of the casing the value
    was observed in — closing the case-sensitivity gap the audit flagged.
    Without a type it falls back to the historical exact-then-``handle@domain``
    prefix behaviour.
    """
    if graph is None:
        return None

    candidates = [entity_value]
    if entity_type:
        try:
            from types import SimpleNamespace  # noqa: PLC0415

            canon = entity_canonical_id(
                SimpleNamespace(entity_type=entity_type, value=entity_value)
            )
            if canon and canon not in candidates:
                candidates.append(canon)
        except Exception:
            pass

    # 1) exact match on any candidate
    for cand in candidates:
        if graph.has_node(cand):
            return cand
    # 2) handle@domain prefix match on any candidate
    for cand in candidates:
        prefix = f"{cand}@"
        for node_id in graph.nodes:
            if isinstance(node_id, str) and node_id.startswith(prefix):
                return node_id
    return None


def _find_similar_actors(
    profile,
    canonical_value: str,
    entity_type: str,
    threshold: float | None = None,
    top_k: int = 5,
) -> list[dict]:
    """
    Find other actors with similar writing styles.
    
    Returns list of matches sorted by similarity score, excluding
    the entity itself and its known aliases (same canonical_value).
    """
    from fingerprint.profiler import match_against_profiles
    from db.session import get_session
    
    with get_session() as session:
        matches = match_against_profiles(
            profile,
            session,
            threshold=threshold,
            exclude_canonical=canonical_value,  # Don't match self
        )
    
    # Format for API response
    result = []
    for match in matches[:top_k]:
        score = match.get("similarity", match.get("score", 0))
        result.append({
            "canonical_value": match.get("canonical_value") or match.get("entity_id"),
            "entity_type": match.get("entity_type", entity_type),
            "similarity_score": round(float(score), 3),
            "confidence": _score_to_confidence(float(score)),
            "calibration_status": "calibrated",
            "matching_features": match.get("matching_features", []),
            "profile_sample_count": match.get("sample_count", 0),
        })
    
    return result


def _score_to_confidence(score: float) -> str:
    if score >= 0.90:
        return "high"
    if score >= 0.80:
        return "medium"
    return "low"
