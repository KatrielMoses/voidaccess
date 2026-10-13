"""
api/routes/actors.py — Persistent actor profile endpoints.

GET  /actors                       — list / search across actor profiles
GET  /actors/{handle}              — full profile (aliases + infrastructure)
GET  /actors/{handle}/investigations — investigations that surfaced this actor
POST /actors/{handle}/notes        — append an analyst note

All endpoints are user-scoped: a profile is only surfaced if at least
one of its linked investigations is owned by the caller.  Notes can
only be appended by the owner of *any* linked investigation — actor
profiles themselves don't have an owner column; access is derived
from the underlying investigations.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from fastapi import Request, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select

from api.auth import CurrentUser, get_current_user

logger = logging.getLogger(__name__)
from api.ownership import require_resource_owner

async def require_owned_actor(request: Request, current: CurrentUser = Depends(get_current_user)):
    if "handle" in request.path_params:
        from api.actor_views import ScopedActorManager
        profile = await ScopedActorManager(current).get_profile(request.path_params["handle"])
        if profile is None:
            raise HTTPException(404, "Actor profile not found")

router = APIRouter(dependencies=[Depends(require_owned_actor), Depends(require_resource_owner)])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class ActorNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000, description="Note text")


class ActorAliasRequest(BaseModel):
    """Body for ``POST /actors/{handle}/aliases``.

    ``alias`` is the alternate handle / PGP fingerprint / wallet that
    should be linked to the actor.  ``alias_type`` defaults to
    ``"confirmed_same_actor"`` (the safe manual-override value) but
    callers can pass any of the documented types.  ``note`` is
    optional and stored as the alias row's source_investigation_id
    column (we don't have a free-form note column on actor_aliases —
    ``source_investigation_id`` is the only provenance field; ``None``
    is fine).
    """

    alias: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="The candidate alias handle or PGP fingerprint / wallet",
    )
    alias_type: str = Field(
        default="confirmed_same_actor",
        description=(
            "Alias type label.  Use 'confirmed_same_actor' for analyst- "
            "verified merges and 'likely_same_actor' for soft signals."
        ),
    )
    note: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Optional provenance / analyst note (not persisted in the row)",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional confidence (defaults to 1.0 for manual confirms)",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db_required() -> None:
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")


def _user_owned_investigation_ids_select(user_id: int):
    from db.models import Investigation

    return select(Investigation.id).where(Investigation.user_id == user_id)


def _profile_accessible(session, profile_id: str, user_id: int) -> bool:
    """True when at least one investigation linked to the profile is owned by the user."""
    from db.models import ActorAlias, ActorInfrastructure, User
    user = session.get(User, user_id)
    if user and user.role == "admin":
        return True
    profile_id = uuid.UUID(str(profile_id))
    inv_ids_select = _user_owned_investigation_ids_select(user_id)
    alias_match = (
        session.query(ActorAlias.id)
        .filter(
            ActorAlias.actor_id == profile_id,
            ActorAlias.source_investigation_id.in_(inv_ids_select),
        )
        .first()
    )
    if alias_match:
        return True
    infra_match = (
        session.query(ActorInfrastructure.id)
        .filter(
            ActorInfrastructure.actor_id == profile_id,
            ActorInfrastructure.source_investigation_id.in_(inv_ids_select),
        )
        .first()
    )
    return infra_match is not None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_actors(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: Optional[str] = Query(
        default=None, description="Case-insensitive partial match on handle or alias"
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """List actor profiles — optionally filtered by a search string.

    Profiles are filtered to those linked to at least one of the
    caller's investigations.  Profiles that no caller has touched yet
    (e.g. created during a system seed) are visible to all signed-in
    users since the seed is public data.
    """
    _db_required()
    from db.models import (
        ActorProfile,
        ActorAlias,
        ActorInfrastructure,
    )

    try:
        with _session() as session:
            user_inv_ids = _user_owned_investigation_ids_select(current_user.user.id)

            # Subquery of profile IDs visible to this user
            visible_alias = select(ActorAlias.actor_id).where(
                ActorAlias.source_investigation_id.in_(user_inv_ids)
            )
            visible_infra = select(ActorInfrastructure.actor_id).where(
                ActorInfrastructure.source_investigation_id.in_(user_inv_ids)
            )

            q = session.query(ActorProfile).filter(
                or_(
                    ActorProfile.id.in_(visible_alias),
                    ActorProfile.id.in_(visible_infra),
                )
            )
            if current_user.user.role == "admin":
                q = session.query(ActorProfile)
            if search:
                pattern = f"%{search.lower()}%"
                alias_select = select(ActorAlias.actor_id).where(
                    ActorAlias.alias_value.ilike(pattern),
                    ActorAlias.user_id == current_user.user.id,
                )
                q = q.filter(
                    or_(
                        ActorProfile.canonical_handle.ilike(pattern),
                        ActorProfile.id.in_(alias_select),
                    )
                )

            total = int(q.count() or 0)
            rows = (
                q.order_by(ActorProfile.last_seen_at.desc().nullslast())
                .offset(offset)
                .limit(limit)
                .all()
            )
            items: list[dict] = []
            for r in rows:
                from api.actor_views import ScopedActorManager
                profile = await ScopedActorManager(current_user).get_profile(r.canonical_handle)
                if profile:
                    items.append({k: profile.get(k) for k in (
                        "id", "canonical_handle", "first_seen_at", "last_seen_at", "investigation_count", "confidence", "alias_count"
                    )})
            return {
                "items": items,
                "total": total,
                "skip": offset,
                "limit": limit,
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("list_actors failed: %s", exc)
        return {"items": [], "total": 0, "skip": offset, "limit": limit}


@router.get("/{handle}")
async def get_actor(
    handle: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return a single actor profile with aliases, infrastructure, and linked investigation IDs."""
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")
    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load actor profile")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    # Visibility: only return profile if the user owns at least one
    # linked investigation.  Otherwise 404 (don't leak existence).
    try:
        with _session() as session:
            if not _profile_accessible(
                session, profile["id"], current_user.user.id
            ):
                raise HTTPException(status_code=404, detail="Actor profile not found")
    except HTTPException:
        raise

    return profile


@router.get("/{node_id}/profile")
async def get_actor_profile_by_node(
    node_id: str,
    investigation_id: str = Query(..., description="Investigation ID"),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return the graph actor profile for a node inside one investigation."""
    _db_required()
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    from db.queries import get_investigation_by_id_or_run
    from graph import build_graph_from_db_cached, get_actor_profile

    with _session() as session:
        inv = get_investigation_by_id_or_run(session, inv_uuid)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if str(inv.user_id) != str(current_user.user.id):
            raise HTTPException(status_code=404, detail="Actor profile not found")
        graph = build_graph_from_db_cached(investigation_id=inv.id)

    profile = get_actor_profile(graph, node_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Graph node not found")
    return profile


@router.get("/{handle}/investigations")
async def get_actor_investigations(
    handle: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """List investigations that have surfaced this actor (user-scoped)."""
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")
    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor_investigations failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load actor")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    from db.models import Investigation

    try:
        with _session() as session:
            user_inv_ids = _user_owned_investigation_ids_select(current_user.user.id)
            all_ids = [
                uuid_value(s)
                for s in profile.get("investigation_ids", [])
                if s
            ]
            all_ids = [v for v in all_ids if v is not None]
            if not all_ids:
                return {"actor_id": profile["id"], "items": []}
            rows = (
                session.query(Investigation)
                .filter(
                    Investigation.id.in_(all_ids),
                    Investigation.id.in_(user_inv_ids),
                )
                .order_by(Investigation.created_at.desc())
                .all()
            )
            return {
                "actor_id": profile["id"],
                "canonical_handle": profile["canonical_handle"],
                "items": [
                    {
                        "id": str(r.id),
                        "query": r.query,
                        "status": r.status,
                        "created_at": _iso(r.created_at),
                        "summary": (r.summary or "")[:240],
                    }
                    for r in rows
                ],
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor_investigations failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to list investigations")


@router.post("/{handle}/notes")
async def add_actor_note(
    handle: str,
    body: ActorNoteRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Append an analyst note to an actor profile."""
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")
    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("add_actor_note lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to look up actor")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    try:
        with _session() as session:
            if not _profile_accessible(
                session, profile["id"], current_user.user.id
            ):
                raise HTTPException(status_code=404, detail="Actor profile not found")

        from db.models import ActorProfile
        from datetime import datetime, timezone

        with _session() as session:
            import uuid as _uuid
            try:
                profile_uuid = _uuid.UUID(profile["id"])
            except (ValueError, KeyError):
                raise HTTPException(status_code=500, detail="Bad actor id")
            row = session.query(ActorProfile).filter_by(id=profile_uuid).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="Actor profile not found")
            from db.models import ActorNote
            ts = datetime.now(timezone.utc).isoformat()
            note_text = f"[{ts}] {body.note}"
            session.add(ActorNote(actor_id=profile_uuid, user_id=current_user.user.id, text=note_text))
            session.commit()

        return {
            "id": profile["id"],
            "canonical_handle": profile["canonical_handle"],
            "notes": note_text,
            "appended_at": ts,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("add_actor_note failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to add note")


@router.get("/{handle}/timeline")
async def get_actor_timeline(
    handle: str,
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of timeline events to return",
    ),
    event_types: Optional[str] = Query(
        default=None,
        description=(
            "Comma-separated event-type filter "
            "(FIRST_SEEN, INVESTIGATION, NEW_ALIAS, "
            "NEW_INFRASTRUCTURE, NOTE_ADDED)"
        ),
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return the chronological activity timeline for an actor.

    The timeline is computed on the fly from existing tables — no new
    schema, no caching.  Events are sorted oldest-first.

    Response shape::

        {
          "actor_id": "...",
          "canonical_handle": "...",
          "handle": "lockbitsupp",
          "event_count": 23,
          "first_seen": "2024-01-15T10:30:00+00:00",
          "last_seen":  "2026-06-25T08:14:00+00:00",
          "events": [
            {
              "event_type": "FIRST_SEEN",
              "timestamp": "2024-01-15T10:30:00+00:00",
              "description": "Actor lockbitsupp first observed",
              "metadata": {}
            },
            ...
          ]
        }
    """
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")

    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor_timeline lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load actor profile")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    # Visibility: same rule as the other actor endpoints — must own at
    # least one linked investigation, otherwise 404 (don't leak
    # existence).
    try:
        with _session() as session:
            if not _profile_accessible(
                session, profile["id"], current_user.user.id
            ):
                raise HTTPException(
                    status_code=404, detail="Actor profile not found"
                )
    except HTTPException:
        raise

    requested_types: Optional[set[str]] = None
    if event_types:
        requested_types = {
            t.strip().upper()
            for t in event_types.split(",")
            if t and t.strip()
        }
        # Drop unknown types silently — better UX than 422 for typos,
        # and the response's event_type list is self-documenting.
        allowed = set(manager._TIMELINE_EVENT_TYPES)  # noqa: SLF001
        requested_types = {t for t in requested_types if t in allowed}

    # Over-fetch when filtering so a narrow filter still returns up to
    # ``limit`` events.  Cap at 1000 to keep the response bounded.
    fetch_limit = limit
    if requested_types:
        fetch_limit = min(max(limit * 4, 100), 1000)

    try:
        events = await manager.get_actor_timeline(
            handle.strip(),
            limit=fetch_limit,
            event_types=requested_types,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "get_actor_timeline generation failed: %s", exc
        )
        raise HTTPException(status_code=500, detail="Failed to build timeline")

    events = events[:limit]

    first_seen = profile.get("first_seen_at")
    last_seen = events[-1].get("timestamp") if events else None

    return {
        "actor_id": profile["id"],
        "canonical_handle": profile["canonical_handle"],
        "handle": handle.strip(),
        "event_count": len(events),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "events": events,
    }


@router.get("/{handle}/aliases")
async def get_actor_aliases(
    handle: str,
    min_confidence: float = Query(
        default=0.60,
        ge=0.0,
        le=1.0,
        description="Drop candidates whose composite confidence is below this",
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return alias candidates grouped by confidence tier.

    Response shape::

        {
          "actor_id": "...",
          "canonical_handle": "...",
          "confirmed": [ { ... } ],
          "likely":    [ { ... } ],
          "possible":  [ { ... } ],
        }

    * ``confirmed`` — confidence ``>= 0.90`` (auto-classed as
      ``confirmed_same_actor``).
    * ``likely`` — confidence ``>= 0.75``.
    * ``possible`` — everything else above ``min_confidence``.

    The list under each tier is sorted by confidence descending.  An
    empty tier is omitted from the response payload to keep the wire
    shape tidy.
    """
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")
    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor_aliases lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load actor profile")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    # Visibility: only return aliases if the user owns at least one
    # linked investigation (same rule as the rest of the actor API).
    try:
        with _session() as session:
            if not _profile_accessible(
                session, profile["id"], current_user.user.id
            ):
                raise HTTPException(
                    status_code=404, detail="Actor profile not found"
                )
    except HTTPException:
        raise

    try:
        candidates = await manager.find_alias_candidates(
            profile["id"], min_confidence=min_confidence
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_actor_aliases: find_alias_candidates failed: %s", exc)
        candidates = []

    confirmed: list[dict] = []
    likely: list[dict] = []
    possible: list[dict] = []
    for c in candidates:
        conf = float(c.get("confidence") or 0.0)
        entry = {
            "candidate_actor_id": c.get("candidate_actor_id"),
            "candidate_handle": c.get("candidate_handle"),
            "confidence": conf,
            "signals": c.get("signals") or [],
            "shared_infrastructure": c.get("shared_infrastructure") or [],
            "shared_pgp": c.get("shared_pgp") or [],
            "shared_investigations": c.get("shared_investigations") or [],
        }
        if conf >= 0.90:
            confirmed.append(entry)
        elif conf >= 0.75:
            likely.append(entry)
        else:
            possible.append(entry)

    response: dict = {
        "actor_id": profile["id"],
        "canonical_handle": profile["canonical_handle"],
        "confirmed": confirmed,
        "likely": likely,
    }
    if possible:
        response["possible"] = possible
    return response


@router.post("/{handle}/aliases")
async def add_actor_alias(
    handle: str,
    body: ActorAliasRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Manually add or confirm an alias for an actor.

    The analyst's confirmation always takes precedence over the
    auto-resolution pass.  Stored with ``alias_type=confirmed_same_actor``
    by default (callers can pass ``likely_same_actor`` for a softer
    "this looks like a different handle I've seen" annotation).

    Idempotent — re-adding the same ``alias`` for the same actor
    updates the existing row's ``confidence`` upward and leaves the
    ``alias_type`` label unchanged so the analyst's first decision
    sticks.
    """
    _db_required()
    if not handle or not handle.strip():
        raise HTTPException(status_code=422, detail="Handle is required")
    if not body.alias or not body.alias.strip():
        raise HTTPException(status_code=422, detail="Alias is required")
    try:
        mgr_cls = _actor_manager_class()
        from api.actor_views import ScopedActorManager
        manager = ScopedActorManager(current_user)
        profile = await manager.get_profile(handle.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("add_actor_alias lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load actor profile")

    if profile is None:
        raise HTTPException(status_code=404, detail="Actor profile not found")

    try:
        with _session() as session:
            if not _profile_accessible(
                session, profile["id"], current_user.user.id
            ):
                raise HTTPException(status_code=404, detail="Actor profile not found")
    except HTTPException:
        raise

    # The manager's add_alias is idempotent — re-adding the same alias
    # bumps confidence but leaves the type alone.  We default confidence
    # to 1.0 for manual confirmations so the row's confidence is at
    # least as high as any auto-persisted candidate.
    confidence = (
        float(body.confidence)
        if body.confidence is not None
        else 1.0
    )

    try:
        await manager.add_alias(
            actor_id=profile["id"],
            alias_value=body.alias.strip(),
            alias_type=body.alias_type.strip() or "confirmed_same_actor",
            investigation_id=None,
            confidence=confidence,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("add_actor_alias failed: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to record alias"
        )

    return {
        "actor_id": profile["id"],
        "canonical_handle": profile["canonical_handle"],
        "alias": body.alias.strip(),
        "alias_type": body.alias_type.strip() or "confirmed_same_actor",
        "confidence": confidence,
        "note": body.note,
    }


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _session():
    """Yield a short-lived DB session (closes itself after the route)."""
    from db.session import get_session

    return get_session()


def _iso(dt) -> Optional[str]:
    if dt is None:
        return None
    from datetime import timezone as _tz

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tz.utc)
    return dt.isoformat()


def _actor_manager_class():
    """Lazy import so a DB outage at module-load doesn't break the route."""
    from sources.actor_profiles import ActorProfileManager

    return ActorProfileManager


def uuid_value(s):
    """Best-effort parse of a string into a UUID."""
    if not s:
        return None
    try:
        import uuid as _uuid
        return _uuid.UUID(str(s))
    except (ValueError, TypeError):
        return None
