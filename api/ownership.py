"""Shared ownership checks for object routes. Foreign objects always return 404."""
from __future__ import annotations

import uuid
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from api.auth import CurrentUser, get_current_user
from db.session import get_db
from db.models import Entity, Investigation, InvestigationEntityLink
from db.queries import get_investigation_by_id_or_run


def owned_investigation(session: Session, identifier: str, user_id: int):
    try:
        key = uuid.UUID(identifier)
    except ValueError:
        raise HTTPException(422, "Invalid investigation ID format")
    row = get_investigation_by_id_or_run(session, key)
    if row is None or row.user_id != user_id:
        raise HTTPException(404, "Investigation not found")
    return row


def accessible_entity(session: Session, identifier: str, user_id: int):
    try:
        key = uuid.UUID(identifier)
    except ValueError:
        raise HTTPException(422, "Invalid entity ID format")
    owned_ids = session.query(Investigation.id).filter(Investigation.user_id == user_id)
    linked_ids = session.query(InvestigationEntityLink.entity_id).filter(
        InvestigationEntityLink.investigation_id.in_(owned_ids)
    )
    row = session.query(Entity).filter(
        Entity.id == key,
        (Entity.investigation_id.in_(owned_ids)) | (Entity.id.in_(linked_ids)),
    ).first()
    if row is None:
        raise HTTPException(404, "Entity not found")
    return row


async def require_resource_owner(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
) -> None:
    """Guard path objects and optional investigation scopes before the handler."""
    from db.session import get_session
    params = request.path_params
    scope = request.query_params.get("investigation_id")
    if not ("investigation_id" in params or "entity_id" in params or scope):
        return
    with get_session() as session:
        if "investigation_id" in params:
            owned_investigation(session, params["investigation_id"], current.user.id)
        if "entity_id" in params:
            accessible_entity(session, params["entity_id"], current.user.id)
        if scope:
            owned_investigation(session, scope, current.user.id)
