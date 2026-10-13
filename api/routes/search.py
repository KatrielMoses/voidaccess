"""
api/routes/search.py — Semantic and full-text search endpoints.

POST /search/semantic   — vector similarity search against scraped pages
POST /search/entities   — full-text search across entity values in DB
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from api.auth import CurrentUser, get_current_user
from api.errors import log_exception, safe_detail

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


def _search_payload(results: list[dict], warnings: list[str] | None = None) -> dict:
    return {"results": results, "warnings": warnings or []}


class EntitySearchRequest(BaseModel):
    query: str
    entity_types: Optional[list[str]] = None
    offset: int = 0
    limit: int = 50


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/semantic")
async def semantic_search(
    q: str = Query(..., min_length=1),
    n: int = Query(10, ge=1, le=100),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    warnings: list[str] = []
    try:
        from vector import search_similar

        results = search_similar(q, n_results=n, user_id=current_user.user.id)
        return _search_payload(results, warnings)
    except Exception as exc:
        warnings.append(
            safe_detail(
                log_exception(exc, context="semantic_search"),
                "Search backend unavailable",
            )
        )
        return _search_payload([], warnings)


@router.get("/similar-to")
async def similar_to(
    url: str = Query(..., min_length=1),
    n: int = Query(10, ge=1, le=100),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    warnings: list[str] = []
    """
    Return pages similar to a reference URL from the vector store.
    """
    try:
        from vector import find_pages_similar_to

        return _search_payload(find_pages_similar_to(url, n_results=n, user_id=current_user.user.id), warnings)
    except Exception as exc:
        warnings.append(
            safe_detail(
                log_exception(exc, context="similar_to"),
                "Search backend unavailable",
            )
        )
        return _search_payload([], warnings)


@router.get("/cross-investigation")
async def cross_investigation(
    q: str = Query(..., min_length=1),
    exclude_investigation: str | None = None,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    warnings: list[str] = []
    try:
        from vector import cross_investigation_recall

        return _search_payload(
            cross_investigation_recall(q, exclude_investigation_id=exclude_investigation, user_id=current_user.user.id),
            warnings,
        )
    except Exception as exc:
        warnings.append(
            safe_detail(
                log_exception(exc, context="cross_investigation"),
                "Search backend unavailable",
            )
        )
        return _search_payload([], warnings)


@router.get("/stats")
async def stats(current_user: CurrentUser = Depends(get_current_user)) -> dict:
    warnings: list[str] = []
    total_documents = 0
    persist_directory = ""
    chromadb_available = False
    try:
        from vector import get_collection, get_collection_stats, count_pages

        chromadb_available = get_collection() is not None
        total_documents = count_pages(user_id=None if current_user.user.role == "admin" else current_user.user.id)
        stats = get_collection_stats()
        persist_directory = str(stats.get("persist_directory", ""))
    except Exception as exc:
        warnings.append(
            safe_detail(
                log_exception(exc, context="search stats"),
                "Vector store stats unavailable",
            )
        )
    return {
        "total_documents": total_documents,
        "persist_directory": persist_directory,
        "chromadb_available": chromadb_available,
        "warnings": warnings,
    }


@router.post("/entities")
async def search_entities(
    body: EntitySearchRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    if not os.getenv("DATABASE_URL"):
        return {"items": [], "total": 0, "offset": 0, "limit": 50}
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity, Investigation, InvestigationEntityLink  # noqa: PLC0415
        import sqlalchemy as sa  # noqa: PLC0415

        limit = max(1, min(body.limit, 200))
        offset = max(0, body.offset)

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
                ),
                Entity.value.contains(body.query),
            )
            if body.entity_types:
                q = q.filter(Entity.entity_type.in_(body.entity_types))
            from db.entity_views import entity_views
            entities = entity_views(session, q.all(), user_id=current_user.user.id)
            entities.sort(key=lambda e: e.created_at.isoformat() if e.created_at else "", reverse=True)
            total = len(entities)
            entities = entities[offset:offset + limit]
            return {
                "items": [
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "value": e.value,
                        "confidence": e.confidence,
                        "investigation_id": str(e.investigation_id) if e.investigation_id else None,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                    }
                    for e in entities
                ],
                "total": total,
                "offset": offset,
                "limit": limit,
            }
    except Exception as exc:
        logger.warning("search_entities failed: %s", exc)
        return {"items": [], "total": 0, "offset": 0, "limit": 50}
