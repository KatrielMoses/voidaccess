"""
Admin routes for VoidAccess API.

Provides administrative endpoints for monitoring and managing the system.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.auth import get_current_user
from api.errors import log_exception
from search.search import SEARCH_ENGINES
from search.circuit_breaker import record_success, is_open, _engine_failures
from sources.seed_manager import get_seed_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

# In-memory registry of seed-validation jobs.  Persistence isn't required —
# validation is best-effort and ephemeral.
_seed_validation_jobs: dict[str, dict] = {}


@router.get("/enrichment-cache/stats", dependencies=[Depends(get_current_user)])
async def get_enrichment_cache_stats() -> dict:
    """
    Return cross-investigation enrichment cache stats.

    Returns backend, hits, misses, hit_rate_pct, size, and the per-source
    TTL defaults. Useful for verifying cache wiring and quota savings.
    """
    try:
        from utils.enrichment_cache import get_enrichment_cache
        cache = await get_enrichment_cache()
        return await cache.stats()
    except Exception as exc:
        correlation_id = log_exception(exc, context="get_enrichment_cache_stats")
        return {
            "backend": "unavailable",
            "hits": 0,
            "misses": 0,
            "hit_rate_pct": 0.0,
            "size": 0,
            "error": "unavailable",
            "correlation_id": correlation_id,
        }


@router.get("/corpus-health", dependencies=[Depends(get_current_user)])
async def get_corpus_health(window_seconds: int = 3600) -> dict:
    """Corpus-health vital signs for the single maintainer (P4.4 / CC-5).

    Aggregates the already-emitted counters — ingest rate, quarantine:promotion
    ratio (the primary poisoning signal), source-reputation distribution + flagged
    contributors, index size/freshness, and read-from-shared cache-hit rate — from
    a single point-in-time pass over existing tables (no parallel metrics pipeline).
    Auth-protected. On a $0/local install with no DB configured it returns an inert
    ``available: false`` payload rather than erroring.
    """
    import os

    if not os.getenv("DATABASE_URL"):
        return {"available": False, "reason": "no central corpus (local/$0 install)"}
    try:
        from db.session import get_session
        from observability import corpus_health

        with get_session() as session:
            data = corpus_health(session, window_seconds=window_seconds)
        data["available"] = True
        return data
    except Exception as exc:
        correlation_id = log_exception(exc, context="get_corpus_health")
        return {"available": False, "error": "unavailable", "correlation_id": correlation_id}


@router.post("/enrichment-cache/invalidate", dependencies=[Depends(get_current_user)])
async def invalidate_enrichment_cache_entry(
    entity_type: str,
    value: str,
    source: str,
) -> dict:
    """
    Force-expire a single enrichment cache entry.
    Useful when an operator knows an upstream source has stale data.
    """
    from utils.enrichment_cache import get_enrichment_cache
    cache = await get_enrichment_cache()
    await cache.invalidate(entity_type, value, source)
    return {
        "invalidated": True,
        "entity_type": entity_type,
        "value": value,
        "source": source,
    }


@router.get("/circuit-breakers")
async def get_circuit_breakers(current_user=Depends(get_current_user)) -> dict:
    """
    Get the current state of all search engine circuit breakers.
    Returns state, failure count, and last success timestamp for each engine.
    """
    engines = {}
    for engine in SEARCH_ENGINES:
        name = engine["name"]
        failures = _engine_failures.get(name, 0)
        open_state = await is_open(name)
        engines[name] = {
            "state": "open" if open_state else "closed",
            "failure_count": failures,
            "url": engine.get("url", "").split("{")[0]  # strip query param
        }
    return {"engines": engines}


@router.post("/circuit-breakers/{engine_name}/reset", dependencies=[Depends(get_current_user)])
async def reset_circuit_breaker(engine_name: str) -> dict:
    """Reset a circuit breaker to closed state manually."""
    await record_success(engine_name)
    return {"engine": engine_name, "state": "closed", "message": "Circuit breaker reset"}


@router.post("/circuit-breakers/reset-all", dependencies=[Depends(get_current_user)])
async def reset_all_circuit_breakers() -> dict:
    """Reset all circuit breakers to closed state."""
    from search.search import SEARCH_ENGINES
    for engine in SEARCH_ENGINES:
        await record_success(engine["name"])
    return {"reset_count": len(SEARCH_ENGINES), "state": "all closed"}


@router.get("/content-safety/events", dependencies=[Depends(get_current_user)])
async def get_content_safety_events() -> dict:
    """
    Return content safety block event counts for operator review.
    Returns counts only — never the blocked content itself.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return {
                "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
                "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            }

        from db.session import get_session
        from db.models import ContentSafetyEvent
        from sqlalchemy import func

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        event_types = ["query_blocked", "url_blocked", "content_blocked"]

        with get_session() as session:
            last_24h: dict[str, int] = {}
            total: dict[str, int] = {}
            for et in event_types:
                last_24h[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(
                        ContentSafetyEvent.event_type == et,
                        ContentSafetyEvent.timestamp >= cutoff,
                    )
                    .scalar()
                    or 0
                )
                total[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(ContentSafetyEvent.event_type == et)
                    .scalar()
                    or 0
                )

        return {"last_24h": last_24h, "total": total}

    except Exception as exc:
        correlation_id = log_exception(exc, context="content_safety_stats")
        return {
            "error": "unavailable",
            "correlation_id": correlation_id,
            "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
        }


# ---------------------------------------------------------------------------
# Seed list management
# ---------------------------------------------------------------------------


class AddSeedBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=8, max_length=500)
    category: str = Field(default="discovered", max_length=80)
    tags: list[str] = Field(default_factory=list)


async def _run_seed_validation_job(job_id: str) -> None:
    """Background coroutine: validate all seeds and record the result."""
    job = _seed_validation_jobs.setdefault(job_id, {})
    job["status"] = "running"
    job["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        seed_manager = get_seed_manager()
        results = await seed_manager.validate_seeds(concurrency=3)
        job["status"] = "completed"
        job["results"] = results
    except Exception as exc:
        correlation_id = log_exception(
            exc, context=f"seed validation job {job_id}"
        )
        job["status"] = "failed"
        job["error"] = "Seed validation failed."
        job["correlation_id"] = correlation_id
    finally:
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.get("/seeds", dependencies=[Depends(get_current_user)])
async def get_seeds_summary() -> dict:
    """Return a summary of the seed list: counts by category and status."""
    try:
        seed_manager = get_seed_manager()
        return seed_manager.summary()
    except Exception as exc:
        logger.warning("get_seeds_summary failed: %s", exc)
        return {"total": 0, "by_category": {}, "by_status": {}, "last_validated": None}


@router.get("/seeds/list", dependencies=[Depends(get_current_user)])
async def list_all_seeds() -> dict:
    """Return the full seed list (admin only)."""
    try:
        seed_manager = get_seed_manager()
        return {"seeds": seed_manager.list_seeds()}
    except Exception as exc:
        logger.warning("list_all_seeds failed: %s", exc)
        return {"seeds": []}


@router.post("/seeds/validate", dependencies=[Depends(get_current_user)])
async def trigger_seed_validation() -> dict:
    """
    Trigger a background validation of every seed over Tor.
    Returns a job_id so callers can poll status.
    """
    seed_manager = get_seed_manager()
    seed_count = len(seed_manager.list_seeds())
    job_id = str(uuid.uuid4())
    _seed_validation_jobs[job_id] = {
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "seed_count": seed_count,
    }
    asyncio.create_task(_run_seed_validation_job(job_id))
    return {
        "job_id": job_id,
        "message": f"Validation started for {seed_count} seeds",
    }


@router.get("/seeds/validate/{job_id}", dependencies=[Depends(get_current_user)])
async def get_seed_validation_status(job_id: str) -> dict:
    """Poll the status of a seed-validation job."""
    job = _seed_validation_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Validation job not found")
    return {"job_id": job_id, **job}


@router.post("/seeds/add", dependencies=[Depends(get_current_user)])
async def add_seed(body: AddSeedBody) -> dict:
    """Manually add a seed URL to the catalogue."""
    seed_manager = get_seed_manager()
    added = seed_manager.add_discovered_seed(
        url=body.url,
        name=body.name,
        tags=body.tags,
        category=body.category,
    )
    if not added:
        raise HTTPException(
            status_code=400,
            detail="Seed not added (duplicate URL or blocked by content safety)",
        )
    return {"added": True, "url": body.url, "category": body.category}


@router.get("/seeds/discovered", dependencies=[Depends(get_current_user)])
async def list_discovered_seeds(
    only_pending: bool = True,
    limit: int = 100,
    investigation_id: Optional[str] = None,
) -> dict:
    """
    List auto-discovered seeds, with provenance metadata.

    Args:
        only_pending: when True (default), restrict to seeds still
            awaiting validate_seeds() confirmation (status == "discovered").
            Set to False to include already-validated discovered seeds too.
        limit: maximum number of results (default 100, hard cap 1000).
        investigation_id: optional filter — return only seeds discovered
            by a specific investigation.

    Returns:
        {
            "total": int,
            "breakdown": { "permanent": N, "discovered_pending": N, ... },
            "last_validated": ISO timestamp | None,
            "seeds": [ { url, name, source_url, investigation_id, added_at, status } ]
        }
    """
    try:
        seed_manager = get_seed_manager()
        limit = max(1, min(int(limit), 1000))

        seeds = seed_manager.list_discovered_seeds(
            only_pending=only_pending,
            limit=None,
        )

        # Optional investigation_id filter — applied after the list call
        # since it's an in-memory filter, not an index lookup.
        if investigation_id:
            seeds = [s for s in seeds if s.get("investigation_id") == investigation_id]

        seeds = seeds[:limit]

        # Project each seed down to the fields the admin UI cares about.
        projected = [
            {
                "url": s.get("url", ""),
                "name": s.get("name", ""),
                "status": s.get("status", ""),
                "added": s.get("added", ""),
                "added_at": s.get("added_at", ""),
                "source_url": s.get("source_url", ""),
                "investigation_id": s.get("investigation_id", ""),
                "tags": s.get("tags", []),
            }
            for s in seeds
        ]

        return {
            "total": len(projected),
            "breakdown": seed_manager.count_by_type(),
            "last_validated": seed_manager.summary().get("last_validated"),
            "seeds": projected,
        }
    except Exception as exc:
        correlation_id = log_exception(exc, context="list_discovered_seeds")
        return {
            "total": 0,
            "breakdown": {
                "permanent": 0,
                "discovered_total": 0,
                "discovered_pending": 0,
                "discovered_validated": 0,
            },
            "last_validated": None,
            "seeds": [],
            "error": "unavailable",
            "correlation_id": correlation_id,
        }