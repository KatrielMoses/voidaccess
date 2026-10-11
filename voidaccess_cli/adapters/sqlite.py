"""
cli/adapters/sqlite.py — SQLite persistence layer for the CLI.

Reuses the existing SQLAlchemy ORM (db.models) and engine factory
(db.session) by setting DATABASE_URL=sqlite:///~/.voidaccess/investigations.db
before any voidaccess module is imported (cli.config.apply_env).

This adapter wraps that infrastructure with CLI-friendly helpers:
init_db()                   — create tables on first run (no Alembic)
save_investigation()        — create an Investigation row
update_investigation()      — patch fields on an existing row
update_investigation_metadata() — merge JSON metadata into the metadata col
list_investigations()       — recent runs
get_investigation()         — single row by id
get_entities()              — entities for an investigation, optionally filtered
get_relationships()         — edges for an investigation
cleanup_stuck_investigations() — Phase 6.3: mark interrupted runs as failed
list_actor_profiles()       — aggregate actor profiles (CLI `voidaccess actors`)
get_actor_profile()         — single actor with aliases + infrastructure
add_actor_note()            — set analyst note on an actor profile
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union
from types import SimpleNamespace

from sqlalchemy import text
from db.search_engine_stats import (
    CREATE_SEARCH_ENGINE_STATS_SQL,
    get_all_engine_stats_async as _get_all_engine_stats_async,
)
from utils.enrichment_cache import _SQLITE_CREATE_TABLE, _SQLITE_INDEX_EXPIRES

from voidaccess_cli.config import DB_PATH as _DB_PATH


class DatabaseSchemaError(RuntimeError):
    """Raised before an investigation when the local DB is behind the code."""


_REQUIRED_SCHEMA_COLUMNS: dict[str, frozenset[str]] = {
    # Added by Alembic migration 0026.  The ORM touches this column during
    # every entity merge, so silently proceeding without it produces an empty
    # investigation that looks successful but can never persist entities.
    "entities": frozenset({"investigation_count"}),
    # Shared tier, added by Alembic migration 0027 (create_all mirrors it on the
    # SQLite path).  ``get_columns`` on a missing table returns [], so this also
    # catches a DB where the shared-corpus tables never materialized.
    "global_entities": frozenset({"canonical_value"}),
}


def _source_quality_from_url(url: str) -> float:
    """Return a multi-tier source quality score derived from the source URL."""
    if not url:
        return 0.85
    u = url.lower()
    if "github.com" in u or "gitlab.com" in u:
        if "/readme" in u or "/blob/" in u or "/tree/" in u:
            return 0.55
        if "/issues/" in u or "/pull/" in u or "/merge_requests/" in u:
            return 0.68
        return 0.62
    if "rss" in u or "/feed" in u or "feed" in u:
        return 0.8
    if "paste" in u or "pastebin" in u:
        return 0.96
    if "forum" in u or "board" in u or "thread" in u:
        return 0.92
    if "blog" in u or "news" in u or "security" in u:
        return 0.88
    if ".onion" in u:
        return 0.98
    return 0.84


def _method_multiplier(method: str) -> float:
    method = (method or "").lower()
    if method == "regex":
        return 1.0
    if method == "ner":
        return 0.96
    if method == "llm":
        return 0.92
    return 0.98


def _source_count_multiplier(source_count: int) -> float:
    if source_count <= 1:
        return 1.0
    return min(1.0 + min(source_count - 1, 8) * 0.025, 1.2)


class _AwaitableStr(str):
    def __await__(self):
        async def _wrap():
            return str(self)

        return _wrap().__await__()


class _AwaitableBool:
    def __init__(self, value: bool):
        self.value = bool(value)

    def __bool__(self):
        return self.value

    def __await__(self):
        async def _wrap():
            return self.value

        return _wrap().__await__()


class _AwaitableDict(dict):
    def __await__(self):
        async def _wrap():
            return self

        return _wrap().__await__()


def get_db_path() -> Path:
    """Return the resolved path of the SQLite database file.

    Used by external scripts and the verify step to inspect the on-disk
    schema; respects ``VOIDACCESS_DB_PATH`` env override when set.
    """
    override = __import__("os").environ.get("VOIDACCESS_DB_PATH", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return _DB_PATH


def _sqlite_url() -> str:
    return f"sqlite:///{get_db_path().as_posix()}"


def init_db() -> None:
    """Create all tables on the SQLite file if missing. Idempotent."""
    from db.models import Base
    from db.session import get_engine
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = get_engine(_sqlite_url())
    Base.metadata.create_all(engine)

    # Phase 6.1: idempotent backfill of the ``metadata`` column on existing
    # SQLite databases created before the 0023 migration.  ``create_all``
    # only creates *missing* tables — it never adds columns to an existing
    # one.  We probe information_schema for the column and ALTER TABLE if
    # absent.  This is a no-op on a fresh DB.
    _ensure_metadata_column(engine)

    # P1.1: guarantee the metrics table exists on pre-existing DB files.
    # ``create_all`` above already creates it (it is an ORM-mapped table), so
    # this is defensive belt-and-suspenders: it keeps the guarantee explicit and
    # local, independent of whether ``db.models`` happened to register the model,
    # and is the regression anchor for the P1.0 baseline-integrity check.
    _ensure_investigation_step_metrics(engine)

    # Create page_extraction_cache table if missing
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS page_extraction_cache (
                page_hash TEXT PRIMARY KEY,
                entities_json TEXT NOT NULL,
                extracted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """))
        conn.execute(text(_SQLITE_CREATE_TABLE))
        conn.execute(text(_SQLITE_INDEX_EXPIRES))
        conn.execute(text(CREATE_SEARCH_ENGINE_STATS_SQL))
        conn.commit()

    # Gate *every* CLI entry point on a migrated schema.  ``init_db`` is the
    # single choke point that all read paths (list/show/export/enrich/actors/
    # timeline/status) and the write path (investigate) call before touching
    # the DB, so validating here guarantees a stale SQLite file produces one
    # actionable ``DatabaseSchemaError`` (rendered by the CLI entry wrapper as
    # a clean message + non-zero exit) instead of a silent zero-entity run on
    # the write path or a raw ``OperationalError`` traceback / misleading exit
    # 0 on a read path.  ``create_all`` above only creates *missing* tables; it
    # never adds columns to an existing one, so a v0.5-shaped DB survives table
    # creation and is caught here.  investigate.py keeps its own explicit
    # ``validate_schema()`` call as documentation of intent (harmless re-check).
    validate_schema()


def validate_schema() -> None:
    """Fail before a run if the DB is missing columns required by the ORM.

    The CLI historically used ``create_all`` for SQLite, which does not alter
    existing tables.  A database created before a migration could therefore
    survive startup and fail only inside per-entity savepoints, yielding a
    misleading zero-entity run.  Validate the migrated contract immediately
    after initialization so the user gets one actionable error instead.
    """
    from sqlalchemy import inspect
    from db.session import get_engine

    engine = get_engine(_sqlite_url())
    inspector = inspect(engine)
    missing: list[str] = []
    for table, required_columns in _REQUIRED_SCHEMA_COLUMNS.items():
        present = {column["name"] for column in inspector.get_columns(table)}
        missing.extend(
            f"{table}.{column}"
            for column in sorted(required_columns - present)
        )
    if missing:
        raise DatabaseSchemaError(
            "Database schema is stale; missing required column(s): "
            f"{', '.join(missing)}. Run `alembic upgrade head` and retry."
        )


def _ensure_metadata_column(engine) -> None:
    """Phase 6.1: idempotent ALTER TABLE to add ``metadata`` JSON column.

    SQLite stores JSON as TEXT under the hood; SQLAlchemy's JSON column
    type round-trips through its serializer.  We use a try/except around
    the ALTER so this is safe to call on every startup — adding a column
    that already exists raises ``OperationalError`` which we swallow.
    """
    try:
        with engine.connect() as conn:
            # Cheap probe via pragma_table_info (SQLite-specific).
            cols = conn.execute(text("PRAGMA table_info(investigations)")).fetchall()
            has_metadata = any(row[1] == "metadata" for row in cols)
            if not has_metadata:
                conn.execute(text(
                    "ALTER TABLE investigations ADD COLUMN metadata TEXT"
                ))
                conn.commit()
                # Backfill empty JSON object so existing rows have a usable
                # default.  The merge logic in update_investigation_metadata
                # also handles NULL gracefully.
                conn.execute(text(
                    "UPDATE investigations SET metadata = '{}' WHERE metadata IS NULL"
                ))
                conn.commit()
    except Exception as exc:
        # Don't let a schema-drift hiccup block CLI startup.
        import logging
        logging.getLogger(__name__).debug(
            "_ensure_metadata_column skipped: %s", exc
        )


def _ensure_investigation_step_metrics(engine) -> None:
    """Idempotently guarantee the ``investigation_step_metrics`` table exists.

    Created drift-free via the ORM table itself (``checkfirst=True``) so its
    schema is byte-identical to what ``Base.metadata.create_all`` would build —
    no hand-written DDL to drift out of sync with the model. Best-effort like the
    other ``_ensure_*`` helpers: a failure here must never block the CLI, because
    step metrics are additive instrumentation, not pipeline control flow.
    """
    try:
        from db.models import InvestigationStepMetric
        InvestigationStepMetric.__table__.create(bind=engine, checkfirst=True)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).debug(
            "_ensure_investigation_step_metrics skipped: %s", exc
        )


async def get_all_engine_stats() -> list[dict[str, Any]]:
    return await _get_all_engine_stats_async()


def _serialize_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _coerce_expires_at(expires_at: Union[str, datetime]) -> datetime:
    """SQLite returns TIMESTAMP columns as strings; normalize for comparisons."""
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at


def get_page_extraction_cache(page_hash: str) -> Optional[dict[str, list[str]]]:
    """Load cached LLM extraction results when present and not expired."""
    try:
        from db.session import get_session
    except Exception:
        return None

    try:
        with get_session() as session:
            row = session.execute(
                text(
                    """
                    SELECT entities_json, expires_at
                    FROM page_extraction_cache
                    WHERE page_hash = :page_hash
                    """
                ),
                {"page_hash": page_hash},
            ).fetchone()

        if row is None:
            return None

        entities_json, expires_at = row[0], row[1]
        expires_at = _coerce_expires_at(expires_at)
        if expires_at < datetime.now(timezone.utc):
            return None

        return json.loads(entities_json)
    except Exception:
        return None


def save_investigation(
    query: Any,
    refined_query: Optional[str] = None,
    model_used: Optional[str] = None,
    status: str = "running",
) -> str:
    """Insert a new Investigation row, return its id (string UUID)."""
    from db.models import Investigation
    from db.session import get_session

    payload = query if isinstance(query, dict) else {}
    if payload:
        raw_id = payload.get("id")
        try:
            inv_id = uuid.UUID(str(raw_id)) if raw_id else uuid.uuid4()
        except (TypeError, ValueError):
            inv_id = uuid.uuid5(uuid.NAMESPACE_URL, str(raw_id))
        query = payload.get("query", "")
        refined_query = payload.get("refined_query", refined_query)
        model_used = payload.get("model_used", model_used)
        status = payload.get("status", status)
        created_at_raw = payload.get("created_at")
        try:
            created_at = (
                datetime.fromisoformat(created_at_raw)
                if created_at_raw
                else datetime.now(timezone.utc)
            )
        except (TypeError, ValueError):
            created_at = datetime.now(timezone.utc)
    else:
        inv_id = uuid.uuid4()
        created_at = datetime.now(timezone.utc)
    run_id = uuid.uuid4()
    with get_session() as session:
        existing = session.query(Investigation).filter_by(id=inv_id).first()
        if existing is not None:
            existing.query = query
            existing.refined_query = refined_query
            existing.model_used = model_used
            existing.status = status
            existing.created_at = created_at
            return _AwaitableStr(str(inv_id))
        inv = Investigation(
            id=inv_id,
            run_id=run_id,
            query=query,
            refined_query=refined_query,
            model_used=model_used,
            status=status,
            created_at=created_at,
            user_id=None,
        )
        session.add(inv)
    return _AwaitableStr(str(inv_id))


def update_investigation(investigation_id: str, updates: dict[str, Any]) -> None:
    from db.models import Investigation
    from db.session import get_session

    inv_uuid = uuid.UUID(investigation_id)
    allowed = {
        "status",
        "refined_query",
        "model_used",
        "preset",
        "summary",
        "graph_status",
        "current_step",
        "current_step_label",
        "entity_count",
        "page_count",
        "metadata_json",
    }
    patch = {k: v for k, v in updates.items() if k in allowed}
    if not patch:
        return
    with get_session() as session:
        session.query(Investigation).filter_by(id=inv_uuid).update(patch)


def update_investigation_metadata(
    investigation_id: str,
    patch: dict[str, Any],
) -> bool:
    """Shallow-merge *patch* into the investigation's ``metadata`` JSON column.

    Phase 6.1 mirror of ``api.routes.investigations._update_investigation_metadata``
    for the CLI SQLite path.  Always opens its own short-lived session.
    Returns True if the row was updated, False otherwise.  Never raises —
    metadata writes are best-effort.
    """
    try:
        from db.models import Investigation
        from db.session import get_session

        try:
            inv_uuid = uuid.UUID(investigation_id)
        except (ValueError, TypeError):
            inv_uuid = uuid.uuid5(uuid.NAMESPACE_URL, str(investigation_id))
        with get_session() as session:
            inv = session.query(Investigation).filter_by(id=inv_uuid).first()
            if inv is None:
                return _AwaitableBool(False)
            current = inv.metadata_json
            if current is None:
                merged: dict[str, Any] = {}
            elif isinstance(current, dict):
                merged = dict(current)
            elif isinstance(current, str):
                try:
                    merged = json.loads(current) if current.strip() else {}
                except (ValueError, TypeError):
                    merged = {}
            else:
                merged = {}
            merged.update(patch)
            inv.metadata_json = merged
        return _AwaitableBool(True)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).debug(
            "update_investigation_metadata failed (non-fatal): %s", exc
        )
        return _AwaitableBool(False)


async def cleanup_stuck_investigations(
    cutoff_minutes: Optional[int] = None,
) -> int:
    """Phase 6.3: mark CLI investigations left in 'running' as 'failed'.

    Mirrors ``api.main._sweep_stuck_investigations`` for the SQLite CLI path.
    The CLI runs investigations synchronously inside ``asyncio.run()`` so
    in-process hangs shouldn't happen, but a Ctrl-C or kill -9 can leave
    a row stuck — this cleanup handles that on next CLI startup.

    The CLI sets status='running' (not 'processing') per the investigation
    command.  The original 'processing' filter was wrong — v1.7 fixes it.

    Args:
        cutoff_minutes: When ``None`` (startup mode), sweep *all* running
            rows.  When ``int``, sweep only rows older than the cutoff.

    Returns the number of rows swept.  Returns 0 when DB is unconfigured.
    Never raises — failures are logged at warning.
    """
    try:
        from db.models import Investigation
        from db.session import get_session

        with get_session() as session:
            query = session.query(Investigation).filter(
                Investigation.status == "running"
            )
            if cutoff_minutes is not None:
                cutoff_dt = datetime.now(timezone.utc) - timedelta(
                    minutes=cutoff_minutes
                )
                query = query.filter(Investigation.created_at < cutoff_dt)

            stuck = query.all()
            if not stuck:
                return 0
            stuck_ids = [inv.id for inv in stuck]
            sweep_reason = (
                "Investigation interrupted — CLI was killed or restarted"
                if cutoff_minutes is None
                else f"Investigation timed out after {cutoff_minutes} min"
            )

        # Update outside the read session.
        from sqlalchemy import update
        with get_session() as session:
            session.execute(
                update(Investigation)
                .where(Investigation.id.in_(stuck_ids))
                .values(
                    status="failed",
                    summary=sweep_reason,
                )
            )
            session.commit()

        import logging
        log = logging.getLogger(__name__)
        for inv_id in stuck_ids:
            log.warning("Cleaned up stuck CLI investigation: %s", inv_id)
        log.info("Cleaned up %d stuck CLI investigations (cutoff=%s)",
                 len(stuck_ids), cutoff_minutes)
        return len(stuck_ids)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "cleanup_stuck_investigations failed: %s", exc
        )
        return 0


def resolve_investigation_id(prefix_or_full: str) -> Optional[str]:
    """Accept a full UUID or a unique prefix; return the full UUID string."""
    from db.models import Investigation
    from db.session import get_session

    try:
        u = uuid.UUID(prefix_or_full)
        return str(u)
    except (ValueError, AttributeError):
        pass

    p = prefix_or_full.strip().lower()
    if not p:
        return None
    with get_session() as session:
        rows = session.query(Investigation).all()
        matches = [str(r.id) for r in rows if str(r.id).startswith(p)]
    if len(matches) == 1:
        return matches[0]
    return None


def get_investigation(investigation_id: str) -> Optional[dict[str, Any]]:
    from db.models import Investigation
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    try:
        inv_uuid = uuid.UUID(full)
    except (ValueError, AttributeError):
        inv_uuid = uuid.uuid5(uuid.NAMESPACE_URL, str(investigation_id))
    with get_session() as session:
        inv = session.query(Investigation).filter_by(id=inv_uuid).one_or_none()
        if inv is None:
            return None
        return _AwaitableDict(_investigation_row(inv))


def list_investigations(limit: int = 50) -> list[dict[str, Any]]:
    from db.models import Investigation
    from db.session import get_session

    with get_session() as session:
        rows = (
            session.query(Investigation)
            .order_by(Investigation.created_at.desc())
            .limit(limit)
            .all()
        )
        return [_investigation_row(r) for r in rows]


def _investigation_row(inv) -> dict[str, Any]:
    metadata_raw = getattr(inv, "metadata_json", None)
    if isinstance(metadata_raw, str):
        try:
            metadata_parsed = json.loads(metadata_raw) if metadata_raw.strip() else {}
        except (ValueError, TypeError):
            metadata_parsed = {}
    elif isinstance(metadata_raw, dict):
        metadata_parsed = metadata_raw
    else:
        metadata_parsed = {}
    return {
        "id": str(inv.id),
        "query": inv.query,
        "refined_query": inv.refined_query,
        "status": inv.status,
        "model_used": inv.model_used,
        "summary": inv.summary,
        "entity_count": inv.entity_count,
        "page_count": inv.page_count,
        "created_at": _serialize_dt(inv.created_at),
        "current_step": inv.current_step,
        "current_step_label": inv.current_step_label,
        "metadata": metadata_parsed,
        "sources_used": metadata_parsed.get("sources_used") or {},
        "infrastructure_clusters": metadata_parsed.get("infrastructure_clusters") or [],
    }


def get_entities(
    investigation_id: str,
    entity_types: Optional[list[str]] = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    from db.models import Entity, InvestigationEntityLink
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    inv_uuid = uuid.UUID(full)
    with get_session() as session:
        q = (
            session.query(Entity)
            .outerjoin(
                InvestigationEntityLink,
                InvestigationEntityLink.entity_id == Entity.id,
            )
            .filter(
                (Entity.investigation_id == inv_uuid)
                | (InvestigationEntityLink.investigation_id == inv_uuid)
            )
        )
        if entity_types:
            q = q.filter(Entity.entity_type.in_(entity_types))
        rows = q.limit(limit).all()
        # Score from ORM rows so CLI confidence uses the same persisted
        # confidence signal as the API, while preserving the CLI's existing
        # display-time effective-confidence adjustment.
        try:
            from utils.entity_priority import rank_map
            relationships = get_relationships(full)
            priority_by_id = rank_map(rows, relationships)
        except Exception:
            priority_by_id = {}
        # Merge only the prioritization fields — never the rank record's raw
        # ``entity_type`` (the CLI keeps its own UPPERCASE-normalized value) or
        # internal keys like ``index``.
        _priority_keys = (
            "priority_score", "priority_score_components",
            "priority_score_centrality_contribution", "typed_relationship_degree",
            "freshness_tag", "rank", "suppressed", "suppression_reason",
            "high_signal",
        )
        row_dicts = []
        for row in rows:
            item = _entity_row(row)
            rec = priority_by_id.get(str(row.id), {})
            item.update({k: rec[k] for k in _priority_keys if k in rec})
            row_dicts.append(item)
        # Low-noise default: order high-signal-first, identical to the API. The
        # full set is retained (non-destructive) — suppressed rows keep their flag
        # + reason and sort last.
        row_dicts.sort(key=lambda d: d.get("rank", 1 << 30))
        try:
            from extractor.normalizer import resolve_entity_type_conflicts
            from extractor.identity import entity_canonical_id

            temp_entities = [
                SimpleNamespace(
                    entity_type=d.get("entity_type") or "",
                    value=d.get("value") or "",
                    confidence=float(d.get("confidence") or 0.0),
                )
                for d in row_dicts
            ]
            resolved = resolve_entity_type_conflicts(temp_entities)
            keep = {
                entity_canonical_id(e)
                for e in resolved
            }
            return [
                d for d in row_dicts
                if (
                    entity_canonical_id({
                        "entity_type": d.get("entity_type") or "",
                        "value": d.get("value") or "",
                    })
                    in keep
                )
            ]
        except Exception:
            return row_dicts


def _entity_row(e) -> dict[str, Any]:
    # Normalize entity_type to UPPERCASE so downstream comparisons work
    # regardless of how the type was originally stored (DB has mixed
    # casing across modules — extractor uses uppercase like "IP_ADDRESS",
    # the EntityType enum in db.models maps to lowercase values, etc.).
    # Single source of truth for the CLI: always UPPERCASE.
    entity_type = (getattr(e, "entity_type", "") or "").upper()
    source_url = ""
    try:
        source_url = getattr(getattr(e, "page", None), "url", "") or ""
    except Exception:
        source_url = ""
    source_quality = _source_quality_from_url(source_url)
    method_multiplier = _method_multiplier(e.extraction_method or "")
    corroboration_multiplier = _source_count_multiplier(int(e.source_count or 1))
    effective_confidence = min(
        1.0,
        float(e.confidence or 0.0) * source_quality * method_multiplier * corroboration_multiplier,
    )
    investigation_count = getattr(e, "investigation_count", 1) or 1
    return {
        "id": str(e.id),
        "entity_type": entity_type,
        "value": e.value,
        "canonical_value": e.canonical_value,
        "confidence": effective_confidence,
        "context_snippet": e.context_snippet,
        "extraction_method": e.extraction_method,
        "source_count": e.source_count,
        "investigation_count": investigation_count,
        "cross_referenced": investigation_count > 1,
        "corroborating_sources": e.corroborating_sources,
        "source_url": source_url,
        "source_quality": source_quality,
        "first_seen": _serialize_dt(e.first_seen),
        "last_seen": _serialize_dt(e.last_seen),
    }


def get_relationships(investigation_id: str, limit: int = 5000) -> list[dict[str, Any]]:
    from db.models import EntityRelationship
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    inv_uuid = uuid.UUID(full)
    with get_session() as session:
        rows = (
            session.query(EntityRelationship)
            .filter(EntityRelationship.investigation_id == inv_uuid)
            .limit(limit)
            .all()
        )
        return [
            {
                "id": str(r.id),
                "entity_a_id": str(r.entity_a_id),
                "entity_b_id": str(r.entity_b_id),
                "relationship_type": r.relationship_type,
                "confidence": float(r.confidence) if r.confidence is not None else None,
            }
            for r in rows
        ]


def save_relationships(investigation_id: str, edges: list[dict[str, Any]]) -> int:
    """Bulk-insert co-occurrence edges; ignores duplicate (a,b,type) triples."""
    from db.models import EntityRelationship
    from db.session import get_session

    inv_uuid = uuid.UUID(investigation_id)
    written = 0
    if not edges:
        return 0
    with get_session() as session:
        existing = {
            (str(r.entity_a_id), str(r.entity_b_id), r.relationship_type)
            for r in session.query(EntityRelationship)
            .filter(EntityRelationship.investigation_id == inv_uuid)
            .all()
        }
        for edge in edges:
            key = (edge.get("entity_a_id"), edge.get("entity_b_id"), edge.get("relationship_type"))
            if not all(key) or key in existing:
                continue
            try:
                row = EntityRelationship(
                    entity_a_id=uuid.UUID(edge["entity_a_id"]),
                    entity_b_id=uuid.UUID(edge["entity_b_id"]),
                    relationship_type=edge["relationship_type"],
                    confidence=float(edge.get("confidence", 1.0)),
                    investigation_id=inv_uuid,
                )
                session.add(row)
                existing.add(key)
                written += 1
            except Exception:
                continue
    return written


def investigation_to_export_dict(investigation_id: str) -> dict[str, Any]:
    """Full export dict: investigation + entities + relationships."""
    full = resolve_investigation_id(investigation_id) or investigation_id
    inv = get_investigation(full)
    if inv is None:
        return {}
    entities = get_entities(full)
    relationships = get_relationships(full)
    return {
        "investigation": inv,
        "entities": entities,
        "relationships": relationships,
    }


def write_json_export(investigation_id: str, path) -> None:
    data = investigation_to_export_dict(investigation_id)
    from pathlib import Path
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Actor profile helpers (CLI-side)
# ---------------------------------------------------------------------------
# These wrap the SQLAlchemy ORM models added in db/models.py with
# CLI-friendly dict returns.  ``voidaccess actors`` and ``voidaccess actor``
# use these to render tables; the write path (used during investigations)
# goes through sources.actor_profiles.ActorProfileManager.


def list_actor_profiles(limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    """Return recent actor profiles ordered by last_seen_at desc."""
    from db.models import ActorProfile, ActorAlias
    from db.session import get_session

    with get_session() as session:
        rows = (
            session.query(ActorProfile)
            .order_by(ActorProfile.last_seen_at.desc().nullslast())
            .offset(offset)
            .limit(limit)
            .all()
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            alias_count = (
                session.query(ActorAlias)
                .filter(ActorAlias.actor_id == r.id)
                .count()
            )
            out.append({
                "id": str(r.id),
                "canonical_handle": r.canonical_handle,
                "first_seen_at": _serialize_dt(r.first_seen_at),
                "last_seen_at": _serialize_dt(r.last_seen_at),
                "investigation_count": int(r.investigation_count or 0),
                "confidence": float(r.confidence) if r.confidence is not None else None,
                "alias_count": int(alias_count),
                "notes": r.notes,
            })
        return out


def search_actor_profiles(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Case-insensitive partial match against canonical_handle or alias."""
    from sqlalchemy import select

    from db.models import ActorProfile, ActorAlias
    from db.session import get_session

    pattern = f"%{query.lower()}%"
    with get_session() as session:
        alias_select = (
            select(ActorAlias.actor_id)
            .where(ActorAlias.alias_value.ilike(pattern))
        )
        rows = (
            session.query(ActorProfile)
            .filter(
                (ActorProfile.canonical_handle.ilike(pattern))
                | (ActorProfile.id.in_(alias_select))
            )
            .order_by(ActorProfile.last_seen_at.desc().nullslast())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": str(r.id),
                "canonical_handle": r.canonical_handle,
                "first_seen_at": _serialize_dt(r.first_seen_at),
                "last_seen_at": _serialize_dt(r.last_seen_at),
                "investigation_count": int(r.investigation_count or 0),
                "confidence": float(r.confidence) if r.confidence is not None else None,
            }
            for r in rows
        ]


def get_actor_profile(handle_or_id: str) -> Optional[dict[str, Any]]:
    """Return a full actor profile by canonical handle or UUID."""
    from db.session import get_session

    with get_session() as session:
        profile = _resolve_actor(session, handle_or_id)
        if profile is None:
            return None
        return _serialize_actor_profile(session, profile)


def _resolve_actor(session, handle_or_id: str):
    """Resolve a profile row by handle (case-insensitive) or UUID."""
    from db.models import ActorProfile

    if not handle_or_id:
        return None
    handle_or_id = handle_or_id.strip()
    if not handle_or_id:
        return None
    try:
        uid = uuid.UUID(handle_or_id)
        return session.query(ActorProfile).filter_by(id=uid).one_or_none()
    except (ValueError, AttributeError):
        pass
    normalized = handle_or_id.lstrip("@").strip().lower()
    if not normalized:
        return None
    return (
        session.query(ActorProfile)
        .filter(ActorProfile.canonical_handle == normalized)
        .one_or_none()
    )


def _serialize_actor_profile(session, profile) -> dict[str, Any]:
    """Hydrate a profile row into the dict shape used by API + CLI."""
    from db.models import ActorAlias, ActorInfrastructure

    aliases = (
        session.query(ActorAlias)
        .filter(ActorAlias.actor_id == profile.id)
        .order_by(ActorAlias.first_seen_at.desc().nullslast())
        .all()
    )
    infra = (
        session.query(ActorInfrastructure)
        .filter(ActorInfrastructure.actor_id == profile.id)
        .order_by(ActorInfrastructure.entity_type, ActorInfrastructure.entity_value)
        .all()
    )

    return {
        "id": str(profile.id),
        "canonical_handle": profile.canonical_handle,
        "first_seen_at": _serialize_dt(profile.first_seen_at),
        "last_seen_at": _serialize_dt(profile.last_seen_at),
        "investigation_count": int(profile.investigation_count or 0),
        "confidence": float(profile.confidence) if profile.confidence is not None else None,
        "notes": profile.notes,
        "created_at": _serialize_dt(profile.created_at),
        "updated_at": _serialize_dt(profile.updated_at),
        "aliases": [
            {
                "id": str(a.id),
                "alias_value": a.alias_value,
                "alias_type": a.alias_type,
                "source_investigation_id": (
                    str(a.source_investigation_id) if a.source_investigation_id else None
                ),
                "first_seen_at": _serialize_dt(a.first_seen_at),
                "confidence": float(a.confidence) if a.confidence is not None else None,
            }
            for a in aliases
        ],
        "infrastructure": [
            {
                "id": str(i.id),
                "entity_type": i.entity_type,
                "entity_value": i.entity_value,
                "source_investigation_id": (
                    str(i.source_investigation_id) if i.source_investigation_id else None
                ),
                "first_seen_at": _serialize_dt(i.first_seen_at),
                "last_seen_at": _serialize_dt(i.last_seen_at),
                "confidence": float(i.confidence) if i.confidence is not None else None,
            }
            for i in infra
        ],
        "investigation_ids": sorted({
            inv_id
            for inv_id in (
                [a.source_investigation_id for a in aliases if a.source_investigation_id]
                + [i.source_investigation_id for i in infra if i.source_investigation_id]
            )
            if inv_id
        }, key=str),
    }


def add_actor_note(handle_or_id: str, note: str) -> bool:
    """Append/set an analyst note on an actor profile. Returns True on success."""
    from db.session import get_session

    with get_session() as session:
        profile = _resolve_actor(session, handle_or_id)
        if profile is None:
            return False
        existing = (profile.notes or "").strip()
        ts = datetime.now(timezone.utc).isoformat()
        appended = (
            f"{existing}\n[{ts}] {note}".strip() if existing else f"[{ts}] {note}"
        )
        profile.notes = appended
        return True


def count_actor_profiles() -> int:
    """Return total number of actor profiles (CLI status helper)."""
    from db.models import ActorProfile
    from db.session import get_session

    with get_session() as session:
        return int(session.query(ActorProfile).count() or 0)


def get_actor_investigations(handle_or_id: str) -> list[dict[str, Any]]:
    """Return investigations that have surfaced this actor (by id list)."""
    from db.models import Investigation
    from db.session import get_session

    def _coerce_uuid(value):
        if value is None or value == "":
            return None
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except (ValueError, TypeError):
            return None

    with get_session() as session:
        profile = _resolve_actor(session, handle_or_id)
        if profile is None:
            return []
        prof = _serialize_actor_profile(session, profile)
        ids: list[uuid.UUID] = []
        for s in prof.get("investigation_ids", []):
            if not s:
                continue
            coerced = _coerce_uuid(s)
            if coerced is not None:
                ids.append(coerced)
        if not ids:
            return []
        rows = (
            session.query(Investigation)
            .filter(Investigation.id.in_(ids))
            .order_by(Investigation.created_at.desc())
            .all()
        )
        return [
            {
                "id": str(r.id),
                "query": r.query,
                "status": r.status,
                "created_at": _serialize_dt(r.created_at),
                "summary": (r.summary or "")[:200],
            }
            for r in rows
        ]
