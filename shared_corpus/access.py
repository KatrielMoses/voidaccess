"""
shared_corpus/access.py — the enforced tier boundary + collision-safe writers.

This module is where the private/shared split stops being a naming convention
and becomes an enforced invariant. It does three jobs:

1. **Structurally enforce that the shared tier carries no private framing.**
   ``_enforce_tier_separation()`` runs at import time and raises if any
   shared-tier table grows a ``user_id`` / ``investigation_id`` / ``query`` /
   ``refined_query`` / ``summary`` (etc.) column. Adding such a column makes
   this package fail to import and the test-suite red — the boundary cannot be
   crossed by accident.

2. **Project shared rows to user-safe dicts.** ``to_shared_dict()`` returns a
   plain dict of a shared row's columns; because of the invariant above, that
   dict provably contains no private fields. This is the read shape P4 will
   serve to any user.

3. **Write to the shared tier collision-safely.** ``upsert_global_entity`` /
   ``record_discovered_onion`` / ``record_page_snapshot`` use the DB-level
   unique constraints + ``INSERT ... ON CONFLICT`` (PostgreSQL and SQLite) with
   a portable savepoint fallback, so two concurrent writers can never
   double-insert the same canonical row. Entity identity is computed only
   through ``extractor.identity`` — the single identity path.

The private-tier scoping helpers (``owned_investigation_ids`` /
``filter_investigations_for_user``) live here too, so "a private investigation's
rows are scoped to the owning user" has one canonical implementation to test
against rather than being re-derived at every call site.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Query, Session

from db.models import Investigation
from extractor.identity import entity_canonical_id, entity_display_id
from shared_corpus.models import (
    ConfidenceTier,
    DiscoveredOnion,
    GlobalEntity,
    GlobalEntitySource,
    PageSnapshot,
    SourceReputation,
)

# ---------------------------------------------------------------------------
# Tier-separation invariant
# ---------------------------------------------------------------------------

#: Column names that frame data as *private* — tied to a user, an
#: investigation, or the query text/report that motivated a search. None of
#: these may appear on a shared-tier table.
PRIVATE_FRAMING_COLUMNS: frozenset[str] = frozenset(
    {
        "user_id",
        "investigation_id",
        "source_investigation_id",
        "run_id",
        "query",
        "refined_query",
        "summary",
        "preset",
        "model_used",
    }
)

#: The shared-tier models. The single source of truth for "what is shared."
SHARED_MODELS: tuple[type, ...] = (
    DiscoveredOnion,
    PageSnapshot,
    GlobalEntity,
    SourceReputation,
    GlobalEntitySource,
)

#: Trust-tier rank — tiers only ever *rise* through the gate (never demote on a
#: later contribution). Used by the tier-aware upsert to guard against a lower
#: tier overwriting a higher one under concurrency.
_TIER_RANK: dict[str, int] = {
    ConfidenceTier.UNCONFIRMED.value: 0,
    ConfidenceTier.CORROBORATED.value: 1,
    ConfidenceTier.FEED_VALIDATED.value: 2,
}

#: Storage bound for the canonical key, derived from the column definition so
#: the two can never drift. A canonical form longer than this is truncated
#: before storage — the same tradeoff the legacy backfill made
#: (``substring(canonical, 1, 1024)`` in migration 0003) to stay under
#: PostgreSQL's btree index-row-size limit. This is a *storage* bound, not a
#: second identity derivation: identity is still produced solely by
#: ``entity_canonical_id``.
_CANONICAL_MAX_LEN: int = GlobalEntity.__table__.c.canonical_value.type.length or 1024


def _enforce_tier_separation() -> None:
    """Fail fast if any shared-tier table carries a private-framing column.

    Runs at import time so a mistaken column addition is caught the moment the
    package is loaded (import error) and by the test-suite, rather than leaking
    private data at runtime.
    """
    offenders: list[str] = []
    for model in SHARED_MODELS:
        for column in model.__table__.columns:
            if column.name in PRIVATE_FRAMING_COLUMNS:
                offenders.append(f"{model.__tablename__}.{column.name}")
    if offenders:
        raise RuntimeError(
            "Shared-tier tables must not carry private-tier framing columns; "
            "found: " + ", ".join(sorted(offenders))
        )


_enforce_tier_separation()


def to_shared_dict(instance: Any) -> dict[str, Any]:
    """Project a shared-tier ORM row to a plain, user-safe dict.

    Because of the import-time tier-separation invariant, the returned dict is
    guaranteed to contain no private-tier fields (no user id, no query text).
    This is the canonical read shape for shared-corpus consumers.
    """
    table = instance.__table__
    return {column.name: getattr(instance, column.name) for column in table.columns}


# ---------------------------------------------------------------------------
# Private-tier scoping (the other half of the boundary)
# ---------------------------------------------------------------------------

def owned_investigation_ids(session: Session, user_id: Optional[int]) -> list[uuid.UUID]:
    """Return the ids of investigations owned by *user_id* (empty if None).

    The canonical "scope private rows to their owner" primitive. A ``None``
    user (e.g. anonymous/CLI-owned rows) owns nothing in the multi-tenant
    sense, so callers must not treat ``None`` as a wildcard.
    """
    if user_id is None:
        return []
    rows = (
        session.query(Investigation.id)
        .filter(Investigation.user_id == user_id)
        .all()
    )
    return [row[0] for row in rows]


def filter_investigations_for_user(query: Query, user_id: Optional[int]) -> Query:
    """Restrict an ``Investigation`` query to those owned by *user_id*.

    A ``None`` user matches nothing (``1 = 0``) rather than every row, so a
    missing/incorrect user id fails closed instead of leaking all private
    investigations.
    """
    if user_id is None:
        return query.filter(sa.false())
    return query.filter(Investigation.user_id == user_id)


# ---------------------------------------------------------------------------
# Collision-safe shared-tier writers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dialect_name(session: Session) -> str:
    bind = session.get_bind()
    return bind.dialect.name if bind is not None else ""


def _insert_ignore(
    session: Session,
    model: type,
    values: dict[str, Any],
    conflict_columns: Iterable[str],
) -> bool:
    """Insert *values* into *model*, ignoring a unique-constraint collision.

    Returns True if this call inserted the row, False if an equal row already
    existed (the conflict was absorbed). Uses native ``ON CONFLICT DO NOTHING``
    on PostgreSQL and SQLite, and a savepoint + ``IntegrityError`` fallback on
    any other dialect, so no concurrent writer can double-insert.
    """
    dialect = _dialect_name(session)

    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        stmt = (
            pg_insert(model)
            .values(**values)
            .on_conflict_do_nothing(index_elements=list(conflict_columns))
        )
        result = session.execute(stmt)
        return bool(result.rowcount)

    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        stmt = (
            sqlite_insert(model)
            .values(**values)
            .on_conflict_do_nothing(index_elements=list(conflict_columns))
        )
        result = session.execute(stmt)
        return bool(result.rowcount)

    # Portable fallback: attempt the insert inside a savepoint; if the unique
    # constraint fires, roll back just the savepoint and report "not created".
    try:
        with session.begin_nested():
            session.execute(sa.insert(model).values(**values))
        return True
    except IntegrityError:
        return False


def upsert_global_entity(
    session: Session,
    entity_type: str,
    value: str,
    *,
    display_value: Optional[str] = None,
    provenance: Optional[dict] = None,
    touch: bool = True,
    confidence_tier: Optional[str] = None,
    corroboration_count: Optional[int] = None,
) -> tuple[Optional[GlobalEntity], bool]:
    """Insert or fetch the canonical ``GlobalEntity`` for *(entity_type, value)*.

    **Sanitization gate (P2.2):** the value is first routed through the single
    sanitizer choke point (``sanitizer.sanitize_entity``) — malformed/noise
    artifacts, raw secrets, and inherently-PII entity types are dropped and this
    returns ``(None, False)`` without writing. This is the same gate the snapshot
    store uses, so there is one sanitize path for every shared write.

    Collision-safe: relies on the ``uq_global_entity_type_canonical`` unique
    constraint plus ``ON CONFLICT DO NOTHING`` so concurrent writers converge on
    exactly one row per canonical entity. Identity is computed solely via
    ``extractor.identity.entity_canonical_id`` (the single identity path); no
    canonicalization is duplicated here.

    **Tier / corroboration (P4.1):** ``confidence_tier`` and
    ``corroboration_count`` are the *gate-assigned* values — the P4.1 promotion
    path passes the trust gate's decision here, and this function persists them
    collision-safely: the tier only ever **rises** (guarded by ``_TIER_RANK`` so a
    concurrent lower-tier write cannot demote a higher one) and the count only
    rises (``max``). Called without them (the legacy default) the row stays
    ``unconfirmed`` at count 1 — the gate remains the only tier assigner.

    Returns ``(row, created)`` — or ``(None, False)`` when the value was dropped
    by the sanitizer. When the row already existed and *touch* is set,
    ``last_seen`` is refreshed. A ``provenance`` stamp is stored on insert.
    """
    from sanitizer import sanitize_entity

    safe_value = sanitize_entity(entity_type, value)
    if safe_value is None:
        return None, False

    entity_like = {"entity_type": entity_type, "value": safe_value}
    canonical = entity_canonical_id(entity_like)[:_CANONICAL_MAX_LEN]
    display = (display_value if display_value is not None else entity_display_id(entity_like)) or None
    now = _now()

    insert_tier = confidence_tier or ConfidenceTier.UNCONFIRMED.value
    insert_count = corroboration_count if corroboration_count is not None else 1

    created = _insert_ignore(
        session,
        GlobalEntity,
        {
            "id": uuid.uuid4(),
            "entity_type": entity_type,
            "canonical_value": canonical,
            "display_value": display,
            "confidence_tier": insert_tier,
            "corroboration_count": insert_count,
            "first_seen": now,
            "last_seen": now,
            "provenance": provenance,
        },
        conflict_columns=("entity_type", "canonical_value"),
    )

    if not created and touch:
        session.execute(
            sa.update(GlobalEntity)
            .where(
                GlobalEntity.entity_type == entity_type,
                GlobalEntity.canonical_value == canonical,
            )
            .values(last_seen=now)
        )

    if not created and (confidence_tier is not None or corroboration_count is not None):
        _raise_entity_tier(session, entity_type, canonical, confidence_tier, corroboration_count)

    session.flush()
    row = session.execute(
        sa.select(GlobalEntity).where(
            GlobalEntity.entity_type == entity_type,
            GlobalEntity.canonical_value == canonical,
        )
    ).scalar_one()
    return row, created


def record_discovered_onion(
    session: Session,
    onion_address: str,
    *,
    discovery_source: Optional[str] = None,
    status: Optional[str] = None,
    title: Optional[str] = None,
    category: Optional[str] = None,
    language: Optional[str] = None,
    provenance: Optional[dict] = None,
    touch: bool = True,
) -> tuple[DiscoveredOnion, bool]:
    """Insert or fetch the shared ``DiscoveredOnion`` for *onion_address*.

    Collision-safe on the ``uq_discovered_onion_address`` unique constraint.
    Returns ``(row, created)``; refreshes ``last_seen`` on an existing row when
    *touch* is set. A ``provenance`` stamp is stored on insert.
    """
    now = _now()
    created = _insert_ignore(
        session,
        DiscoveredOnion,
        {
            "id": uuid.uuid4(),
            "onion_address": onion_address,
            "discovery_source": discovery_source,
            "status": status or "unknown",
            "title": title,
            "category": category,
            "language": language,
            "first_seen": now,
            "last_seen": now,
            "provenance": provenance,
        },
        conflict_columns=("onion_address",),
    )

    if not created and touch:
        session.execute(
            sa.update(DiscoveredOnion)
            .where(DiscoveredOnion.onion_address == onion_address)
            .values(last_seen=now)
        )

    session.flush()
    row = session.execute(
        sa.select(DiscoveredOnion).where(
            DiscoveredOnion.onion_address == onion_address
        )
    ).scalar_one()
    return row, created


def record_page_snapshot(
    session: Session,
    content_hash: str,
    url: str,
    *,
    onion_id: Optional[uuid.UUID] = None,
    storage_ref: Optional[str] = None,
    byte_size: Optional[int] = None,
    language: Optional[str] = None,
    provenance: Optional[dict] = None,
    touch: bool = True,
) -> tuple[PageSnapshot, bool]:
    """Insert or fetch the shared ``PageSnapshot`` deduped by *content_hash*.

    Collision-safe on the ``uq_page_snapshot_content_hash`` unique constraint —
    byte-identical content captured twice collapses to one snapshot. Returns
    ``(row, created)``; refreshes ``last_seen`` on an existing row when *touch*
    is set. A ``provenance`` stamp is stored on insert.
    """
    now = _now()
    created = _insert_ignore(
        session,
        PageSnapshot,
        {
            "id": uuid.uuid4(),
            "content_hash": content_hash,
            "url": url,
            "onion_id": onion_id,
            "storage_ref": storage_ref,
            "byte_size": byte_size,
            "language": language,
            "captured_at": now,
            "first_seen": now,
            "last_seen": now,
            "provenance": provenance,
        },
        conflict_columns=("content_hash",),
    )

    if not created and touch:
        session.execute(
            sa.update(PageSnapshot)
            .where(PageSnapshot.content_hash == content_hash)
            .values(last_seen=now)
        )

    session.flush()
    row = session.execute(
        sa.select(PageSnapshot).where(PageSnapshot.content_hash == content_hash)
    ).scalar_one()
    return row, created


# ---------------------------------------------------------------------------
# P4.1 — trust-tier promotion, corroboration source-set, reputation persistence
# ---------------------------------------------------------------------------

def _raise_entity_tier(
    session: Session,
    entity_type: str,
    canonical: str,
    confidence_tier: Optional[str],
    corroboration_count: Optional[int],
) -> None:
    """Raise (never lower) an existing ``GlobalEntity``'s tier + corroboration count.

    Reads the current row and writes the tier only when the new one out-ranks it
    (``_TIER_RANK``), and the count only when higher — so a concurrent lower-tier
    contribution can never demote a row the gate already promoted.
    """
    current = session.execute(
        sa.select(GlobalEntity.confidence_tier, GlobalEntity.corroboration_count).where(
            GlobalEntity.entity_type == entity_type,
            GlobalEntity.canonical_value == canonical,
        )
    ).first()
    if current is None:
        return
    cur_tier, cur_count = current[0], current[1]

    updates: dict[str, Any] = {}
    if confidence_tier is not None:
        if _TIER_RANK.get(confidence_tier, 0) > _TIER_RANK.get(cur_tier, 0):
            updates["confidence_tier"] = confidence_tier
    if corroboration_count is not None and corroboration_count > (cur_count or 0):
        updates["corroboration_count"] = corroboration_count

    if updates:
        session.execute(
            sa.update(GlobalEntity)
            .where(
                GlobalEntity.entity_type == entity_type,
                GlobalEntity.canonical_value == canonical,
            )
            .values(**updates)
        )


def record_global_entity_source(
    session: Session,
    global_entity_id: uuid.UUID,
    source: str,
    *,
    contributor: Optional[str] = None,
    feed_hits: Optional[Iterable[str]] = None,
    provenance: Optional[dict] = None,
) -> tuple[Optional[GlobalEntitySource], bool]:
    """Record that *source* (an ORIGIN) attested the entity — the corroboration set.

    Collision-safe on ``uq_global_entity_source`` (``ON CONFLICT DO NOTHING``): the
    same origin re-observing an entity collapses to one row, so the distinct row
    count is the independent-origin basis and can never be inflated by resubmission.
    ``contributor`` is persisted alongside so the distinct-contributor requirement
    survives reload. Returns ``(row, created)``.
    """
    now = _now()
    hits = sorted({str(h) for h in (feed_hits or [])}) or None
    created = _insert_ignore(
        session,
        GlobalEntitySource,
        {
            "id": uuid.uuid4(),
            "global_entity_id": global_entity_id,
            "source": source,
            "contributor": contributor,
            "feed_hits": hits,
            "first_seen": now,
            "provenance": provenance,
        },
        conflict_columns=("global_entity_id", "source"),
    )
    session.flush()
    row = session.execute(
        sa.select(GlobalEntitySource).where(
            GlobalEntitySource.global_entity_id == global_entity_id,
            GlobalEntitySource.source == source,
        )
    ).scalar_one_or_none()
    return row, created


def upsert_source_reputation(
    session: Session,
    source: str,
    *,
    score: float,
    blocked: bool,
    contributed: int,
    corroborated: int,
    contradicted: int,
    anomalies: int,
) -> SourceReputation:
    """Insert-or-update the per-source reputation row to the gate-emitted counters.

    The trust gate computes the authoritative next reputation from the loaded
    state, so this simply persists it (``ON CONFLICT DO UPDATE``). One row per
    ``source`` (``uq_source_reputation_source``).
    """
    now = _now()
    values = {
        "source": source,
        "score": score,
        "blocked": blocked,
        "contributed": contributed,
        "corroborated": corroborated,
        "contradicted": contradicted,
        "anomalies": anomalies,
        "last_seen": now,
    }
    dialect = _dialect_name(session)
    if dialect in ("postgresql", "sqlite"):
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as _insert
        else:
            from sqlalchemy.dialects.sqlite import insert as _insert
        stmt = _insert(SourceReputation).values(
            id=uuid.uuid4(), first_seen=now, **values
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["source"],
            set_={k: getattr(stmt.excluded, k) for k in values},
        )
        session.execute(stmt)
    else:  # portable fallback
        try:
            with session.begin_nested():
                session.execute(
                    sa.insert(SourceReputation).values(
                        id=uuid.uuid4(), first_seen=now, **values
                    )
                )
        except IntegrityError:
            session.execute(
                sa.update(SourceReputation)
                .where(SourceReputation.source == source)
                .values(**values)
            )
    session.flush()
    return session.execute(
        sa.select(SourceReputation).where(SourceReputation.source == source)
    ).scalar_one()


def set_entity_disposition(
    session: Session, entity_type: str, canonical: str, disposition: str
) -> None:
    """Establish the entity's disposition baseline — first promoted claim wins.

    Sets ``global_entities.disposition`` only when it is currently NULL, so the
    established (corroborated/feed-validated) disposition cannot be overwritten by
    a later conflicting claim; that conflict is instead surfaced to the gate as a
    contradiction (which downweights the contributor).
    """
    if not disposition:
        return
    session.execute(
        sa.update(GlobalEntity)
        .where(
            GlobalEntity.entity_type == entity_type,
            GlobalEntity.canonical_value == canonical,
            GlobalEntity.disposition.is_(None),
        )
        .values(disposition=disposition)
    )


def fetch_global_entities(
    session: Session, pairs: Iterable[tuple[str, str]]
) -> dict[tuple[str, str], GlobalEntity]:
    """Batch-load ``GlobalEntity`` rows for a set of ``(entity_type, canonical)``.

    One query (over the indexed columns) then an exact-pair filter in Python —
    avoids an N+1 when loading ``CorpusState`` for an investigation's entity set.
    """
    pairs = list(pairs)
    if not pairs:
        return {}
    types = {t for t, _ in pairs}
    canons = {c for _, c in pairs}
    wanted = set(pairs)
    rows = session.execute(
        sa.select(GlobalEntity).where(
            GlobalEntity.entity_type.in_(types),
            GlobalEntity.canonical_value.in_(canons),
        )
    ).scalars()
    out: dict[tuple[str, str], GlobalEntity] = {}
    for row in rows:
        key = (row.entity_type, row.canonical_value)
        if key in wanted:
            out[key] = row
    return out


def fetch_entity_sources(
    session: Session, entity_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, list[GlobalEntitySource]]:
    """Batch-load the source rows for a set of global-entity ids."""
    ids = list(entity_ids)
    if not ids:
        return {}
    rows = session.execute(
        sa.select(GlobalEntitySource).where(
            GlobalEntitySource.global_entity_id.in_(ids)
        )
    ).scalars()
    out: dict[uuid.UUID, list[GlobalEntitySource]] = {}
    for row in rows:
        out.setdefault(row.global_entity_id, []).append(row)
    return out


def fetch_source_reputations(
    session: Session, sources: Iterable[str]
) -> dict[str, SourceReputation]:
    """Batch-load reputation rows for a set of sources."""
    srcs = {s for s in sources if s}
    if not srcs:
        return {}
    rows = session.execute(
        sa.select(SourceReputation).where(SourceReputation.source.in_(srcs))
    ).scalars()
    return {row.source: row for row in rows}


def entity_provenance(
    session: Session, entity_type: str, value: str
) -> Optional[dict[str, Any]]:
    """Queryable provenance (spec 3.4): a shared entity → its sources + first_seen + tier.

    Resolves the ``GlobalEntity`` via the single identity path, then returns its
    tier / corroboration count / first_seen plus every contributing source with
    that source's first_seen and any trusted-feed cross-hits. ``None`` if the
    entity is not in the shared corpus.
    """
    canonical = entity_canonical_id({"entity_type": entity_type, "value": value})[
        :_CANONICAL_MAX_LEN
    ]
    row = session.execute(
        sa.select(GlobalEntity).where(
            GlobalEntity.entity_type == entity_type,
            GlobalEntity.canonical_value == canonical,
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    sources = session.execute(
        sa.select(GlobalEntitySource)
        .where(GlobalEntitySource.global_entity_id == row.id)
        .order_by(GlobalEntitySource.first_seen)
    ).scalars()
    return {
        "entity_type": row.entity_type,
        "canonical_value": row.canonical_value,
        "display_value": row.display_value,
        "confidence_tier": row.confidence_tier,
        "corroboration_count": row.corroboration_count,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "provenance": row.provenance,
        "sources": [
            {
                "source": s.source,
                "first_seen": s.first_seen,
                "feed_hits": s.feed_hits or [],
                "provenance": s.provenance,
            }
            for s in sources
        ],
    }
