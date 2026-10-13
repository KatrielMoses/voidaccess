"""
Common query helpers for the VoidAccess database layer.

All functions accept a SQLAlchemy Session as their first argument so callers
control transaction boundaries.  None of these helpers call session.commit()
— that is the caller's responsibility (or the get_session() context manager's).

Where a helper needs an intermediate ID before the transaction is committed,
it calls session.flush() to write the row without finalising the transaction.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import func
import sqlalchemy as sa

from db.models import (
    Entity,
    EntityRelationship,
    Investigation,
    MonitorAlert,
    Page,
    RelationshipType,
    Source,
    SourceStatus,
    SourceType,
)


def db_health_check(session: Session) -> bool:
    """Return True when DB responds to a trivial heartbeat query."""
    try:
        session.execute(sa.text("SELECT 1"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Investigation helpers
# ---------------------------------------------------------------------------

def get_investigation_by_id_or_run(
    session: Session,
    id_or_run: uuid.UUID,
) -> Optional[Investigation]:
    """Return the investigation row matching primary key *or* ``run_id``."""
    return (
        session.query(Investigation)
        .filter(
            (Investigation.id == id_or_run) | (Investigation.run_id == id_or_run)
        )
        .first()
    )


def count_distinct_pages_for_investigation(
    session: Session,
    investigation_id: uuid.UUID,
) -> int:
    """Count distinct scraped pages that contributed entities to this investigation.

    Includes both entities owned by this investigation and entities linked via the
    junction table (deduped entities from previous investigations re-linked here).
    """
    from db.models import InvestigationEntityLink  # noqa: PLC0415
    linked_ids_select = (
        sa.select(InvestigationEntityLink.entity_id)
        .where(InvestigationEntityLink.investigation_id == investigation_id)
    )
    n = (
        session.query(sa.func.count(sa.distinct(Entity.page_id)))
        .filter(
            (Entity.investigation_id == investigation_id)
            | Entity.id.in_(linked_ids_select)
        )
        .scalar()
    )
    return int(n or 0)


def create_investigation(
    session: Session,
    query: str,
    refined_query: Optional[str] = None,
    model_used: Optional[str] = None,
    preset: Optional[str] = None,
    summary: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Investigation:
    """Insert a new Investigation row and flush to populate id/run_id."""
    inv = Investigation(
        query=query,
        refined_query=refined_query,
        model_used=model_used,
        preset=preset,
        summary=summary,
        user_id=user_id,
    )
    session.add(inv)
    session.flush()
    return inv


def get_investigation_by_run_id(
    session: Session, run_id: uuid.UUID
) -> Optional[Investigation]:
    """Return the Investigation with the given run_id, or None."""
    return session.query(Investigation).filter_by(run_id=run_id).first()


def get_investigation_by_query(
    session: Session,
    query: str,
    user_id: Optional[int] = None,
) -> Optional[Investigation]:
    """Return the newest Investigation with an exact query match."""
    q = session.query(Investigation).filter(Investigation.query == query)
    if user_id is not None:
        q = q.filter(Investigation.user_id == user_id)
    return q.order_by(Investigation.created_at.desc()).first()


def get_recent_investigations(
    session: Session, limit: int = 20
) -> List[Investigation]:
    """Return the *limit* most recent investigations, newest first."""
    return (
        session.query(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .all()
    )


def update_investigation_summary(
    session: Session, investigation_id: uuid.UUID, summary: str
) -> None:
    """Patch the summary field of an existing investigation."""
    session.query(Investigation).filter_by(id=investigation_id).update(
        {"summary": summary}
    )


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------

def get_or_create_source(
    session: Session,
    onion_address: str,
    source_type: str = SourceType.SEARCH_RESULT.value,
) -> Tuple[Source, bool]:
    """
    Return (source, created) where *created* is True if a new row was inserted.

    Uses flush (not commit) so the caller retains transaction control.
    The onion_address is stored as-is — normalisation (strip trailing slashes,
    lower-case) is the caller's responsibility.
    """
    existing = session.query(Source).filter_by(onion_address=onion_address).first()
    if existing:
        return existing, False

    source = Source(
        onion_address=onion_address,
        source_type=source_type,
        status=SourceStatus.UNKNOWN.value,
    )
    session.add(source)
    session.flush()
    return source, True


def update_source_status(
    session: Session, source_id: uuid.UUID, status: str
) -> None:
    """Update the status of a Source and refresh last_seen to now."""
    session.query(Source).filter_by(id=source_id).update(
        {
            "status": status,
            "last_seen": datetime.now(timezone.utc),
        }
    )


def link_source_to_investigation(
    session: Session, investigation: Investigation, source: Source
) -> None:
    """Add *source* to *investigation*.sources if not already present."""
    if source not in investigation.sources:
        investigation.sources.append(source)


# ---------------------------------------------------------------------------
# Page helpers
# ---------------------------------------------------------------------------

def create_page(
    session: Session,
    url: str,
    source_id: Optional[uuid.UUID] = None,
    cleaned_text: Optional[str] = None,
    raw_content_hash: Optional[str] = None,
    byte_size: Optional[int] = None,
    language: Optional[str] = None,
    posted_at: Optional[datetime] = None,
    investigation_id: Optional[uuid.UUID] = None,
) -> Page:
    """Insert a new Page row and flush to populate its id."""
    page = Page(
        investigation_id=investigation_id,
        url=url,
        source_id=source_id,
        cleaned_text=cleaned_text,
        raw_content_hash=raw_content_hash,
        byte_size=byte_size,
        language=language,
        posted_at=posted_at,
    )
    session.add(page)
    session.flush()
    return page


def get_page_by_url(session: Session, url: str, investigation_id: Optional[uuid.UUID] = None) -> Optional[Page]:
    """Return the Page with the exact URL, or None."""
    q = session.query(Page).filter_by(url=url)
    if investigation_id is not None:
        q = q.filter_by(investigation_id=investigation_id)
    return q.first()


def get_page_by_hash(session: Session, content_hash: str) -> Optional[Page]:
    """
    Return the first Page whose raw_content_hash matches.
    Used by the crawler to skip re-scraping identical content.
    """
    return session.query(Page).filter_by(raw_content_hash=content_hash).first()


def get_pages_for_source(
    session: Session, source_id: uuid.UUID, limit: int = 100
) -> List[Page]:
    """Return pages belonging to a given source, newest first."""
    return (
        session.query(Page)
        .filter_by(source_id=source_id)
        .order_by(Page.scrape_timestamp.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Entity helpers
# ---------------------------------------------------------------------------

def create_entity(
    session: Session,
    page_id: uuid.UUID,
    entity_type: str,
    value: str,
    confidence: float = 1.0,
    context: Optional[str] = None,
    investigation_id: Optional[uuid.UUID] = None,
) -> Entity:
    """Insert an Entity row and flush to populate its id."""
    entity = Entity(
        page_id=page_id,
        investigation_id=investigation_id,
        entity_type=entity_type,
        value=value,
        confidence=confidence,
        context_snippet=context,
    )
    session.add(entity)
    session.flush()
    return entity


def _link_entity_to_investigation(
    session: Session, entity_id: uuid.UUID, investigation_id: uuid.UUID
) -> bool:
    """Link an entity to an investigation via InvestigationEntityLink."""
    from db.models import InvestigationEntityLink

    # Check committed rows
    existing = session.query(InvestigationEntityLink).filter_by(
        entity_id=entity_id, investigation_id=investigation_id
    ).first()
    if existing:
        return False

    # Also check pending (unflushed) objects — autoflush=False means they won't
    # appear in the query above, causing UNIQUE VIOLATION on batch flush.
    for obj in session.new:
        if (
            isinstance(obj, InvestigationEntityLink)
            and obj.entity_id == entity_id
            and obj.investigation_id == investigation_id
        ):
            return False

    link = InvestigationEntityLink(
        entity_id=entity_id,
        investigation_id=investigation_id
    )
    session.add(link)
    return True


def _entity_investigation_count(session: Session, entity: Entity) -> int:
    """Count distinct investigations that surfaced *entity*, including owner."""
    from db.models import InvestigationEntityLink

    ids = {
        row[0]
        for row in session.query(InvestigationEntityLink.investigation_id)
        .filter_by(entity_id=entity.id)
        .all()
    }
    if entity.investigation_id:
        ids.add(entity.investigation_id)
    return max(1, len(ids))


def upsert_entity_canonical(
    session: Session,
    investigation_id: uuid.UUID,
    entity_type: str,
    entity_value: str,
    confidence: float,
    source_page_id: Optional[uuid.UUID] = None,
    context_snippet: str = "",
    extraction_method: Optional[str] = None,
) -> tuple[Entity, bool]:
    """
    Insert or update an entity using canonical deduplication.
    
    Dedup strategy:
    1. Compute canonical key for this entity
    2. Check if any entity with same (canonical_key, entity_type) exists
       in ANY investigation (global dedup)
    3. If found: update confidence to max(existing, new), link to this investigation
    4. If not found: insert new entity
    
    Returns: (entity, was_created)
    """
    from db.models import InvestigationEntityLink
    from extractor.normalizer import canonicalize_entity_value
    
    canonical = canonicalize_entity_value(entity_type, entity_value)
    
    # Look for existing entity with same canonical form (any investigation)
    existing = (
        session.query(Entity)
        .filter(
            Entity.entity_type == entity_type,
            Entity.canonical_value == canonical,
        )
        .order_by(Entity.confidence.desc())  # Prefer highest confidence existing
        .first()
    )
    
    if existing:
        # The shared row is identity only. Extraction context belongs to a link.
        _link_entity_to_investigation(session, existing.id, investigation_id)
        session.flush()
        link = session.query(InvestigationEntityLink).filter_by(
            entity_id=existing.id, investigation_id=investigation_id,
        ).one()
        link.confidence = max(link.confidence or 0, confidence)
        if context_snippet:
            link.context_snippet = context_snippet
        if source_page_id:
            link.page_id = source_page_id
        if extraction_method:
            link.extraction_method = extraction_method
        return existing, False
    else:
        # Create new entity
        entity = Entity(
            investigation_id=investigation_id,
            entity_type=entity_type,
            value=entity_value,
            canonical_value=canonical,
            confidence=confidence,
            context_snippet=context_snippet,
            page_id=source_page_id,
            extraction_method=extraction_method,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(entity)
        session.flush()  # populate entity.id before creating the link
        _link_entity_to_investigation(session, entity.id, investigation_id)
        session.flush()
        link = session.query(InvestigationEntityLink).filter_by(
            entity_id=entity.id, investigation_id=investigation_id,
        ).one()
        link.confidence = confidence
        link.context_snippet = context_snippet
        link.page_id = source_page_id
        link.extraction_method = extraction_method
        entity.investigation_count = 1
        return entity, True


def cross_reference_with_seeds(session: Session, investigation_id: uuid.UUID) -> int:
    """
    For each entity in this investigation, check if it matches any seed entity.
    If match found, update the investigation entity with historical context.
    Returns count of matches found.
    """
    from db.models import Investigation

    inv_entities = session.query(Entity).join(Investigation, Entity.investigation_id == Investigation.id).filter(
        Entity.investigation_id == investigation_id,
        ~Investigation.is_seed
    ).all()

    if not inv_entities:
        return 0

    canonical_keys = [(ent.entity_type, ent.canonical_value) for ent in inv_entities if ent.canonical_value]
    if not canonical_keys:
        return 0

    entity_types = [k[0] for k in canonical_keys]
    canonical_values = [k[1] for k in canonical_keys]

    seed_entities = (
        session.query(Entity)
        .join(Investigation, Entity.investigation_id == Investigation.id)
        .filter(
            Entity.entity_type.in_(entity_types),
            Entity.canonical_value.in_(canonical_values),
            Investigation.is_seed
        )
        .all()
    )

    seed_map: dict[tuple, Entity] = {}
    for seed in seed_entities:
        key = (seed.entity_type, seed.canonical_value)
        if key not in seed_map:
            seed_map[key] = seed

    entity_ids = [ent.id for ent in inv_entities]
    seed_ids = [seed.id for seed in seed_entities]
    existing_rels = (
        session.query(EntityRelationship)
        .filter(
            sa.or_(
                EntityRelationship.entity_a_id.in_(entity_ids),
                EntityRelationship.entity_b_id.in_(entity_ids),
            ),
            sa.or_(
                EntityRelationship.entity_a_id.in_(seed_ids),
                EntityRelationship.entity_b_id.in_(seed_ids),
            ),
        )
        .all()
    )

    existing_rel_set: set[tuple] = set()
    for rel in existing_rels:
        existing_rel_set.add((rel.entity_a_id, rel.entity_b_id))
        existing_rel_set.add((rel.entity_b_id, rel.entity_a_id))

    matches = 0
    now = datetime.now(timezone.utc)

    for ent in inv_entities:
        key = (ent.entity_type, ent.canonical_value)
        seed_match = seed_map.get(key)

        if seed_match:
            if not ent.historical_context:
                ent.historical_context = seed_match.context_snippet
            ent.first_seen = min(
                ent.first_seen or now,
                seed_match.first_seen or now
            )

            rel_key = (ent.id, seed_match.id)
            if rel_key not in existing_rel_set:
                session.add(
                    EntityRelationship(
                        entity_a_id=ent.id,
                        entity_b_id=seed_match.id,
                        relationship_type=RelationshipType.LIKELY_SAME_ACTOR.value,
                        source_page_id=ent.page_id,
                        confidence=0.90,
                    )
                )
                existing_rel_set.add(rel_key)
                existing_rel_set.add((seed_match.id, ent.id))
            matches += 1

    session.flush()
    return matches


def get_entities_by_type(
    session: Session,
    entity_type: str,
    limit: int = 200,
) -> List[Entity]:
    """Return up to *limit* entities of the given type, most recently created first."""
    return (
        session.query(Entity)
        .filter_by(entity_type=entity_type)
        .order_by(Entity.created_at.desc())
        .limit(limit)
        .all()
    )


def get_entities_by_value(
    session: Session,
    value: str,
) -> List[Entity]:
    """Return all Entity rows whose value exactly matches *value*."""
    return session.query(Entity).filter(Entity.value == value).all()


def get_entities_for_investigation(
    session: Session,
    investigation_id: uuid.UUID,
    entity_type: Optional[str] = None,
) -> List[Entity]:
    """Return all entities linked to an investigation, optionally filtered by type."""
    from db.models import InvestigationEntityLink
    linked = sa.select(InvestigationEntityLink.entity_id).where(InvestigationEntityLink.investigation_id == investigation_id)
    q = session.query(Entity).filter((Entity.investigation_id == investigation_id) | Entity.id.in_(linked))
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    from db.entity_views import entity_views
    return entity_views(session, q.order_by(Entity.created_at.desc()).all(), investigation_id=investigation_id)


# ---------------------------------------------------------------------------
# EntityRelationship helpers
# ---------------------------------------------------------------------------

def create_entity_relationship(
    session: Session,
    entity_a_id: uuid.UUID,
    entity_b_id: uuid.UUID,
    relationship_type: str,
    source_page_id: Optional[uuid.UUID] = None,
    confidence: float = 1.0,
) -> EntityRelationship:
    """Insert an EntityRelationship edge and flush to populate its id."""
    rel = EntityRelationship(
        entity_a_id=entity_a_id,
        entity_b_id=entity_b_id,
        relationship_type=relationship_type,
        source_page_id=source_page_id,
        confidence=confidence,
    )
    session.add(rel)
    session.flush()
    return rel


def save_typed_relationships(
    session: Session,
    investigation_id: uuid.UUID,
    relationships: List[dict],
) -> int:
    """
    Persist LLM-extracted typed relationships as EntityRelationship rows.

    Each dict needs ``entity_a_id``, ``entity_b_id`` and ``relationship_type``;
    ``confidence`` (defaults to 0.5) and ``source_page_id`` are optional.  The
    stored confidence is the relationship's OWN claim confidence — deliberately
    independent of the confidence of the two entities it connects.

    Rows are deduped against existing edges (and each other) on the triple
    ``(entity_a_id, entity_b_id, relationship_type)``.  For an existing edge the
    confidence is only ever raised, never lowered.  Returns the number of new
    rows inserted.  Never raises on a bad individual row — it is skipped.
    """
    if not relationships:
        return 0

    def _uuid(value) -> Optional[uuid.UUID]:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            return None

    # Load existing edges for the endpoints in play so we can dedup/upgrade.
    endpoint_ids: set[uuid.UUID] = set()
    normalized: List[tuple] = []
    for rel in relationships:
        a_id = _uuid(rel.get("entity_a_id"))
        b_id = _uuid(rel.get("entity_b_id"))
        rel_type = str(rel.get("relationship_type", "") or "").strip()
        if a_id is None or b_id is None or a_id == b_id or not rel_type:
            continue
        try:
            confidence = float(rel.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        page_id = _uuid(rel.get("source_page_id"))
        normalized.append((a_id, b_id, rel_type, confidence, page_id))
        endpoint_ids.add(a_id)
        endpoint_ids.add(b_id)

    if not normalized:
        return 0

    existing_rows = (
        session.query(EntityRelationship)
        .filter(
            EntityRelationship.investigation_id == investigation_id,
            (
                (EntityRelationship.entity_a_id.in_(endpoint_ids))
                | (EntityRelationship.entity_b_id.in_(endpoint_ids))
            ),
        )
        .all()
    )
    existing: dict[tuple, EntityRelationship] = {}
    for row in existing_rows:
        existing[(row.entity_a_id, row.entity_b_id, row.relationship_type)] = row

    # Track triples added within this call to avoid inserting duplicates when
    # the same relationship shows up on more than one page.
    added_this_call: dict[tuple, EntityRelationship] = {}
    inserted = 0
    for a_id, b_id, rel_type, confidence, page_id in normalized:
        key = (a_id, b_id, rel_type)
        prior = existing.get(key) or added_this_call.get(key)
        if prior is not None:
            if confidence > (prior.confidence or 0.0):
                prior.confidence = confidence
            continue
        row = EntityRelationship(
            entity_a_id=a_id,
            entity_b_id=b_id,
            relationship_type=rel_type,
            source_page_id=page_id,
            confidence=confidence,
            investigation_id=investigation_id,
        )
        session.add(row)
        added_this_call[key] = row
        inserted += 1

    session.flush()
    return inserted


def get_relationships_for_entity(
    session: Session,
    entity_id: uuid.UUID,
) -> List[EntityRelationship]:
    """Return all edges where *entity_id* is either end of the relationship."""
    return (
        session.query(EntityRelationship)
        .filter(
            (EntityRelationship.entity_a_id == entity_id)
            | (EntityRelationship.entity_b_id == entity_id)
        )
        .all()
    )


def get_entity_neighbors_db(
    entity_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = None,
    session: Optional[Session] = None,
    user_id: Optional[int] = None,
) -> List[dict]:
    """
    Return direct neighbors of an entity with relationship metadata.
    Uses a single SQL JOIN query - no NetworkX graph construction needed.

    Args:
        entity_id: UUID of the entity to find neighbors for
        investigation_id: Optional scope to a specific investigation
        session: Optional existing DB session (creates one if not provided)

    Returns:
        List of dicts with: neighbor_id, entity_type, value, relationship_type,
        confidence, source_page_id
    """
    from db.session import get_session as _get_session

    if session is None:
        _session = _get_session().__enter__()
        should_close = True
    else:
        _session = session
        should_close = False

    try:
        query = (
            _session.query(
                Entity.id.label("neighbor_id"),
                Entity.entity_type,
                Entity.value,
                EntityRelationship.relationship_type,
                EntityRelationship.confidence,
                EntityRelationship.source_page_id,
                EntityRelationship.entity_a_id,
            )
            .join(
                EntityRelationship,
                (EntityRelationship.entity_a_id == entity_id)
                | (EntityRelationship.entity_b_id == entity_id),
            )
            .join(
                Entity,
                sa.or_(
                    Entity.id == EntityRelationship.entity_a_id,
                    Entity.id == EntityRelationship.entity_b_id,
                ),
            )
            .filter(Entity.id != entity_id)
        )

        if investigation_id is not None:
            query = query.filter(EntityRelationship.investigation_id == investigation_id)

        if user_id is not None:
            owned_ids = sa.select(Investigation.id).where(Investigation.user_id == user_id)
            query = query.filter(EntityRelationship.investigation_id.in_(owned_ids))
        rows = query.all()

        neighbors: dict[str, dict] = {}
        for row in rows:
            key = str(row.neighbor_id)
            if key not in neighbors or row.confidence > neighbors[key].get("confidence", 0):
                neighbors[key] = {
                    "neighbor_id": str(row.neighbor_id),
                    "entity_type": row.entity_type,
                    "value": row.value,
                    "relationship_type": row.relationship_type,
                    "confidence": row.confidence,
                    "source_page_id": str(row.source_page_id) if row.source_page_id else None,
                }

        return list(neighbors.values())
    finally:
        if should_close:
            _session.close()


def get_entity_appearances(
    session: Session,
    entity_id: uuid.UUID,
    user_id: int,
) -> List[dict]:
    """
    Return investigations owned by user_id where this entity appears,
    including via InvestigationEntityLink (cross-investigation references).
    Returns list of {investigation_id, run_id, query, created_at}, newest first.
    """
    from db.models import InvestigationEntityLink  # noqa: PLC0415

    appearances: dict[str, dict] = {}

    entity = session.query(Entity).filter_by(id=entity_id).first()
    investigation_ids = []
    if entity and entity.investigation_id:
        investigation_ids.append(entity.investigation_id)

    links = (
        session.query(InvestigationEntityLink)
        .filter_by(entity_id=entity_id)
        .all()
    )
    for link in links:
        if link.investigation_id not in investigation_ids:
            investigation_ids.append(link.investigation_id)

    if investigation_ids:
        investigations = (
            session.query(Investigation)
            .filter(Investigation.id.in_(investigation_ids))
            .filter(Investigation.user_id == user_id)
            .all()
        )
        inv_map = {inv.id: inv for inv in investigations}
        for inv_id in investigation_ids:
            inv = inv_map.get(inv_id)
            if inv:
                appearances[str(inv.id)] = {
                    "investigation_id": str(inv.id),
                    "run_id": str(inv.run_id),
                    "query": inv.query,
                    "created_at": inv.created_at.isoformat() if inv.created_at else None,
                }

    result = list(appearances.values())
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return result


# ---------------------------------------------------------------------------
# Monitor alerts
# ---------------------------------------------------------------------------


def create_monitor_alert(
    session: Session,
    monitor_name: str,
    change_type: str,
    summary: str,
    diff_data: Optional[dict] = None,
    severity: str = "info",
    entity_count_delta: int = 0,
    delivery_channels: Optional[List[str]] = None,
    user_id: Optional[int] = None,
) -> MonitorAlert:
    """
    Persist a new alert record.
    Called immediately when a monitor detects a change.
    """
    alert = MonitorAlert(
        user_id=user_id,
        monitor_name=monitor_name,
        triggered_at=datetime.now(timezone.utc),
        change_type=change_type,
        summary=summary,
        diff_data=diff_data or {},
        severity=severity,
        entity_count_delta=entity_count_delta,
        delivered=bool(delivery_channels),
        delivery_channels=delivery_channels or [],
    )
    session.add(alert)
    session.flush()
    session.refresh(alert)
    return alert


def get_alerts_for_monitor(
    session: Session,
    monitor_name: str,
    limit: int = 20,
    include_acknowledged: bool = True,
) -> List[MonitorAlert]:
    """Get recent alerts for a specific monitor, newest first."""
    query = session.query(MonitorAlert).filter(
        MonitorAlert.monitor_name == monitor_name
    )
    if not include_acknowledged:
        query = query.filter(MonitorAlert.acknowledged.is_(False))
    return (
        query.order_by(MonitorAlert.triggered_at.desc()).limit(limit).all()
    )


def get_unacknowledged_alert_count(session: Session) -> int:
    """Total unacknowledged alerts across all monitors. Used for nav badge."""
    n = (
        session.query(func.count(MonitorAlert.id))
        .filter(MonitorAlert.acknowledged.is_(False))
        .scalar()
    )
    return int(n or 0)


def get_alert_counts_by_monitor(session: Session) -> dict[str, int]:
    """
    Returns {monitor_name: unacknowledged_count} for all monitors.
    Used to show per-monitor alert badges in the table.
    """
    rows = (
        session.query(
            MonitorAlert.monitor_name,
            func.count(MonitorAlert.id).label("count"),
        )
        .filter(MonitorAlert.acknowledged.is_(False))
        .group_by(MonitorAlert.monitor_name)
        .all()
    )
    return {row.monitor_name: int(row.count) for row in rows}


def acknowledge_alerts(
    session: Session,
    monitor_name: str,
    alert_ids: Optional[List[int]] = None,
) -> int:
    """
    Mark alerts as acknowledged.
    If alert_ids is None, acknowledges ALL unacknowledged alerts for monitor.
    Returns count of acknowledged alerts.
    """
    query = (
        session.query(MonitorAlert)
        .filter(MonitorAlert.monitor_name == monitor_name)
        .filter(MonitorAlert.acknowledged.is_(False))
    )
    if alert_ids:
        query = query.filter(MonitorAlert.id.in_(alert_ids))

    now = datetime.now(timezone.utc)
    count = query.update(
        {"acknowledged": True, "acknowledged_at": now},
        synchronize_session=False,
    )
    session.flush()
    return int(count)


# ---------------------------------------------------------------------------
# Monitor stats
# ---------------------------------------------------------------------------


def get_monitor_stats(session: Session, monitor_name: str) -> dict:
    """
    Return aggregate stats for a monitor based on its alert history.

    Returns:
        last_run_at: ISO timestamp of most recent alert, or None
        last_run_status: derived from most recent alert change_type, or None
        total_runs: count of alerts for this monitor
        last_entity_count: entity_count_delta from the most recent alert
    """
    latest = (
        session.query(MonitorAlert)
        .filter(MonitorAlert.monitor_name == monitor_name)
        .order_by(MonitorAlert.triggered_at.desc())
        .limit(1)
        .first()
    )

    total_runs = (
        session.query(func.count(MonitorAlert.id))
        .filter(MonitorAlert.monitor_name == monitor_name)
        .scalar() or 0
    )

    return {
        "last_run_at": latest.triggered_at.isoformat() if latest and latest.triggered_at else None,
        "last_run_status": latest.change_type if latest else None,
        "total_runs": int(total_runs),
        "last_entity_count": getattr(latest, "entity_count_delta", 0) or 0,
    }


def update_entity_source_count(
    session: Session,
    entity_id: uuid.UUID,
    source_name: str,
) -> None:
    """
    Increment source count and add source name to corroborating_sources for an entity.
    """
    import json

    entity = session.query(Entity).filter_by(id=entity_id).first()
    if not entity:
        return

    existing = json.loads(entity.corroborating_sources or "[]")

    if source_name not in existing:
        existing.append(source_name)
        entity.corroborating_sources = json.dumps(existing)
        entity.source_count = len(existing)

    session.flush()
