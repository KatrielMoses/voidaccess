"""Detached per-investigation entity projections; never mutate canonical rows."""
from types import SimpleNamespace
from db.models import Entity, Investigation, InvestigationEntityLink, Page


def entity_views(session, entities, user_id=None, investigation_id=None, all_links=False):
    result = []
    for entity in entities:
        links = session.query(InvestigationEntityLink, Investigation).join(
            Investigation, Investigation.id == InvestigationEntityLink.investigation_id,
        ).filter(InvestigationEntityLink.entity_id == entity.id)
        if user_id is not None:
            links = links.filter(Investigation.user_id == user_id)
        if investigation_id is not None:
            links = links.filter(Investigation.id == investigation_id)
        rows = links.order_by(Investigation.created_at.desc()).all()
        if rows:
            for link, inv in (rows if all_links else rows[:1]):
                data = {c.name: getattr(entity, c.name) for c in Entity.__table__.columns}
                data.update(
                    confidence=link.confidence if link.confidence is not None else 0,
                    context_snippet=link.context_snippet,
                    context=link.context_snippet,
                    page_id=link.page_id,
                    page=session.get(Page, link.page_id) if link.page_id else None,
                    investigation_id=inv.id,
                    investigation=inv,
                    extraction_method=link.extraction_method,
                    investigation_count=len(rows),
                    source_count=1,
                    corroborating_sources=None,
                    first_seen=link.linked_at, last_seen=link.linked_at,
                    first_seen_at=link.linked_at, last_seen_at=link.linked_at,
                    created_at=link.linked_at,
                    historical_context=None,
                )
                result.append(SimpleNamespace(**data))
        else:
            # Legacy origin-only rows are safe only for their origin's owner.
            inv = session.get(Investigation, entity.investigation_id) if entity.investigation_id else None
            if inv and (user_id is None or inv.user_id == user_id) and (
                investigation_id is None or inv.id == investigation_id
            ):
                data = {c.name: getattr(entity, c.name) for c in Entity.__table__.columns}
                data.update(context=entity.context_snippet, page=entity.page, investigation=inv)
                result.append(SimpleNamespace(**data))
    return result
