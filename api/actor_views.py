"""Actor API views derived only from the caller's investigation evidence."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import or_
from db.models import ActorProfile, ActorAlias, ActorInfrastructure, ActorNote, Investigation
from db.session import get_session
from sources.actor_profiles import _serialize_profile


class ScopedActorManager:
    _TIMELINE_EVENT_TYPES = {"FIRST_SEEN", "INVESTIGATION", "NEW_ALIAS", "NEW_INFRASTRUCTURE", "NOTE_ADDED"}

    def __init__(self, current):
        self.owner = current.user.id
        self.admin = current.user.role == "admin"

    async def get_profile(self, handle):
        canonical = handle.strip().lower().lstrip("@")
        with get_session() as session:
            aliases = session.query(ActorAlias).filter(ActorAlias.alias_value == handle)
            if not self.admin:
                aliases = aliases.filter(ActorAlias.user_id == self.owner)
            alias_ids = [a.actor_id for a in aliases.all()]
            row = session.query(ActorProfile).filter(or_(ActorProfile.canonical_handle == canonical, ActorProfile.id.in_(alias_ids))).first()
            if row is None:
                return None
            owned = session.query(Investigation.id).filter_by(user_id=self.owner)
            aq = session.query(ActorAlias).filter_by(actor_id=row.id)
            iq = session.query(ActorInfrastructure).filter_by(actor_id=row.id)
            if not self.admin:
                aq = aq.filter(ActorAlias.user_id == self.owner)
                iq = iq.filter(ActorInfrastructure.source_investigation_id.in_(owned))
            aliases, infra = aq.all(), iq.all()
            if not self.admin and not (aliases or infra):
                return None
            result = _serialize_profile(row, aliases, infra)
            nq = session.query(ActorNote).filter_by(actor_id=row.id)
            if not self.admin:
                nq = nq.filter_by(user_id=self.owner)
            notes = nq.order_by(ActorNote.created_at).all()
            result["notes"] = "\n".join(n.text for n in notes)
            if not self.admin:
                times = [x.first_seen_at for x in aliases + infra if x.first_seen_at]
                result["first_seen_at"] = min(times).isoformat() if times else None
                result["last_seen_at"] = max(times).isoformat() if times else None
                result["created_at"] = result["first_seen_at"]
                result["updated_at"] = result["last_seen_at"]
                result["investigation_count"] = len(result["investigation_ids"])
                result["confidence"] = max([x.confidence or 0 for x in aliases + infra], default=0)
            return result

    async def add_alias(self, actor_id, alias_value, alias_type, investigation_id, confidence=None):
        with get_session() as session:
            row = session.query(ActorAlias).filter_by(actor_id=uuid.UUID(actor_id), alias_value=alias_value, user_id=self.owner).first()
            if row:
                row.confidence = max(row.confidence or 0, confidence or 0)
            else:
                session.add(ActorAlias(actor_id=uuid.UUID(actor_id), alias_value=alias_value,
                                      alias_type=alias_type, user_id=self.owner, confidence=confidence,
                                      first_seen_at=datetime.now(timezone.utc)))

    async def find_alias_candidates(self, actor_id, min_confidence=0.60):
        # Candidate evidence must itself be owner-scoped. Analyst annotations
        # are the authoritative candidates; global aggregate scoring is CLI-only.
        with get_session() as session:
            query = session.query(ActorAlias).filter_by(actor_id=uuid.UUID(actor_id))
            if not self.admin:
                query = query.filter_by(user_id=self.owner)
            return [{"candidate_handle": a.alias_value, "confidence": a.confidence, "signals": ["owned_alias"]}
                    for a in query.all() if (a.confidence or 0) >= min_confidence]

    async def get_actor_timeline(self, handle, limit=50, event_types=None):
        profile = await self.get_profile(handle)
        if not profile:
            return []
        events = []
        for item in profile["aliases"]:
            events.append({"event_type": "NEW_ALIAS", "timestamp": item["first_seen_at"],
                           "description": item["alias_value"], "metadata": item})
        for item in profile["infrastructure"]:
            events.append({"event_type": "NEW_INFRASTRUCTURE", "timestamp": item["first_seen_at"],
                           "description": item["entity_value"], "metadata": item})
        with get_session() as session:
            query = session.query(ActorNote).filter_by(actor_id=uuid.UUID(profile["id"]))
            if not self.admin:
                query = query.filter_by(user_id=self.owner)
            for n in query.all():
                events.append({"event_type": "NOTE_ADDED", "timestamp": n.created_at.isoformat(),
                               "description": n.text, "metadata": {}})
        return sorted([e for e in events if not event_types or e["event_type"] in event_types],
                      key=lambda e: e["timestamp"] or "")[-limit:]
