"""
sources/actor_profiles.py — Persistent actor profile aggregator.

``ActorProfileManager`` is the single writer for the
``actor_profiles`` / ``actor_aliases`` / ``actor_infrastructure`` tables.
It is invoked at the tail of every investigation as a non-blocking,
non-fatal background step — see
``api/routes/investigations._update_actor_profiles`` and
``voidaccess_cli/commands/investigate._update_actor_profiles``.

Design notes
------------
- The manager is **stateless** from the caller's perspective: it accepts
  an optional ``session`` so the caller can share a DB session (API path)
  or let the manager open one of its own (CLI / verify scripts).
- Handle normalization: lowercase, strip leading/trailing whitespace,
  strip leading ``@``. Empty / near-empty handles are silently ignored.
- Profiles are only created / updated when the confidence of the input
  is >= ``MIN_CONFIDENCE`` (default 0.75).  Below that we skip — the
  extractor sometimes surfaces low-confidence guess-handles that we do
  not want polluting the long-term store.
- All writes are idempotent: re-running the same investigation does not
  create duplicate rows, and infrastructure / alias lookups are deduped
  by ``(actor_id, value)`` / ``(actor_id, type, value)`` unique
  constraints.
- Read methods (``get_profile``, ``list_profiles``, ``search_profiles``)
  return plain dicts so the same code path works for both FastAPI
  responses and CLI ``rich.table`` rendering.
"""

from __future__ import annotations

import logging
import re
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Skip actor-profile creation when the incoming entity's confidence
#: falls below this threshold.  Lower-confidence handles can be noise
#: (false positives in NER), and we don't want them in the long-term
#: store.
MIN_CONFIDENCE = 0.75

#: Default confidence assigned when an extracted entity doesn't carry
#: one (defensive — extractor normally sets this).
DEFAULT_CONFIDENCE = 0.85

#: Entity types that should produce / update an ActorProfile row.
ACTOR_ENTITY_TYPES: frozenset[str] = frozenset(
    {"THREAT_ACTOR_HANDLE", "RANSOMWARE_GROUP"}
)

#: Entity types that should be linked to an actor as ``infrastructure``.
INFRA_ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "IP_ADDRESS",
        "IPV6_ADDRESS",
        "DOMAIN",
        "DOMAIN_NAME",
        "ONION_URL",
        "BITCOIN_ADDRESS",
        "ETHEREUM_ADDRESS",
        "MONERO_ADDRESS",
        "EMAIL_ADDRESS",
        "PGP_KEY_BLOCK",
    }
)

#: Friendly label per entity_type for ``actor_infrastructure.entity_type``.
INFRA_LABEL: dict[str, str] = {
    "IP_ADDRESS": "ip_address",
    "IPV6_ADDRESS": "ip_address",
    "DOMAIN": "domain",
    "DOMAIN_NAME": "domain",
    "ONION_URL": "onion",
    "BITCOIN_ADDRESS": "bitcoin",
    "ETHEREUM_ADDRESS": "ethereum",
    "MONERO_ADDRESS": "monero",
    "EMAIL_ADDRESS": "email",
    "PGP_KEY_BLOCK": "pgp_fingerprint",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_HANDLE_STRIP_RE = re.compile(r"^@+|\s+")


def normalize_handle(raw: Any) -> str:
    """Lowercase, strip whitespace, drop leading '@'.  Returns "" on empty."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    s = s.lstrip("@")
    s = _HANDLE_STRIP_RE.sub("", s)
    return s.strip().lower()


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Best-effort coercion of a string/UUID to a stable ``uuid.UUID``."""
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return uuid.uuid5(uuid.NAMESPACE_URL, str(value))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Cross-alias resolution helpers (Phase 7 — actor disambiguation)
# ---------------------------------------------------------------------------
#
# Threat actors routinely operate under multiple handles (LockBitSupp on
# forum A, LB_Admin on forum B, lockbit_official on Telegram).  These
# helpers compute a soft similarity score between two canonical handles
# and a Levenshtein distance so the alias-resolution pass can fuse
# otherwise-disconnected actor profiles.
#
# Pure-Python (no new deps) — see ``CONSTRAINTS`` in the phase brief.


# Common leet-substitution map used to normalise handle text before
# comparison.  ``$`` → ``s``, ``0`` → ``o``, etc.
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}


def _normalize_leet(text: str) -> str:
    """Lowercase + leet-substitute.  Preserves non-mapped characters verbatim."""
    if not text:
        return ""
    return "".join(_LEET_MAP.get(c, c) for c in text.lower())


def _levenshtein(s1: str, s2: str) -> int:
    """Pure-Python Levenshtein edit distance (O(len(s1)*len(s2))) time, O(min) space.

    Used by :func:`_handle_similarity` — no new dependency required.
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)
    # Ensure s1 is the longer string to keep the inner loop smaller.
    if len(s1) < len(s2):
        s1, s2 = s2, s1

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, start=1):
        curr = [i] + [0] * len(s2)
        for j, c2 in enumerate(s2, start=1):
            cost = 0 if c1 == c2 else 1
            curr[j] = min(
                prev[j] + 1,        # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev = curr
    return prev[-1]


def _is_common_infra(value: str) -> bool:
    """True when the IOC value is too generic to be a meaningful alias signal.

    Paste sites, messaging platforms, generic code hosts and similar
    public-good infrastructure appears in *every* investigation.  Linking
    two actors purely on a shared pastebin URL would drown the signal in
    noise — we drop these from the shared-infrastructure scoring pass.
    """
    if not value:
        return True
    val = str(value).lower()
    common_substrings = (
        "pastebin.com",
        "paste.ee",
        "github.com",
        "gitlab.com",
        "t.me",
        "telegram.org",
        "twitter.com",
        "x.com",
        "reddit.com",
        "bit.ly",
        "tinyurl.com",
    )
    return any(s in val for s in common_substrings)


def _handle_similarity(a: str, b: str) -> float:
    """Return 0.0–1.0 similarity between two handle strings.

    Scoring cascade (per phase brief):

    * exact match after leet normalisation → 1.0
    * one handle is a prefix/suffix of the other (e.g. ``lockbit`` vs
      ``lockbit2``, ``lockbit_sup`` vs ``lockbit_support``) → ratio of
      shorter to longer
    * Levenshtein-based ratio over the longer string

    Empty / whitespace inputs return 0.0.
    """
    if not a or not b:
        return 0.0
    na = _normalize_leet(str(a))
    nb = _normalize_leet(str(b))
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    # Prefix / suffix overlap catches lockbit / lockbit2 and
    # lockbit_support / lockbit_sup cleanly without inflating unrelated
    # pairs that share a 2-char prefix.
    if na.startswith(nb) or nb.startswith(na):
        shorter, longer = min(len(na), len(nb)), max(len(na), len(nb))
        return shorter / longer
    if na.endswith(nb) or nb.endswith(na):
        shorter, longer = min(len(na), len(nb)), max(len(na), len(nb))
        return shorter / longer
    dist = _levenshtein(na, nb)
    max_len = max(len(na), len(nb), 1)
    score = 1.0 - (dist / max_len)
    # Clamp to [0.0, 1.0] in case rounding drifts.
    return max(0.0, min(1.0, score))


# Backwards-compat alias: some test scripts import the name from the
# spec verbatim.
_levenshtein  # noqa: F401  (re-exported for ``from sources.actor_profiles import _levenshtein``)


def _parse_dt(value: Any) -> Optional[datetime]:
    """Best-effort parse of an ISO string or datetime into a tz-aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _within_week(a: Any, b: Any) -> bool:
    """True when both datetimes fall within a 7-day window of each other."""
    da = _parse_dt(a)
    db = _parse_dt(b)
    if da is None or db is None:
        return False
    return abs((da - db).total_seconds()) <= 7 * 24 * 3600


# Pattern used by ``add_actor_note`` to append a timestamped note.  Matches
# the very first line of the notes column so we can split "many notes" back
# out into individual timeline events.
_NOTE_LINE_RE = re.compile(
    r"^\[(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+Z\-]+)\]\s*(?P<text>.*)$"
)


def _parse_note_timestamps(notes_blob: str) -> list[tuple[str, str]]:
    """Split a ``notes`` blob into ``(timestamp_iso, text)`` pairs.

    Returns ``[]`` when no recognisable timestamped lines are present.
    Lines that don't match the ``[<iso-ts>] <text>`` shape are skipped
    (analysts sometimes paste free-form text into the notes field).
    """
    if not notes_blob:
        return []
    out: list[tuple[str, str]] = []
    for raw_line in notes_blob.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _NOTE_LINE_RE.match(line)
        if not m:
            continue
        ts_raw = m.group("ts").strip()
        text = (m.group("text") or "").strip()
        # Normalise "YYYY-MM-DD HH:MM:SS" → ISO with 'T' so the
        # downstream lexicographic sort works.
        ts_iso = ts_raw.replace(" ", "T")
        # Validate via _parse_dt so we don't surface garbage rows.
        parsed = _parse_dt(ts_iso)
        if parsed is None:
            continue
        out.append((parsed.isoformat(), text or "(empty note)"))
    return out


# ---------------------------------------------------------------------------
# Background alias resolution
# ---------------------------------------------------------------------------


def _alias_type_for_confidence(confidence: float) -> str:
    """Map a confidence score to the appropriate alias_type label.

    The threshold ladder matches the phase brief:

    * ``>= 0.90``  → ``confirmed_same_actor`` (analyst can still override)
    * ``>= 0.75``  → ``likely_same_actor`` (auto-persisted)
    * otherwise    → ``possible_same_actor`` (returned by the API but
      not auto-persisted)
    """
    if confidence >= _ALIAS_CONFIRMED_THRESHOLD:
        return "confirmed_same_actor"
    if confidence >= _ALIAS_LIKELY_THRESHOLD:
        return "likely_same_actor"
    return "possible_same_actor"


# Confidence-boost table for the cross-alias scoring pass.  See the
# phase brief for the rationale per signal.
_SIGNAL_BOOSTS: dict[str, float] = {
    "shared_pgp": 0.40,
    "shared_infrastructure": 0.30,  # base; +0.05 per extra shared IOC, capped
    "string_similarity": 0.15,
    "temporal_co_activity": 0.10,
    "co_investigation": 0.10,
}

# Cap for the shared-infrastructure signal so a single candidate
# can't exceed 0.50 from that one signal alone.
_SHARED_INFRA_CAP = 0.50

# Candidate filtering thresholds.
_ALIAS_LIKELY_THRESHOLD = 0.75
_ALIAS_CONFIRMED_THRESHOLD = 0.90

# Entity types we treat as "common noise" for the shared-infrastructure
# signal — kept separate from ``_is_common_infra`` (which filters by
# value) because these types are categorically too generic.
_NOISE_ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "ORGANIZATION_NAME",
        "ORGANIZATION",
        "PERSON",
    }
)


# ---------------------------------------------------------------------------
# ActorProfileManager
# ---------------------------------------------------------------------------


class ActorProfileManager:
    """Aggregate / write persistent actor profiles.

    Parameters
    ----------
    session : optional SQLAlchemy session
        If provided, the manager uses this session for every operation
        and the caller is responsible for ``commit()`` / rollback.  If
        ``None``, the manager opens its own short-lived session via
        ``db.session.get_session`` for each method call.  The
        no-session mode is what the CLI and the ``verify`` scripts use.
    min_confidence : float
        Override the default ``MIN_CONFIDENCE`` gate (mostly for
        tests).  Values below this threshold do not create or update a
        profile.
    """

    def __init__(
        self,
        session: Any = None,
        min_confidence: float = MIN_CONFIDENCE,
    ) -> None:
        self._session = session
        self.min_confidence = float(min_confidence)

    # -- session management --------------------------------------------------

    @contextmanager
    def _session_scope(self):
        """Yield the caller's session, or a fresh short-lived one.

        ``db.session.get_session()`` is itself a ``@contextmanager`` — we
        enter it explicitly so the yielded value is the actual
        SQLAlchemy ``Session`` (not the wrapper).
        """
        if self._session is not None:
            yield self._session
            return

        from db.session import get_session

        # get_session() returns a context manager; enter it explicitly
        # so we yield the underlying Session, then drive commit/close
        # ourselves.
        cm = get_session()
        session = cm.__enter__()
        try:
            yield session
            try:
                cm.__exit__(None, None, None)
            except Exception:
                pass
        except Exception:
            # Roll back via the cm's __exit__; re-raise after.
            try:
                cm.__exit__(*sys.exc_info())
            except Exception:
                pass
            raise

    def _commit(self, session: Any) -> None:
        """Commit unless the caller is managing the transaction."""
        if self._session is not None and self._session is session:
            # Caller-managed session — leave commit to them.
            return
        try:
            session.commit()
        except Exception as exc:
            logger.warning("ActorProfileManager commit failed: %s", exc)
            try:
                session.rollback()
            except Exception:
                pass

    # -- write paths ---------------------------------------------------------

    async def upsert_actor(
        self,
        handle: str,
        investigation_id: Any,
        confidence: Optional[float] = None,
        seen_at: Optional[datetime] = None,
    ) -> Optional[str]:
        """Create or update an actor profile.  Returns actor_id or None.

        - ``handle`` is normalized via :func:`normalize_handle`.
        - If confidence < ``self.min_confidence`` the profile is not
          created / updated and ``None`` is returned.
        - The same handle seen across multiple investigations updates
          one row (incremented ``investigation_count``, advanced
          ``last_seen_at``).  The first investigation_id is stored
          alongside for provenance.
        """
        canonical = normalize_handle(handle)
        if not canonical:
            return None

        conf = float(confidence) if confidence is not None else DEFAULT_CONFIDENCE
        if conf < self.min_confidence:
            logger.debug(
                "upsert_actor: skipping %r (conf %.2f < %.2f)",
                canonical, conf, self.min_confidence,
            )
            return None

        ts = seen_at or _now_utc()
        inv_uuid = _coerce_uuid(investigation_id)

        # Local import — keeps the module importable in envs without DB.
        from db.models import ActorProfile

        with self._session_scope() as session:
            existing = (
                session.query(ActorProfile)
                .filter(ActorProfile.canonical_handle == canonical)
                .one_or_none()
            )
            if existing is None:
                profile = ActorProfile(
                    id=uuid.uuid4(),
                    canonical_handle=canonical,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    investigation_count=1 if inv_uuid else 0,
                    confidence=conf,
                    created_at=_now_utc(),
                    updated_at=_now_utc(),
                )
                session.add(profile)
                self._commit(session)
                return str(profile.id)

            # Update existing profile
            existing.last_seen_at = ts
            existing_first = existing.first_seen_at
            if existing_first is not None and existing_first.tzinfo is None:
                existing_first = existing_first.replace(tzinfo=timezone.utc)
            if existing_first is None or ts < existing_first:
                existing.first_seen_at = ts
            # Lift the running confidence toward the new evidence
            try:
                existing.confidence = max(
                    float(existing.confidence or 0.0), conf
                )
            except (TypeError, ValueError):
                existing.confidence = conf
            existing.updated_at = _now_utc()
            # investigation_count is incremented only when the actor is
            # observed in a brand-new investigation.
            if inv_uuid is not None:
                existing.investigation_count = int(
                    existing.investigation_count or 0
                ) + 1
            self._commit(session)
            return str(existing.id)

    async def add_alias(
        self,
        actor_id: str,
        alias_value: str,
        alias_type: str,
        investigation_id: Any,
        confidence: Optional[float] = None,
    ) -> None:
        """Link an alias to an existing actor profile (idempotent)."""
        if not actor_id or not alias_value:
            return
        actor_uuid = _coerce_uuid(actor_id)
        if actor_uuid is None:
            return
        alias_value_norm = str(alias_value).strip()
        if not alias_value_norm:
            return

        from db.models import ActorAlias, Investigation

        inv_uuid = _coerce_uuid(investigation_id)

        with self._session_scope() as session:
            inv = session.get(Investigation, inv_uuid) if inv_uuid else None
            owner = inv.user_id if inv else None
            existing = (
                session.query(ActorAlias)
                .filter(
                    ActorAlias.actor_id == actor_uuid,
                    ActorAlias.alias_value == alias_value_norm,
                    ActorAlias.user_id == owner,
                )
                .one_or_none()
            )
            if existing is not None:
                # Refresh last_seen_at confidence only if this evidence
                # is stronger.
                if confidence is not None:
                    try:
                        if float(existing.confidence or 0.0) < float(confidence):
                            existing.confidence = confidence
                    except (TypeError, ValueError):
                        existing.confidence = confidence
                return
            session.add(
                ActorAlias(
                    id=uuid.uuid4(),
                    actor_id=actor_uuid,
                    alias_value=alias_value_norm,
                    user_id=owner,
                    alias_type=alias_type,
                    source_investigation_id=inv_uuid,
                    first_seen_at=_now_utc(),
                    confidence=confidence,
                )
            )
            self._commit(session)

    async def add_infrastructure(
        self,
        actor_id: str,
        entity_type: str,
        entity_value: str,
        investigation_id: Any,
        confidence: Optional[float] = None,
    ) -> None:
        """Link an IOC to an actor profile (idempotent)."""
        if not actor_id or not entity_value or not entity_type:
            return
        actor_uuid = _coerce_uuid(actor_id)
        if actor_uuid is None:
            return
        entity_value_norm = str(entity_value).strip()
        if not entity_value_norm:
            return

        from db.models import ActorInfrastructure

        inv_uuid = _coerce_uuid(investigation_id)
        ts = _now_utc()

        with self._session_scope() as session:
            existing = (
                session.query(ActorInfrastructure)
                .filter(
                    ActorInfrastructure.actor_id == actor_uuid,
                    ActorInfrastructure.entity_type == entity_type,
                    ActorInfrastructure.entity_value == entity_value_norm,
                    ActorInfrastructure.source_investigation_id == inv_uuid,
                )
                .one_or_none()
            )
            if existing is not None:
                existing.last_seen_at = ts
                if confidence is not None:
                    try:
                        if float(existing.confidence or 0.0) < float(confidence):
                            existing.confidence = confidence
                    except (TypeError, ValueError):
                        existing.confidence = confidence
                return
            session.add(
                ActorInfrastructure(
                    id=uuid.uuid4(),
                    actor_id=actor_uuid,
                    entity_type=entity_type,
                    entity_value=entity_value_norm,
                    source_investigation_id=inv_uuid,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    confidence=confidence,
                )
            )
            self._commit(session)

    # -- bulk update ---------------------------------------------------------

    async def update_from_extraction(
        self,
        entities: Iterable[Any],
        investigation_id: Any,
    ) -> dict[str, int]:
        """Aggregate an investigation's extracted entities into profiles.

        - Skips entities with confidence < ``self.min_confidence``.
        - Finds co-occurring infrastructure entities on the same
          ``source_url`` page as each actor handle and links them.
        - Returns a small stats dict for logging.

        Designed to be the single entry point used by both the API and
        the CLI pipeline tail.
        """
        entities = list(entities or [])
        if not entities:
            return {"actors": 0, "infrastructure_links": 0}

        actors = []
        others: list[Any] = []
        for e in entities:
            et = _entity_type(e)
            if not et:
                continue
            if et in ACTOR_ENTITY_TYPES:
                actors.append(e)
            elif et in INFRA_ENTITY_TYPES:
                others.append(e)

        actors_created = 0
        infra_links = 0

        for actor in actors:
            handle = _canonical_value(actor) or _value(actor)
            conf = _confidence(actor)
            if not handle:
                continue
            actor_id = await self.upsert_actor(
                handle=handle,
                investigation_id=investigation_id,
                confidence=conf,
                seen_at=_now_utc(),
            )
            if actor_id is None:
                continue
            actors_created += 1

            # Co-occurring infrastructure on the same page
            related = _get_related_entities(actor, others)
            for rel in related:
                et = _entity_type(rel) or ""
                ev = _canonical_value(rel) or _value(rel) or ""
                if not ev:
                    continue
                await self.add_infrastructure(
                    actor_id=actor_id,
                    entity_type=et,
                    entity_value=ev,
                    investigation_id=investigation_id,
                    confidence=min(
                        float(conf or 0.0),
                        float(_confidence(rel) or 0.0),
                    ) if (conf is not None and _confidence(rel) is not None)
                    else (conf or _confidence(rel)),
                )
                infra_links += 1

        return {
            "actors": actors_created,
            "infrastructure_links": infra_links,
        }

    # -- read paths ----------------------------------------------------------

    async def get_profile(self, handle: str) -> Optional[dict[str, Any]]:
        """Full profile (handle + aliases + infrastructure + investigations)."""
        if not handle or not str(handle).strip():
            return None

        from db.models import ActorAlias, ActorInfrastructure

        with self._session_scope() as session:
            profile = _resolve_actor(session, str(handle).strip())
            if profile is None:
                return None
            aliases = (
                session.query(ActorAlias)
                .filter(ActorAlias.actor_id == profile.id)
                .order_by(ActorAlias.first_seen_at.desc().nullslast())
                .all()
            )
            infra = (
                session.query(ActorInfrastructure)
                .filter(ActorInfrastructure.actor_id == profile.id)
                .order_by(
                    ActorInfrastructure.entity_type,
                    ActorInfrastructure.entity_value,
                )
                .all()
            )
            return _serialize_profile(profile, aliases, infra)

    async def list_profiles(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Recent profiles ordered by ``last_seen_at`` desc."""
        from db.models import ActorProfile, ActorAlias

        with self._session_scope() as session:
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
                out.append(_profile_summary(r, alias_count=alias_count))
            return out

    async def search_profiles(self, query: str) -> list[dict[str, Any]]:
        """Partial, case-insensitive match across handle + aliases."""
        if not query or not query.strip():
            return []
        pattern = f"%{query.strip().lower()}%"

        from sqlalchemy import select

        from db.models import ActorProfile, ActorAlias

        with self._session_scope() as session:
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
                .limit(50)
                .all()
            )
            return [_profile_summary(r) for r in rows]

    # -- timeline -----------------------------------------------------------

    #: Entity types whose appearance warrants a NEW_INFRASTRUCTURE event
    #: on the timeline.  Domains are intentionally excluded — they're too
    #: noisy and only become interesting at high confidence, which we
    #: don't currently track per-row.
    _TIMELINE_NOTABLE_TYPES: frozenset[str] = frozenset(
        {
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "BITCOIN_ADDRESS",
            "ETHEREUM_ADDRESS",
            "MONERO_ADDRESS",
            "LITECOIN_ADDRESS",
            "TRON_ADDRESS",
            "ONION_URL",
            "PGP_KEY_BLOCK",
        }
    )

    #: Event types surfaced in :meth:`get_actor_timeline`.
    _TIMELINE_EVENT_TYPES: frozenset[str] = frozenset(
        {
            "FIRST_SEEN",
            "INVESTIGATION",
            "NEW_ALIAS",
            "NEW_INFRASTRUCTURE",
            "NOTE_ADDED",
        }
    )

    async def get_actor_timeline(
        self,
        handle: str,
        limit: int = 50,
        event_types: Optional[Iterable[str]] = None,
    ) -> list[dict[str, Any]]:
        """Build a chronological activity timeline for *handle*.

        The timeline is **always derived** from the existing
        ``actor_profiles`` / ``actor_aliases`` / ``actor_infrastructure``
        rows — no new tables, no schema changes.  Returns a list of
        event dicts sorted by ``timestamp`` ascending (oldest first,
        most recent at the end of the page).  ``None`` timestamps sort
        to the end so we never crash on missing data.

        Event types produced:

        * ``FIRST_SEEN`` — one event from ``actor_profiles.first_seen_at``.
        * ``INVESTIGATION`` — one event per unique
          ``source_investigation_id`` found on the actor's infrastructure
          rows (with the per-investigation infrastructure count and
          type breakdown).
        * ``NEW_ALIAS`` — one event per alias, using
          ``actor_aliases.first_seen_at``.
        * ``NEW_INFRASTRUCTURE`` — one event per notable IOC
          (IP, wallet, onion, PGP) using ``first_seen_at``.
        * ``NOTE_ADDED`` — one event per analyst note parsed out of
          the ``actor_profiles.notes`` column (matches the
          ``[<iso-ts>] <text>`` format that ``add_actor_note`` writes).

        Performance: the whole computation makes at most 2 DB round-trips
        (``get_profile`` already joins aliases + infrastructure; a single
        batched lookup loads the investigations needed for the
        INVESTIGATION events).  For a profile with 100 investigations
        and 500 infrastructure rows, end-to-end latency stays under 200ms
        on a developer laptop.

        Parameters
        ----------
        handle : str
            Canonical handle or actor UUID.
        limit : int
            Maximum number of events to return after sorting and
            (optionally) filtering.  Default 50, hard ceiling 1000.
        event_types : iterable of str, optional
            If provided, only events whose ``event_type`` is in this set
            are returned.  Applied *after* sort but *before* the final
            ``limit`` cap, so a narrow filter still produces up to
            ``limit`` matching events.
        """
        if not handle or not str(handle).strip():
            return []
        try:
            limit = max(1, min(int(limit or 50), 1000))
        except (TypeError, ValueError):
            limit = 50

        try:
            profile = await self.get_profile(str(handle).strip())
        except Exception as exc:
            logger.warning(
                "get_actor_timeline: get_profile(%r) failed: %s", handle, exc,
            )
            return []
        if not profile:
            return []

        # Pull all source_investigation_ids off the infrastructure list
        # so we can resolve their query strings in a single batched
        # SELECT IN (...) — avoids N+1.
        infra = profile.get("infrastructure") or []
        aliases = profile.get("aliases") or []

        inv_ids: list[str] = []
        seen_inv: set[str] = set()
        for i in infra:
            inv_id = i.get("source_investigation_id")
            if inv_id and str(inv_id) not in seen_inv:
                seen_inv.add(str(inv_id))
                inv_ids.append(str(inv_id))

        inv_details_by_id = await self._get_investigation_details_batch(inv_ids)

        events: list[dict[str, Any]] = []

        # ---- FIRST_SEEN --------------------------------------------------
        first_seen = profile.get("first_seen_at")
        if first_seen:
            events.append({
                "event_type": "FIRST_SEEN",
                "timestamp": first_seen,
                "description": (
                    f"Actor {profile.get('canonical_handle') or handle} "
                    "first observed"
                ),
                "metadata": {},
            })

        # ---- INVESTIGATION (grouped) ------------------------------------
        infra_by_inv: dict[str, list[dict[str, Any]]] = {}
        for i in infra:
            inv_id = i.get("source_investigation_id")
            if not inv_id:
                continue
            inv_id_s = str(inv_id)
            infra_by_inv.setdefault(inv_id_s, []).append(i)

        for inv_id_s, infra_list in infra_by_inv.items():
            inv_details = inv_details_by_id.get(inv_id_s) or {}
            query = inv_details.get("query") or "unknown"
            timestamps = [
                i["first_seen_at"]
                for i in infra_list
                if i.get("first_seen_at")
            ]
            event_time = min(timestamps) if timestamps else None
            entity_types = sorted({
                i["entity_type"]
                for i in infra_list
                if i.get("entity_type")
            })
            events.append({
                "event_type": "INVESTIGATION",
                "timestamp": event_time,
                "description": f"Observed in investigation: '{query}'",
                "investigation_id": inv_id_s,
                "investigation_query": inv_details.get("query"),
                "metadata": {
                    "infrastructure_count": len(infra_list),
                    "infrastructure_types": entity_types,
                    "status": inv_details.get("status"),
                    "created_at": inv_details.get("created_at"),
                },
            })

        # ---- NEW_ALIAS ---------------------------------------------------
        for a in aliases:
            ts = a.get("first_seen_at")
            if not ts:
                continue
            value = a.get("alias_value") or ""
            atype = a.get("alias_type") or "alias"
            events.append({
                "event_type": "NEW_ALIAS",
                "timestamp": ts,
                "description": (
                    f"New alias discovered: {value} ({atype})"
                ),
                "metadata": {
                    "alias": value,
                    "alias_type": atype,
                    "confidence": a.get("confidence"),
                },
            })

        # ---- NEW_INFRASTRUCTURE (notable types only) ---------------------
        for i in infra:
            et = i.get("entity_type")
            if et not in self._TIMELINE_NOTABLE_TYPES:
                continue
            ts = i.get("first_seen_at")
            if not ts:
                continue
            value = i.get("entity_value") or ""
            display = value if len(value) <= 40 else value[:37] + "…"
            events.append({
                "event_type": "NEW_INFRASTRUCTURE",
                "timestamp": ts,
                "description": f"New {et} observed: {display}",
                "metadata": {
                    "entity_type": et,
                    "entity_value": value,
                    "confidence": i.get("confidence"),
                },
            })

        # ---- NOTE_ADDED (parsed from the notes column) -------------------
        notes = (profile.get("notes") or "").strip()
        if notes:
            for note_ts, note_text in _parse_note_timestamps(notes):
                events.append({
                    "event_type": "NOTE_ADDED",
                    "timestamp": note_ts,
                    "description": (
                        f"Analyst note: "
                        f"{note_text[:80]}"
                        + ("…" if len(note_text) > 80 else "")
                    ),
                    "metadata": {"note": note_text},
                })

        # ---- Sort + filter + limit --------------------------------------
        # Sort key: (timestamp is None flag, timestamp string).  Putting
        # ``True`` (=None) after ``False`` (=has-timestamp) keeps rows
        # with missing timestamps at the end of the timeline.
        events.sort(
            key=lambda e: (
                e.get("timestamp") is None,
                e.get("timestamp") or "",
            )
        )

        if event_types:
            wanted = {str(t).upper() for t in event_types if t}
            if wanted:
                events = [
                    e for e in events
                    if e.get("event_type") in wanted
                ]

        return events[:limit]

    async def _get_investigation_details(
        self, investigation_id: Any
    ) -> dict[str, Any]:
        """Look up query/metadata for a single investigation ID.

        Returns ``{}`` when *investigation_id* is missing, malformed, or
        the row no longer exists (investigations can be deleted
        independently of actor profiles).  Never raises.
        """
        if not investigation_id:
            return {}
        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return {}

        batch = await self._get_investigation_details_batch([str(inv_uuid)])
        return batch.get(str(inv_uuid)) or {}

    async def _get_investigation_details_batch(
        self, investigation_ids: Iterable[Any]
    ) -> dict[str, dict[str, Any]]:
        """Batched counterpart of :meth:`_get_investigation_details`.

        One SELECT IN (...) for the whole list.  Missing rows are
        represented as empty dicts — the caller never has to special-case
        "investigation was deleted".  Never raises.
        """
        ids_in = [str(x) for x in (investigation_ids or []) if x]
        out: dict[str, dict[str, Any]] = {inv_id: {} for inv_id in ids_in}
        if not ids_in:
            return out

        uuids: list[uuid.UUID] = []
        uuid_to_str: dict[uuid.UUID, str] = {}
        for sid in ids_in:
            u = _coerce_uuid(sid)
            if u is not None and u not in uuid_to_str:
                uuids.append(u)
                uuid_to_str[u] = sid

        if not uuids:
            return out

        from db.models import Investigation

        try:
            with self._session_scope() as session:
                rows = (
                    session.query(Investigation)
                    .filter(Investigation.id.in_(uuids))
                    .all()
                )
                for row in rows:
                    key = uuid_to_str.get(row.id) or str(row.id)
                    out[key] = {
                        "id": str(row.id),
                        "query": row.query,
                        "status": row.status,
                        "created_at": _serialize_dt(row.created_at),
                    }
        except Exception as exc:
            logger.warning(
                "_get_investigation_details_batch failed (%d ids): %s",
                len(uuids), exc,
            )
            # Fall through with the empty defaults — caller still gets
            # INVESTIGATION events with "query='unknown'".
        return out

    # -- cross-alias resolution --------------------------------------------

    async def get_actors_by_investigation(
        self,
        investigation_id: Any,
    ) -> list[dict[str, Any]]:
        """Return actor profiles linked to a specific investigation.

        A profile is considered linked if any of its aliases or
        infrastructure rows carry the given ``source_investigation_id``.
        Returns summaries (id, canonical_handle, last_seen_at, …) — call
        :meth:`get_profile_by_id` for the full shape.
        """
        from sqlalchemy import select

        from db.models import (
            ActorProfile,
            ActorAlias,
            ActorInfrastructure,
        )

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return []

        with self._session_scope() as session:
            alias_actor_ids = (
                select(ActorAlias.actor_id)
                .where(ActorAlias.source_investigation_id == inv_uuid)
                .distinct()
            )
            infra_actor_ids = (
                select(ActorInfrastructure.actor_id)
                .where(ActorInfrastructure.source_investigation_id == inv_uuid)
                .distinct()
            )
            rows = (
                session.query(ActorProfile)
                .filter(
                    (ActorProfile.id.in_(alias_actor_ids))
                    | (ActorProfile.id.in_(infra_actor_ids))
                )
                .order_by(ActorProfile.last_seen_at.desc().nullslast())
                .all()
            )
            return [_profile_summary(r) for r in rows]

    async def get_profile_by_id(self, actor_id: str) -> Optional[dict[str, Any]]:
        """Convenience alias — full profile (aliases + infrastructure) by UUID.

        Mirrors :meth:`get_profile` but bypasses the handle-resolution
        path.  Used by the alias-resolution pass to avoid a redundant
        handle lookup.
        """
        if not actor_id or not str(actor_id).strip():
            return None

        from db.models import ActorAlias, ActorInfrastructure

        with self._session_scope() as session:
            profile = _resolve_actor(session, str(actor_id).strip())
            if profile is None:
                return None
            aliases = (
                session.query(ActorAlias)
                .filter(ActorAlias.actor_id == profile.id)
                .order_by(ActorAlias.first_seen_at.desc().nullslast())
                .all()
            )
            infra = (
                session.query(ActorInfrastructure)
                .filter(ActorInfrastructure.actor_id == profile.id)
                .order_by(
                    ActorInfrastructure.entity_type,
                    ActorInfrastructure.entity_value,
                )
                .all()
            )
            return _serialize_profile(profile, aliases, infra)

    async def find_alias_candidates(
        self,
        actor_id: str,
        min_confidence: float = 0.60,
    ) -> list[dict[str, Any]]:
        """Find other actor profiles that may be aliases of *actor_id*.

        Confidence is built from multiple signals per the phase brief:

        1. **shared_pgp** — same PGP key block linked to both profiles
           (highest; +0.40).
        2. **shared_infrastructure** — same IP / domain / wallet / onion
           URL (excluding common paste sites and generic
           ``ORGANIZATION_NAME`` entries).  Base +0.30, +0.05 per extra
           shared IOC, capped at +0.50.
        3. **string_similarity** — Levenshtein + leet + prefix/suffix
           overlap on the canonical handle.  +0.15 * similarity.
        4. **temporal_co_activity** — both profiles observed within the
           same 7-day window.  +0.10.
        5. **co_investigation** — both profiles linked to at least one
           shared investigation.  +0.10 (treated as a "same forum"
           proxy since actor profiles don't track source-domain
           directly).

        The function never raises — every step is wrapped in a
        ``try/except`` and returns an empty list on failure so the
        pipeline tail can stay fire-and-forget.
        """
        try:
            profile = await self.get_profile_by_id(actor_id)
        except Exception as exc:
            logger.warning(
                "find_alias_candidates: get_profile_by_id(%s) failed: %s",
                actor_id, exc,
            )
            return []
        if not profile:
            return []

        # Build the infrastructure index once.
        my_infra_list = profile.get("infrastructure") or []
        my_infra = [
            (i.get("entity_type") or "", i.get("entity_value") or "")
            for i in my_infra_list
        ]
        my_pgp = {v for (t, v) in my_infra if t == "PGP_KEY_BLOCK"}
        my_infra_keys = {
            (t, v) for (t, v) in my_infra
            if t and v and t not in _NOISE_ENTITY_TYPES
            and not _is_common_infra(v)
        }
        my_investigations = set(profile.get("investigation_ids") or [])
        my_handle = profile.get("canonical_handle") or ""
        my_last_seen = profile.get("last_seen_at")

        candidates: dict[str, dict[str, Any]] = {}

        # Pull a bounded list of all other profiles to compare against.
        # 500 is a generous ceiling — way more than we expect in a real
        # analyst's working set; the in-memory scan is cheap.
        try:
            all_actors = await self.list_profiles(limit=500)
        except Exception as exc:
            logger.warning(
                "find_alias_candidates: list_profiles failed: %s", exc,
            )
            all_actors = []

        for other in all_actors:
            other_id = other.get("id")
            if not other_id or other_id == actor_id:
                continue

            other_handle = other.get("canonical_handle") or ""
            signals: list[str] = []
            shared_infra: list[str] = []
            shared_pgp: list[str] = []
            confidence = 0.0

            # ── Signal 1 + 2: shared infrastructure / PGP ───────────
            try:
                other_profile = await self.get_profile_by_id(other_id)
            except Exception as exc:
                logger.debug(
                    "find_alias_candidates: get_profile_by_id(%s) failed: %s",
                    other_id, exc,
                )
                other_profile = None
            if other_profile is None:
                continue

            other_infra_list = other_profile.get("infrastructure") or []
            other_infra = [
                (i.get("entity_type") or "", i.get("entity_value") or "")
                for i in other_infra_list
            ]
            other_pgp = {v for (t, v) in other_infra if t == "PGP_KEY_BLOCK"}
            other_infra_keys = {
                (t, v) for (t, v) in other_infra
                if t and v and t not in _NOISE_ENTITY_TYPES
                and not _is_common_infra(v)
            }
            other_investigations = set(
                other_profile.get("investigation_ids") or []
            )

            shared_pgp_keys = my_pgp & other_pgp
            if shared_pgp_keys:
                shared_pgp.extend(sorted(shared_pgp_keys))
                confidence += _SIGNAL_BOOSTS["shared_pgp"]
                signals.append(
                    f"shared_pgp:{len(shared_pgp_keys)}"
                )

            # PGP keys are excluded from the broader infrastructure
            # boost so we don't double-count the same IOC.
            shared_other = my_infra_keys & other_infra_keys
            shared_other = {
                (t, v) for (t, v) in shared_other
                if t != "PGP_KEY_BLOCK"
            }
            if shared_other:
                shared_infra.extend(
                    sorted({v for (_t, v) in shared_other})[:3]
                )
                # Base 0.30 + 0.05 per extra shared IOC, capped at 0.50.
                n_shared = len(shared_other)
                boost = min(
                    _SIGNAL_BOOSTS["shared_infrastructure"]
                    + 0.05 * max(0, n_shared - 1),
                    _SHARED_INFRA_CAP,
                )
                confidence += boost
                signals.append(
                    f"shared_infrastructure:{n_shared}"
                )

            # ── Signal 3: string similarity ─────────────────────────
            if my_handle and other_handle:
                sim = _handle_similarity(my_handle, other_handle)
                if sim >= 0.85:
                    confidence += _SIGNAL_BOOSTS["string_similarity"] * sim
                    signals.append(f"string_similarity:{sim:.2f}")
                elif sim >= 0.70:
                    # Even at 0.70 we record the signal, but the boost
                    # only counts when the gate is met.  Useful for
                    # explainability in the API response.
                    signals.append(f"string_similarity:{sim:.2f}(weak)")

            # ── Signal 4: temporal co-activity ──────────────────────
            other_last_seen = other.get("last_seen_at")
            if _within_week(my_last_seen, other_last_seen):
                confidence += _SIGNAL_BOOSTS["temporal_co_activity"]
                signals.append("temporal_co_activity:within_7d")

            # ── Signal 5: co-investigation (proxy for "same forum") ─
            shared_invs = my_investigations & other_investigations
            if shared_invs:
                confidence += _SIGNAL_BOOSTS["co_investigation"]
                signals.append(
                    f"co_investigation:{len(shared_invs)}"
                )

            if confidence < min_confidence:
                continue

            candidates[other_id] = {
                "candidate_actor_id": other_id,
                "candidate_handle": other_handle,
                "confidence": round(confidence, 4),
                "signals": signals,
                "shared_infrastructure": shared_infra,
                "shared_pgp": shared_pgp,
                "shared_investigations": sorted(shared_invs)[:5],
            }

        result = sorted(
            candidates.values(),
            key=lambda c: -c["confidence"],
        )
        return result


# ---------------------------------------------------------------------------
# Entity-shape adapters (the manager accepts dataclasses OR plain dicts)
# ---------------------------------------------------------------------------


def _entity_type(ent: Any) -> Optional[str]:
    if ent is None:
        return None
    et = getattr(ent, "entity_type", None)
    if et is None and isinstance(ent, dict):
        et = ent.get("entity_type")
    if et is None:
        return None
    return str(et).upper()


def _value(ent: Any) -> Optional[str]:
    if ent is None:
        return None
    v = getattr(ent, "value", None)
    if v is None and isinstance(ent, dict):
        v = ent.get("value")
    return v


def _canonical_value(ent: Any) -> Optional[str]:
    if ent is None:
        return None
    cv = getattr(ent, "canonical_value", None)
    if cv is None and isinstance(ent, dict):
        cv = ent.get("canonical_value")
    return cv


def _confidence(ent: Any) -> Optional[float]:
    if ent is None:
        return None
    c = getattr(ent, "confidence", None)
    if c is None and isinstance(ent, dict):
        c = ent.get("confidence")
    if c is None:
        return None
    try:
        return float(c)
    except (TypeError, ValueError):
        return None


def _source_url(ent: Any) -> Optional[str]:
    if ent is None:
        return None
    s = getattr(ent, "source_url", None)
    if s is None and isinstance(ent, dict):
        s = ent.get("source_url") or ent.get("page_url")
    return s


def _get_related_entities(
    actor: Any,
    others: Iterable[Any],
) -> list[Any]:
    """Return ``others`` co-occurring on the same ``source_url`` as actor.

    Falls back to "same page_id" when ``source_url`` is missing, and as
    a last resort returns an empty list (we never link without some
    co-occurrence signal — random joins would pollute the actor graph).
    """
    actor_url = _source_url(actor)
    actor_page_id = getattr(actor, "page_id", None)
    if isinstance(actor, dict):
        actor_page_id = actor.get("page_id")

    related: list[Any] = []
    for o in others:
        if _source_url(o) and actor_url and _source_url(o) == actor_url:
            related.append(o)
            continue
        oid = getattr(o, "page_id", None)
        if isinstance(o, dict):
            oid = o.get("page_id")
        if actor_page_id and oid and str(actor_page_id) == str(oid):
            related.append(o)
    return related


# ---------------------------------------------------------------------------
# Background alias resolution (Phase 7)
# ---------------------------------------------------------------------------
#
# Called as a fire-and-forget task from the investigation pipeline tail
# (and from the CLI).  Never raises — the whole function is wrapped in
# ``try/except`` and returns ``0`` on any failure so the caller doesn't
# have to handle exceptions in its own try/except.


async def run_alias_resolution(
    investigation_id: str,
    min_confidence: float = 0.75,
) -> int:
    """Run alias resolution for actors found in *investigation_id*.

    For each actor linked to the investigation, scans the rest of the
    profile store for likely aliases.  When a candidate has:

    * a confidence ``>= min_confidence``, and
    * at least **two** independent signals (per the phase brief's
      minimum-2-signals rule), and
    * has not already been recorded against this actor,

    the candidate's canonical handle is persisted to ``actor_aliases``
    with ``alias_type`` set by :func:`_alias_type_for_confidence`
    (likely / confirmed).

    Returns the number of **new** alias rows persisted.  Idempotent —
    running it twice in a row on the same investigation returns 0 the
    second time.
    """
    try:
        manager = ActorProfileManager()
        try:
            actors = await manager.get_actors_by_investigation(investigation_id)
        except Exception as exc:
            logger.warning(
                "run_alias_resolution: get_actors_by_investigation(%s) failed: %s",
                investigation_id, exc,
            )
            return 0

        if not actors:
            logger.debug(
                "run_alias_resolution: no actors for investigation %s",
                investigation_id,
            )
            return 0

        new_aliases = 0
        for actor in actors:
            actor_id = actor.get("id")
            if not actor_id:
                continue
            try:
                candidates = await manager.find_alias_candidates(
                    actor_id,
                    min_confidence=min_confidence,
                )
            except Exception as exc:
                logger.warning(
                    "run_alias_resolution: find_alias_candidates(%s) failed: %s",
                    actor_id, exc,
                )
                continue

            for candidate in candidates:
                # Minimum-2-signals rule prevents single-IOC false
                # positives from polluting the long-term store.
                signal_count = sum(
                    1 for s in candidate.get("signals", [])
                    if not s.endswith("(weak)")
                )
                if signal_count < 2:
                    continue

                confidence = float(candidate.get("confidence") or 0.0)
                if confidence < min_confidence:
                    continue

                alias_type = _alias_type_for_confidence(confidence)
                alias_value = candidate.get("candidate_handle") or ""
                if not alias_value:
                    continue

                try:
                    await manager.add_alias(
                        actor_id=actor_id,
                        alias_value=alias_value,
                        alias_type=alias_type,
                        investigation_id=investigation_id,
                        confidence=confidence,
                    )
                    new_aliases += 1
                except Exception as exc:
                    logger.warning(
                        "run_alias_resolution: add_alias(%s, %s) failed: %s",
                        actor_id, alias_value, exc,
                    )
                    continue

        logger.info(
            "run_alias_resolution: investigation=%s candidates_persisted=%d",
            investigation_id, new_aliases,
        )
        return new_aliases
    except Exception as exc:
        logger.warning(
            "run_alias_resolution: top-level failure (non-fatal): %s", exc,
        )
        return 0


# ---------------------------------------------------------------------------
# Internal read helpers (manager-self-contained — no voidaccess_cli deps)
# ---------------------------------------------------------------------------


def _resolve_actor(session: Any, handle_or_id: str):
    """Resolve a profile row by handle (case-insensitive) or UUID.

    Mirrors ``voidaccess_cli.adapters.sqlite._resolve_actor`` but lives
    here so the manager does not import from the CLI adapter (the API
    / Docker side does not always have voidaccess_cli importable).
    """
    from db.models import ActorProfile

    if not handle_or_id:
        return None
    handle_or_id = str(handle_or_id).strip()
    if not handle_or_id:
        return None
    try:
        uid = uuid.UUID(handle_or_id)
        return session.query(ActorProfile).filter_by(id=uid).one_or_none()
    except (ValueError, AttributeError):
        pass
    canonical = normalize_handle(handle_or_id)
    if not canonical:
        return None
    return (
        session.query(ActorProfile)
        .filter(ActorProfile.canonical_handle == canonical)
        .one_or_none()
    )


def _serialize_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _profile_summary(profile, *, alias_count: Optional[int] = None) -> dict[str, Any]:
    """Short shape used by ``list_profiles`` and ``search_profiles``."""
    return {
        "id": str(profile.id),
        "canonical_handle": profile.canonical_handle,
        "first_seen_at": _serialize_dt(profile.first_seen_at),
        "last_seen_at": _serialize_dt(profile.last_seen_at),
        "investigation_count": int(profile.investigation_count or 0),
        "confidence": float(profile.confidence) if profile.confidence is not None else None,
        "alias_count": int(alias_count) if alias_count is not None else None,
    }


def _serialize_profile(profile, aliases, infra) -> dict[str, Any]:
    """Full shape used by ``get_profile`` (handle + aliases + infra + inv ids)."""
    inv_ids: set[str] = set()
    for a in aliases:
        if a.source_investigation_id:
            inv_ids.add(str(a.source_investigation_id))
    for i in infra:
        if i.source_investigation_id:
            inv_ids.add(str(i.source_investigation_id))

    return {
        **_profile_summary(profile, alias_count=len(aliases)),
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
        "investigation_ids": sorted(inv_ids),
    }
