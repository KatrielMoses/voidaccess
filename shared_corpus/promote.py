"""
shared_corpus/promote.py — write observed entities into the shared tier through
the P4.0 trust gate (P4.1).

This is the write-path wiring the P4.0 gate was built pure and isolated for. As a
**byproduct of normal use** (spec 2.3) — no separate user action — each entity/IOC
an investigation observed is promoted into the shared ``global_entities`` tier at
the tier the *gate* assigns:

    observation → Artifact → trust_gate(artifact, corpus_state) → GateDecision
                → upsert_global_entity(at gate tier) + record source + reputation

Invariants (all reused, none reforked):

* **The gate is the only tier assigner.** Every shared write runs the full
  eight-step gate; the gate-assigned tier + corroboration count are persisted via
  the existing ``upsert_global_entity`` (which sanitizes — one sanitize path).
* **feed_hits are platform-derived.** They come from *our* ``feeds/`` matching
  (the ``feed:<name>`` tags the P1.4 enrichment already wrote onto the entity),
  filtered to the trusted-feed allowlist — never from user/investigation input.
  This is the pattern P4.3's ingest path inherits.
* **Consent-gated** (P2.2 ``contribution_enabled``): private mode writes nothing.
* **Non-fatal**: a promotion failure never breaks the investigation — each
  artifact is persisted inside its own savepoint and per-artifact/whole-batch
  failures are swallowed (CC-3), exactly like the P3.1 usage hook.
* **Collision-safe**: the P2.0 unique constraints + ``ON CONFLICT`` mean concurrent
  writers converge on one row per canonical entity / one row per (entity, source).

``EntityObservation`` + ``load_corpus_state`` are the small typed contract shared
with P4.3's cross-install ingest: it builds ``EntityObservation``s from its payload
and calls ``promote_entities`` the same way.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from extractor.identity import entity_canonical_id
from shared_corpus.access import (
    _CANONICAL_MAX_LEN,
    fetch_entity_sources,
    fetch_global_entities,
    fetch_source_reputations,
    record_global_entity_source,
    set_entity_disposition,
    upsert_global_entity,
    upsert_source_reputation,
)
from shared_corpus.consent import contribution_enabled
from shared_corpus.models import ConfidenceTier
from trust_gate import (
    Artifact,
    CorpusState,
    GateDecision,
    SourceReputationView,
    TrustGateConfig,
    Verdict,
    default_config,
    trust_gate,
)
from trust_gate.model import corpus_key

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EntityObservation:
    """One observed entity — the promotion input contract (shared by P4.1 + P4.3).

    Two-layer identity (the P4.3 Sybil split):

    * ``origin`` — where it was observed (onion/host): the corroboration unit.
    * ``contributor`` — who submitted it (ingest key / ``"local"``): the
      reputation / rate-limit unit.

    ``source`` is the P4.1-local convenience: when only it is given both resolve to
    it (observer == corroboration unit). P4.3 ingest passes the two explicitly.

    ``feed_hits`` must already be platform-derived (from ``feeds/`` matching), never
    submitter input. ``disposition`` is the gate's contradiction signal — ``None``
    for ordinary scraped observations, populated by P4.3 external claims.
    """

    entity_type: str
    value: str
    source: Optional[str] = None
    origin: Optional[str] = None
    contributor: Optional[str] = None
    feed_hits: frozenset[str] = frozenset()
    disposition: Optional[str] = None
    context_text: Optional[str] = None
    observed_at: Optional[datetime] = None

    def resolved_origin(self) -> str:
        return self.origin or self.source or "unknown"

    def resolved_contributor(self) -> str:
        return self.contributor or self.source or self.resolved_origin()


@dataclass
class PromotionReport:
    """What a promotion pass wrote (for logging / the pipeline report)."""

    considered: int = 0
    promoted: int = 0
    corroborated: int = 0
    feed_validated: int = 0
    quarantined: int = 0
    rejected: int = 0
    skipped_private: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical(entity_type: str, value: str) -> str:
    return entity_canonical_id({"entity_type": entity_type, "value": value})[:_CANONICAL_MAX_LEN]


# ---------------------------------------------------------------------------
# CorpusState loading (batch — no N+1) — the typed loader P4.3 reuses
# ---------------------------------------------------------------------------

def load_corpus_state(
    session: Any, observations: Iterable[EntityObservation]
) -> CorpusState:
    """Batch-load the ``CorpusState`` the gate needs for *observations*.

    Three queries total: the ``GlobalEntity`` rows for the observed
    ``(entity_type, canonical)`` set, their ``GlobalEntitySource`` rows (the
    corroboration source-sets + feed validations), and the ``SourceReputation``
    rows for the observed sources. No per-entity query.

    ``established_disposition`` is loaded from each entity's stored disposition
    baseline (set once it was promoted), so a later external claim (P4.3 ingest)
    that conflicts with it is detected as a contradiction and downweights the
    contributor. Ordinary scraped observations carry no disposition, so nothing is
    contradicted for them.
    """
    obs = list(observations)
    pairs = {(o.entity_type, _canonical(o.entity_type, o.value)) for o in obs}
    entities = fetch_global_entities(session, pairs)
    sources_by_id = fetch_entity_sources(session, [e.id for e in entities.values()])
    # Reputation is loaded per CONTRIBUTOR (the Sybil split), not per origin.
    reps = fetch_source_reputations(session, {o.resolved_contributor() for o in obs})

    state = CorpusState()
    for (etype, canonical), ent in entities.items():
        key = corpus_key(etype, canonical)
        src_rows = sources_by_id.get(ent.id, [])
        if src_rows:
            state.corroborations[key] = {s.source for s in src_rows}
            # Distinct contributors (fall back to the origin for pre-P4.4 rows,
            # where contributor == origin held for P4.1-local).
            state.corroborating_contributors[key] = {
                (s.contributor or s.source) for s in src_rows
            }
        feeds: set[str] = set()
        for s in src_rows:
            for h in (s.feed_hits or []):
                feeds.add(str(h))
        if feeds:
            state.feed_validations[key] = feeds
        # Established disposition baseline for contradiction detection (P4.3).
        if getattr(ent, "disposition", None):
            state.established_disposition[key] = ent.disposition

    for src, rr in reps.items():
        state.reputation[src] = SourceReputationView(
            source=src,
            score=rr.score,
            contributed=rr.contributed,
            corroborated=rr.corroborated,
            contradicted=rr.contradicted,
            anomalies=rr.anomalies,
            blocked=rr.blocked,
        )
    return state


# ---------------------------------------------------------------------------
# Persistence of a single gate decision (collision-safe, gate-assigned tier)
# ---------------------------------------------------------------------------

def _persist_reputation(session: Any, decision: GateDecision) -> None:
    rep = decision.counter_deltas.source_reputation
    if rep is None:
        return
    upsert_source_reputation(
        session,
        rep.source,
        score=rep.score,
        blocked=rep.blocked,
        contributed=rep.contributed,
        corroborated=rep.corroborated,
        contradicted=rep.contradicted,
        anomalies=rep.anomalies,
    )


def _persist_decision(session: Any, decision: GateDecision, provenance: dict) -> bool:
    """Persist a stored (non-rejected) decision at its gate-assigned tier.

    A source row is recorded **only when the source counted** toward corroboration
    (``added_source``), so the durable distinct-source count never includes a
    blocked/low-reputation contribution — the reputation veto survives reload.
    """
    art = decision.artifact
    row, _created = upsert_global_entity(
        session,
        decision.entity_type,
        art.value,
        provenance=provenance,
        confidence_tier=decision.tier.value,
        corroboration_count=decision.independent_sources,
    )
    if row is None:
        return False  # sanitizer dropped at the write boundary
    if decision.counter_deltas.added_source:
        # The corroboration source-set stores the ORIGIN + its CONTRIBUTOR (the two
        # independence axes).
        record_global_entity_source(
            session,
            row.id,
            art.origin,
            contributor=art.contributor,
            feed_hits=decision.trusted_feed_hits,
            provenance=provenance,
        )
    # Establish the disposition baseline once the entity is promoted (P4.1 seam).
    if decision.influences_scoring and art.disposition:
        set_entity_disposition(
            session, decision.entity_type, decision.canonical_value, art.disposition
        )
    _persist_reputation(session, decision)
    return True


# ---------------------------------------------------------------------------
# The promotion pass
# ---------------------------------------------------------------------------

def promote_entities(
    session: Any,
    observations: Iterable[EntityObservation],
    *,
    config: Optional[TrustGateConfig] = None,
    now: Optional[datetime] = None,
) -> PromotionReport:
    """Promote *observations* into the shared corpus through the trust gate.

    Consent-gated, non-fatal, collision-safe. The gate runs with in-memory state
    advanced between artifacts (``CorpusState.apply``) so multiple independent
    sources *within one investigation* corroborate; the loaded state carries the
    corpus history so corroboration also accrues across investigations. The caller
    owns the transaction (commit after).
    """
    report = PromotionReport()
    if not contribution_enabled():
        report.skipped_private = True
        return report

    obs = list(observations)
    report.considered = len(obs)
    if not obs:
        return report

    cfg = config or default_config()
    now = now or _now()

    try:
        state = load_corpus_state(session, obs)
    except Exception as exc:  # loading must never break the pipeline
        logger.info("promotion: CorpusState load failed (non-fatal): %s", exc)
        return report

    from sanitizer import provenance_stamp
    from trust_gate import detect_submission_anomaly

    # Build the artifacts up front and detect batch-level anomalies (entity-
    # stuffing / templated injection) PER CONTRIBUTOR — so one contributor's
    # near-identical flood is caught even though the gate scores artifacts one at a
    # time. (Per-artifact flood/mass-identical are caught in-gate via the state.)
    arts = [
        Artifact(
            entity_type=o.entity_type,
            value=o.value,
            origin=o.resolved_origin(),
            contributor=o.resolved_contributor(),
            observed_at=o.observed_at or now,
            context_text=o.context_text,
            feed_hits=frozenset(o.feed_hits),
            disposition=o.disposition,
        )
        for o in obs
    ]
    by_contributor: dict[str, list] = {}
    for art in arts:
        by_contributor.setdefault(art.contributor, []).append(art)
    anomaly_by_contributor = {
        contrib: detect_submission_anomaly(group, cfg)
        for contrib, group in by_contributor.items()
    }

    for art in arts:
        try:
            decision = trust_gate(
                art, state, cfg,
                submission_anomaly=anomaly_by_contributor.get(art.contributor),
            )
            state.apply(decision)  # in-memory; enables within-batch corroboration

            if not decision.stored:
                report.rejected += 1
                # A flood/anomaly reject still downweights the source durably.
                try:
                    with session.begin_nested():
                        _persist_reputation(session, decision)
                except Exception as exc:
                    logger.debug("promotion: reputation persist failed (non-fatal): %s", exc)
                continue

            stamp = provenance_stamp(source=art.source, captured_at=art.observed_at)
            with session.begin_nested():
                stored = _persist_decision(session, decision, stamp)
            if not stored:
                continue

            report.promoted += 1
            if decision.tier is ConfidenceTier.FEED_VALIDATED:
                report.feed_validated += 1
            elif decision.tier is ConfidenceTier.CORROBORATED:
                report.corroborated += 1
            else:
                report.quarantined += 1
        except Exception as exc:  # per-artifact, strictly non-fatal (CC-3)
            logger.debug("promotion failed for %r (non-fatal): %s", art.value, exc)

    return report


# ---------------------------------------------------------------------------
# Investigation seam — build observations from an investigation's DB entities
# ---------------------------------------------------------------------------

def _source_of(url: Optional[str]) -> str:
    """The contributing source id for a page url — the onion host when present."""
    if not url:
        return "unknown"
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return "unknown"
    return host or "unknown"


def _platform_feed_hits(
    corroborating_sources: Optional[str], trusted_feeds: frozenset[str]
) -> frozenset[str]:
    """Derive trusted-feed cross-hits from the entity's ``feed:<name>`` tags.

    The tags were written by ``feeds/`` matching (platform-side, P1.4), so this is
    a platform derivation, never user input. Only allowlisted feeds survive.
    """
    if not corroborating_sources:
        return frozenset()
    try:
        tags = json.loads(corroborating_sources)
        if not isinstance(tags, list):
            tags = [tags]
    except Exception:
        tags = [t for t in str(corroborating_sources).replace("|", ",").split(",")]
    hits = set()
    for tag in tags:
        t = str(tag).strip().lower()
        if t.startswith("feed:"):
            name = t[5:].strip()
            if name in trusted_feeds:
                hits.add(name)
    return frozenset(hits)


def observations_from_investigation(
    session: Any,
    investigation_id: Any,
    *,
    config: Optional[TrustGateConfig] = None,
) -> list[EntityObservation]:
    """Build ``EntityObservation``s from an investigation's persisted entities.

    Groups the per-page ``Entity`` rows by ``(entity_type, value, source-onion)`` so
    an entity seen on several onions yields several independent-source observations;
    ``feed_hits`` are derived platform-side from each entity's ``feed:`` tags.
    """
    import sqlalchemy as sa

    from db.models import Entity, Page

    cfg = config or default_config()
    if isinstance(investigation_id, str):
        try:
            investigation_id = uuid.UUID(investigation_id)
        except (ValueError, AttributeError):
            pass

    rows = session.execute(
        sa.select(
            Entity.entity_type, Entity.value, Entity.corroborating_sources, Page.url
        )
        .join(Page, Entity.page_id == Page.id)
        .where(Entity.investigation_id == investigation_id)
    ).all()

    # Dedupe by (type, value, source); union feed hits across the group.
    grouped: dict[tuple[str, str, str], set[str]] = {}
    for entity_type, value, corroborating, url in rows:
        if not entity_type or not value:
            continue
        source = _source_of(url)
        key = (entity_type, value, source)
        hits = _platform_feed_hits(corroborating, cfg.trusted_feeds)
        grouped.setdefault(key, set()).update(hits)

    return [
        EntityObservation(
            entity_type=etype,
            value=value,
            source=source,
            feed_hits=frozenset(hits),
        )
        for (etype, value, source), hits in grouped.items()
    ]


def promote_investigation(
    session: Any,
    investigation_id: Any,
    *,
    config: Optional[TrustGateConfig] = None,
    now: Optional[datetime] = None,
) -> PromotionReport:
    """Convenience: build observations from an investigation and promote them.

    The single call the API/CLI pipelines make at the post-extraction seam.
    Consent-gated + non-fatal end to end.
    """
    if not contribution_enabled():
        return PromotionReport(skipped_private=True)
    cfg = config or default_config()
    try:
        observations = observations_from_investigation(session, investigation_id, config=cfg)
    except Exception as exc:
        logger.info("promotion: building observations failed (non-fatal): %s", exc)
        return PromotionReport()
    return promote_entities(session, observations, config=cfg, now=now)
