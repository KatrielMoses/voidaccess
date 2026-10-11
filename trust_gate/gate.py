"""
trust_gate/gate.py — the one ordered eight-step trust gate (P4.0).

This is the single choke point every shared-corpus write will route through
(wiring is P4.1). It is a **pure, deterministic** function: identical
``(artifact, corpus_state, config)`` always yields an identical ``GateDecision``.
It performs no I/O — no network, no LLM, no clock, no randomness. Time comes from
``artifact.observed_at``; every threshold comes from the ``TrustGateConfig``
snapshot.

The eight steps, run strictly in order (``GATE_STEPS``):

    1. sanitize    — P2.2 ``sanitizer.sanitize_entity`` (drop PII/secret/noise).
    2. validate    — P2.2 ``sanitizer.is_valid_shape`` (drop malformed).
    3. provenance  — P2.2 ``sanitizer.provenance_stamp`` (attribute the artifact).
    4. quarantine  — every new artifact enters UNCONFIRMED; influences nothing yet.
    5. corroborate — promote only on >= N independent sources OR a trusted-feed
                     cross-hit (feed cross-hit → FEED_VALIDATED; else CORROBORATED).
    6. reputation  — a source's contribution counts only if its reputation clears
                     the bar; contradicted data downweights/blocks the source and
                     holds the artifact in quarantine.
    7. anomaly     — flood / entity-stuffing / templated / mass-identical → reject
                     + downweight the source.
    8. dedup       — canonicalize/dedup via ``extractor.identity`` (the single
                     identity path) and finalize the decision.

Steps 1, 2 and 7 can terminate the pipeline early (REJECTED). Steps 4–6 and 8
refine the tier. The gate is the *only* thing that assigns or raises a
``ConfidenceTier``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from extractor.identity import entity_canonical_id, entity_display_id
from sanitizer import is_valid_shape, provenance_stamp, sanitize_entity
from trust_gate.anomaly import (
    SubmissionAnomaly,
    detect_submission_anomaly,
    flood_detected,
    mass_identical_detected,
)
from trust_gate.model import (
    Artifact,
    ConfidenceTier,
    CorpusState,
    CounterDeltas,
    GateDecision,
    SourceReputationView,
    Verdict,
    _bump,
    corpus_key,
)
from trust_gate.thresholds import TrustGateConfig, default_config

__all__ = ["trust_gate", "trust_gate_submission", "GATE_STEPS"]


# ---------------------------------------------------------------------------
# Working state threaded through the ordered steps
# ---------------------------------------------------------------------------

@dataclass
class _Work:
    artifact: Artifact
    state: CorpusState
    config: TrustGateConfig
    submission_anomaly: Optional[SubmissionAnomaly]

    # Identity — computed once via the single identity path (extractor.identity).
    canonical_key: str = ""
    canonical_value: str = ""
    entity_type: str = ""
    safe_value: str = ""

    # Decision-in-progress.
    tier: ConfidenceTier = ConfidenceTier.UNCONFIRMED
    verdict: Verdict = Verdict.QUARANTINED
    reason: str = "new"
    step_name: str = ""
    halted: bool = False

    # Corroboration bookkeeping.
    existing_sources: frozenset[str] = frozenset()
    existing_contributors: frozenset[str] = frozenset()
    trusted_hits: frozenset[str] = frozenset()
    independent_sources: int = 0
    added_source: bool = False
    source_counts: bool = True

    # Emitted reputation (None until step 6 touches it; steps 1/2 never do).
    rep_view: Optional[SourceReputationView] = None


def _terminate(work: _Work, verdict: Verdict, tier: ConfidenceTier, reason: str) -> None:
    work.verdict = verdict
    work.tier = tier
    work.reason = reason
    work.halted = True


# ---------------------------------------------------------------------------
# The eight steps
# ---------------------------------------------------------------------------

def _step_sanitize(work: _Work) -> None:
    """1. Sanitize — reuse the single P2.2 sanitize choke point."""
    art = work.artifact
    safe = sanitize_entity(art.entity_type, art.value, context_text=art.context_text)
    if safe is None:
        _terminate(work, Verdict.REJECTED, ConfidenceTier.UNCONFIRMED, "sanitize_dropped")
        return
    work.safe_value = safe


def _step_validate(work: _Work) -> None:
    """2. Validate — explicit shape/schema gate (P2.2)."""
    art = work.artifact
    if not is_valid_shape(art.entity_type, work.safe_value, context_text=art.context_text):
        _terminate(work, Verdict.REJECTED, ConfidenceTier.UNCONFIRMED, "invalid_shape")


def _step_provenance(work: _Work) -> None:
    """3. Provenance — ensure an origin stamp (deterministic; no clock)."""
    art = work.artifact
    if art.provenance is None:
        # captured_at is passed explicitly so provenance_stamp never calls the
        # clock — the gate stays deterministic.
        work.artifact = _with_provenance(
            art,
            provenance_stamp(source=art.source, captured_at=art.observed_at),
        )


def _step_quarantine(work: _Work) -> None:
    """4. Quarantine-by-default — every new artifact enters UNCONFIRMED.

    It does not influence scoring/triage until a later step promotes it.
    """
    work.tier = ConfidenceTier.UNCONFIRMED
    work.verdict = Verdict.QUARANTINED
    work.reason = "quarantined"


def _step_corroborate(work: _Work) -> None:
    """5. Corroboration → promotion (provisional; reputation finalizes in step 6).

    Promotion is earned only by >= N independent sources or a trusted-feed
    cross-hit — never auto-trusted. A trusted-feed cross-hit is source-independent
    (an attacker cannot fabricate ``feed_hits``; they are set by the platform's
    own feed matcher), so it reaches FEED_VALIDATED outright.
    """
    art = work.artifact
    cfg = work.config
    key = work.canonical_key

    # Corroboration independence is keyed on the ORIGIN, never the contributor key;
    # a parallel set of CONTRIBUTORS blocks single-contributor self-promotion.
    work.existing_sources = frozenset(work.state.corroborations.get(key, set()))
    work.existing_contributors = frozenset(
        work.state.corroborating_contributors.get(key, set())
    )
    work.trusted_hits = _trusted_hits(art, work.state, cfg, key)

    # Provisional resolution assuming this contributor is eligible; step 6
    # re-resolves after applying the contributor-reputation verdict.
    prospective_origins = work.existing_sources | {art.origin}
    prospective_contributors = work.existing_contributors | {art.contributor}
    tier, verdict = _resolve_tier(
        len(prospective_origins), len(prospective_contributors), work.trusted_hits, cfg
    )
    work.tier, work.verdict = tier, verdict
    work.independent_sources = len(prospective_origins)
    work.added_source = art.origin not in work.existing_sources
    work.reason = _tier_reason(tier)


def _step_reputation(work: _Work) -> None:
    """6. Source reputation — count the contribution only if the source is reliable.

    Reads the source's current reputation, updates it for this contribution,
    detects *contradiction* against the entity's established disposition, and
    re-resolves the tier with the source excluded when it is blocked/too low or
    contradicting. Feed validation (step 5) is source-independent and survives a
    bad source's contradiction.
    """
    art = work.artifact
    cfg = work.config
    key = work.canonical_key

    # Reputation is the CONTRIBUTOR's (the ingest key / "local"), never the origin.
    rep = work.state.reputation_of(art.contributor, cfg.reputation_start)

    established = work.state.established_disposition.get(key)
    contradicted = bool(art.disposition and established and established != art.disposition)

    # Is this entity independently established as trustworthy WITHOUT this
    # contributor's origin? A trusted-feed cross-hit, or >= N origins already
    # contributed by *other* eligible contributors. This is how a contributor
    # *earns* reputation: by agreeing with independently-corroborated data — never
    # by its own say-so, so a fresh key cannot bootstrap itself.
    independently_trusted = bool(work.trusted_hits) or (
        len(work.existing_sources) >= cfg.min_independent_sources
        and len(work.existing_contributors) >= cfg.min_independent_contributors
    )

    contributed = rep.contributed + 1
    score = rep.score
    contradicted_count = rep.contradicted
    corroborated_count = rep.corroborated
    if contradicted:
        contradicted_count += 1
        score = round(score * cfg.contradiction_decay, 6)
    elif independently_trusted:
        corroborated_count += 1
        score = round(min(cfg.reputation_start, score + cfg.reputation_reward), 6)

    blocked = rep.blocked or (
        score < cfg.reputation_block_threshold
        or contradicted_count >= cfg.max_contradictions
    )
    rep = _bump(
        rep,
        contributed=contributed,
        corroborated=corroborated_count,
        contradicted=contradicted_count,
        score=score,
        blocked=blocked,
    )
    work.rep_view = rep

    # Does this contributor's claimed origin count toward corroboration? Only if
    # the contributor has earned enough reputation and is not blocked/contradicting.
    eligible = (not blocked) and score >= cfg.reputation_min_to_corroborate and not contradicted
    work.source_counts = eligible

    effective_origins = work.existing_sources | ({art.origin} if eligible else set())
    effective_contributors = work.existing_contributors | (
        {art.contributor} if eligible else set()
    )
    work.independent_sources = len(effective_origins)
    work.added_source = eligible and (art.origin not in work.existing_sources)

    tier, verdict = _resolve_tier(
        len(effective_origins), len(effective_contributors), work.trusted_hits, cfg
    )

    # A contradiction holds the artifact in quarantine — unless a trusted feed
    # independently validates it (feed validation is authoritative).
    if contradicted and not work.trusted_hits:
        tier, verdict = ConfidenceTier.UNCONFIRMED, Verdict.QUARANTINED
        work.reason = "contradicted"
    elif not eligible and not work.trusted_hits and tier is ConfidenceTier.UNCONFIRMED:
        work.reason = (
            "low_reputation_contributor"
            if blocked or score < cfg.reputation_min_to_corroborate
            else _tier_reason(tier)
        )
    else:
        work.reason = _tier_reason(tier)

    work.tier, work.verdict = tier, verdict


def _step_anomaly(work: _Work) -> None:
    """7. Anomaly / flood — reject and downweight on any attack-pattern hit."""
    art = work.artifact
    cfg = work.config
    reason: Optional[str] = None

    if work.submission_anomaly is not None and work.submission_anomaly.flagged:
        reason = work.submission_anomaly.reason
    elif flood_detected(work.state, art.contributor, art.observed_at, cfg):
        reason = "flood"
    elif mass_identical_detected(work.state, art.contributor, art.record_fingerprint(), cfg):
        reason = "mass_identical"

    if reason is None:
        return

    # Downweight the CONTRIBUTOR for the anomaly (layering on step 6's rep view).
    base = work.rep_view or work.state.reputation_of(art.contributor, cfg.reputation_start)
    anomalies = base.anomalies + 1
    score = round(base.score * cfg.anomaly_decay, 6)
    blocked = base.blocked or score < cfg.reputation_block_threshold or anomalies >= cfg.max_anomalies
    work.rep_view = _bump(base, anomalies=anomalies, score=score, blocked=blocked)

    _terminate(work, Verdict.REJECTED, ConfidenceTier.UNCONFIRMED, reason)


def _step_dedup(work: _Work) -> None:
    """8. Dedup / canonicalize — via the single identity path (extractor.identity).

    ``canonical_value`` was produced once, at gate entry, by
    ``entity_canonical_id`` — the only canonicalization in the whole gate — and
    the type-qualified ``canonical_key`` derived from it via ``corpus_key``. This
    step finalizes the values and flags a pure duplicate (an already-known source
    re-asserting an already-quarantined entity) so it emits no spurious promotion.
    """
    work.entity_type = work.artifact.entity_type

    if (
        not work.added_source
        and work.artifact.origin in work.existing_sources
        and work.tier is ConfidenceTier.UNCONFIRMED
    ):
        work.reason = "duplicate"


GATE_STEPS: tuple[tuple[str, object], ...] = (
    ("1. sanitize", _step_sanitize),
    ("2. validate", _step_validate),
    ("3. provenance", _step_provenance),
    ("4. quarantine", _step_quarantine),
    ("5. corroborate", _step_corroborate),
    ("6. reputation", _step_reputation),
    ("7. anomaly", _step_anomaly),
    ("8. dedup", _step_dedup),
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def _with_provenance(art: Artifact, provenance: dict) -> Artifact:
    from dataclasses import replace

    return replace(art, provenance=provenance)


def _resolve_tier(
    independent_origins: int,
    independent_contributors: int,
    trusted_hits: frozenset[str],
    cfg: TrustGateConfig,
) -> tuple[ConfidenceTier, Verdict]:
    """The one place tier is derived — from (origins, contributors, trusted-feed hit).

    A trusted-feed cross-hit validates outright. Otherwise corroboration requires
    BOTH >= N distinct origins AND >= M distinct contributors, so neither many keys
    on one origin nor one contributor on many origins can manufacture promotion.
    """
    if trusted_hits:
        return ConfidenceTier.FEED_VALIDATED, Verdict.ACCEPTED
    if (
        independent_origins >= cfg.min_independent_sources
        and independent_contributors >= cfg.min_independent_contributors
    ):
        return ConfidenceTier.CORROBORATED, Verdict.ACCEPTED
    return ConfidenceTier.UNCONFIRMED, Verdict.QUARANTINED


def _tier_reason(tier: ConfidenceTier) -> str:
    return {
        ConfidenceTier.FEED_VALIDATED: "feed_validated",
        ConfidenceTier.CORROBORATED: "corroborated",
        ConfidenceTier.UNCONFIRMED: "quarantined",
    }[tier]


def _trusted_hits(
    art: Artifact, state: CorpusState, cfg: TrustGateConfig, key: str
) -> frozenset[str]:
    """Trusted-feed ids validating this artifact (case-insensitive, allowlisted).

    Combines the platform-verified ``feed_hits`` on the artifact, any feed
    validations already recorded for the entity, and — when the contributing
    source *is itself* a trusted feed — the source. Only ids in the configured
    allowlist survive, so unrecognized/attacker-claimed feed names are ignored.
    """
    hits = {h.lower() for h in art.feed_hits}
    hits |= {h.lower() for h in state.feed_validations.get(key, set())}
    # A trusted feed contributing directly (server-assigned contributor id) also
    # counts — an attacker cannot name their own ingest key after a trusted feed.
    if (art.contributor or "").lower() in cfg.trusted_feeds:
        hits.add((art.contributor or "").lower())
    return frozenset(hits & cfg.trusted_feeds)


def _finalize(work: _Work) -> GateDecision:
    d = _deltas(work)
    return GateDecision(
        artifact=work.artifact,
        canonical_key=work.canonical_key,
        entity_type=work.entity_type or work.artifact.entity_type,
        canonical_value=work.canonical_value or work.canonical_key,
        verdict=work.verdict,
        tier=work.tier,
        reason=work.reason,
        step=work.step_name,
        independent_sources=work.independent_sources,
        trusted_feed_hits=work.trusted_hits,
        counter_deltas=d,
    )


def _deltas(work: _Work) -> CounterDeltas:
    v, t = work.verdict, work.tier
    return CounterDeltas(
        quarantined=1 if v is Verdict.QUARANTINED else 0,
        promoted_corroborated=1 if t is ConfidenceTier.CORROBORATED else 0,
        promoted_feed_validated=1 if t is ConfidenceTier.FEED_VALIDATED else 0,
        rejected=1 if v is Verdict.REJECTED else 0,
        added_source=work.added_source,
        corroboration_count=(work.independent_sources if v is not Verdict.REJECTED else None),
        source_reputation=work.rep_view,
    )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def trust_gate(
    artifact: Artifact,
    corpus_state: CorpusState,
    config: Optional[TrustGateConfig] = None,
    *,
    submission_anomaly: Optional[SubmissionAnomaly] = None,
) -> GateDecision:
    """Run the ordered eight-step trust gate over *artifact*. Pure/deterministic.

    Does not mutate *corpus_state*; the returned ``GateDecision`` carries the
    emitted counters, and callers advance state via ``CorpusState.apply``.
    """
    cfg = config or default_config()
    work = _Work(
        artifact=artifact,
        state=corpus_state,
        config=cfg,
        submission_anomaly=submission_anomaly,
    )
    # The single identity derivation for the whole gate (extractor.identity).
    work.canonical_value = entity_canonical_id(artifact)
    work.canonical_key = corpus_key(artifact.entity_type, work.canonical_value)
    work.entity_type = artifact.entity_type

    for name, fn in GATE_STEPS:
        work.step_name = name
        fn(work)
        if work.halted:
            break

    return _finalize(work)


def trust_gate_submission(
    source: str,
    artifacts: Sequence[Artifact],
    corpus_state: CorpusState,
    config: Optional[TrustGateConfig] = None,
    *,
    apply: bool = False,
) -> list[GateDecision]:
    """Gate a whole submission (a batch of artifacts from one *source*).

    Runs batch-level anomaly detection (entity-stuffing / templated injection)
    once over the submission, then gates each artifact with that verdict in hand.
    With ``apply=True`` the shared state is advanced between artifacts (so a
    within-submission flood/mass-identical run trips the per-artifact guards) —
    the mode the red-team harness and the P4.1 write path use.

    Still deterministic: identical inputs → identical list of decisions.
    """
    cfg = config or default_config()
    anomaly = detect_submission_anomaly(artifacts, cfg)
    decisions: list[GateDecision] = []
    for art in artifacts:
        decision = trust_gate(art, corpus_state, cfg, submission_anomaly=anomaly)
        decisions.append(decision)
        if apply:
            corpus_state.apply(decision)
    return decisions
