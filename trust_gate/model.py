"""
trust_gate/model.py — the pure data model the trust gate operates over.

The trust gate (``trust_gate.gate.trust_gate``) is a **pure, deterministic**
function of exactly two things:

    trust_gate(artifact, corpus_state) -> GateDecision

``Artifact``      — one candidate contribution to the shared corpus.
``CorpusState``   — a read-only, in-memory snapshot of the counters the gate
                    needs: which sources have already corroborated each entity,
                    per-source reputation, per-source submission/ fingerprint
                    windows, trusted-feed validations, and established
                    dispositions. It is projected from the shared-tier tables
                    (``shared_corpus`` — ``GlobalEntity.corroboration_count`` and
                    the ``SourceReputation`` store) by the P4.1 write path; how it
                    is materialized is wiring the gate never sees.
``GateDecision``  — the tier decision (``ConfidenceTier``), a coarse ``Verdict``,
                    the reason + originating step, and the ``CounterDeltas`` the
                    gate *emits* (quarantine/promotion + source-reputation
                    counters that P4.4 observability reads).

Nothing here touches the network, an LLM, the clock, or randomness. The gate
never mutates ``CorpusState``; callers (and the red-team harness) advance state
explicitly via :meth:`CorpusState.apply`, which is what lets a test simulate
*sustained* multi-source corroboration and prove single-source claims stay
quarantined.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Optional

# The single tier enum — the gate is the ONLY thing that assigns/raises tiers.
from shared_corpus.models import ConfidenceTier

__all__ = [
    "ConfidenceTier",
    "Verdict",
    "Artifact",
    "SourceReputationView",
    "CorpusState",
    "CounterDeltas",
    "GateDecision",
    "corpus_key",
]

# Unit separator — keeps the type-qualified corpus key unambiguous even if a
# canonical value contained a colon.
_KEY_SEP = "\x1f"


def corpus_key(entity_type: str, canonical_value: str) -> str:
    """The ``CorpusState`` dict key for an entity.

    Type-qualified so two *different* entity types that happen to canonicalize to
    the same string never share a corroboration set (they are distinct
    ``GlobalEntity`` rows — ``UniqueConstraint(entity_type, canonical_value)``).
    ``canonical_value`` must be the pure ``extractor.identity.entity_canonical_id``
    output; this function is the single place the two are combined, so the P4.1
    loader and the gate always agree on the key.
    """
    return f"{(entity_type or '').strip().upper()}{_KEY_SEP}{canonical_value}"


class Verdict(str, enum.Enum):
    """Coarse disposition of an artifact after the gate runs.

    Orthogonal to (but consistent with) the fine-grained ``ConfidenceTier``:

    * ``REJECTED``     — dropped by sanitize/validate or an anomaly/flood guard;
                         never stored, never counted. Tier stays ``unconfirmed``.
    * ``QUARANTINED``  — stored but ``unconfirmed``; does not influence scoring or
                         triage until corroborated. The default for any new,
                         single-source, non-feed artifact.
    * ``ACCEPTED``     — promoted past quarantine to ``corroborated`` (>= N
                         independent sources) or ``feed_validated`` (trusted-feed
                         cross-hit). Only ``ACCEPTED`` artifacts influence scoring.
    """

    REJECTED = "rejected"
    QUARANTINED = "quarantined"
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class Artifact:
    """One candidate contribution to the shared corpus.

    Immutable so it can be a stable, hashable-ish input to a pure function and
    safely reused across the determinism tests.

    **Two-layer identity (the P4.3 Sybil split).** A contribution has two distinct
    identities, and conflating them is exactly the Sybil hole:

    * ``origin`` — *where the artifact was observed* (the onion/host). This is the
      **corroboration-independence unit**: promotion counts distinct origins. The
      same IOC reported from one origin — even via a thousand different ingest
      keys — is still **one** origin (set dedup), so keys cannot manufacture
      independent corroboration.
    * ``contributor`` — *who submitted it* (an ingest key, or ``"local"`` for this
      install's own runs). This is the **reputation / rate-limit / revocation
      unit**. A contributor's claimed origins count toward corroboration only once
      the contributor has *earned* reputation; a fresh self-registered key — or a
      thousand of them — promotes nothing (the P4.0 reputation veto).

    ``source`` is a back-compat convenience: when only ``source`` is given (the
    P4.0/P4.1 local path, where the observer *is* the corroboration unit), both
    ``origin`` and ``contributor`` resolve to it, so the gate behaves exactly as
    before. P4.3 ingest passes the two explicitly (origin = claimed onion,
    contributor = ingest key) — the split that makes cross-install contribution
    Sybil-safe.

    Other fields:
        entity_type / value — the raw artifact (canonicalized via
            ``extractor.identity`` inside the gate; never pre-canonicalized here).
        observed_at — capture time (tz-aware UTC); the gate reads it, never the
            clock, so identical artifacts yield identical decisions.
        feed_hits — trusted-feed ids this value matched, **computed by the
            platform's own feed matcher** (``feeds/``), never copied from submitter
            metadata. An attacker cannot fabricate a feed cross-hit → forged
            feed_hits can never reach ``feed_validated``.
        disposition — the contributor's claim (e.g. ``"malicious"``/``"benign"``),
            checked for contradiction against the established disposition.
        submission_id / fingerprint — batch + mass-identical/templated detection.
    """

    entity_type: str
    value: str
    observed_at: datetime
    source: Optional[str] = None
    origin: Optional[str] = None
    contributor: Optional[str] = None
    context_text: Optional[str] = None
    provenance: Optional[dict[str, Any]] = None
    feed_hits: frozenset[str] = frozenset()
    disposition: Optional[str] = None
    submission_id: Optional[str] = None
    fingerprint: Optional[str] = None

    def __post_init__(self) -> None:
        # Resolve the two-layer identity from whichever fields were supplied.
        origin = self.origin or self.source or "unknown"
        contributor = self.contributor or self.source or origin
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "contributor", contributor)
        # Keep ``source`` populated (== origin) for any legacy reader.
        if self.source is None:
            object.__setattr__(self, "source", origin)

    def record_fingerprint(self) -> str:
        """Stable fingerprint for identical/templated detection.

        Explicit ``fingerprint`` wins; otherwise derived from the normalized
        ``(entity_type, value)`` so byte-identical resubmissions collide.
        """
        if self.fingerprint is not None:
            return self.fingerprint
        return f"{(self.entity_type or '').strip().upper()}::{(self.value or '').strip()}"


@dataclass(frozen=True)
class SourceReputationView:
    """Read model of a source's reputation — mirrors the ``SourceReputation`` row.

    Immutable; the gate produces a *new* view (never mutates the input) and emits
    it in ``CounterDeltas.source_reputation``.
    """

    source: str
    score: float = 1.0
    contributed: int = 0
    corroborated: int = 0
    contradicted: int = 0
    anomalies: int = 0
    blocked: bool = False


@dataclass(frozen=True)
class CounterDeltas:
    """The counters the gate emits for one artifact (what P4.4 observability reads).

    ``source_reputation`` is the updated view to persist for the contributing
    source; ``corroboration_count`` is the new independent-source count for the
    entity (maps to ``GlobalEntity.corroboration_count``). The boolean/int tallies
    are per-decision increments an observability layer can sum.
    """

    quarantined: int = 0
    promoted_corroborated: int = 0
    promoted_feed_validated: int = 0
    rejected: int = 0
    added_source: bool = False
    corroboration_count: Optional[int] = None
    source_reputation: Optional[SourceReputationView] = None


@dataclass(frozen=True)
class GateDecision:
    """The outcome of running the eight-step gate over one artifact."""

    artifact: Artifact
    canonical_key: str
    entity_type: str
    canonical_value: str
    verdict: Verdict
    tier: ConfidenceTier
    reason: str
    step: str
    independent_sources: int
    trusted_feed_hits: frozenset[str]
    counter_deltas: CounterDeltas

    @property
    def stored(self) -> bool:
        """True if the artifact is stored at all (quarantined or accepted)."""
        return self.verdict is not Verdict.REJECTED

    @property
    def influences_scoring(self) -> bool:
        """True only when the artifact is promoted past quarantine.

        The load-bearing poison-resistance property: an ``unconfirmed`` artifact
        never influences scoring/triage.
        """
        return self.verdict is Verdict.ACCEPTED and self.tier is not ConfidenceTier.UNCONFIRMED


@dataclass
class CorpusState:
    """In-memory snapshot of everything the pure gate reads.

    Mutable only through :meth:`apply` (used by callers / the red-team harness to
    advance state between artifacts). The gate treats it as strictly read-only.
    """

    #: canonical_key -> set of distinct ORIGINS that have attested it. This set is
    #: the independent-origin basis for corroboration (an origin appears at most
    #: once, so resubmission — even via many keys — can never inflate the count).
    corroborations: dict[str, set[str]] = field(default_factory=dict)
    #: canonical_key -> set of distinct CONTRIBUTORS that have attested it.
    #: Corroboration additionally requires >= min_independent_contributors of these,
    #: so a single contributor claiming many fabricated origins cannot self-promote
    #: (the reputation-gaming Sybil defense).
    corroborating_contributors: dict[str, set[str]] = field(default_factory=dict)
    #: canonical_key -> the established disposition (set once an entity reaches a
    #: promoted tier), used to detect contradicting later claims.
    established_disposition: dict[str, str] = field(default_factory=dict)
    #: canonical_key -> set of trusted feeds that have validated it.
    feed_validations: dict[str, set[str]] = field(default_factory=dict)
    #: source id -> reputation view.
    reputation: dict[str, SourceReputationView] = field(default_factory=dict)
    #: source id -> recent submission timestamps (rolling; for rate/flood).
    recent_submissions: dict[str, list[datetime]] = field(default_factory=dict)
    #: source id -> recent record fingerprints (for mass-identical detection).
    recent_fingerprints: dict[str, list[str]] = field(default_factory=dict)

    def reputation_of(self, source: str, default_score: float) -> SourceReputationView:
        """Return the reputation view for *source*, or a neutral starting view."""
        existing = self.reputation.get(source)
        if existing is not None:
            return existing
        return SourceReputationView(source=source, score=default_score)

    def submissions_within(self, source: str, window: timedelta, now: datetime) -> int:
        """Count *source*'s submissions in the window ending at *now* (inclusive)."""
        cutoff = now - window
        return sum(1 for ts in self.recent_submissions.get(source, []) if ts >= cutoff)

    def identical_count(self, source: str, fingerprint: str) -> int:
        """How many prior *source* records share *fingerprint*."""
        return sum(1 for fp in self.recent_fingerprints.get(source, []) if fp == fingerprint)

    def apply(self, decision: "GateDecision") -> "CorpusState":
        """Fold *decision* into this state, in place, and return self.

        Records the submission attempt (always — rate-limiting counts attempts,
        not just accepted writes), persists the emitted reputation, and — only
        when the artifact is stored and its source counted — advances the
        corroboration set, feed validations and established disposition. This is
        the deterministic bridge the harness uses to simulate sustained
        corroboration; the real write path (P4.1) does the equivalent against the
        shared-tier tables.
        """
        art = decision.artifact
        contributor = art.contributor
        origin = art.origin
        key = decision.canonical_key

        # Rate/anomaly windows + reputation are keyed on the CONTRIBUTOR. Record
        # the attempt + reputation always (flood/anomaly counting must see
        # rejected attempts too).
        self.recent_submissions.setdefault(contributor, []).append(art.observed_at)
        self.recent_fingerprints.setdefault(contributor, []).append(art.record_fingerprint())
        if decision.counter_deltas.source_reputation is not None:
            self.reputation[contributor] = decision.counter_deltas.source_reputation

        if not decision.stored:
            return self

        # Corroboration is keyed on the ORIGIN — the independence unit — and the
        # CONTRIBUTOR is tracked in parallel so a lone contributor can't self-promote.
        if decision.counter_deltas.added_source:
            self.corroborations.setdefault(key, set()).add(origin)
            self.corroborating_contributors.setdefault(key, set()).add(contributor)
        if decision.trusted_feed_hits:
            self.feed_validations.setdefault(key, set()).update(decision.trusted_feed_hits)
        if decision.influences_scoring and art.disposition:
            # Establish the disposition once the entity is promoted, so later
            # contradicting single-source claims are caught.
            self.established_disposition.setdefault(key, art.disposition)
        return self

    def copy(self) -> "CorpusState":
        """A deep-enough copy for determinism tests (independent mutable containers)."""
        return CorpusState(
            corroborations={k: set(v) for k, v in self.corroborations.items()},
            corroborating_contributors={
                k: set(v) for k, v in self.corroborating_contributors.items()
            },
            established_disposition=dict(self.established_disposition),
            feed_validations={k: set(v) for k, v in self.feed_validations.items()},
            reputation=dict(self.reputation),
            recent_submissions={k: list(v) for k, v in self.recent_submissions.items()},
            recent_fingerprints={k: list(v) for k, v in self.recent_fingerprints.items()},
        )


def _bump(view: SourceReputationView, **changes: Any) -> SourceReputationView:
    """Return a copy of *view* with *changes* applied (pure helper for the gate)."""
    return replace(view, **changes)
