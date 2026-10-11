"""
trust_gate — the automated, deterministic anti-poisoning gate (P4.0).

The shared corpus is live and automatically contributed to, so poisoning must be
stopped by an automated, deterministic gate rather than human review. This module
is the *scoring* half of the Epic-3 trust gate (3.2 steps 4–8) composed on top of
the P2.2 *blocking* half (``sanitizer`` — steps 1–3), giving one ordered
eight-step choke point:

    sanitize → validate → provenance → quarantine → corroborate → reputation
    → anomaly → dedup

``trust_gate(artifact, corpus_state)`` is a pure, deterministic function — no
network, no LLM, no clock, no randomness. It is the *only* thing that assigns or
raises a ``ConfidenceTier`` (unconfirmed → corroborated → feed_validated): a new
artifact is quarantined (unconfirmed) and influences nothing until >= N
independent sources corroborate it or it cross-hits a trusted feed. It emits the
quarantine/promotion and per-source reputation counters that P4.4 observability
reads and the P4.1 write path persists (to ``shared_corpus.SourceReputation`` and
``GlobalEntity.corroboration_count``).

Out of scope (later phases): wiring into the pipeline write path (P4.1),
read-from-shared (P4.2), the cross-install ingest API (P4.3), observability
dashboards (P4.4). See ``trust_gate/README.md``.
"""

from trust_gate.anomaly import (
    SubmissionAnomaly,
    detect_submission_anomaly,
    flood_detected,
    mass_identical_detected,
)
from trust_gate.gate import GATE_STEPS, trust_gate, trust_gate_submission
from trust_gate.model import (
    Artifact,
    ConfidenceTier,
    CorpusState,
    CounterDeltas,
    GateDecision,
    SourceReputationView,
    Verdict,
)
from trust_gate.thresholds import TrustGateConfig, default_config

__all__ = [
    "trust_gate",
    "trust_gate_submission",
    "GATE_STEPS",
    "Artifact",
    "CorpusState",
    "CounterDeltas",
    "GateDecision",
    "SourceReputationView",
    "Verdict",
    "ConfidenceTier",
    "TrustGateConfig",
    "default_config",
    "SubmissionAnomaly",
    "detect_submission_anomaly",
    "flood_detected",
    "mass_identical_detected",
]
