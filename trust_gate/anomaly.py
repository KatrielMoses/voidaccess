"""
trust_gate/anomaly.py — step-7 anomaly / flood detection (pure).

Four attack classes, four deterministic detectors — no network, no clock, no
randomness (times come from the artifacts, windows from ``CorpusState``):

* **single-source flood** — more than ``source_rate_limit`` submissions from one
  source inside ``rate_window`` (per-artifact, against the rolling window).
* **mass-identical** — the same record fingerprint repeated more than
  ``mass_identical_max`` times from one source (per-artifact, against history).
* **entity-stuffing** — a single submission carrying more than
  ``stuffing_max_entities`` entities (batch-level).
* **templated injection** — a single submission of near-identical records: its
  distinct-fingerprint ratio falls below ``templated_min_distinct_ratio``
  (batch-level, only once the submission is large enough to be meaningful).

The two per-artifact detectors read the rolling windows on ``CorpusState``; the
two batch-level detectors read the whole submission and are computed once by
``trust_gate.gate.trust_gate_submission`` and handed to every member artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from trust_gate.model import Artifact, CorpusState
from trust_gate.thresholds import TrustGateConfig


@dataclass(frozen=True)
class SubmissionAnomaly:
    """Batch-level anomaly verdict for one submission (from one source)."""

    entity_stuffing: bool = False
    templated: bool = False

    @property
    def flagged(self) -> bool:
        return self.entity_stuffing or self.templated

    @property
    def reason(self) -> str:
        parts = []
        if self.entity_stuffing:
            parts.append("entity_stuffing")
        if self.templated:
            parts.append("templated_injection")
        return "+".join(parts) or "none"


def detect_submission_anomaly(
    artifacts: Sequence[Artifact], config: TrustGateConfig
) -> SubmissionAnomaly:
    """Batch-level detection over one submission's artifacts.

    Pure: depends only on the artifacts and the config. Entity-stuffing is a raw
    count; templated injection is a distinct-fingerprint ratio (guarded by a
    minimum submission size so a small legit batch of similar IOCs is not flagged).
    """
    n = len(artifacts)
    if n == 0:
        return SubmissionAnomaly()

    entity_stuffing = n > config.stuffing_max_entities

    templated = False
    if n >= config.templated_min_submission:
        distinct = len({a.record_fingerprint() for a in artifacts})
        ratio = distinct / n
        templated = ratio < config.templated_min_distinct_ratio

    return SubmissionAnomaly(entity_stuffing=entity_stuffing, templated=templated)


def flood_detected(
    state: CorpusState, source: str, observed_at: datetime, config: TrustGateConfig
) -> bool:
    """True if adding this submission would exceed the source's rate limit.

    Counts prior submissions in the window ending at ``observed_at``; the current
    artifact is the ``+1`` that would breach ``source_rate_limit``.
    """
    prior = state.submissions_within(source, config.rate_window, observed_at)
    return (prior + 1) > config.source_rate_limit


def mass_identical_detected(
    state: CorpusState, source: str, fingerprint: str, config: TrustGateConfig
) -> bool:
    """True if this fingerprint has already repeated at the mass-identical limit."""
    prior = state.identical_count(source, fingerprint)
    return (prior + 1) > config.mass_identical_max
