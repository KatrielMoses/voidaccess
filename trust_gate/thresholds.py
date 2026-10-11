"""
trust_gate/thresholds.py — the single tunable surface for the gate (CC-4).

The gate hardcodes no threshold. Every number it uses comes from a frozen
``TrustGateConfig`` snapshot, whose defaults are read from ``config`` (which
reads the environment). Passing an explicit ``TrustGateConfig`` to the gate makes
every decision reproducible regardless of the ambient environment — the red-team
suite constructs configs directly so it can calibrate thresholds in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import FrozenSet


@dataclass(frozen=True)
class TrustGateConfig:
    """Immutable snapshot of every trust-gate threshold.

    Built once via :meth:`from_config` (reading ``config``), or constructed
    directly in tests. Frozen so a decision can never mutate its own thresholds.
    """

    # --- corroboration / promotion ---
    min_independent_sources: int = 2
    min_independent_contributors: int = 2
    trusted_feeds: FrozenSet[str] = frozenset()

    # --- source reputation ---
    reputation_start: float = 1.0
    reputation_block_threshold: float = 0.3
    reputation_min_to_corroborate: float = 0.5
    reputation_reward: float = 0.25
    contradiction_decay: float = 0.5
    anomaly_decay: float = 0.6
    max_contradictions: int = 3
    max_anomalies: int = 3

    # --- anomaly / flood ---
    source_rate_limit: int = 50
    rate_window_seconds: int = 60
    stuffing_max_entities: int = 100
    mass_identical_max: int = 5
    templated_min_distinct_ratio: float = 0.2
    templated_min_submission: int = 5

    @property
    def rate_window(self) -> timedelta:
        return timedelta(seconds=self.rate_window_seconds)

    @classmethod
    def from_config(cls) -> "TrustGateConfig":
        """Build a snapshot from the ``config`` module (env-backed defaults)."""
        import config

        return cls(
            min_independent_sources=int(
                getattr(config, "TRUST_GATE_MIN_INDEPENDENT_SOURCES", 2)
            ),
            min_independent_contributors=int(
                getattr(config, "TRUST_GATE_MIN_INDEPENDENT_CONTRIBUTORS", 2)
            ),
            trusted_feeds=frozenset(
                str(f).lower() for f in getattr(config, "TRUST_GATE_TRUSTED_FEEDS", set())
            ),
            reputation_start=float(getattr(config, "TRUST_GATE_REPUTATION_START", 1.0)),
            reputation_block_threshold=float(
                getattr(config, "TRUST_GATE_REPUTATION_BLOCK_THRESHOLD", 0.3)
            ),
            reputation_min_to_corroborate=float(
                getattr(config, "TRUST_GATE_REPUTATION_MIN_TO_CORROBORATE", 0.5)
            ),
            reputation_reward=float(getattr(config, "TRUST_GATE_REPUTATION_REWARD", 0.25)),
            contradiction_decay=float(
                getattr(config, "TRUST_GATE_CONTRADICTION_DECAY", 0.5)
            ),
            anomaly_decay=float(getattr(config, "TRUST_GATE_ANOMALY_DECAY", 0.6)),
            max_contradictions=int(getattr(config, "TRUST_GATE_MAX_CONTRADICTIONS", 3)),
            max_anomalies=int(getattr(config, "TRUST_GATE_MAX_ANOMALIES", 3)),
            source_rate_limit=int(getattr(config, "TRUST_GATE_SOURCE_RATE_LIMIT", 50)),
            rate_window_seconds=int(getattr(config, "TRUST_GATE_RATE_WINDOW_SECONDS", 60)),
            stuffing_max_entities=int(
                getattr(config, "TRUST_GATE_STUFFING_MAX_ENTITIES", 100)
            ),
            mass_identical_max=int(getattr(config, "TRUST_GATE_MASS_IDENTICAL_MAX", 5)),
            templated_min_distinct_ratio=float(
                getattr(config, "TRUST_GATE_TEMPLATED_MIN_DISTINCT_RATIO", 0.2)
            ),
            templated_min_submission=int(
                getattr(config, "TRUST_GATE_TEMPLATED_MIN_SUBMISSION", 5)
            ),
        )


def default_config() -> TrustGateConfig:
    """The process-default config snapshot (env-backed)."""
    return TrustGateConfig.from_config()
