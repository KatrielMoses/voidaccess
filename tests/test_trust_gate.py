"""
tests/test_trust_gate.py — P4.0 trust-gate acceptance + red-team suite.

Proves the automated anti-poisoning gate against every acceptance bullet:

* it is a pure, deterministic function (identical inputs → identical decision;
  no mutation of corpus state; no network/LLM/clock inside);
* a new artifact is quarantined (unconfirmed) and never auto-trusted; tier rises
  only via >= N independent sources or a trusted-feed cross-hit;
* a source producing contradicted data is downweighted/blocked;
* each flood class — single-source flood, entity-stuffing, templated injection,
  mass-identical — is detected and rate-limited;
* the red-team scenario: an attacker feeding false single-source IOCs cannot move
  scoring; sustained multi-source corroboration is required;
* tiers move only via the gate; dedup uses the single ``extractor.identity`` path;
* thresholds are config-tunable.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from extractor.identity import entity_canonical_id
from trust_gate import (
    Artifact,
    ConfidenceTier,
    CorpusState,
    GateDecision,
    TrustGateConfig,
    Verdict,
    detect_submission_anomaly,
    trust_gate,
    trust_gate_submission,
)
from trust_gate.model import corpus_key
from trust_gate.gate import GATE_STEPS

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _cfg(**over) -> TrustGateConfig:
    base = dict(
        min_independent_sources=2,
        trusted_feeds=frozenset({"kev", "sslbl", "feodo"}),
        source_rate_limit=50,
        rate_window_seconds=60,
        stuffing_max_entities=100,
        mass_identical_max=5,
        templated_min_distinct_ratio=0.2,
        templated_min_submission=5,
    )
    base.update(over)
    return TrustGateConfig(**base)


def _ip(
    value: str = "185.220.101.5",
    *,
    source: str = "onionA.onion",
    at: datetime = T0,
    feed_hits=frozenset(),
    disposition=None,
    fingerprint=None,
) -> Artifact:
    return Artifact(
        entity_type="IP_ADDRESS",
        value=value,
        source=source,
        observed_at=at,
        feed_hits=feed_hits,
        disposition=disposition,
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# Purity / determinism / composition
# ---------------------------------------------------------------------------

def _key_fields(d: GateDecision):
    return (
        d.canonical_key,
        d.verdict,
        d.tier,
        d.reason,
        d.independent_sources,
        d.trusted_feed_hits,
        d.counter_deltas,
    )


def test_gate_has_eight_ordered_steps():
    names = [n for n, _ in GATE_STEPS]
    assert names == [
        "1. sanitize",
        "2. validate",
        "3. provenance",
        "4. quarantine",
        "5. corroborate",
        "6. reputation",
        "7. anomaly",
        "8. dedup",
    ]


def test_pure_and_deterministic():
    cfg = _cfg()
    state = CorpusState()
    art = _ip()
    d1 = trust_gate(art, state, cfg)
    d2 = trust_gate(art, state, cfg)
    assert _key_fields(d1) == _key_fields(d2)


def test_gate_does_not_mutate_corpus_state():
    cfg = _cfg()
    state = CorpusState()
    before = state.copy()
    trust_gate(_ip(), state, cfg)
    assert state.corroborations == before.corroborations
    assert state.reputation == before.reputation
    assert state.recent_submissions == before.recent_submissions
    assert state.recent_fingerprints == before.recent_fingerprints


def test_no_clock_used_provenance_stamped_from_observed_at():
    """The gate stamps provenance from observed_at, never the wall clock."""
    cfg = _cfg()
    d = trust_gate(_ip(at=T0), CorpusState(), cfg)
    assert d.artifact.provenance is not None
    assert d.artifact.provenance["captured_at"] == T0.isoformat()


def test_no_network_or_llm_imports_in_gate_source():
    """Static guard: the gate module imports nothing that does I/O."""
    src = Path(__file__).resolve().parents[1] / "trust_gate" / "gate.py"
    text = src.read_text(encoding="utf-8")
    for forbidden in ("import requests", "aiohttp", "openai", "anthropic", "langchain", "urllib.request"):
        assert forbidden not in text, f"gate.py must not reference {forbidden}"


# ---------------------------------------------------------------------------
# Quarantine-by-default + corroboration promotion
# ---------------------------------------------------------------------------

def test_new_artifact_is_quarantined_unconfirmed():
    d = trust_gate(_ip(), CorpusState(), _cfg())
    assert d.verdict is Verdict.QUARANTINED
    assert d.tier is ConfidenceTier.UNCONFIRMED
    assert d.influences_scoring is False
    assert d.counter_deltas.quarantined == 1


def test_two_independent_sources_promote_to_corroborated():
    cfg = _cfg()
    state = CorpusState()
    d1 = trust_gate(_ip(source="onionA.onion"), state, cfg)
    state.apply(d1)
    assert d1.tier is ConfidenceTier.UNCONFIRMED

    d2 = trust_gate(_ip(source="onionB.onion"), state, cfg)
    assert d2.tier is ConfidenceTier.CORROBORATED
    assert d2.verdict is Verdict.ACCEPTED
    assert d2.influences_scoring is True
    assert d2.independent_sources == 2


def test_single_source_resubmission_never_promotes():
    cfg = _cfg()
    state = CorpusState()
    last = None
    for _ in range(4):
        last = trust_gate(_ip(source="onionA.onion"), state, cfg)
        state.apply(last)
    assert last.tier is ConfidenceTier.UNCONFIRMED
    assert last.independent_sources == 1
    assert last.reason == "duplicate"


def test_trusted_feed_crosshit_is_feed_validated_single_source():
    cfg = _cfg()
    d = trust_gate(_ip(feed_hits=frozenset({"kev"})), CorpusState(), cfg)
    assert d.tier is ConfidenceTier.FEED_VALIDATED
    assert d.verdict is Verdict.ACCEPTED
    assert d.trusted_feed_hits == frozenset({"kev"})
    assert d.counter_deltas.promoted_feed_validated == 1


def test_attacker_cannot_fabricate_untrusted_feed_hit():
    cfg = _cfg()
    d = trust_gate(_ip(feed_hits=frozenset({"totally-made-up-feed"})), CorpusState(), cfg)
    assert d.tier is ConfidenceTier.UNCONFIRMED
    assert d.trusted_feed_hits == frozenset()


def test_source_that_is_a_trusted_feed_validates():
    cfg = _cfg()
    d = trust_gate(_ip(source="sslbl"), CorpusState(), cfg)
    assert d.tier is ConfidenceTier.FEED_VALIDATED


# ---------------------------------------------------------------------------
# Source reputation: contradiction downweights / blocks
# ---------------------------------------------------------------------------

def _corroborate_malicious(state, cfg, value="185.220.101.5"):
    for src in ("onionA.onion", "onionB.onion"):
        d = trust_gate(_ip(value=value, source=src, disposition="malicious"), state, cfg)
        state.apply(d)


def test_contradicted_data_downweights_source_and_quarantines():
    cfg = _cfg()
    state = CorpusState()
    _corroborate_malicious(state, cfg)
    key = corpus_key("IP_ADDRESS", entity_canonical_id(_ip()))
    assert state.established_disposition[key] == "malicious"

    d = trust_gate(_ip(source="evil.onion", disposition="benign"), state, cfg)
    assert d.reason == "contradicted"
    assert d.verdict is Verdict.QUARANTINED
    assert d.counter_deltas.source_reputation.score < 1.0
    assert d.counter_deltas.source_reputation.contradicted == 1
    assert d.counter_deltas.added_source is False


def test_repeated_contradictions_block_the_source():
    cfg = _cfg(max_contradictions=3)
    state = CorpusState()
    # Establish three corroborated malicious entities.
    for i in range(3):
        val = f"185.220.101.{10 + i}"
        _corroborate_malicious(state, cfg, value=val)

    last = None
    for i in range(3):
        val = f"185.220.101.{10 + i}"
        last = trust_gate(_ip(value=val, source="evil.onion", disposition="benign"), state, cfg)
        state.apply(last)
    assert last.counter_deltas.source_reputation.blocked is True

    # A blocked source cannot corroborate a fresh entity even alongside a peer.
    fresh = "45.9.148.99"
    d_evil = trust_gate(_ip(value=fresh, source="evil.onion"), state, cfg)
    state.apply(d_evil)
    d_peer = trust_gate(_ip(value=fresh, source="honest.onion"), state, cfg)
    assert d_peer.tier is ConfidenceTier.UNCONFIRMED
    assert d_peer.independent_sources == 1


# ---------------------------------------------------------------------------
# Anomaly / flood detection — one test per attack class
# ---------------------------------------------------------------------------

def test_single_source_flood_is_rate_limited():
    cfg = _cfg(source_rate_limit=3, rate_window_seconds=60)
    state = CorpusState()
    decisions = []
    for i in range(4):
        d = trust_gate(_ip(value=f"185.220.101.{i}", source="flooder.onion", at=T0), state, cfg)
        state.apply(d)
        decisions.append(d)
    assert decisions[-1].verdict is Verdict.REJECTED
    assert decisions[-1].reason == "flood"
    assert decisions[-1].counter_deltas.source_reputation.anomalies == 1


def test_flood_window_resets_outside_window():
    cfg = _cfg(source_rate_limit=2, rate_window_seconds=60)
    state = CorpusState()
    for i in range(2):
        state.apply(trust_gate(_ip(value=f"1.1.1.{i}", source="s.onion", at=T0), state, cfg))
    # Same-window third → flood.
    d_in = trust_gate(_ip(value="1.1.1.9", source="s.onion", at=T0), state, cfg)
    assert d_in.verdict is Verdict.REJECTED
    # Far outside the window → allowed again.
    later = T0 + timedelta(seconds=120)
    d_out = trust_gate(_ip(value="1.1.1.9", source="s.onion", at=later), state, cfg)
    assert d_out.verdict is not Verdict.REJECTED


def test_entity_stuffing_submission_is_rejected():
    cfg = _cfg(stuffing_max_entities=5)
    arts = [_ip(value=f"185.220.101.{i}", source="stuffer.onion") for i in range(6)]
    anomaly = detect_submission_anomaly(arts, cfg)
    assert anomaly.entity_stuffing is True
    decisions = trust_gate_submission("stuffer.onion", arts, CorpusState(), cfg, apply=True)
    assert all(d.verdict is Verdict.REJECTED for d in decisions)
    assert all(d.reason == "entity_stuffing" for d in decisions)


def test_templated_injection_submission_is_rejected():
    cfg = _cfg(templated_min_submission=3, templated_min_distinct_ratio=0.5, stuffing_max_entities=1000)
    # 10 near-identical records (same fingerprint) → distinct ratio 0.1 < 0.5.
    arts = [_ip(value="185.220.101.5", source="tmpl.onion", fingerprint="X") for _ in range(10)]
    anomaly = detect_submission_anomaly(arts, cfg)
    assert anomaly.templated is True
    decisions = trust_gate_submission("tmpl.onion", arts, CorpusState(), cfg)
    assert all(d.verdict is Verdict.REJECTED for d in decisions)
    assert all("templated" in d.reason for d in decisions)


def test_mass_identical_repeats_are_rejected():
    cfg = _cfg(mass_identical_max=2)
    state = CorpusState()
    decisions = []
    for _ in range(4):
        d = trust_gate(_ip(value="185.220.101.5", source="dup.onion", fingerprint="SAME"), state, cfg)
        state.apply(d)
        decisions.append(d)
    assert decisions[-1].verdict is Verdict.REJECTED
    assert decisions[-1].reason == "mass_identical"


# ---------------------------------------------------------------------------
# Red-team acceptance (3.2): false single-source IOCs cannot move scoring
# ---------------------------------------------------------------------------

def test_redteam_single_source_false_iocs_cannot_influence_scoring():
    cfg = _cfg(min_independent_sources=2)
    state = CorpusState()

    # Attacker floods 60 distinct false IOCs from ONE source.
    attacker_decisions = []
    for i in range(60):
        art = _ip(value=f"10.0.{i // 256}.{i % 256}", source="attacker.onion", at=T0)
        d = trust_gate(art, state, cfg)
        state.apply(d)
        attacker_decisions.append(d)

    # Not one attacker artifact influences scoring.
    assert not any(d.influences_scoring for d in attacker_decisions)
    # Everything the attacker submitted is quarantined or rejected (never accepted).
    assert all(d.verdict is not Verdict.ACCEPTED for d in attacker_decisions)
    # The rate limit tripped, so the source got downweighted for the flood.
    assert any(d.verdict is Verdict.REJECTED for d in attacker_decisions)

    # Meanwhile, sustained multi-source corroboration DOES promote a real IOC.
    real = "45.9.148.99"
    d_a = trust_gate(_ip(value=real, source="honest1.onion"), state, cfg)
    state.apply(d_a)
    assert d_a.influences_scoring is False
    d_b = trust_gate(_ip(value=real, source="honest2.onion"), state, cfg)
    assert d_b.influences_scoring is True
    assert d_b.tier is ConfidenceTier.CORROBORATED


def test_redteam_attacker_cannot_self_corroborate_via_aliased_resubmission():
    """The same source resubmitting under the same id can never reach 2 sources."""
    cfg = _cfg(min_independent_sources=2)
    state = CorpusState()
    last = None
    for _ in range(10):
        last = trust_gate(_ip(source="attacker.onion"), state, cfg)
        state.apply(last)
    assert last.influences_scoring is False
    assert last.independent_sources == 1


# ---------------------------------------------------------------------------
# Tier assignment only via the gate + single identity path + tunability
# ---------------------------------------------------------------------------

def test_dedup_uses_single_identity_path():
    art = _ip()
    d = trust_gate(art, CorpusState(), _cfg())
    assert d.canonical_value == entity_canonical_id(art)


def test_gate_is_the_only_canonicalization_grep():
    """The gate derives identity solely through extractor.identity (single path)."""
    src = (Path(__file__).resolve().parents[1] / "trust_gate" / "gate.py").read_text(encoding="utf-8")
    # The only canonicalization call in the gate is entity_canonical_id.
    assert "entity_canonical_id(" in src
    assert "canonicalize_entity_value" not in src  # no second identity derivation
    assert "canonical_value or value" not in src


def test_thresholds_are_config_tunable():
    strict = _cfg(min_independent_sources=3)
    state = CorpusState()
    state.apply(trust_gate(_ip(source="a.onion"), state, strict))
    d2 = trust_gate(_ip(source="b.onion"), state, strict)
    assert d2.tier is ConfidenceTier.UNCONFIRMED  # 2 < 3, not yet promoted
    d3 = trust_gate(_ip(source="c.onion"), state, strict)
    # d2 was not applied; apply d2 then submit c for a real 3rd source.
    state.apply(d2)
    d3 = trust_gate(_ip(source="c.onion"), state, strict)
    assert d3.tier is ConfidenceTier.CORROBORATED
    assert d3.independent_sources == 3


def test_sanitize_rejects_pii_before_scoring():
    # An inherently-PII entity type is dropped at step 1, never quarantined/scored.
    art = Artifact(entity_type="PERSON", value="Jane Q Public", source="x.onion", observed_at=T0)
    d = trust_gate(art, CorpusState(), _cfg())
    assert d.verdict is Verdict.REJECTED
    assert d.reason in ("sanitize_dropped", "invalid_shape")
    assert d.counter_deltas.source_reputation is None  # hygiene reject, not a trust penalty
    assert d.counter_deltas.rejected == 1
