"""
tests/test_observability.py — P4.4 corpus-health view acceptance.

Proves the view surfaces every vital sign from already-emitted counters (no
parallel pipeline), computes the quarantine:promotion ratio correctly, flags
abusive contributors, and is inert (not crashing) on an empty/$0 corpus.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base, InvestigationStepMetric
from observability import corpus_health
from shared_corpus.models import (
    ConfidenceTier,
    DiscoveredOnion,
    GlobalEntity,
    GlobalEntitySource,
    PageSnapshot,
    SourceReputation,
)

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'obs.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()
    eng.dispose()


def _entity(session, value, tier, count=1):
    session.add(
        GlobalEntity(
            id=uuid.uuid4(), entity_type="IP_ADDRESS", canonical_value=value,
            confidence_tier=tier, corroboration_count=count, first_seen=NOW, last_seen=NOW,
        )
    )
    session.flush()


def test_empty_corpus_is_inert(session):
    h = corpus_health(session, now=NOW)
    assert h["tiers"]["total"] == 0
    assert h["tiers"]["quarantine_ratio"] == 0.0
    assert h["reputation"]["contributors"] == 0
    assert h["cache"]["hit_rate"] == 0.0
    assert h["index"]["onions"]["total"] == 0


def test_quarantine_promotion_ratio(session):
    _entity(session, "1.1.1.1", ConfidenceTier.UNCONFIRMED.value)
    _entity(session, "1.1.1.2", ConfidenceTier.UNCONFIRMED.value)
    _entity(session, "1.1.1.3", ConfidenceTier.UNCONFIRMED.value)
    _entity(session, "1.1.1.4", ConfidenceTier.CORROBORATED.value)
    session.commit()
    tiers = corpus_health(session, now=NOW)["tiers"]
    assert tiers["total"] == 4
    assert tiers["unconfirmed"] == 3
    assert tiers["quarantine_ratio"] == 0.75
    assert tiers["promotion_ratio"] == 0.25


def test_flagged_contributors_and_distribution(session):
    session.add(SourceReputation(id=uuid.uuid4(), source="good.onion", score=0.9, blocked=False, contributed=10, corroborated=5, contradicted=0, anomalies=0, first_seen=NOW, last_seen=NOW))
    session.add(SourceReputation(id=uuid.uuid4(), source="flooder", score=0.1, blocked=True, contributed=200, corroborated=0, contradicted=2, anomalies=9, first_seen=NOW, last_seen=NOW))
    session.commit()
    rep = corpus_health(session, now=NOW)["reputation"]
    assert rep["contributors"] == 2
    assert rep["blocked"] == 1
    assert rep["total_anomalies"] == 9
    # The flooder is flagged, most-abusive first.
    assert rep["flagged"][0]["source"] == "flooder"
    assert rep["flagged"][0]["blocked"] is True


def test_index_and_cache_sections(session):
    session.add(DiscoveredOnion(id=uuid.uuid4(), onion_address="a.onion", status="alive", first_seen=NOW, last_seen=NOW))
    session.add(DiscoveredOnion(id=uuid.uuid4(), onion_address="b.onion", status="dead", first_seen=NOW, last_seen=NOW))
    session.add(PageSnapshot(id=uuid.uuid4(), content_hash="h1", url="http://a.onion/1", storage_ref="h1", captured_at=NOW, first_seen=NOW, last_seen=NOW))
    inv = uuid.uuid4()
    session.add(InvestigationStepMetric(investigation_id=inv, step_name="scraping", pages_attempted=10, pages_cache_hits=4))
    session.commit()
    h = corpus_health(session, now=NOW)
    assert h["index"]["onions"]["alive"] == 1
    assert h["index"]["onions"]["dead"] == 1
    assert h["index"]["snapshots"]["total"] == 1
    assert h["cache"]["pages_cache_hits"] == 4
    assert h["cache"]["hit_rate"] == 0.4


def test_no_parallel_metrics_pipeline():
    """The view is read-only over emitted counters — no writes, no metrics stack."""
    src = (Path(__file__).resolve().parents[1] / "observability" / "corpus_health.py").read_text(encoding="utf-8")
    for forbidden in ("prometheus", "statsd", "insert(", "session.add", "INSERT ", "op.create"):
        assert forbidden not in src, f"observability must not use {forbidden!r}"
    # It reads the already-emitted counter tables.
    for tbl in ("GlobalEntity", "SourceReputation", "InvestigationStepMetric"):
        assert tbl in src
