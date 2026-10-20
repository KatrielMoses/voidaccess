"""
tests/test_corpus_promotion.py — P4.1 write-to-shared-through-the-gate acceptance.

Proves, against a real SQLite schema (``Base.metadata.create_all`` — the CLI/$0
path):

* observed entities are promoted into ``global_entities`` through the *real* P4.0
  gate, at the gate-assigned tier (unconfirmed by default);
* ≥ N independent sources → corroborated; a trusted-feed cross-hit → feed_validated
  — both across one batch and across successive promotion passes (durable);
* feed_hits are derived platform-side from the entity's ``feed:`` tags, never from
  investigation input;
* provenance is queryable — a shared record → its sources + first_seen + tier;
* private mode / consent-off writes nothing;
* concurrent writers don't double-insert (P2.0 unique constraint);
* promotion is additive + strictly non-fatal (a bad observation is skipped).
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from db.models import Base, Entity, Page
from shared_corpus import (
    GlobalEntity,
    GlobalEntitySource,
    SourceReputation,
    entity_provenance,
)
from shared_corpus.promote import (
    EntityObservation,
    observations_from_investigation,
    promote_entities,
    promote_investigation,
)
from trust_gate import TrustGateConfig

IP = "185.220.101.5"


def _cfg() -> TrustGateConfig:
    return TrustGateConfig(
        min_independent_sources=2,
        trusted_feeds=frozenset({"feodo", "sslbl", "kev"}),
    )


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setattr("config.PRIVATE_MODE", False)
    db_path = (tmp_path / "promote.db").as_posix()
    eng = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )

    @event.listens_for(eng, "connect")
    def _pragmas(dbapi_conn, _rec):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.close()

    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


def _obs(value=IP, source="a.onion", feed_hits=frozenset()):
    return EntityObservation(
        entity_type="IP_ADDRESS", value=value, source=source, feed_hits=feed_hits
    )


def _count(session, model):
    return session.execute(sa.select(sa.func.count()).select_from(model)).scalar()


# ---------------------------------------------------------------------------
# Promotion at gate-assigned tiers
# ---------------------------------------------------------------------------

def test_single_observation_promoted_unconfirmed(session):
    report = promote_entities(session, [_obs()], config=_cfg())
    session.commit()
    assert report.considered == 1
    assert report.promoted == 1
    assert report.quarantined == 1

    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov is not None
    assert prov["confidence_tier"] == "unconfirmed"
    assert prov["corroboration_count"] == 1
    assert [s["source"] for s in prov["sources"]] == ["a.onion"]


def test_two_independent_sources_reach_corroborated_in_one_batch(session):
    report = promote_entities(
        session, [_obs(source="a.onion"), _obs(source="b.onion")], config=_cfg()
    )
    session.commit()
    assert report.corroborated == 1
    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov["confidence_tier"] == "corroborated"
    assert prov["corroboration_count"] == 2
    assert set(s["source"] for s in prov["sources"]) == {"a.onion", "b.onion"}


def test_corroboration_accrues_across_promotion_passes(session):
    promote_entities(session, [_obs(source="a.onion")], config=_cfg())
    session.commit()
    assert entity_provenance(session, "IP_ADDRESS", IP)["confidence_tier"] == "unconfirmed"

    # A second, separate investigation (fresh promotion pass) on another onion.
    promote_entities(session, [_obs(source="b.onion")], config=_cfg())
    session.commit()
    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov["confidence_tier"] == "corroborated"
    assert prov["corroboration_count"] == 2


def test_trusted_feed_crosshit_reaches_feed_validated(session):
    report = promote_entities(
        session, [_obs(feed_hits=frozenset({"feodo"}))], config=_cfg()
    )
    session.commit()
    assert report.feed_validated == 1
    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov["confidence_tier"] == "feed_validated"
    assert "feodo" in prov["sources"][0]["feed_hits"]


def test_tier_only_rises_never_demotes(session):
    # Feed-validate first, then a plain single-source observation must not demote.
    promote_entities(session, [_obs(feed_hits=frozenset({"feodo"}))], config=_cfg())
    session.commit()
    promote_entities(session, [_obs(source="z.onion")], config=_cfg())
    session.commit()
    assert entity_provenance(session, "IP_ADDRESS", IP)["confidence_tier"] == "feed_validated"


# ---------------------------------------------------------------------------
# feed_hits are platform-derived (from feeds/ tags), never investigation input
# ---------------------------------------------------------------------------

def _make_entity(session, *, inv, value, url, corroborating):
    page = Page(id=uuid.uuid4(), url=url)
    session.add(page)
    session.flush()
    session.add(
        Entity(
            id=uuid.uuid4(),
            page_id=page.id,
            investigation_id=inv,
            entity_type="IP_ADDRESS",
            value=value,
            corroborating_sources=corroborating,
        )
    )
    session.flush()


def test_feed_hits_derived_from_platform_tags(session):
    inv = uuid.uuid4()
    _make_entity(
        session, inv=inv, value=IP, url="http://abc.onion/p",
        corroborating='["dark_web_scrape", "feed:feodo", "feed:not-a-trusted-feed"]',
    )
    obs = observations_from_investigation(session, inv, config=_cfg())
    assert len(obs) == 1
    # Only the allowlisted feed tag becomes a feed hit; the unknown one is ignored.
    assert obs[0].feed_hits == frozenset({"feodo"})


def test_no_feed_tags_means_no_feed_hits(session):
    inv = uuid.uuid4()
    _make_entity(
        session, inv=inv, value=IP, url="http://abc.onion/p",
        corroborating='["dark_web_scrape"]',
    )
    obs = observations_from_investigation(session, inv, config=_cfg())
    assert obs[0].feed_hits == frozenset()


def test_promote_investigation_end_to_end_corroborates_across_onions(session):
    inv = uuid.uuid4()
    _make_entity(session, inv=inv, value=IP, url="http://aaa.onion/1", corroborating="[]")
    _make_entity(session, inv=inv, value=IP, url="http://bbb.onion/2", corroborating="[]")
    report = promote_investigation(session, inv, config=_cfg())
    session.commit()
    assert report.corroborated == 1
    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov["confidence_tier"] == "corroborated"
    assert set(s["source"] for s in prov["sources"]) == {"aaa.onion", "bbb.onion"}


# ---------------------------------------------------------------------------
# Provenance queryable (spec 3.4)
# ---------------------------------------------------------------------------

def test_provenance_exposes_sources_first_seen_and_tier(session):
    promote_entities(session, [_obs(source="a.onion", feed_hits=frozenset({"feodo"}))], config=_cfg())
    session.commit()
    prov = entity_provenance(session, "IP_ADDRESS", IP)
    assert prov["first_seen"] is not None
    assert prov["confidence_tier"] == "feed_validated"
    src = prov["sources"][0]
    assert src["source"] == "a.onion"
    assert src["first_seen"] is not None
    assert src["feed_hits"] == ["feodo"]


def test_provenance_none_for_unknown_entity(session):
    assert entity_provenance(session, "IP_ADDRESS", "8.8.8.8") is None


# ---------------------------------------------------------------------------
# Consent gate — private mode writes nothing
# ---------------------------------------------------------------------------

def test_private_mode_writes_nothing(session, monkeypatch):
    import config as _config

    monkeypatch.setattr(_config, "PRIVATE_MODE", True)
    report = promote_entities(session, [_obs()], config=_cfg())
    session.commit()
    assert report.skipped_private is True
    assert report.promoted == 0
    assert _count(session, GlobalEntity) == 0
    assert entity_provenance(session, "IP_ADDRESS", IP) is None


# ---------------------------------------------------------------------------
# Collision-safety (P2.0 unique constraint)
# ---------------------------------------------------------------------------

def test_resubmission_is_idempotent(session):
    promote_entities(session, [_obs(source="a.onion")], config=_cfg())
    session.commit()
    promote_entities(session, [_obs(source="a.onion")], config=_cfg())
    session.commit()
    assert _count(session, GlobalEntity) == 1
    assert _count(session, GlobalEntitySource) == 1  # same source → one row
    assert entity_provenance(session, "IP_ADDRESS", IP)["corroboration_count"] == 1


def test_concurrent_writers_do_not_double_insert(engine):
    Session = sessionmaker(bind=engine)

    def _promote():
        s = Session()
        try:
            promote_entities(s, [_obs(source="a.onion")], config=_cfg())
            s.commit()
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: _promote(), range(4)))

    check = Session()
    try:
        assert _count(check, GlobalEntity) == 1
        assert _count(check, GlobalEntitySource) == 1
    finally:
        check.close()


# ---------------------------------------------------------------------------
# Non-fatal / additive
# ---------------------------------------------------------------------------

def test_sanitize_drop_is_skipped_not_fatal(session):
    # A PII-typed observation is dropped at the gate; the batch continues.
    obs = [
        EntityObservation(entity_type="PERSON", value="Jane Public", source="a.onion"),
        _obs(source="a.onion"),
    ]
    report = promote_entities(session, obs, config=_cfg())
    session.commit()
    # The IP promoted; the PERSON was rejected — no crash, no PERSON row.
    assert report.promoted == 1
    assert report.rejected == 1
    assert _count(session, GlobalEntity) == 1
    assert entity_provenance(session, "IP_ADDRESS", IP) is not None
    assert entity_provenance(session, "PERSON", "Jane Public") is None


def test_flood_reject_still_downweights_source(session):
    cfg = TrustGateConfig(
        min_independent_sources=2,
        trusted_feeds=frozenset({"feodo"}),
        source_rate_limit=2,
        rate_window_seconds=60,
    )
    # 4 distinct IOCs from one source in one window → the later ones flood-reject.
    obs = [
        EntityObservation(entity_type="IP_ADDRESS", value=f"185.220.101.{i}", source="flood.onion")
        for i in range(4)
    ]
    report = promote_entities(session, obs, config=cfg)
    session.commit()
    assert report.rejected >= 1
    rep = session.execute(
        sa.select(SourceReputation).where(SourceReputation.source == "flood.onion")
    ).scalar_one()
    assert rep.anomalies >= 1
