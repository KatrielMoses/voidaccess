"""
tests/test_shared_read.py — P4.2 read-from-shared acceptance.

Proves, against a real SQLite schema (``Base.metadata.create_all`` — the $0/CLI
path):

* cached shared content is served without a Tor re-scrape, respecting the P3.3
  freshness + liveness policy (stale or dead/dropped-onion snapshots are never
  served — they fall through to a live scrape);
* query-relevant seeds + pre-extracted entities are read from the shared tier,
  entities carrying + respecting their confidence tier (unconfirmed down-weighted
  and labeled, not silently trusted);
* the read path touches ONLY user-agnostic shared tables — never a private-tier
  table (the airtight 2.2 privacy assertion, via captured SQL);
* private mode / consent-off reads nothing central.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from db.models import Base
from shared_corpus.models import ConfidenceTier, DiscoveredOnion, GlobalEntity, PageSnapshot
from shared_corpus.read import (
    read_shared_before_scrape,
    relevant_entities,
    relevant_seeds,
    serve_shared_snapshots,
    tier_weight,
)

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
TTL = timedelta(hours=24)

# Injected object-store reader — maps storage_ref → bytes (no real S3 in tests).
_BLOBS: dict[str, bytes] = {}


async def _reader(ref: str):
    return _BLOBS.get(ref)


@pytest.fixture(autouse=True)
def _clear_blobs(monkeypatch):
    monkeypatch.setattr("config.PRIVATE_MODE", False)
    _BLOBS.clear()
    yield
    _BLOBS.clear()


@pytest.fixture
def session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'read.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    s = Session()
    yield s
    s.close()
    eng.dispose()


def _onion(session, address, status="alive"):
    o = DiscoveredOnion(
        id=uuid.uuid4(), onion_address=address, status=status,
        first_seen=NOW, last_seen=NOW,
    )
    session.add(o)
    session.flush()
    return o


def _snapshot(session, url, ref, *, captured, content=b"cached body", onion=None):
    _BLOBS[ref] = content
    snap = PageSnapshot(
        id=uuid.uuid4(), content_hash=ref, url=url, storage_ref=ref,
        onion_id=(onion.id if onion else None),
        captured_at=captured, first_seen=captured, last_seen=captured,
    )
    session.add(snap)
    session.flush()
    return snap


def _entity(session, etype, canonical, tier, count=1, display=None):
    e = GlobalEntity(
        id=uuid.uuid4(), entity_type=etype, canonical_value=canonical,
        display_value=display, confidence_tier=tier, corroboration_count=count,
        first_seen=NOW, last_seen=NOW,
    )
    session.add(e)
    session.flush()
    return e


# ---------------------------------------------------------------------------
# Cached content — serve without re-scraping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fresh_alive_snapshot_is_served(session):
    o = _onion(session, "abc.onion", status="alive")
    _snapshot(session, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=1), onion=o, content=b"hello world")
    res = await serve_shared_snapshots(
        session, ["http://abc.onion/p", "http://miss.onion/x"],
        now=NOW, ttl=TTL, reader=_reader,
    )
    assert res.served == {"http://abc.onion/p": "hello world"}
    assert res.hits == 1
    # The miss (and only the miss) falls through to scrape.
    assert [(_u if isinstance(_u, str) else _u.get("link")) for _u in res.remaining] == ["http://miss.onion/x"]


@pytest.mark.asyncio
async def test_stale_snapshot_is_not_served(session):
    o = _onion(session, "abc.onion", status="alive")
    _snapshot(session, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=48), onion=o)
    res = await serve_shared_snapshots(session, ["http://abc.onion/p"], now=NOW, ttl=TTL, reader=_reader)
    assert res.served == {}
    assert res.hits == 0
    assert len(res.remaining) == 1  # stale → re-scrape


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["dead", "dropped"])
async def test_dead_or_dropped_onion_snapshot_is_not_served(session, status):
    o = _onion(session, "abc.onion", status=status)
    _snapshot(session, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=1), onion=o)
    res = await serve_shared_snapshots(session, ["http://abc.onion/p"], now=NOW, ttl=TTL, reader=_reader)
    assert res.served == {}
    assert len(res.remaining) == 1  # liveness gate → re-scrape, not stale serve


@pytest.mark.asyncio
async def test_latest_snapshot_wins(session):
    o = _onion(session, "abc.onion", status="alive")
    _snapshot(session, "http://abc.onion/p", "old", captured=NOW - timedelta(hours=10), onion=o, content=b"OLD")
    _snapshot(session, "http://abc.onion/p", "new", captured=NOW - timedelta(hours=1), onion=o, content=b"NEW")
    res = await serve_shared_snapshots(session, ["http://abc.onion/p"], now=NOW, ttl=TTL, reader=_reader)
    assert res.served == {"http://abc.onion/p": "NEW"}


# ---------------------------------------------------------------------------
# Seeds + entities (tier-carrying)
# ---------------------------------------------------------------------------

def test_relevant_seeds_match_query_and_exclude_dead(session):
    _onion(session, "ransomabc.onion", status="alive")
    _onion(session, "deadxyz.onion", status="dropped")
    o = _onion(session, "market123.onion", status="alive")
    o.category = "ransomware"
    session.flush()

    seeds = relevant_seeds(session, "ransomware leak", limit=10)
    addrs = {s["onion_address"] for s in seeds}
    assert "market123.onion" in addrs  # matched via category
    assert "deadxyz.onion" not in addrs  # dropped excluded


def test_relevant_entities_carry_and_rank_by_tier(session):
    _entity(session, "IP_ADDRESS", "185.220.101.5", ConfidenceTier.UNCONFIRMED.value, count=1)
    _entity(session, "IP_ADDRESS", "185.220.101.6", ConfidenceTier.CORROBORATED.value, count=2)
    _entity(session, "IP_ADDRESS", "185.220.101.7", ConfidenceTier.FEED_VALIDATED.value, count=1)

    ents = relevant_entities(session, "185.220.101", limit=10)
    assert len(ents) == 3
    # Trusted-first ordering.
    assert [e["confidence_tier"] for e in ents] == ["feed_validated", "corroborated", "unconfirmed"]
    # Every entity carries its tier + weight; unconfirmed is down-weighted, not trusted.
    unconf = next(e for e in ents if e["confidence_tier"] == "unconfirmed")
    feedval = next(e for e in ents if e["confidence_tier"] == "feed_validated")
    assert unconf["trusted"] is False
    assert feedval["trusted"] is True
    assert unconf["trust_weight"] < feedval["trust_weight"]
    assert "unverified" in unconf["tier_label"]


def test_entities_require_a_query_to_avoid_dumping_corpus(session):
    _entity(session, "IP_ADDRESS", "185.220.101.5", ConfidenceTier.UNCONFIRMED.value)
    assert relevant_entities(session, "", limit=10) == []
    assert relevant_entities(session, None, limit=10) == []


def test_tier_weight_monotonic():
    assert tier_weight("unconfirmed") < tier_weight("corroborated") < tier_weight("feed_validated")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_shared_before_scrape_bundles_all_three(session):
    o = _onion(session, "abc.onion", status="alive")
    _snapshot(session, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=1), onion=o, content=b"body")
    _onion(session, "leaksite.onion", status="alive")
    _entity(session, "DOMAIN", "leaksite.onion", ConfidenceTier.CORROBORATED.value, count=2)

    bundle = await read_shared_before_scrape(
        session, "leaksite", ["http://abc.onion/p", "http://miss.onion/y"],
        now=NOW, reader=_reader,
    )
    assert bundle.served == {"http://abc.onion/p": "body"}
    assert bundle.served_count == 1
    assert any(s["onion_address"] == "leaksite.onion" for s in bundle.seeds)
    assert any(e["canonical_value"] == "leaksite.onion" for e in bundle.entities)
    assert bundle.skipped_private is False


# ---------------------------------------------------------------------------
# Consent gate — private mode reads nothing central
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_mode_reads_nothing(session, monkeypatch):
    import config as _config

    monkeypatch.setattr(_config, "PRIVATE_MODE", True)
    o = _onion(session, "abc.onion", status="alive")
    _snapshot(session, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=1), onion=o)
    _entity(session, "DOMAIN", "abc.onion", ConfidenceTier.FEED_VALIDATED.value)

    bundle = await read_shared_before_scrape(session, "abc", ["http://abc.onion/p"], now=NOW, reader=_reader)
    assert bundle.skipped_private is True
    assert bundle.served == {}
    assert bundle.served_count == 0
    assert bundle.seeds == []
    assert bundle.entities == []
    # Nothing served → everything falls through to a live scrape.
    assert len(bundle.remaining) == 1
    assert relevant_seeds(session, "abc") == []
    assert relevant_entities(session, "abc") == []


# ---------------------------------------------------------------------------
# Privacy boundary (the 2.2 acceptance) — only shared tables are touched
# ---------------------------------------------------------------------------

_ALLOWED_SHARED_TABLES = {"page_snapshots", "discovered_onions", "global_entities"}


@pytest.mark.asyncio
async def test_read_path_touches_only_shared_tables(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'privacy.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)

    seen_tables: set[str] = set()

    @event.listens_for(eng, "before_cursor_execute")
    def _capture(conn, cursor, statement, params, context, executemany):
        for m in re.finditer(r'(?:from|join)\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?', statement, re.I):
            name = m.group(1).lower()
            if name != "sqlite_master":
                seen_tables.add(name)

    Session = sessionmaker(bind=eng)
    s = Session()
    try:
        o = _onion(s, "abc.onion", status="alive")
        _snapshot(s, "http://abc.onion/p", "ref1", captured=NOW - timedelta(hours=1), onion=o, content=b"x")
        _onion(s, "seed.onion", status="alive")
        _entity(s, "DOMAIN", "seed.onion", ConfidenceTier.CORROBORATED.value)
        s.commit()
        seen_tables.clear()  # only observe the READ path below

        await read_shared_before_scrape(s, "seed", ["http://abc.onion/p"], now=NOW, reader=_reader)
    finally:
        s.close()
        eng.dispose()

    assert seen_tables, "expected the read path to query the shared tables"
    leaked = seen_tables - _ALLOWED_SHARED_TABLES
    assert not leaked, f"read path touched non-shared (private) tables: {leaked}"
