"""
tests/test_shared_corpus.py — the P2.0 two-tier acceptance suite.

Proves, against a real SQLite schema built by ``Base.metadata.create_all``:

* the shared tier materializes on the ORM/create_all path (same path the CLI and
  PostgreSQL/Alembic share a definition with);
* a shared-tier read exposes no private-tier fields (user id / query text);
* a private investigation's rows are scoped to the owning user (fail-closed);
* ``UniqueConstraint(entity_type, canonical_value)`` exists on the shared/global
  entity tier and concurrent writers cannot double-insert;
* identity flows through the single ``extractor.identity`` path.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from db.models import Base, Investigation, User
from extractor.identity import entity_canonical_id
from shared_corpus import (
    ConfidenceTier,
    DiscoveredOnion,
    GlobalEntity,
    PageSnapshot,
    PRIVATE_FRAMING_COLUMNS,
    SHARED_MODELS,
    filter_investigations_for_user,
    owned_investigation_ids,
    record_discovered_onion,
    record_page_snapshot,
    to_shared_dict,
    upsert_global_entity,
)


# ---------------------------------------------------------------------------
# Engine fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """A file-backed SQLite engine with the full ORM schema via create_all.

    File-backed (not :memory:) so the concurrent-writer test can open real
    independent connections. WAL + a generous busy_timeout keep SQLite's
    single-writer lock from turning legitimate contention into spurious errors.
    """
    db_path = (tmp_path / "shared.db").as_posix()
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.close()

    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def Session(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Schema-path parity
# ---------------------------------------------------------------------------

def test_shared_tables_registered_and_materialized(engine):
    """Shared tables are on Base.metadata and created by create_all."""
    for name in ("discovered_onions", "page_snapshots", "global_entities"):
        assert name in Base.metadata.tables, f"{name} not on Base.metadata"

    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names())
    assert {"discovered_onions", "page_snapshots", "global_entities"} <= tables


def test_global_entity_has_db_level_unique_constraint(engine):
    """The load-bearing UniqueConstraint(entity_type, canonical_value) exists."""
    inspector = sa.inspect(engine)
    uniques = inspector.get_unique_constraints("global_entities")
    cols = {tuple(u["column_names"]) for u in uniques}
    assert ("entity_type", "canonical_value") in cols, (
        f"expected a unique constraint on (entity_type, canonical_value); "
        f"found {cols}"
    )


# ---------------------------------------------------------------------------
# Tier boundary — shared reads expose nothing private
# ---------------------------------------------------------------------------

def test_shared_models_carry_no_private_columns():
    for model in SHARED_MODELS:
        names = {c.name for c in model.__table__.columns}
        leaked = names & PRIVATE_FRAMING_COLUMNS
        assert not leaked, f"{model.__tablename__} leaks private columns: {leaked}"


def test_shared_read_exposes_no_user_identity_or_query(Session):
    """Acceptance: a shared-tier read returns no user id and no query text,
    even when a private investigation carrying exactly that data exists in the
    same database."""
    with Session() as s, s.begin():
        # Private data present in the same DB.
        user = User(email="analyst@example.com", hashed_password="x")
        s.add(user)
        s.flush()
        s.add(
            Investigation(
                query="zzsecretquery ransomware",
                refined_query="zzsecretrefined",
                summary="zzsecretreport",
                user_id=user.id,
            )
        )
        # Shared observations derived from the same run.
        upsert_global_entity(s, "email", "victim@example.com")
        record_discovered_onion(s, "abcdefghij.onion", discovery_source="search")
        record_page_snapshot(s, "deadbeef" * 8, "http://abcdefghij.onion/leak")

    with Session() as s:
        shared_rows = (
            s.query(GlobalEntity).all()
            + s.query(DiscoveredOnion).all()
            + s.query(PageSnapshot).all()
        )
        assert shared_rows
        for row in shared_rows:
            projected = to_shared_dict(row)
            # Structural guarantee: no private-framing columns (incl. user_id).
            assert not (set(projected) & PRIVATE_FRAMING_COLUMNS)
            # No private text (query / refined_query / summary / owner email)
            # bleeds into any shared value.
            blob = " ".join(str(v) for v in projected.values()).lower()
            assert "zzsecret" not in blob
            assert "analyst@example.com" not in blob


# ---------------------------------------------------------------------------
# Tier boundary — private rows scoped to owner (fail-closed)
# ---------------------------------------------------------------------------

def test_private_investigation_scoped_to_owner(Session):
    with Session() as s, s.begin():
        u1 = User(email="u1@example.com", hashed_password="x")
        u2 = User(email="u2@example.com", hashed_password="x")
        s.add_all([u1, u2])
        s.flush()
        s.add(Investigation(query="u1 private", user_id=u1.id))
        s.add(Investigation(query="u2 private", user_id=u2.id))

    with Session() as s:
        u1 = s.query(User).filter_by(email="u1@example.com").one()
        u2 = s.query(User).filter_by(email="u2@example.com").one()

        u1_ids = owned_investigation_ids(s, u1.id)
        assert len(u1_ids) == 1

        # u1's scoped query never returns u2's private investigation/query text.
        u1_rows = filter_investigations_for_user(
            s.query(Investigation), u1.id
        ).all()
        assert {r.query for r in u1_rows} == {"u1 private"}

        # Fail-closed: a None user owns nothing and its scoped query is empty,
        # rather than leaking every private investigation.
        assert owned_investigation_ids(s, None) == []
        assert filter_investigations_for_user(s.query(Investigation), None).all() == []


# ---------------------------------------------------------------------------
# Collision-safe upsert
# ---------------------------------------------------------------------------

def test_upsert_global_entity_uses_single_identity_path(Session):
    with Session() as s, s.begin():
        row, created = upsert_global_entity(s, "email", "Foo@Example.COM")
        assert created is True
        # canonical_value is exactly what the single identity path produces —
        # no second canonicalization in shared_corpus.
        assert row.canonical_value == entity_canonical_id(
            {"entity_type": "email", "value": "Foo@Example.COM"}
        )
        assert row.confidence_tier == ConfidenceTier.UNCONFIRMED.value


def test_upsert_global_entity_second_writer_absorbed(Session):
    """Deterministic race analogue: two independent sessions both insert the
    same canonical entity; the second is absorbed, leaving exactly one row."""
    with Session() as s1, s1.begin():
        _, created1 = upsert_global_entity(s1, "email", "dup@example.com")
    with Session() as s2, s2.begin():
        _, created2 = upsert_global_entity(s2, "email", "DUP@example.com")

    assert created1 is True
    assert created2 is False
    with Session() as s:
        rows = (
            s.query(GlobalEntity)
            .filter_by(entity_type="email")
            .all()
        )
        assert len(rows) == 1


def test_upsert_global_entity_no_double_insert_under_concurrency(Session):
    """Many threads upserting the same canonical entity converge on one row."""
    n_threads = 8
    per_thread = 5
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()  # maximize overlap on the write path
        for _ in range(per_thread):
            for _attempt in range(10):
                try:
                    with Session() as s, s.begin():
                        upsert_global_entity(s, "ip_address", "203.0.113.7")
                    break
                except OperationalError:
                    # SQLite writer lock contention — retry.
                    continue

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futures = [pool.submit(worker) for _ in range(n_threads)]
        for f in futures:
            f.result()

    with Session() as s:
        rows = s.query(GlobalEntity).filter_by(entity_type="ip_address").all()
        assert len(rows) == 1, f"expected exactly one canonical row, got {len(rows)}"


def test_upsert_global_entity_routes_through_sanitizer_and_stamps_provenance(Session):
    from sanitizer import provenance_stamp

    with Session() as s, s.begin():
        # Inherently-PII entity type is dropped (victim identity never shared).
        row, created = upsert_global_entity(s, "PERSON_NAME", "John Smith")
        assert (row, created) == (None, False)
        # A raw secret is dropped (presence-only lives elsewhere).
        row, created = upsert_global_entity(s, "api_key", "AKIAIOSFODNN7EXAMPLE")
        assert row is None
        # A legitimate IOC is stored, carrying its provenance stamp.
        row, created = upsert_global_entity(
            s, "ip_address", "203.0.113.9", provenance=provenance_stamp(source="abcd.onion")
        )
        assert created is True
        assert row.provenance["source"] == "abcd.onion"
        assert row.provenance["scraper_version"]

    with Session() as s:
        assert s.query(GlobalEntity).filter_by(entity_type="PERSON_NAME").count() == 0
        assert s.query(GlobalEntity).filter_by(entity_type="api_key").count() == 0
        assert s.query(GlobalEntity).filter_by(entity_type="ip_address").count() == 1


def test_contribution_enabled_reflects_private_mode(monkeypatch):
    import config
    from shared_corpus import contribution_enabled

    monkeypatch.setattr(config, "PRIVATE_MODE", False, raising=False)
    assert contribution_enabled() is True
    monkeypatch.setattr(config, "PRIVATE_MODE", True, raising=False)
    assert contribution_enabled() is False


def test_record_discovered_onion_deduplicates(Session):
    with Session() as s, s.begin():
        _, c1 = record_discovered_onion(s, "same.onion")
    with Session() as s, s.begin():
        _, c2 = record_discovered_onion(s, "same.onion")
    assert (c1, c2) == (True, False)
    with Session() as s:
        assert s.query(DiscoveredOnion).count() == 1


def test_record_page_snapshot_deduplicates_by_content_hash(Session):
    h = "cafebabe" * 8
    with Session() as s, s.begin():
        _, c1 = record_page_snapshot(s, h, "http://a.onion/1")
    with Session() as s, s.begin():
        # Same content captured at a different URL collapses to one snapshot.
        _, c2 = record_page_snapshot(s, h, "http://a.onion/2-mirror")
    assert (c1, c2) == (True, False)
    with Session() as s:
        assert s.query(PageSnapshot).count() == 1
