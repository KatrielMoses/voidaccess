"""
tests/test_freshness.py — P3.3 freshness loop (durable-queue re-crawl).

Offline: the Tor fetch is injected, the owned index is a fake in-memory client,
the snapshot read-back + monitor feed are patched, and the durable queue runs on a
file-backed SQLite DB. Covers the P3.3 acceptance criteria:
* a stale onion is re-crawled on schedule via the queue; last_seen + liveness update;
* the dead→drop policy;
* a changed onion → new sanitized snapshot + re-index + a diff fed to the monitor;
* re-crawl volume is bounded/capped per cycle (no exhaustive crawl);
* a queued re-crawl survives a process restart (orphan-requeue);
* unconfigured index → inert, no crash;
* dead/dropped onions are filtered from owned-index retrieval.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from aioresponses import aioresponses
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

import config
from db.models import Base
from jobqueue import Job, claim_one, enqueue, requeue_orphans
from owned_index import OwnedIndex, SearchHit
from sanitizer import sanitize_page
from shared_corpus import DiscoveredOnion, PageSnapshot, record_discovered_onion
from snapshot_store import content_hash
import freshness
from freshness import recrawl_onion, enqueue_freshness_batch, select_stale_onions
from freshness import recrawl as recrawl_mod
from freshness.scheduler import TASK_RECRAWL, TASK_SCAN, freshness_scan_handler

_NER_AVAILABLE = sanitize_page("the quick brown fox jumps over the lazy dog") is not None
_needs_ner = pytest.mark.skipif(
    not _NER_AVAILABLE, reason="spaCy NER unavailable; sanitize_page fail-closes to None"
)


def _addr(ch: str) -> str:
    return ch * 56 + ".onion"


def _aware(dt):
    """SQLite returns naive datetimes; normalize to UTC-aware for comparison."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _fake_embedder(text):
    if not text:
        return None
    d = hashlib.sha256(text.encode()).digest()
    return [((d[i % len(d)] / 255.0) * 2.0) - 1.0 for i in range(384)]


class FakeIndexClient:
    def __init__(self):
        self.store: dict[str, dict] = {}
        self.index_uid = "onion_pages"

    async def ensure_index(self, *, wait=True):
        pass

    async def add_documents(self, docs, *, wait=True):
        for d in docs:
            self.store[d["content_hash"]] = d

    async def get_document(self, i):
        return self.store.get(i)

    async def search(self, body):
        return {"hits": list(self.store.values())}


def _fake_index():
    return OwnedIndex(FakeIndexClient(), embedder=_fake_embedder)


@pytest.fixture
def Session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng, "connect")
    def _pragmas(dbapi_conn, _rec):  # pragma: no cover
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.close()

    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng, expire_on_commit=False)
    eng.dispose()


@pytest.fixture(autouse=True)
def _contribute(monkeypatch):
    monkeypatch.setattr(config, "PRIVATE_MODE", False, raising=False)


def _seed_onion(session, ch, *, status="alive", last_seen=None, consecutive_dead=0):
    row, _ = record_discovered_onion(session, _addr(ch), discovery_source="investigation", status=status)
    row.consecutive_dead = consecutive_dead
    if last_seen is not None:
        row.last_seen = last_seen
    session.flush()
    return row


# ---------------------------------------------------------------------------
# Re-crawl worker — liveness
# ---------------------------------------------------------------------------

@_needs_ner
async def test_recrawl_alive_updates_liveness_and_last_seen(Session):
    with Session() as s:
        old_seen = datetime(2020, 1, 1, tzinfo=timezone.utc)
        _seed_onion(s, "a", status="unknown", last_seen=old_seen)
        s.commit()

        async def fetch(url):
            return "market vendor listing escrow shipping payments"

        out = await recrawl_onion(s, _addr("a"), fetch=fetch, index=_fake_index())
        s.commit()

        assert out.status == "alive"
        row = s.query(DiscoveredOnion).filter_by(onion_address=_addr("a")).one()
        assert row.status == "alive"
        assert _aware(row.last_seen) > old_seen
        assert row.consecutive_dead == 0


async def test_recrawl_dead_increments_then_drops(Session):
    threshold = int(config.FRESHNESS_DEAD_DROP_THRESHOLD)
    with Session() as s:
        _seed_onion(s, "b", status="alive", consecutive_dead=threshold - 1)
        s.commit()

        async def dead_fetch(url):
            return ""

        out = await recrawl_onion(s, _addr("b"), fetch=dead_fetch, index=None)
        s.commit()

        # One more dead re-crawl hits the threshold → dropped (terminal).
        assert out.status == "dropped"
        row = s.query(DiscoveredOnion).filter_by(onion_address=_addr("b")).one()
        assert row.status == "dropped"
        assert row.consecutive_dead == threshold


async def test_recrawl_dead_below_threshold_marks_dead(Session):
    with Session() as s:
        _seed_onion(s, "c", status="alive", consecutive_dead=0)
        s.commit()
        out = await recrawl_onion(s, _addr("c"), fetch=lambda u: _aret(""), index=None)
        s.commit()
        assert out.status == "dead"
        row = s.query(DiscoveredOnion).filter_by(onion_address=_addr("c")).one()
        assert row.status == "dead" and row.consecutive_dead == 1


async def test_recrawl_skips_dropped_onion(Session):
    with Session() as s:
        _seed_onion(s, "d", status="dropped")
        s.commit()
        called = {"n": 0}

        async def fetch(url):
            called["n"] += 1
            return "content"

        out = await recrawl_onion(s, _addr("d"), fetch=fetch, index=None)
        assert out.status == "dropped"
        assert called["n"] == 0  # a dropped onion is never re-fetched


def _aret(value):
    async def _c(*a, **k):
        return value
    return _c(value)


# ---------------------------------------------------------------------------
# Re-crawl worker — changed content → snapshot + re-index + monitor diff
# ---------------------------------------------------------------------------

@_needs_ner
async def test_recrawl_changed_stores_snapshot_reindexes_and_alerts(Session, monkeypatch):
    _ENDPOINT = "https://acct.example.com"
    for name, val in [
        ("S3_ENDPOINT_URL", _ENDPOINT), ("S3_BUCKET", "snaps"),
        ("S3_ACCESS_KEY_ID", "AKIA"), ("S3_SECRET_ACCESS_KEY", "sk"), ("S3_REGION", "auto"),
    ]:
        monkeypatch.setattr(config, name, val, raising=False)

    # Old snapshot content the re-crawl diffs against.
    monkeypatch.setattr(recrawl_mod, "read_snapshot", AsyncMock(return_value=b"old alpha beta gamma content"))
    alert = AsyncMock()
    import monitor.alerts as monitor_alerts
    monkeypatch.setattr(monitor_alerts, "evaluate_and_dispatch_alerts", alert)

    index = _fake_index()
    with Session() as s:
        onion = _seed_onion(s, "e", status="alive")
        # A prior snapshot with a DIFFERENT content hash → change will be detected.
        s.add(PageSnapshot(
            content_hash="0" * 64, onion_id=onion.id, url=f"http://{_addr('e')}/",
            storage_ref="snapshots/00/" + "0" * 64, captured_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
        ))
        s.commit()

        async def fetch(url):
            return "brand new completely different market listing delta epsilon zeta content"

        url_re = re.compile(r"^https://acct\.example\.com/.*")
        with aioresponses() as m:
            m.head(url_re, status=404, repeat=True)
            m.put(url_re, status=200, repeat=True)
            out = await recrawl_onion(s, _addr("e"), fetch=fetch, index=index)
            s.commit()

        assert out.changed is True and out.indexed is True
        # A new snapshot row was stored (old + new).
        assert s.query(PageSnapshot).filter_by(onion_id=onion.id).count() == 2
        # The changed content was re-indexed.
        assert len(index._client.store) == 1
        # A significant diff was fed to the monitor subsystem.
        alert.assert_awaited_once()


@_needs_ner
async def test_recrawl_unchanged_does_not_reindex_or_alert(Session, monkeypatch):
    alert = AsyncMock()
    import monitor.alerts as monitor_alerts
    monkeypatch.setattr(monitor_alerts, "evaluate_and_dispatch_alerts", alert)

    text = "market vendor listing escrow shipping"
    sanitized = sanitize_page(text)
    index = _fake_index()
    with Session() as s:
        onion = _seed_onion(s, "f", status="alive")
        # Prior snapshot whose hash EQUALS the re-crawl's sanitized hash → unchanged.
        s.add(PageSnapshot(
            content_hash=content_hash(sanitized.encode()), onion_id=onion.id,
            url=f"http://{_addr('f')}/", captured_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
        ))
        s.commit()

        out = await recrawl_onion(s, _addr("f"), fetch=lambda u: _aret(text), index=index)
        s.commit()

        assert out.changed is False
        assert index._client.store == {}
        alert.assert_not_awaited()


# ---------------------------------------------------------------------------
# Scheduler — bounded, staleness-prioritized, capped
# ---------------------------------------------------------------------------

async def test_enqueue_batch_is_capped(Session, monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", "http://meili.test:7700", raising=False)
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with Session() as s:
        for ch in "ghijkl":  # 6 stale onions
            _seed_onion(s, ch, status="alive", last_seen=old)
        s.commit()

        n = enqueue_freshness_batch(s, cap=2)
        s.commit()
        assert n == 2  # hard cap — no exhaustive crawl
        assert s.query(Job).filter_by(task_type=TASK_RECRAWL).count() == 2


async def test_select_stale_prioritizes_oldest(Session):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session() as s:
        _seed_onion(s, "g", last_seen=now - timedelta(days=10))
        _seed_onion(s, "h", last_seen=now - timedelta(days=30))  # stalest
        _seed_onion(s, "i", last_seen=now - timedelta(seconds=5))  # fresh, excluded
        _seed_onion(s, "j", status="dropped", last_seen=now - timedelta(days=99))  # dropped, excluded
        s.commit()
        stale = select_stale_onions(s, limit=10, now=now)
        addrs = [o.onion_address for o in stale]
        assert addrs[0] == _addr("h")  # stalest first
        assert _addr("i") not in addrs and _addr("j") not in addrs


async def test_enqueue_batch_skips_in_flight(Session, monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", "http://meili.test:7700", raising=False)
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with Session() as s:
        _seed_onion(s, "g", last_seen=old)
        # Already an in-flight re-crawl for this onion.
        enqueue(s, TASK_RECRAWL, {"onion_address": _addr("g")}, dedup_key=_addr("g"))
        s.commit()
        n = enqueue_freshness_batch(s, cap=5)
        s.commit()
        assert n == 0  # skipped — no duplicate re-crawl


# ---------------------------------------------------------------------------
# Unconfigured index → inert
# ---------------------------------------------------------------------------

async def test_enqueue_batch_noop_when_index_unconfigured(Session, monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    with Session() as s:
        _seed_onion(s, "g", last_seen=datetime(2020, 1, 1, tzinfo=timezone.utc))
        s.commit()
        assert enqueue_freshness_batch(s, cap=5) == 0
        assert freshness.bootstrap(s) is False


# ---------------------------------------------------------------------------
# Durable queue: restart-safety + on-queue dispatch
# ---------------------------------------------------------------------------

async def test_queued_recrawl_survives_restart(Session):
    with Session() as s:
        enqueue(s, TASK_RECRAWL, {"onion_address": _addr("g")}, dedup_key=_addr("g"))
        s.commit()
        claimed = claim_one(s, "worker-1", task_types=[TASK_RECRAWL])
        assert claimed is not None  # now 'running'
        # Simulate a process crash: the running job is orphaned and requeued.
        n = requeue_orphans(s, all_running=True)
        s.commit()
        assert n == 1
        row = s.query(Job).filter_by(task_type=TASK_RECRAWL).one()
        assert row.status == "queued"  # durably re-claimable after restart


async def test_scan_handler_enqueues_recrawls_and_rearms(db_engine, monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", "http://meili.test:7700", raising=False)
    from db.session import get_session

    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with get_session() as s:
        _seed_onion(s, "g", last_seen=old)
        _seed_onion(s, "h", last_seen=old)
        s.commit()

    await freshness_scan_handler({})

    with get_session() as s:
        assert s.query(Job).filter_by(task_type=TASK_RECRAWL).count() == 2
        # The scan re-armed itself for a future cycle (durable "cron tick").
        next_scan = s.query(Job).filter_by(task_type=TASK_SCAN, status="queued").one()
        assert _aware(next_scan.available_at) > datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Liveness surfaced to retrieval (P3.2 owned-index projection)
# ---------------------------------------------------------------------------

async def test_dead_onions_filtered_from_retrieval(db_engine, monkeypatch):
    from db.session import get_session
    from search.ranking import _query_owned_index

    with get_session() as s:
        _seed_onion(s, "a", status="alive")
        _seed_onion(s, "b", status="dead")
        _seed_onion(s, "c", status="dropped")
        s.commit()

    async def fake_search_index(query, **kwargs):
        return [
            SearchHit(content_hash="1" * 64, url=f"http://{_addr('a')}/", title="alive"),
            SearchHit(content_hash="2" * 64, url=f"http://{_addr('b')}/", title="dead"),
            SearchHit(content_hash="3" * 64, url=f"http://{_addr('c')}/", title="dropped"),
        ]

    import owned_index
    monkeypatch.setattr(owned_index, "search_index", fake_search_index)

    links = await _query_owned_index("anything")
    hosts = {re.sub(r"^http://|/$", "", link["link"]) for link in links}
    assert hosts == {_addr("a")}  # dead + dropped filtered out
