"""
tests/test_jobqueue.py — P2.3 durable-queue acceptance.

Proves atomic claim (no double execution) under concurrent workers, retry,
reboot + lease-based restart survival, and the worker running a handler — all on
a real SQLite schema built by create_all.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from db.models import Base
from jobqueue import (
    active_dedup_keys,
    claim_one,
    complete,
    enqueue,
    fail_or_retry,
    requeue_orphans,
)
from jobqueue.models import Job, JobStatus


@pytest.fixture
def Session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}",
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


def test_enqueue_and_claim_once(Session):
    with Session() as s:
        enqueue(s, "demo", {"n": 1})
        s.commit()
    with Session() as s:
        job = claim_one(s, "worker-1")
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.attempts == 1
        assert job.claimed_by == "worker-1"
    # No more work.
    with Session() as s:
        assert claim_one(s, "worker-1") is None


def test_atomic_claim_no_double_execution(Session):
    n_jobs = 40
    with Session() as s:
        for i in range(n_jobs):
            enqueue(s, "demo", {"i": i})
        s.commit()

    claimed: list = []
    lock = threading.Lock()

    def worker(wid: str) -> None:
        while True:
            with Session() as s:
                job = claim_one(s, wid)
            if job is None:
                with Session() as s:
                    remaining = (
                        s.query(Job).filter(Job.status == JobStatus.QUEUED.value).count()
                    )
                if remaining == 0:
                    return
                continue
            with lock:
                claimed.append(job.id)

    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = [pool.submit(worker, f"w{i}") for i in range(10)]
        for f in futs:
            f.result()

    assert len(claimed) == n_jobs             # every job claimed
    assert len(set(claimed)) == n_jobs        # none claimed twice


def test_retry_then_fail(Session):
    with Session() as s:
        job = enqueue(s, "demo", {}, max_attempts=2)
        s.commit()
        jid = job.id

    with Session() as s:
        claim_one(s, "w")  # attempts -> 1
    with Session() as s:
        assert fail_or_retry(s, jid, "boom") == JobStatus.QUEUED.value  # 1 < 2, retry

    # Clear the backoff so the retry is immediately claimable.
    with Session() as s:
        s.query(Job).filter(Job.id == jid).update(
            {"available_at": datetime.now(timezone.utc)}
        )
        s.commit()

    with Session() as s:
        claim_one(s, "w")  # attempts -> 2
    with Session() as s:
        assert fail_or_retry(s, jid, "boom again") == JobStatus.FAILED.value  # exhausted
    with Session() as s:
        assert s.get(Job, jid).status == JobStatus.FAILED.value


def test_reboot_requeues_running_jobs(Session):
    """Restart survival: a claimed (running) job is requeued after reboot, not
    orphaned, and can be claimed again."""
    with Session() as s:
        enqueue(s, "investigation", {"x": 1}, dedup_key="inv-1")
        s.commit()
    with Session() as s:
        job = claim_one(s, "w")
        assert job.status == JobStatus.RUNNING.value

    # Simulate reboot: previous worker is gone.
    with Session() as s:
        assert requeue_orphans(s, all_running=True) == 1
    with Session() as s:
        assert s.query(Job).one().status == JobStatus.QUEUED.value
    with Session() as s:
        assert claim_one(s, "w2") is not None  # resumable


def test_lease_expiry_requeues(Session):
    with Session() as s:
        enqueue(s, "demo", {})
        s.commit()
    with Session() as s:
        claim_one(s, "w", lease_seconds=0)  # lease already at 'now'
    time.sleep(0.05)
    with Session() as s:
        assert requeue_orphans(s, all_running=False) == 1  # lease lapsed → requeued


def test_active_dedup_keys(Session):
    with Session() as s:
        enqueue(s, "investigation", {}, dedup_key="inv-A")
        enqueue(s, "investigation", {}, dedup_key="inv-B")
        s.commit()
    with Session() as s:
        job = claim_one(s, "w")  # one becomes running (still active)
    with Session() as s:
        keys = active_dedup_keys(s, task_type="investigation")
        assert keys == {"inv-A", "inv-B"}
    # Completing one removes it from the active set.
    with Session() as s:
        complete(s, job.id)
    with Session() as s:
        assert len(active_dedup_keys(s, task_type="investigation")) == 1


async def test_investigation_with_live_job_survives_restart_sweep(db_engine):
    """Headline acceptance: an in-flight investigation that still has a durable
    job is NOT orphaned to 'failed' by the startup sweep — it is left for a
    worker to resume."""
    import uuid as _uuid

    from db.session import get_session
    from db.models import Investigation
    from jobqueue import enqueue, requeue_orphans
    from api.main import _sweep_stuck_investigations

    with get_session() as s:
        inv = Investigation(query="in flight", status="processing")
        s.add(inv)
        s.flush()
        inv_id = str(inv.id)
        job = enqueue(s, "investigation", {"investigation_id": inv_id}, dedup_key=inv_id)
        s.commit()
        job_id = job.id

    # Simulate the crash: the job was mid-flight ('running').
    with get_session() as s:
        s.query(Job).filter(Job.id == job_id).update({"status": JobStatus.RUNNING.value})
        s.commit()

    # Reboot recovery requeues the orphaned job...
    with get_session() as s:
        assert requeue_orphans(s, all_running=True) == 1

    # ...and the backstop sweep leaves the investigation alone (live job).
    swept = await _sweep_stuck_investigations(cutoff_minutes=None)
    assert swept == 0
    with get_session() as s:
        row = s.query(Investigation).filter(Investigation.id == _uuid.UUID(inv_id)).one()
        assert row.status == "processing"  # NOT failed — resumable


async def test_investigation_without_job_is_swept_by_backstop(db_engine):
    """A truly orphaned 'processing' investigation (no queue job) is still
    failed by the backstop."""
    import uuid as _uuid

    from db.session import get_session
    from db.models import Investigation
    from api.main import _sweep_stuck_investigations

    with get_session() as s:
        inv = Investigation(query="orphaned", status="processing")
        s.add(inv)
        s.flush()
        inv_id = str(inv.id)
        s.commit()

    swept = await _sweep_stuck_investigations(cutoff_minutes=None)
    assert swept == 1
    with get_session() as s:
        row = s.query(Investigation).filter(Investigation.id == _uuid.UUID(inv_id)).one()
        assert row.status == "failed"


async def test_worker_runs_registered_handler(db_engine):
    """The worker claims a job and runs its async handler, marking it done.

    Uses the conftest ``db_engine`` fixture so the worker's ``get_session()``
    resolves to the test DB.
    """
    from db.session import get_session
    from jobqueue import register_handler, run_once

    ran: list = []

    async def _handler(payload: dict) -> None:
        ran.append(payload["x"])

    register_handler("demo-worker", _handler)

    with get_session() as s:
        enqueue(s, "demo-worker", {"x": 99})
        s.commit()

    did = await run_once("w", task_types=["demo-worker"])
    assert did is True
    assert ran == [99]
    with get_session() as s:
        job = s.query(Job).filter(Job.task_type == "demo-worker").one()
        assert job.status == JobStatus.DONE.value
