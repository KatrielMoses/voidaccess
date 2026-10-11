"""
jobqueue/queue.py — durable-queue operations (enqueue / atomic claim / retry / reap).

Portable atomic claim across PostgreSQL and SQLite behind one interface:

* **PostgreSQL** — the candidate ``SELECT`` uses ``FOR UPDATE SKIP LOCKED`` so
  concurrent workers never contend on the same row.
* **SQLite** — no ``SKIP LOCKED``; instead the claim is a guarded
  ``UPDATE … WHERE id = :cand AND status = 'queued'`` and the ``rowcount`` is
  checked. SQLite serializes writers, so exactly one worker's guarded update
  matches; the loser sees ``rowcount == 0`` and retries with the next row.

Both strategies guarantee **no double-execution**: a row leaves ``queued`` under
a write that only one worker can win. The claim also stamps a ``lease_expires_at``;
if the worker dies mid-job, ``requeue_orphans`` returns the row to ``queued`` so
no work is orphaned by a restart.

Timing (poll/backoff) flows through ``pacing`` per CC-4.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

import sqlalchemy as sa
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import pacing
from jobqueue.models import Job, JobStatus

logger = logging.getLogger(__name__)

# ``normal`` baseline for retry backoff — scaled through pacing at use (CC-4).
_RETRY_BACKOFF_BASE = 30.0
DEFAULT_MAX_ATTEMPTS = 3

# How long a claimed row's lease lasts before a reaper may reclaim it. A
# correctness parameter (how long to wait before deciding a worker is dead), not
# a politeness delay — kept a named, env-overridable constant. Default 1h
# comfortably exceeds the 30-min investigation hard timeout.
DEFAULT_LEASE_SECONDS = int(os.getenv("VOIDACCESS_JOB_LEASE_SECONDS", "3600") or 3600)

_ACTIVE = (JobStatus.QUEUED.value, JobStatus.RUNNING.value)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enqueue(
    session: Session,
    task_type: str,
    payload: dict[str, Any],
    *,
    dedup_key: Optional[str] = None,
    priority: int = 100,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    available_at: Optional[datetime] = None,
) -> Job:
    """Insert a new ``queued`` job and flush to populate its id."""
    job = Job(
        task_type=task_type,
        payload=payload,
        dedup_key=dedup_key,
        priority=priority,
        max_attempts=max_attempts,
        available_at=available_at or _now(),
        status=JobStatus.QUEUED.value,
    )
    session.add(job)
    session.flush()
    return job


def claim_one(
    session: Session,
    worker_id: str,
    *,
    task_types: Optional[Sequence[str]] = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> Optional[Job]:
    """Atomically claim one due ``queued`` job, or return ``None`` if none.

    Manages its own transaction (commits the claim, rolls back a lost race).
    """
    now = _now()
    dialect = session.get_bind().dialect.name

    sel = sa.select(Job.id).where(
        Job.status == JobStatus.QUEUED.value,
        Job.available_at <= now,
    )
    if task_types:
        sel = sel.where(Job.task_type.in_(list(task_types)))
    sel = sel.order_by(Job.priority.asc(), Job.created_at.asc()).limit(1)
    if dialect == "postgresql":
        sel = sel.with_for_update(skip_locked=True)

    try:
        candidate = session.execute(sel).scalar_one_or_none()
        if candidate is None:
            session.rollback()
            return None

        result = session.execute(
            sa.update(Job)
            .where(Job.id == candidate, Job.status == JobStatus.QUEUED.value)
            .values(
                status=JobStatus.RUNNING.value,
                claimed_by=worker_id,
                claimed_at=now,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                attempts=Job.attempts + 1,
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            # Lost the race to another worker (SQLite / PG-without-skip-locked).
            session.rollback()
            return None
        session.commit()
    except OperationalError:
        # SQLite "database is locked" under contention — caller retries.
        session.rollback()
        return None

    return session.get(Job, candidate)


def complete(session: Session, job_id: uuid.UUID) -> None:
    """Mark a job ``done``."""
    session.execute(
        sa.update(Job)
        .where(Job.id == job_id)
        .values(status=JobStatus.DONE.value, updated_at=_now())
    )
    session.commit()


def fail_or_retry(session: Session, job_id: uuid.UUID, error: str) -> str:
    """Fail a job, or requeue it for retry if attempts remain.

    Returns the resulting status (``queued`` if retried, ``failed`` if
    exhausted). Retry backoff (``available_at``) is scaled through pacing.
    """
    job = session.get(Job, job_id)
    if job is None:
        return JobStatus.FAILED.value

    now = _now()
    err = (error or "")[:2000]
    if job.attempts < job.max_attempts:
        backoff = pacing.scale_retry_delay(_RETRY_BACKOFF_BASE * max(1, job.attempts))
        session.execute(
            sa.update(Job)
            .where(Job.id == job_id)
            .values(
                status=JobStatus.QUEUED.value,
                available_at=now + timedelta(seconds=backoff),
                claimed_by=None,
                claimed_at=None,
                lease_expires_at=None,
                last_error=err,
                updated_at=now,
            )
        )
        session.commit()
        return JobStatus.QUEUED.value

    session.execute(
        sa.update(Job)
        .where(Job.id == job_id)
        .values(status=JobStatus.FAILED.value, last_error=err, updated_at=now)
    )
    session.commit()
    return JobStatus.FAILED.value


def requeue_orphans(session: Session, *, all_running: bool = False) -> int:
    """Return orphaned ``running`` jobs to ``queued`` (or fail if exhausted).

    Args:
        all_running: when True (startup/reboot recovery), every ``running`` row
            is an orphan — the prior worker process is gone. When False
            (periodic reaper), only rows whose ``lease_expires_at`` has lapsed.

    A row that has already used all its attempts is marked ``failed`` rather than
    requeued, so crashes cannot retry forever.
    """
    now = _now()
    query = session.query(Job).filter(Job.status == JobStatus.RUNNING.value)
    if not all_running:
        query = query.filter(
            Job.lease_expires_at.isnot(None), Job.lease_expires_at < now
        )
    orphans = query.all()
    if not orphans:
        return 0

    requeued = 0
    for job in orphans:
        if job.attempts >= job.max_attempts:
            job.status = JobStatus.FAILED.value
            job.last_error = "exhausted retries after worker interruption"
        else:
            job.status = JobStatus.QUEUED.value
            job.available_at = now
            job.claimed_by = None
            job.claimed_at = None
            job.lease_expires_at = None
            requeued += 1
        job.updated_at = now
    session.commit()
    return requeued


def active_dedup_keys(
    session: Session, *, task_type: Optional[str] = None
) -> set[str]:
    """Return the dedup keys of all non-terminal (queued/running) jobs.

    Used by the investigation-sweep *backstop* to avoid failing an investigation
    that still has live queue work (it will be re-run by a worker).
    """
    q = session.query(Job.dedup_key).filter(
        Job.status.in_(_ACTIVE), Job.dedup_key.isnot(None)
    )
    if task_type is not None:
        q = q.filter(Job.task_type == task_type)
    return {row[0] for row in q.all() if row[0]}


def stats(session: Session) -> dict[str, int]:
    """Return job counts by status (observability)."""
    rows = (
        session.query(Job.status, sa.func.count(Job.id))
        .group_by(Job.status)
        .all()
    )
    return {status: int(count) for status, count in rows}
