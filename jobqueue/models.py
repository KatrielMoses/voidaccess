"""
jobqueue/models.py — the durable job-queue table (P2.3).

A single ``jobs`` table is the restart-safe substrate the central service runs
background work on — investigation dispatch now, P3 crawl/freshness and P4 ingest
later. Built on the existing database (no Redis, no broker), so the whole stack
deploys on one $0 always-on box.

Declared on the shared ``db.models.Base`` so a single ORM definition materializes
on both schema paths (``create_all`` for SQLite/CLI/tests, Alembic for
PostgreSQL) — the same convention the shared-corpus tables use.

Lifecycle: ``queued`` → ``running`` → ``done`` | ``failed``. A worker claims a
``queued`` row atomically (``jobqueue.queue.claim_one``), runs its handler, and
marks it terminal. A claimed row carries a ``lease_expires_at``; if the worker
dies, the lease lapses and a reaper returns the row to ``queued`` (retry), so no
work is orphaned by a process restart.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from db.models import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, enum.Enum):
    """Stored as VARCHAR (portability)."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Job(Base):
    """One unit of durable background work."""

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    task_type: Mapped[str] = mapped_column(sa.String(50), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default=JobStatus.QUEUED.value,
        server_default=JobStatus.QUEUED.value, index=True,
    )
    priority: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=100, server_default="100"
    )
    attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    max_attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=3, server_default="3"
    )
    # Earliest time this row may be claimed. Retry backoff pushes this forward.
    available_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    # Optional correlation key (e.g. the investigation id) so a backstop sweep
    # can tell which domain rows still have live queue work. Not unique: a job
    # may be retried/re-created for the same subject.
    dedup_key: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    claimed_by: Mapped[Optional[str]] = mapped_column(sa.String(100), nullable=True)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    # When a claimed row's lease lapses it is reclaimable by the reaper.
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        # The claim scan: pending rows that are due, oldest-first.
        sa.Index("ix_jobs_claim", "status", "available_at"),
        sa.Index("ix_jobs_lease", "lease_expires_at"),
        sa.Index("ix_jobs_dedup_key", "dedup_key"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Job {self.task_type!r} status={self.status!r} attempts={self.attempts}>"
