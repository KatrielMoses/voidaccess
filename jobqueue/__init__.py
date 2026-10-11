"""
jobqueue — a durable, DB-backed job queue + worker (P2.3).

The restart-safe substrate the central service runs background work on, built on
the existing database (no Redis, no broker) so the whole stack deploys on one $0
box. The server's investigation dispatch runs on it; P3 (crawl/freshness) and P4
(ingest) will too. The local CLI stays synchronous and never touches the queue.

See ``jobqueue/README.md``.
"""

from jobqueue.models import Job, JobStatus
from jobqueue.queue import (
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    active_dedup_keys,
    claim_one,
    complete,
    enqueue,
    fail_or_retry,
    requeue_orphans,
    stats,
)
from jobqueue.worker import (
    register_handler,
    registered_task_types,
    reaper_loop,
    run_once,
    start_workers,
    worker_loop,
)

__all__ = [
    "Job",
    "JobStatus",
    "DEFAULT_LEASE_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "active_dedup_keys",
    "claim_one",
    "complete",
    "enqueue",
    "fail_or_retry",
    "requeue_orphans",
    "stats",
    "register_handler",
    "registered_task_types",
    "reaper_loop",
    "run_once",
    "start_workers",
    "worker_loop",
]
