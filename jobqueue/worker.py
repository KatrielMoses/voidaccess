"""
jobqueue/worker.py — the async worker loop + handler registry (P2.3).

A worker claims one job at a time from the durable queue, runs the async handler
registered for its ``task_type``, and marks it ``done`` or ``failed``/retried.
Workers run as ``asyncio`` tasks inside the API process's lifespan — the server
substrate for investigation dispatch now, and P3 crawl/freshness + P4 ingest
later. The CLI never runs a worker (it stays synchronous).

Restart safety: a reaper periodically returns lease-expired ``running`` jobs to
``queued`` (``requeue_orphans``); at startup every ``running`` row is an orphan
of the dead process and is requeued wholesale, so no in-flight work is lost.

All DB work is synchronous SQLAlchemy run in a thread (``asyncio.to_thread``) so
the event loop stays responsive while the (long, async) handler runs inline.
Poll cadence and idle backoff flow through ``pacing`` (CC-4).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from typing import Awaitable, Callable, Optional, Sequence

import pacing
from jobqueue import queue as _q

logger = logging.getLogger(__name__)

# task_type -> async handler(payload: dict) -> None
Handler = Callable[[dict], Awaitable[None]]
_HANDLERS: dict[str, Handler] = {}

# ``normal`` baselines, scaled through pacing at use.
_IDLE_POLL_SECONDS = 1.0    # sleep between polls when the queue is empty
_REAPER_INTERVAL_SECONDS = 60.0


def register_handler(task_type: str, handler: Handler) -> None:
    """Register the async handler that runs jobs of *task_type*."""
    _HANDLERS[task_type] = handler


def registered_task_types() -> list[str]:
    return list(_HANDLERS)


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


async def run_once(worker_id: str, task_types: Optional[Sequence[str]] = None) -> bool:
    """Claim and run at most one job. Returns True if a job was executed."""
    from db.session import get_session

    def _claim():
        with get_session() as session:
            job = _q.claim_one(session, worker_id, task_types=task_types)
            if job is None:
                return None
            # Detach the fields we need before the session closes.
            return (job.id, job.task_type, dict(job.payload or {}))

    claimed = await asyncio.to_thread(_claim)
    if claimed is None:
        return False
    job_id, task_type, payload = claimed

    handler = _HANDLERS.get(task_type)
    if handler is None:
        await asyncio.to_thread(
            lambda: _finish(job_id, ok=False, error=f"no handler for task_type {task_type!r}")
        )
        return True

    try:
        await handler(payload)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - queue must survive any handler error
        logger.exception("Job %s (%s) failed: %s", job_id, task_type, exc)
        await asyncio.to_thread(lambda: _finish(job_id, ok=False, error=str(exc)))
        return True

    await asyncio.to_thread(lambda: _finish(job_id, ok=True, error=""))
    return True


def _finish(job_id, *, ok: bool, error: str) -> None:
    from db.session import get_session

    with get_session() as session:
        if ok:
            _q.complete(session, job_id)
        else:
            _q.fail_or_retry(session, job_id, error)


async def worker_loop(
    worker_id: Optional[str] = None,
    *,
    task_types: Optional[Sequence[str]] = None,
    stop_when_idle: bool = False,
) -> None:
    """Run jobs until cancelled (or until idle when *stop_when_idle*)."""
    wid = worker_id or _worker_id()
    logger.info("jobqueue worker %s started (types=%s)", wid, task_types or "all")
    try:
        while True:
            try:
                did_work = await run_once(wid, task_types)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - never let the loop die
                logger.warning("worker %s iteration error: %s", wid, exc)
                did_work = False
            if not did_work:
                if stop_when_idle:
                    return
                await asyncio.sleep(pacing.scale_delay(_IDLE_POLL_SECONDS))
    except asyncio.CancelledError:
        logger.info("jobqueue worker %s cancelled", wid)
        return


async def reaper_loop() -> None:
    """Periodically requeue lease-expired ``running`` jobs (mid-life recovery)."""
    from db.session import get_session

    try:
        while True:
            await asyncio.sleep(pacing.scale_delay(_REAPER_INTERVAL_SECONDS))
            try:
                def _reap():
                    with get_session() as session:
                        return _q.requeue_orphans(session, all_running=False)

                n = await asyncio.to_thread(_reap)
                if n:
                    logger.warning("reaper requeued %d lease-expired job(s)", n)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("reaper iteration error: %s", exc)
    except asyncio.CancelledError:
        logger.info("jobqueue reaper cancelled")
        return


def start_workers(
    n: int = 1, *, task_types: Optional[Sequence[str]] = None
) -> list[asyncio.Task]:
    """Spawn *n* worker tasks plus one reaper task. Returns all tasks."""
    tasks = [
        asyncio.create_task(worker_loop(task_types=task_types), name=f"voidaccess-worker-{i}")
        for i in range(max(1, n))
    ]
    tasks.append(asyncio.create_task(reaper_loop(), name="voidaccess-jobqueue-reaper"))
    return tasks
