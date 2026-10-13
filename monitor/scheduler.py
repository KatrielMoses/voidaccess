"""
APScheduler-based background runner for monitor watches.
Uses AsyncIOScheduler to properly integrate with the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Coroutine

from monitor import jobs
from monitor.alerts import evaluate_and_dispatch_alerts
from monitor.config import load_watches
logger = logging.getLogger(__name__)


def _wrap_keyword(watch: dict, llm) -> Coroutine[Any, Any, None]:
    """
    Create an async job function for keyword watches.
    Returns a coroutine that can be awaited.
    """
    async def _run_watch() -> None:
        if not _watch_is_active(watch):
            return
        result = await jobs.run_keyword_watch(watch, llm=llm)
        await evaluate_and_dispatch_alerts(watch, result)

    return _run_watch


def _wrap_url(watch: dict, llm) -> Coroutine[Any, Any, None]:
    """
    Create an async job function for URL watches.
    Returns a coroutine that can be awaited.
    """
    async def _run_watch() -> None:
        if not _watch_is_active(watch):
            return
        result = await jobs.run_url_watch(watch, llm=llm if watch.get("use_llm", False) else None)
        await evaluate_and_dispatch_alerts(watch, result)

    return _run_watch


def _wrap_seed_refresh() -> Coroutine[Any, Any, None]:
    """Create an async job function for seed data refresh."""
    async def _run_refresh() -> None:
        await jobs.refresh_seed_data()

    return _run_refresh


def _wrap_seed_validation() -> Coroutine[Any, Any, None]:
    """Create an async job function for .onion seed reachability validation."""
    async def _run_validation() -> None:
        await jobs.validate_seeds_job()

    return _run_validation


def start_scheduler(llm=None, event_loop: asyncio.AbstractEventLoop | None = None):
    """
    Register interval jobs for each enabled watch. Returns AsyncIOScheduler or None.

    Args:
        llm: Optional LLM instance for keyword watches
        event_loop: Optional event loop to use. If not provided, attempts to get the running loop.
    """
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler  # noqa: PLC0415
        from apscheduler.triggers.interval import IntervalTrigger  # noqa: PLC0415
        from apscheduler.triggers.cron import CronTrigger  # noqa: PLC0415
    except ImportError:
        logger.warning("APScheduler not installed; scheduler disabled")
        return None

    if event_loop is None:
        try:
            event_loop = asyncio.get_running_loop()
            logger.debug("Using existing event loop for scheduler")
        except RuntimeError:
            logger.debug("No running event loop, creating new one")
            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)

    watches = [w for w in load_watches() if w.get("enabled", True)]
    scheduler = AsyncIOScheduler(event_loop=event_loop)

    for w in watches:
        wid = w.get("scheduler_id", w["name"])
        hours = float(w["interval_hours"])
        trigger = IntervalTrigger(hours=hours)
        if w.get("type") == "keyword":
            func = _wrap_keyword(w, llm)
        else:
            func = _wrap_url(w, llm)
        try:
            scheduler.add_job(
                func,
                trigger=trigger,
                id=wid,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
        except Exception as exc:
            logger.error("Failed to add job %r: %s", wid, exc)

    try:
        scheduler.add_job(
            _wrap_seed_refresh(),
            trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
            id="weekly_seed_refresh",
            replace_existing=True,
        )
    except Exception as exc:
        logger.error("Failed to add weekly_seed_refresh job: %s", exc)

    try:
        scheduler.add_job(
            _wrap_seed_validation(),
            trigger=CronTrigger(day_of_week="sun", hour=2, minute=0),
            id="seed_validation",
            replace_existing=True,
        )
    except Exception as exc:
        logger.error("Failed to add seed_validation job: %s", exc)

    try:
        scheduler.start()
    except Exception as exc:
        logger.error("Scheduler start failed: %s", exc)
        return None

    logger.info("AsyncIOScheduler started with %d jobs", len(watches) + 2)
    return scheduler


def stop_scheduler(scheduler) -> None:
    if scheduler is None:
        return
    try:
        scheduler.shutdown(wait=True)
    except Exception as exc:
        logger.warning("scheduler shutdown: %s", exc)


def get_job_status(scheduler) -> list[dict]:
    """Return {name, next_run_time, last_run_time} for each job."""
    if scheduler is None:
        return []
    out: list[dict] = []
    try:
        for job in scheduler.get_jobs():
            next_t = job.next_run_time
            last_t = getattr(job, "last_run_time", None)
            out.append(
                {
                    "name": job.id,
                    "next_run_time": next_t,
                    "last_run_time": last_t,
                }
            )
    except Exception as exc:
        logger.warning("get_job_status: %s", exc)
    return out


def trigger_job_now(scheduler, watch_name: str) -> bool:
    """Run the watch job as soon as possible (reschedule to now)."""
    if scheduler is None:
        return False
    try:
        job = scheduler.get_job(watch_name)
        if job is None:
            return False
        scheduler.modify_job(
            watch_name,
            next_run_time=datetime.now(timezone.utc),
        )
        return True
    except Exception as exc:
        logger.warning("trigger_job_now: %s", exc)
        return False


def _watch_is_active(watch):
    if not watch.get("scheduler_id"):
        return True
    import uuid
    from db.models import Monitor
    from db.session import get_session
    with get_session() as session:
        return session.query(Monitor.id).filter_by(id=uuid.UUID(watch["scheduler_id"]), user_id=watch["user_id"], enabled=True, deleted=False).first() is not None
