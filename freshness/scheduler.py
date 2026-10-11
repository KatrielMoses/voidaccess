"""
freshness/scheduler.py — the periodic re-crawl enqueuer on the durable queue (P3.3).

There is no in-process timer here (the audit flagged the APScheduler monitor as
dying on restart). Instead a single ``freshness_scan`` job lives on the P2.3
durable queue and, each time it runs, (1) enqueues a bounded, staleness-prioritized
batch of ``freshness_recrawl`` jobs, then (2) re-enqueues *itself* with a future
``available_at`` — a persisted "cron tick" that survives a reboot (a restart's
orphan-requeue re-runs the interrupted scan; an enqueued re-crawl job is just a
durable row waiting to be claimed).

Bounded + cost-controlled (the 1.4/1.6 acceptance): a re-crawl cycle re-crawls at
most ``FRESHNESS_BATCH_CAP`` onions, chosen oldest-``last_seen``-first among onions
past the staleness cutoff and not already ``dropped`` — never an exhaustive crawl.

Inert on a local/$0 install: enqueuing no-ops without a database, without consent
(private mode), or when the owned index is unconfigured (nothing to keep fresh).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jobqueue import Job, active_dedup_keys, enqueue
from owned_index import OwnedIndex
from shared_corpus import DiscoveredOnion, contribution_enabled

logger = logging.getLogger(__name__)

TASK_SCAN = "freshness_scan"
TASK_RECRAWL = "freshness_recrawl"

#: dedup_key for the singleton scan chain.
_SCAN_DEDUP = "freshness_scan"

#: Re-crawl jobs run below live investigations (priority 100) so a re-crawl never
#: preempts a user's investigation on the shared worker pool.
_RECRAWL_PRIORITY = 200

# Terminal liveness — never re-crawled again.
_DROPPED = "dropped"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cfg(name: str, default: int) -> int:
    import config

    try:
        return int(getattr(config, name, default) or default)
    except (TypeError, ValueError):
        return default


def select_stale_onions(
    session: Any,
    *,
    limit: int,
    now: Optional[datetime] = None,
    stale_after: Optional[int] = None,
) -> list[DiscoveredOnion]:
    """Staleness-prioritized, capped batch of onions due for re-crawl.

    Onions past the staleness cutoff (``last_seen`` older than
    ``FRESHNESS_STALE_AFTER_SECONDS``) and not ``dropped``, oldest first, capped at
    *limit*. This is the bound that keeps re-crawl volume from ballooning.
    """
    now = now or _now()
    stale_after = stale_after if stale_after is not None else _cfg("FRESHNESS_STALE_AFTER_SECONDS", 24 * 3600)
    cutoff = now - timedelta(seconds=stale_after)
    return (
        session.query(DiscoveredOnion)
        .filter(DiscoveredOnion.status != _DROPPED)
        .filter(DiscoveredOnion.last_seen < cutoff)
        .order_by(DiscoveredOnion.last_seen.asc())
        .limit(limit)
        .all()
    )


def enqueue_freshness_batch(
    session: Any,
    *,
    cap: Optional[int] = None,
    now: Optional[datetime] = None,
) -> int:
    """Enqueue up to *cap* re-crawl jobs for the stalest onions. Returns the count.

    No-op (returns 0) in private mode or when the owned index is unconfigured —
    there is nothing to keep fresh without an index. Skips onions that already
    have a live re-crawl job (``dedup_key`` = onion address) so cycles don't pile
    duplicate work.
    """
    if not contribution_enabled():
        return 0
    if OwnedIndex.from_config() is None:
        return 0

    cap = cap if cap is not None else _cfg("FRESHNESS_BATCH_CAP", 20)
    if cap <= 0:
        return 0

    in_flight = active_dedup_keys(session, task_type=TASK_RECRAWL)
    # Over-select to still fill the cap after skipping in-flight onions.
    candidates = select_stale_onions(session, limit=cap * 2, now=now)

    enqueued = 0
    for onion in candidates:
        if enqueued >= cap:
            break
        if onion.onion_address in in_flight:
            continue
        enqueue(
            session,
            TASK_RECRAWL,
            {"onion_address": onion.onion_address},
            dedup_key=onion.onion_address,
            priority=_RECRAWL_PRIORITY,
        )
        enqueued += 1
    return enqueued


def _pending_scan_exists(session: Any) -> bool:
    """True if a not-yet-running (queued) scan tick is already scheduled.

    Checks queued-only so the *currently running* scan does not count itself —
    this is what keeps the self-re-arm from either dropping the chain or drifting
    into multiple concurrent chains across restarts.
    """
    return (
        session.query(Job.id)
        .filter(Job.task_type == TASK_SCAN, Job.status == "queued")
        .first()
        is not None
    )


def rearm_scan(session: Any, *, now: Optional[datetime] = None) -> bool:
    """Schedule the next scan tick (future ``available_at``) if none is queued."""
    if _pending_scan_exists(session):
        return False
    now = now or _now()
    interval = _cfg("FRESHNESS_INTERVAL_SECONDS", 6 * 3600)
    enqueue(
        session,
        TASK_SCAN,
        {},
        dedup_key=_SCAN_DEDUP,
        available_at=now + timedelta(seconds=interval),
    )
    return True


async def freshness_scan_handler(payload: dict) -> None:
    """Durable-queue handler: enqueue a re-crawl batch, then re-arm the next tick."""
    if not os.getenv("DATABASE_URL"):
        return
    from db.session import get_session

    with get_session() as session:
        try:
            count = enqueue_freshness_batch(session)
            logger.info("freshness scan: enqueued %d re-crawl jobs", count)
        finally:
            # Always re-arm — even if the batch step raised — so the chain survives.
            rearm_scan(session)
        session.commit()


def bootstrap(session: Any, *, now: Optional[datetime] = None) -> bool:
    """Seed the singleton scan chain if none is pending (idempotent at startup).

    Enqueues the first scan available immediately. Gated so a restart doesn't
    start a second concurrent chain, and inert (no chain seeded) when the owned
    index is unconfigured or contribution is off — nothing to keep fresh.
    """
    if not contribution_enabled() or OwnedIndex.from_config() is None:
        return False
    if _SCAN_DEDUP in active_dedup_keys(session, task_type=TASK_SCAN):
        return False
    enqueue(session, TASK_SCAN, {}, dedup_key=_SCAN_DEDUP, available_at=(now or _now()))
    return True
