"""
freshness — P3.3: the owned-index freshness loop (requirement 1.6).

The owned index goes stale without maintenance. This module adds a scheduled
re-crawl of previously-seen onions for liveness + content-diff — updating
``last_seen``/liveness, refreshing changed snapshots + re-indexing, and feeding
diffs to the monitor subsystem — **on the P2.3 durable queue**, so a re-crawl
survives a reboot (not a fresh in-process scheduler).

Two durable-queue task types:

* ``freshness_scan`` — the periodic enqueuer (``scheduler.freshness_scan_handler``):
  enqueues a bounded, staleness-prioritized batch of re-crawl jobs, then
  re-enqueues itself with a future ``available_at`` (the "cron tick").
* ``freshness_recrawl`` — the worker (``recrawl.recrawl_handler``): re-fetch one
  onion over Tor, update liveness, and on content change store a new sanitized
  snapshot + re-index (reusing the P3.1 path) + feed a diff to the monitor.

Reuse-not-rebuild: P2.1 staleness, the P3.1 usage indexing path, ``monitor/diff.py``,
and the existing scrape + monitor/alert subsystems. Inert on a local/$0 install
(no queue worker runs there) and when the owned index is unconfigured.

Wiring: ``register_handlers()`` registers both handlers on the durable queue, and
``bootstrap(session)`` seeds the singleton scan chain — both are called from the
API startup lifespan (see ``api/main.py``). See ``freshness/README.md``.
"""

from freshness.recrawl import RecrawlOutcome, recrawl_handler, recrawl_onion
from freshness.scheduler import (
    TASK_RECRAWL,
    TASK_SCAN,
    bootstrap,
    enqueue_freshness_batch,
    freshness_scan_handler,
    rearm_scan,
    select_stale_onions,
)


def register_handlers() -> None:
    """Register the freshness task handlers on the durable queue (idempotent)."""
    from jobqueue import register_handler

    register_handler(TASK_SCAN, freshness_scan_handler)
    register_handler(TASK_RECRAWL, recrawl_handler)


__all__ = [
    "RecrawlOutcome",
    "recrawl_onion",
    "recrawl_handler",
    "TASK_SCAN",
    "TASK_RECRAWL",
    "bootstrap",
    "enqueue_freshness_batch",
    "freshness_scan_handler",
    "rearm_scan",
    "select_stale_onions",
    "register_handlers",
]
