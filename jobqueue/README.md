# jobqueue — durable DB-backed job queue + worker (P2.3)

The restart-safe substrate the central service runs background work on. Built on
the existing database — **no Redis, no broker** — so the whole stack deploys on
one $0 always-on box, on SQLite or PostgreSQL. It closes the audit's #1
structural ceiling: today the multi-minute pipeline runs in FastAPI
`BackgroundTasks`, so a process restart orphans every in-flight investigation (a
sweeper flips them to `failed`). Now dispatch is durable.

## What it replaces

- **Server dispatch** moves off `BackgroundTasks` onto the queue. `POST
  /investigations` enqueues an `investigation` job (keyed to the investigation
  via `dedup_key`); a worker in the API lifespan claims and runs the existing
  `_run_investigation_task`. An investigation interrupted by a restart is
  **resumed/re-queued** by a worker on reboot — not orphaned.
- **The startup sweeper is now a backstop**, not the primary recovery: it only
  fails `processing` investigations that have *no* live (queued/running) job.
- **The CLI stays synchronous.** `voidaccess investigate` runs in-process as
  before; it never enqueues or runs a worker. The shared pipeline logic is
  unchanged — only the server's dispatch moved.

## Portable atomic claim (no double-execution)

`claim_one` is one interface with a per-dialect strategy:

| Backend | Strategy |
|---|---|
| **PostgreSQL** | candidate `SELECT … FOR UPDATE SKIP LOCKED` — workers never contend on the same row |
| **SQLite** | guarded `UPDATE … WHERE id=:cand AND status='queued'` + `rowcount` check — SQLite serializes writers, so exactly one worker's update matches; losers retry the next row |

Both guarantee a row leaves `queued` under a write only one worker can win — **no
job is executed twice**. `OperationalError` ("database is locked") under SQLite
contention is caught and retried.

## Restart survival

A claimed row carries `lease_expires_at`. Two recoveries:

- **Reboot** (`requeue_orphans(all_running=True)`, run at startup): every
  `running` row belonged to the dead process → requeued wholesale.
- **Mid-life** (`requeue_orphans(all_running=False)`, the periodic reaper): only
  rows whose lease lapsed (a worker that died while the server stayed up).

A row that has used all `max_attempts` is marked `failed` instead of requeued,
so crashes can't retry forever.

## Lifecycle

`queued` → `running` → `done` | `failed`. `fail_or_retry` requeues with a
pacing-scaled backoff (`available_at`) until attempts are exhausted, then fails.

## Public API

```python
from jobqueue import (
    enqueue, claim_one, complete, fail_or_retry, requeue_orphans,
    active_dedup_keys, stats,                       # queue ops
    register_handler, run_once, worker_loop, start_workers, reaper_loop,  # worker
)
```

- `enqueue(session, task_type, payload, *, dedup_key=None, priority=100, max_attempts=3, available_at=None)`
- `claim_one(session, worker_id, *, task_types=None, lease_seconds=…) -> Job | None`
- `register_handler(task_type, async_fn)` — `async_fn(payload: dict)`
- `start_workers(n=1, *, task_types=None) -> list[asyncio.Task]` (workers + reaper)

## Configuration

- `VOIDACCESS_QUEUE_WORKERS` — worker count (default 1).
- `VOIDACCESS_DISABLE_QUEUE_WORKER=true` — don't start workers (dispatch still enqueues).
- `VOIDACCESS_JOB_LEASE_SECONDS` — claim lease (default 3600; > the 30-min investigation hard timeout).

Poll cadence and retry backoff flow through `pacing` (CC-4). Timing that is a
correctness parameter (the lease) is a named, env-overridable constant.

## Tests

`tests/test_jobqueue.py` — atomic claim under concurrent workers (no double
execution), retry-then-fail, reboot + lease-based restart survival, the worker
running a registered handler, and the dedup-key backstop query.
