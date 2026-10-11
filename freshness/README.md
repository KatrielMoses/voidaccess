
# `freshness/` — the owned-index freshness loop (P3.3)

Point 3 of the four-point standard (requirement 1.6). The owned index goes stale
without maintenance. This module adds a **scheduled re-crawl of previously-seen
onions** for liveness + content-diff — updating `last_seen`/liveness, refreshing
changed snapshots + re-indexing, and feeding diffs to the monitor subsystem.

It runs on the **P2.3 durable queue**, not a fresh in-process scheduler (the audit
flagged the existing APScheduler as dying on restart), so a re-crawl **survives a
reboot**. It is bounded and cost-controlled: staleness-prioritized and capped per
cycle, never an exhaustive re-crawl.

## How it works — two durable-queue task types

| Task | Handler | Role |
|---|---|---|
| `freshness_scan` | `scheduler.freshness_scan_handler` | The periodic enqueuer. Enqueues a bounded, staleness-prioritized batch of `freshness_recrawl` jobs, then **re-enqueues itself** with a future `available_at` (the durable "cron tick"). |
| `freshness_recrawl` | `recrawl.recrawl_handler` | Re-fetch one onion over Tor; update liveness + `last_seen`; on content change, store a new sanitized snapshot + re-index + feed a diff to the monitor. |

There is no in-process timer. The scan is a persisted job whose `available_at`
gates when it may next run; a restart's orphan-requeue re-runs an interrupted
scan, and an enqueued re-crawl is just a durable row waiting to be claimed —
that is the restart-safety guarantee.

## Bounded / cost-controlled (the 1.4 / 1.6 acceptance)

- `select_stale_onions` returns onions whose `last_seen` is older than
  `FRESHNESS_STALE_AFTER_SECONDS`, **oldest first**, excluding `dropped` onions.
- Each cycle enqueues **at most `FRESHNESS_BATCH_CAP`** re-crawl jobs — a hard cap,
  so re-crawl volume never balloons regardless of index size. No exhaustive crawl.
- Re-crawl jobs run at a lower queue priority (200) than live investigations (100),
  so freshness never preempts a user's investigation.
- The Tor fetch uses the existing scrape path (pacing-aware, CC-4).

## Change detection (reuse, not rebuild)

The re-crawl sanitizes the fetched text **once** (`sanitizer.sanitize_page`) and
hash-compares against the stored snapshot's `content_hash` (P2.1). Unchanged →
stop. Changed → re-index via the P3.1 `index_sanitized_page` path (so the single
NER pass + provenance + `content_hash` dedup all apply — nothing reimplemented),
then `monitor/diff.py::compute_diff` + `is_significant_change` produce a diff that
is handed to the existing monitor/alert subsystem via
`monitor.alerts.evaluate_and_dispatch_alerts` (a `MonitorAlert` row + delivery).

## Liveness → retrieval + the dead→drop policy

- A re-crawl sets `DiscoveredOnion.status` to `alive` or `dead` and updates
  `last_seen`. `consecutive_dead` counts consecutive dead re-crawls (reset to 0 on
  any live one).
- At `FRESHNESS_DEAD_DROP_THRESHOLD` consecutive dead re-crawls the onion is marked
  **`dropped`** — terminal: it is excluded from re-crawl scheduling (stops burning
  budget) and filtered from retrieval.
- **Retrieval reads liveness** (P3.2): `search/ranking.py` filters owned-index hits
  whose onion is `dead` or `dropped` (consulting the authoritative
  `discovered_onions.status`, not the possibly-stale index doc). A `dead` onion
  that comes back alive on a later re-crawl is un-filtered automatically.

## Configuration (env-tunable, `config.py`)

| Var | Default | Meaning |
|---|---|---|
| `FRESHNESS_INTERVAL_SECONDS` | 21600 (6h) | Seconds between scan ticks. |
| `FRESHNESS_BATCH_CAP` | 20 | Max onions re-crawled per cycle. |
| `FRESHNESS_STALE_AFTER_SECONDS` | 86400 (24h) | `last_seen` age at which an onion is due. |
| `FRESHNESS_DEAD_DROP_THRESHOLD` | 3 | Consecutive dead re-crawls before `dropped`. |

## Unconfigured / local-$0 → inert

- `bootstrap()` seeds nothing when the owned index is unconfigured or in private
  mode — no scan chain, fully inert.
- Enqueuing no-ops without a database, without consent, or without an index.
- The durable-queue worker only runs in the API/central-service process; the CLI
  stays synchronous and never re-crawls. So a local/$0 install never runs the loop.

## Wiring

`register_handlers()` (both task handlers) and `bootstrap(session)` (seed the scan
chain) are called from the API startup lifespan (`api/main.py`), right beside the
investigation-handler registration and the reboot orphan-requeue.

## Out of scope / deferred

- Read-from-shared / serving a cached snapshot to skip re-scraping (P4, point 2).
- The trust gate / entity promotion (P4).
- Overhauling the APScheduler monitor watches (a separate audit item — here we only
  *feed* the monitor subsystem).

## Nice-to-have (flagged, not built)

Liveness data could revive a P1.1-quarantined external search engine that has come
back online (an engine is just another host we now know is reachable). That is a
search-engine-health concern, not owned-index freshness, so it is intentionally
**not** built here — the hook would be `search.db.search_engine_stats` consuming a
liveness signal, and it can be added later without touching this loop.

## Tests

```bash
pytest tests/test_freshness.py
```

Offline: the Tor fetch is injected, the owned index is a fake client, the monitor
feed is patched, and the durable queue runs one deterministic `run_once` tick on a
file-backed SQLite DB. Covers: a stale onion is re-crawled and liveness updates;
the dead→drop policy; a changed onion → new snapshot + re-index + a monitor diff;
per-cycle cap (no exhaustive crawl); restart-safety (a queued re-crawl survives an
orphan-requeue); and the unconfigured no-op.
