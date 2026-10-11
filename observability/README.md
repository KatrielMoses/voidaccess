# observability — corpus-health for the single maintainer (P4.4 / CC-5)

The moat (P4.0–P4.3) blocks poisoning; this lets the one maintainer **see** it. A
single low-ops aggregation surfaces the corpus vital signs from the counters the
gate / promote / read paths **already emit** — no parallel metrics pipeline, no
time-series store, no Prometheus/Grafana (that would violate the $0 / low-ops
north star).

## Vital signs (all point-in-time SELECTs over existing tables)

| Signal | Source (already-emitted) |
|---|---|
| **Ingest rate** (per window) | `global_entities.first_seen`, `global_entity_sources.first_seen`, `source_reputations.last_seen` |
| **Quarantine : promotion ratio** (primary poisoning signal) | `global_entities.confidence_tier` |
| **Source-reputation distribution + flagged abusers** | `source_reputations` (score, blocked, contributed, contradicted, anomalies) |
| **Distinct origins / contributors** | `global_entity_sources` (source, contributor) |
| **Index size + freshness** | `discovered_onions.status`, `page_snapshots.captured_at` |
| **Cache-hit rate** (read-from-shared effectiveness) | `investigation_step_metrics.pages_cache_hits / pages_attempted` |

`corpus_health(session, window_seconds=…)` returns them as one JSON dict. Each
section is independently guarded, so a missing/empty table (a $0/local install with
no central corpus) yields zeros — never a crash.

## Surfacing

`GET /admin/corpus-health` (JSON) — mounted on the existing admin router, so it is
**auth-protected** (`get_current_user`) and never leaks corpus internals
unauthenticated. On an install with no `DATABASE_URL` it returns
`{"available": false}`. A web panel is intentionally not added — the JSON endpoint
is the low-ops minimum the brief asks for.

## Seeing an attack in progress

The point of CC-5 is that an attack is *visible*, not merely blocked:

- A **flood of single-source / Sybil artifacts** piles up as `unconfirmed`, so
  `tiers.quarantine_ratio` spikes toward 1.0 — the primary poisoning signal.
- A **templated / mass-identical / flood batch** increments the offending
  contributor's `anomalies`, so it appears in `reputation.flagged` (ordered
  most-abusive first) and lifts `reputation.total_anomalies`.
- **Reputation movement** (contradictions, a contributor's score collapsing to
  `blocked`) is visible in `reputation.flagged` / `score_buckets`.

`tests/test_redteam_moat.py` asserts the view reflects the attack while it runs.

## No parallel pipeline

`corpus_health.py` is **read-only** — it issues only SELECTs over the emitted-counter
tables; it never writes, and adds no metrics library. If a needed signal lacked a
counter, the fix is to emit it at the gate/promote source, not to recompute it here.
(P4.4 needed none — the existing counters covered every vital sign.)
