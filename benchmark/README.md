# `benchmark/` — Measurement foundation (P1.0)

The project's **ruler**. Half of EPIC 1 and most of EPIC 4–5
(`docs/ENGINEERING_REQUIREMENTS.md`) are specified as "measurable reduction/
improvement vs. current baseline," and requirement 1.1 demands a repeatable live
engine probe *before* any engine is culled. This module builds the ruler and
produces the first engine report.

It is **measurement-only**: nothing here removes an engine (that is P1.1) or
changes extraction/ranking/pipeline behavior. New capabilities are parallel
modules (CC-3).

## What's here

| File | Role |
|---|---|
| `data/benchmark_queries.json` | Versioned, representative query set (ransomware, actor handles, malware families, infra indicators, credential/breach, multilingual). Extend by appending + bumping `version`. |
| `queries.py` | Load + validate the query set (`load_query_set`). |
| `artifact.py` | Canonical-JSON writer + fixed schema enumerations (entity types, phases, confidence tiers) + `confidence_tier()`. |
| `metrics.py` | Metrics harness — runs the set through the real SQLite pipeline, captures a diffable artifact. |
| `engine_probe.py` | Read-only live engine health probe over Tor (req 1.1). |
| `artifacts/` | Output dir. Commit the latest artifact for phase-over-phase `git diff`s. |

## One-command invocations

Both run entirely on the SQLite/CLI path — no Postgres, runnable locally at $0.
Tor must be running for the live paths.

```bash
# Read-only engine health probe (req 1.1). --sample N limits queries.
voidaccess benchmark probe --sample 2

# Metrics harness. No-LLM by default ($0, deterministic); --llm for the full pipeline.
voidaccess benchmark metrics
```

Both accept `--pace quiet|normal|aggressive`, `--out PATH`, `--queries PATH`, and
`--no-tor` (structural dry-run). Artifacts default to
`benchmark/artifacts/{engine-health,metrics}-latest.json`.

## Artifacts

Canonical JSON (`sort_keys=True`, trailing newline, UTF-8 preserved). The schema
is **fixed**: every entity-type bucket, confidence tier, and pipeline phase is
enumerated up front and zero-filled, so two runs on an unchanged codebase produce
structurally identical JSON — only the measured *values* move with live data.
`run.generated_at` and `run.git_commit` are provenance metadata (expected to vary /
track code).

**Metrics artifact** (`pipeline_metrics`): per-query and aggregate entity counts by
type and confidence tier, junk ratio, page cache-hit rate, extraction cache-hit
rate, pages fetched vs. empty, per-source contribution, and per-phase wall-clock.

**Engine-health artifact** (`engine_health_probe`): every catalog engine with its
catalog `status`, `success_rate`, `mean_result_count`, `mean_latency_ms`,
`error_class_counts`, `dominant_error`, and `flagged_zero`.
`summary.flagged_engine_names` lists every engine at 0% over the sample. The probe
scans the **full** catalog (including `quarantined` engines) so a P3 freshness
re-probe can revive one that comes back. (`darksearch.io` was already removed in
P1.1 — confirmed defunct — so it is no longer probed.)

### Engine cull (P1.1)

[`engine_cull.py`](engine_cull.py) turns a committed engine-health artifact into a
per-engine disposition via one documented rule (0% → `quarantined`; `<10%`
borderline → `quarantined`; confirmed-defunct → `removed`; else `active`), so every
engine's status is traceable to a baseline row. Regenerate the ledger with
`python -m benchmark.engine_cull benchmark/artifacts/engine-health-latest.json`,
then apply `quarantined` results to `search/engine_catalog.py`. The ledger of record
is [`search/ENGINE_CULL.md`](../search/ENGINE_CULL.md).

### Confidence tiers

On the persisted *effective* confidence (0..1): `high ≥0.90`, `medium ≥0.72`,
`low ≥0.42`, `junk <0.42`. The junk cut reuses the shape "reject" boundary in
`extractor/entity_shape.py:_tier_from_score`, so "junk" here means exactly what the
extractor already treats as sub-threshold noise.

### Stored vs visible junk (P1.6)

`junk_ratio` counts *all stored* entities. P1.6's low-noise ranking is
**non-destructive** — it deprioritizes/collapses low-value entities but never
deletes them — so it does not move `junk_ratio`. The harness therefore also emits
`visible_junk_ratio` and `entities_suppressed`, computed over the
**default-visible** set (entities the ranking did *not* mark `suppressed`). The gap
`junk_ratio − visible_junk_ratio` is the measurable low-value-entity reduction
Epic 4.1 asks for. The suppression levers live in `utils/entity_priority.py`
(`DEFAULT_PRIORITY_FLOOR` / `VOIDACCESS_PRIORITY_FLOOR` env override,
`PER_TYPE_DISPLAY_CAPS`); sweep the floor between baseline runs to find which lever
moves `visible_junk_ratio` most.

## Design notes

- **The probe is read-only by construction.** It reuses only the *pure*
  `search.search._fetch_engine` primitive plus `search/tor_isolation.py`. It never
  calls `record_engine_attempt` / `should_skip_engine` and never mutates
  `engine_catalog.py` or the `search_engine_stats` circuit-breaker table — so it
  measures every engine as-is, including circuit-open ones. `tests/test_benchmark.py`
  pins this by poisoning the stats functions and asserting they're never hit.
- **The metrics harness forks nothing.** It drives the CLI pipeline unchanged
  (`voidaccess_cli.commands.investigate._run_investigation`), which already persists
  per-phase timing/page/cache counters to `investigation_step_metrics` and writes a
  result JSON with entities + `sources_used` + pages. The harness reads both back.
- **Pacing (CC-4).** No hardcoded timeouts. The probe's one outer timeout derives
  from the same pacing-aware `search_config` knobs `_fetch_engine` uses, so it
  scales with `--pace`.

## Downstream

P1.2 / P4 / P5 assert deltas against a committed baseline artifact: run the harness,
`git diff benchmark/artifacts/`, and confirm the intended metric moved (e.g. EPIC
4.1's "measurable reduction in low-value entities" = a drop in
`totals.visible_junk_ratio` vs the committed baseline's `junk_ratio`, plus a
non-zero `totals.entities_suppressed`). P1.1 reads `flagged_engine_names` to decide
the cull.

## Tests

`pytest tests/test_benchmark.py` — fully offline (no Tor, LLM, or network): query-set
validation, tier boundaries, artifact determinism, metrics aggregation on sparse
input, error classification, and the probe read-only + zero-flag guarantees.
