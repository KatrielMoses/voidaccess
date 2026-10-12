# progress/

The official progress hook for investigations. The CLI pipeline reports to a
`ProgressEmitter`; anything that wants to watch a run subscribes a **sink**.
It replaces the old approach of monkey-patching the Rich display class and
parsing its display strings.

## Event shape

`ProgressEvent` follows `ENGINE-CONTRACT.md` §2:

| field | meaning |
|---|---|
| `type` | `stage` \| `counts` \| `refined` \| `completed` \| `failed` \| `cancelled` |
| `stage` | one of the 8 stages below (on `stage` / `refined` events) |
| `stage_index`, `stage_total` | 1-based position in execution order, and `8` |
| `counts` | cumulative, **numeric**: `sources_queried`, `results_found`, `pages_fetched`, `entities_found`, `actors_found` |
| `refined_queries` | on `refined`: the refined query list |
| `message` | short human label, never raw dark-web text |
| `stages_completed`, `reason` | on `failed` / `cancelled` (`blocked_query`, `no_results`, `deadline`, `error`, `cancelled`) |
| `metrics` | on terminal events: `stage_ms` per stage. On `completed` (CLI) also `source_requests` (HTTP calls per source id), `source_requests_by_step`, `sources_status`, `summary_kind`, and `report_path` / `data_path` (the output files; `--quiet` prints nothing, so this is where a runner finds them) |
| `run_id`, `seq`, `at` | stamped by the emitter (`seq` is monotonic from 1) |

Additive fields (not in the contract): `status` on `stage` events
(`start` / `end` / `skipped` / `failed`) and `duration_ms` on a stage end.

A `cancelled` event is emitted when the run is cancelled cooperatively (SIGTERM on
the CLI, `cancel_token` for an embedding caller): `stages_completed` lists only
stages that finished, and no output file is written. See `utils/cancel.py`.

### Stages and their order

`refine, collect, filter, fetch, extract, enrich, graph, summarize`

`extract` runs **before** `enrich` because enrichment is driven by the extracted
entities (CVEs, IPs, domains, hashes, emails). The contract's `Stage` union lists
`enrich` before `extract`; `stage_index` here follows real execution order.
Every run emits start and end for all eight stages; a stage that does not apply
(for example `refine` with `--no-llm`) ends with `status: "skipped"`.

## Sinks

| Sink | Use |
|---|---|
| Rich display (`voidaccess_cli.display.RichDisplaySink`) | the live terminal UI; output is identical to before |
| `JsonlSink(path)` | one JSON object per line; CLI flag `--events-jsonl PATH` |
| `CallbackSink(fn)` | in-process callback, e.g. a cloud runner forwarding to a webhook |

Anything with `handle(event)` is an `EventSink`.

## Safety guarantees

- A sink that raises is caught and logged; the run continues.
- Sinks other than the Rich display run on a daemon worker thread fed by a
  bounded queue (`EVENT_QUEUE_MAX`). A slow sink cannot block a stage. When the
  queue is full, intermediate `counts` events are dropped; `stage`, `refined`
  and terminal events are never dropped.
- `ProgressEmitter.close()` flushes with a bounded wait (`EVENT_FLUSH_TIMEOUT_S`).
- Display UI calls travel as internal `display` events that only the Rich sink
  consumes; `JsonlSink` and `CallbackSink` ignore them.

## API path

The FastAPI pipeline (`api/routes/investigations.py`) keeps its DB progress
columns (`current_step`, `current_step_label`) and does **not** emit these events
yet. Its steps map onto the same 8 stages, but its progress updates go through
`_update_progress` with step numbers and labels, interleaved with DB-session
handling and SSE; wiring an emitter through it is a separate change.
