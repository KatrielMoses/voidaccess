# progress/

The official progress hook for investigations. The CLI pipeline reports to a
`ProgressEmitter`; anything that wants to watch a run subscribes a **sink**.
It replaces the old approach of monkey-patching the Rich display class and
parsing its display strings.

## Event shape

`ProgressEvent` follows `ENGINE-CONTRACT.md` §2:

| field | meaning |
|---|---|
| `type` | `stage` \| `counts` \| `refined` \| `completed` \| `failed` \| `cancelled` \| `trace` (opt-in, below) |
| `schema` | `2` on every event |
| `stage` | one of the 8 stages below (on `stage` / `refined` events) |
| `stage_index`, `stage_total` | 1-based position in execution order, and `8` |
| `counts` | cumulative, **numeric**: `sources_queried`, `results_found`, `pages_fetched`, `entities_found`, `actors_found` |
| `refined_queries` | on `refined`: the refined query list |
| `message` | short human label, never raw dark-web text |
| `stages_completed`, `reason` | on `failed` / `cancelled` (`blocked_query`, `no_results`, `deadline`, `error`, `cancelled`) |
| `metrics` | on terminal events: `stage_ms` per stage. On `completed` (CLI) also `source_requests` (HTTP calls per source id), `source_requests_by_step`, `sources_status`, `summary_kind`, and `report_path` / `data_path` (the output files; `--quiet` prints nothing, so this is where a runner finds them) |
| `run_id`, `seq`, `at` | stamped by the emitter (`seq` is monotonic from 1) |

JSON Schema for every event: `schema/progress-v2.schema.json`.

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

## Trace events (schema 2, opt-in)

Off unless `VOIDACCESS_TRACE_EVENTS=1`, `voidaccess investigate --trace`, or
`ProgressEmitter(trace=True)`. With tracing off nothing below is emitted and a run
is unchanged. Shape: `{type: "trace", schema: 2, run_id, seq, at, stage, kind, data}`.

| kind | data (`*` always present) | emitted |
|---|---|---|
| `query.refined` | `index`\*, `text`\* (≤ 200 chars) | refine (index 0); collect for the LLM's alternative queries (1, 2) |
| `search.request` | `engine`\*, `query_index`\* | each Tor engine and side source (`paste_sites`, `github`, `gitlab`, `rss`, `onion_search`, `telegram`) |
| `search.result` | `engine`\*, `query_index`\*, `status`\* (`ok` `error` `timeout` `disabled` `no_key`), `results`\*, `ms` | when it answers; circuit-open engines report `disabled` with no request |
| `url.found` | `url_id`\*, `host`\*, `engine`, `depth` (0 = seed) | first sighting of a URL |
| `url.kept` | `url_id`\*, `score` (0..1, the semantic rank when there is one) | filter; shared-corpus seeds in fetch |
| `url.dropped` | `url_id`\*, `reason`\* (`duplicate` `irrelevant` `cap` `invalid` `ssrf` `safety` `disabled_source`) | collect, filter, fetch |
| `page.fetched` | `url_id`\*, `outcome`\* (`ok` `http_404` `http_4xx` `http_5xx` `timeout` `tor_error` `too_large` `safety_dropped` `empty` `error`), `http_status`, `bytes`, `ms` | fetch |
| `page.entities` | `url_id`\*, `by_type`\* (`{TYPE: count}`) | extract, for pages whose entities were kept |
| `entity.found` | `entity_id`\*, `type`\*, `display`\* (masked, ≤ 80), `confidence`, `url_id` | extract (enrich for enrichment-page entities), once per entity |
| `enrich.source` | `source`\*, `status`\* (`ok` `error` `timeout` `disabled` `no_key` `skipped`), `hits` | enrich, per source |
| `graph.progress` | `nodes`\*, `edges`\*, `communities` | graph |
| `summary.status` | `kind`\* (`llm` `fallback` `none`), `attempt` | summarize |
| `filter_fallback` | `scope`\* (`onion` `clearnet`), `candidates`\*, `kept`\* | filter, when the LLM filter returned nothing usable and the candidates were kept by default (counts only) |
| `trace.truncated` | `kind`\*, `dropped`\* | once per capped kind, just before the terminal event |

Rules a consumer can rely on:

- `url_id` (`u17`) and `entity_id` (`e204`) are unique within a run; one URL keeps
  its id from `url.found` to `page.entities`.
- A host is never a URL: onions are `lockbit3…xyz7[.]onion`, clearnet hosts are
  defanged (`example[.]com`). A name that says too much (a vanity onion prefix
  or hostname with a child-abuse, sexual or violence-for-hire term, or a result
  title with one) is masked: `********…fcid[.]onion`. No paths, query strings,
  page text, titles, raw credentials, emails, phones or names
  (`progress/trace.py::mask_entity`).
- Content safety: a blocked URL is only ever `url.dropped {url_id, reason: "safety"}`;
  a blocked page is only `page.fetched {url_id, outcome: "safety_dropped"}`, with no
  later events for that id. Its host may already have been shown by `url.found`
  (the URL passed the URL check), so hide it on `safety_dropped`. A blocked query
  emits no trace at all.
- Caps (`VOIDACCESS_TRACE_CAPS`, `VOIDACCESS_TRACE_MAX_EVENTS`): `url.found`,
  `url.kept`, `url.dropped` 600 each, `page.fetched` 400, `entity.found` 300, the
  rest 200, at most 3,000 per run. Overflow is counted, then reported once per kind.
- `seq` is monotonic across trace and schema-1 events. Expect gaps: traces are the
  first thing dropped when a sink falls behind.
- A later `page.fetched` for the same `url_id` supersedes an earlier one (a
  post-scrape gate can still drop a page as `safety_dropped`).

`ProgressEmitter.trace(stage, kind, data)` is the low-level call; pipeline code
uses the hooks in `progress/trace.py` (`url_found`, `page_fetched`, ...), which
build display-safe data and do nothing when tracing is off.

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
  bounded queue (`EVENT_QUEUE_MAX`, or `TRACE_QUEUE_MAX` with tracing on). A slow
  sink cannot block a stage. When the queue is full, `trace` events are dropped
  first, then intermediate `counts` events; `stage`, `refined` and terminal events
  are never dropped.
- `ProgressEmitter.close()` flushes with a bounded wait (`EVENT_FLUSH_TIMEOUT_S`).
  With tracing on, queued traces still waiting after half that wait are shed so
  the terminal event goes out.
- Inline sinks (the Rich display) never receive `trace` events.
- Display UI calls travel as internal `display` events that only the Rich sink
  consumes; `JsonlSink` and `CallbackSink` ignore them.

## API path

The FastAPI pipeline (`api/routes/investigations.py`) keeps its DB progress
columns (`current_step`, `current_step_label`) and does **not** emit these events
yet. Its steps map onto the same 8 stages, but its progress updates go through
`_update_progress` with step numbers and labels, interleaved with DB-session
handling and SSE; wiring an emitter through it is a separate change.
