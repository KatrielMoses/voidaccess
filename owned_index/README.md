
# `owned_index/` — the owned, persistent, semantically-ranked page index (P3.0)

The differentiator epic (requirements **1.3** / **1.7** / **1.8**). Today search
depends entirely on third-party `.onion` engines — when they die, coverage dies.
`owned_index/` stands up an **owned** keyword + semantic index over the sanitized
page snapshots we already store, so search has a source that survives any
external engine going dark. It runs on **Meilisearch**.

P3.0 is the index itself — the storage + search capability. It is deliberately
**not** the population (Ahmia + usage-seeded — P3.1), the wiring into the
investigation search fan-out (P3.2), or the freshness/re-crawl loop (P3.3).

## What it is

A **central-service / shared-tier** component: the index lives on the Oracle box
alongside the shared corpus. A local/`$0` install or a private-mode install that
does not configure Meilisearch simply **falls back to live fan-out** — the index
no-ops cleanly and the tool never crashes.

## Configuration

Set in `.env` (all optional; see `.env.example`):

| Var | Meaning |
|---|---|
| `MEILI_HOST` | Base URL of the Meilisearch instance, e.g. `http://127.0.0.1:7700`. **The sole "configured" gate** — unset → the index no-ops and search falls back to fan-out. |
| `MEILI_KEY` | Master/API key. Empty is valid for a keyless local dev container (the `Authorization` header is then omitted). |
| `MEILI_INDEX` | Index uid (default `onion_pages`). |

`MeiliConfig.from_config()` reads these **live** (so tests can monkeypatch and a
late `.env` takes effect) and returns `None` when `MEILI_HOST` is unset.

## Index schema (requirement 1.3, exact fields)

Stored per document: `url`, `title`, `content_snapshot_ref`, `content_hash`,
`first_seen`, `last_seen`, `liveness`, `language`, `category` — plus a `content`
field holding the **sanitized snapshot text** that is actually searched, and a
user-provided `_vectors` payload.

| Attribute role | Fields |
|---|---|
| **primary key** | `content_hash` (→ dedup, see below) |
| **searchable** | `title`, `content` |
| **filterable** | `liveness`, `language`, `category`, `first_seen`, `last_seen` |
| **sortable** | `first_seen`, `last_seen` |
| **vectors** | user-provided, `default` embedder, 384-dim |

A document is built by joining a `page_snapshots` row (url / content_hash /
storage_ref / first_seen / last_seen / language) with its `DiscoveredOnion`
(title / category / `status` = liveness). `first_seen`/`last_seen` are stored as
epoch seconds so numeric range filters work.

A hit's `content_snapshot_ref` resolves back to the R2 snapshot via the existing
`snapshot_store.read_snapshot` — no duplicate ref→content lookup is added.

## Public API

| Symbol | Role |
|---|---|
| `OwnedIndex.from_config()` | High-level handle, or `None` when unconfigured. |
| `OwnedIndex.ensure_ready()` | Create index + apply 1.3 settings (idempotent). |
| `OwnedIndex.upsert_document(**fields)` / `upsert_snapshot(snapshot, content, onion=)` | Build (sanitize + embed) and upsert a document; dedup by `content_hash`. |
| `OwnedIndex.get(content_hash)` | Read one document back. |
| `OwnedIndex.search(query, filters=, limit=, semantic_ratio=, keyword_only=)` | Hybrid keyword+semantic search → ranked `SearchHit`s. |
| `index_snapshot(...)` / `search_index(...)` / `ensure_index()` | Module-level helpers that fold in the "unconfigured → no-op / `[]`" check. |
| `read_hit_content(hit)` | Resolve a hit → sanitized R2 bytes via `snapshot_store`. |
| `build_document(...)` / `document_from_snapshot(...)` | The schema doc builders (the sanitization gate lives here). |

## Design decisions

- **No `meilisearch` SDK dependency.** Like `snapshot_store` declines boto3, the
  client (`client.py`) hand-rolls the REST calls over the shared clearnet
  `aiohttp` session (`netpool`), with timeouts/retries from `pacing` (CC-4). It
  mocks cleanly with `aioresponses`, so no Meilisearch is needed in CI for the
  unit tests. Meilisearch is our own infra (not a third-party quota), so plain
  `pacing.scale_timeout` / `pacing.retry_plan` apply — not `scale_delay_floor`.
- **Reuse the existing embedder — no new embedding service.** Vectors come from
  `vector.embed_text` (MiniLM, with the SHA-256 fallback), supplied to Meili as
  *user-provided* vectors. `grep -rn "embed_text" owned_index/` shows the single
  reuse point in `index.py`; there is no new embedding dependency.
- **Dedup by `content_hash` is automatic.** `content_hash` (P2.0/P2.1, computed
  over the *sanitized* bytes) is the Meili primary key, so re-indexing identical
  content replaces the document rather than duplicating it. No second hashing
  path is introduced.
- **Legal invariant: the index ingests only sanitized content.** Every document
  is built through `sanitizer.sanitize_page` — the single shared choke point the
  snapshot store also uses. If the gate drops the text (empty, content-safety
  flagged, or fail-closed when NER is unavailable) nothing is indexed. Raw
  creds/PII therefore can never enter the index even if an upstream caller
  forgot to sanitize.
- **Vector config is best-effort.** Core settings must apply; the user-provided
  embedder is enabled best-effort so the index still stands up (keyword-only) on
  a Meilisearch build where vector search is not enabled.

## Out of scope / deferred

- Ahmia crawler adoption + usage-seeded population — **P3.1**.
- Wiring the index into the investigation search fan-out + merged result
  ranking — **P3.2**.
- The freshness / re-crawl loop (liveness + content-diff) — **P3.3**.
- The live Meilisearch/Oracle deploy (the P2→P3 boundary validation, which the
  one real-Meili integration test rides on).

## Tests

```bash
pytest tests/test_owned_index.py
```

Unit tests run against a `FakeMeiliClient` (an in-memory stand-in keyed by
`content_hash`) — no network. The one real-Meilisearch integration test is gated
by the `MEILI_TEST_URL` environment variable and skips when it is unset (it rides
the P2→P3 deploy validation).
