# shared_corpus — the shared tier (P2.0)

VoidAccess persists two kinds of data with two very different lifecycles. This
module owns the **shared** one.

| Tier | Lives in | Holds | Access |
|---|---|---|---|
| **Private** | `db.models` (`Investigation`, …) | `query`, `refined_query`, `summary`, `user_id` | Owning user only. Never exposed to another user or the shared corpus. |
| **Shared** | `shared_corpus.models` | `discovered_onions`, `page_snapshots`, `global_entities`, `source_reputations`, `global_entity_sources` | Corpus-wide, user-agnostic. Accelerates future investigations. |

The point of the split: one user's *observations* (which onions exist, what page
content was captured, which canonical IOCs were seen) should speed up the next
investigation — cache hits, seed expansion, pre-extracted entities — **without**
revealing who searched for what.

## Why this is a separate tier, not columns on the existing tables

`db.models.Entity` already straddles both lifecycles: it records a
per-investigation, per-page *observation* **and** carries cross-investigation
canonical-identity fields. Rather than overload one table with two lifecycles,
the shared canonical entity is modeled as a first-class row here
(`GlobalEntity`), distinct from the per-investigation `Entity` observation. The
private-tier tables are left untouched, so the existing pipeline keeps working
(project rule CC-3).

## The boundary is enforced, not conventional

`shared_corpus.access._enforce_tier_separation()` runs at **import time** and
raises if any shared-tier table grows a private-framing column (`user_id`,
`investigation_id`, `query`, `refined_query`, `summary`, …). Adding such a
column makes this package fail to import and the test-suite red — the boundary
"cannot be crossed by accident" (the P2.0 acceptance goal).

`to_shared_dict(row)` is the canonical user-safe read shape; by the invariant
above it provably contains no private fields.

The other half of the boundary — "private rows are scoped to their owner" — has
one canonical implementation here too: `owned_investigation_ids()` /
`filter_investigations_for_user()`, both of which **fail closed** for a `None`
user (match nothing, never everything).

## One ORM definition, both schema paths

The shared tables are declared on the *same* `db.models.Base` as the private
tier, so a single definition materializes identically on both of VoidAccess's
schema paths:

- **SQLite / CLI / tests** — `Base.metadata.create_all(engine)` (via
  `voidaccess_cli.adapters.sqlite.init_db` and `tests/conftest.py`).
- **PostgreSQL** — Alembic migration `0027_add_shared_corpus_tier`.

No hand-written `CREATE TABLE` mirrors these anywhere, so the shared tier is
**not** born into the Alembic-vs-raw-SQL drift the audit flagged. Registration
on `Base.metadata` is guaranteed by a bottom-of-file import in `db.models`
(order-independent) and re-stated in `db.migrations.env`.

## The dedup race, closed

The old global-entity dedup relied on a **non-unique** index
(`ix_entity_canonical`) plus an application-level SELECT-then-INSERT in
`db.queries.upsert_entity_canonical`, so two concurrent writers could
double-insert the same canonical entity. `global_entities` instead has a
**DB-level** `UniqueConstraint(entity_type, canonical_value)`
(`uq_global_entity_type_canonical`), and `access.upsert_global_entity` writes
through `INSERT … ON CONFLICT DO NOTHING` (PostgreSQL + SQLite) with a portable
savepoint fallback. One row per canonical entity is now a database guarantee —
which the P4 trust gate's corroboration counting depends on.

## Single identity path

Canonical identity is computed **only** via
`extractor.identity.entity_canonical_id`; there is no second canonicalization in
this module. `grep -rn "canonical_value or value"` stays clean.

## Public API

```python
from shared_corpus import (
    DiscoveredOnion, PageSnapshot, GlobalEntity, ConfidenceTier,
    upsert_global_entity, record_discovered_onion, record_page_snapshot,
    to_shared_dict, owned_investigation_ids, filter_investigations_for_user,
)
```

- `upsert_global_entity(session, entity_type, value, *, display_value=None)` →
  `(GlobalEntity, created)` — collision-safe.
- `record_discovered_onion(session, onion_address, …)` → `(DiscoveredOnion, created)`.
- `record_page_snapshot(session, content_hash, url, …)` → `(PageSnapshot, created)`.
- `to_shared_dict(row)` → user-safe dict of a shared row.

## Write-to-shared through the trust gate (P4.1)

`shared_corpus/promote.py` is the write path that fills the corpus as a
**byproduct of normal use** (spec 2.3). After extraction, each observed entity
runs through the full P4.0 `trust_gate` and is persisted at the **gate-assigned**
tier — never a tier chosen here.

- `EntityObservation` + `load_corpus_state(session, observations)` — the small
  typed contract (batch-loads corroboration source-sets + reputation in three
  queries, no N+1). P4.3's ingest path reuses this same contract.
- `promote_entities(session, observations, …)` — consent-gated, non-fatal,
  collision-safe: runs the gate per artifact (state advanced in memory so
  multiple sources within one investigation corroborate), then persists via
  `upsert_global_entity(confidence_tier=…, corroboration_count=…)` +
  `record_global_entity_source` + `upsert_source_reputation`.
- `observations_from_investigation` / `promote_investigation` — the API/CLI seam;
  `feed_hits` are derived **platform-side** from each entity's `feed:<name>` tags
  (written by `feeds/` matching, P1.4), filtered to the trusted-feed allowlist —
  never from investigation input.
- **New tables.** `source_reputations` (per-source reliability — P4.0 store) and
  `global_entity_sources` (the corroboration source-set: distinct rows per entity
  = the independent-source count, `uq_global_entity_source` prevents inflation).
- **Queryable provenance (spec 3.4).** `entity_provenance(session, type, value)`
  → the entity's tier + corroboration count + first_seen, plus each contributing
  source with its first_seen and trusted-feed cross-hits.

Tiers only ever **rise** (`_raise_entity_tier` guards against a concurrent
lower-tier write demoting a promoted row). The gate remains the only tier
assigner: `upsert_global_entity` still defaults to `unconfirmed` when called
without a gate-supplied tier.

## Read-from-shared before scraping (P4.2)

`shared_corpus/read.py` is the read half that makes the populated corpus pay off.
Before the pipeline scrapes over Tor it calls `read_shared_before_scrape(session,
query, urls)` — the one call the API (folded into the STEP 4.5 cache lookup) and
CLI (Step 3.9, before scraping) both make — which consults the shared tier
populated by *other users' runs*:

- **Cached content** (`serve_shared_snapshots`) — serves a URL's stored snapshot
  and **skips the Tor re-scrape** (point 2 of the four-point standard), but only
  when it is **fresh** (within the P3.3 `FRESHNESS_STALE_AFTER_SECONDS` window)
  and its onion is **alive** — a stale or dead/dropped snapshot falls through to a
  live scrape, never a stale serve. Batched (one query for snapshots, one for
  onions), object reads via `snapshot_store.read_snapshot`.
- **Known seeds** (`relevant_seeds`) — query-relevant, non-dead discovered onions
  added to the scrape queue.
- **Pre-extracted entities** (`relevant_entities`) — query-relevant global
  entities, ranked trusted-first and tagged with `confidence_tier` + `trust_weight`
  + `trusted`, so consumers **respect the tier**: `unconfirmed` is visible but
  down-weighted and labeled "(unverified)", never silently trusted (spec 3.3).

**Privacy (the 2.2 acceptance) is airtight by construction:** every query hits only
`page_snapshots` / `discovered_onions` / `global_entities` (+ the object store) —
never a private-tier table — so one user's run accelerates the next without ever
exposing that user's investigation/query/report. `tests/test_shared_read.py`
asserts (via captured SQL) the read path's table set ⊆ the three shared tables.
Consent-gated (P2.4): corpus sharing is opt-in. Private mode reads nothing central (`skipped_private=True`),
and the $0/no-corpus path serves nothing without crashing.

The served cache-hit count flows into the `pages_cache_hits` metric, so the
point-2 win (serve-from-cache, zero re-scrape) is measurable. The local 24h vector
cache and this persistent shared snapshot cache are **layered** (shared first, then
vector, then live scrape) rather than merged: the shared cache is sanitized +
consent-gated + liveness-gated, whereas the local vector cache holds raw text with
its own semantics — unifying them would change the local cache's sanitization
contract.

## Explicitly out of scope (later phases)

- The R2 object store itself (P2.1) — `page_snapshots.storage_ref` is modeled
  here; the upload/serve wiring is not.
- The cross-install ingest API (P4.3).
- Observability dashboards (P4.4) — the gate/promotion emit the counters they
  consume.

## Tests

`tests/test_shared_corpus.py` covers the tier-separation invariant, the user-safe
projection, private-tier owner scoping (fail-closed), collision-safe upsert under
concurrent writers, and the single-identity-path guarantee.
`tests/test_corpus_promotion.py` covers the P4.1 write path: promotion at
gate-assigned tiers, corroboration (in-batch + across passes), feed-validation,
platform-derived `feed_hits`, queryable provenance, private-mode no-op,
collision-safety, and non-fatal skipping.
