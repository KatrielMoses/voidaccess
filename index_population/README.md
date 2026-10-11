
# `index_population/` — filling the owned index (P3.1)

P3.0 built an empty owned index. P3.1 **populates** it, from two sources
(requirement 1.4):

1. **Curated seeds** — Ahmia's known-onion list + dark.fail — for *breadth*, so a
   brand-new query still returns owned-index results before this instance has
   investigated anything. ([`seeds.py`](seeds.py))
2. **Usage-seeding** — every `.onion` page this instance's own investigations
   touch, via the existing scrape path — for *depth/relevance*. Indexing volume
   scales with usage, not with the size of Tor. ([`usage.py`](usage.py))

Everything here writes **sanitized, consent-gated, provenance-stamped** artifacts
to the **shared tier** (`discovered_onions`, `page_snapshots`, owned-index docs)
at the **unconfirmed** confidence tier. It never promotes `global_entities`,
never assigns a trust tier, never runs corroboration/quarantine/reputation, and
never opens cross-install ingest — all of that is **P4**. Rationale: indexing a
sanitized onion/page is low-poisoning-risk (a fake onion just wastes a future
crawl); the poisoning risk lives in entity/IOC *scoring*, which P4's trust gate
governs. So the index can populate now; trust-scoring of what's derived from it
waits.

## Public API

| Symbol | Role |
|---|---|
| `ingest_seed_sources(session, *, index=None)` | Fetch Ahmia + dark.fail (clearnet, TTL-cached), normalize, and write `discovered_onions` + bootstrap index docs. |
| `parse_ahmia(text)` / `parse_darkfail(html)` | Pure parsers (unit-tested against fixtures). |
| `index_investigation_pages(session, pages, *, index=…)` | The pipeline hook: auto-index the `.onion` pages an investigation touched (snapshot store + owned index). |

Both orchestrators are **graceful no-ops** in private mode and when the store/
index is unconfigured, and never raise into the pipeline (CC-3). The caller owns
the DB transaction (commit after).

## How it plugs into the pipeline

`index_investigation_pages` is called once, post-scrape / post-content-safety, in
both paths — right where the finalized page list exists:

- **API**: `api/routes/investigations.py::_run_investigation_task`, just after the
  deduped `page_records` are built (before entity extraction).
- **CLI**: `voidaccess_cli/commands/investigate.py::_run_investigation`, just
  after `page_id`s are resolved onto the finalized `scraped_pages`.

Both wrap the call in a non-fatal `try/except` and open a short-lived
`db.session.get_session()`. Clearnet side-sources (paste sites, GitHub, RSS) are
skipped automatically — only `.onion` hosts are corpus onions.

### Avoiding a double sanitization pass

The snapshot store (P2.1) and the index (P3.0) each sanitize by default. The
usage hook sanitizes **once** (`sanitizer.sanitize_page`) and passes the result
to both via `presanitized=` — one NER pass per page, the single-gate invariant
intact (the gate still ran, just at the caller).

## Design decisions

- **Seeds are ingested as DATA, reusing `sources.cache.CachedFeed`** (the feeds/
  fetch+TTL+clearnet-guard primitive) with `parse="text"` — not `BlocklistFeed`,
  whose per-entity `match()`/tagging machinery is the wrong shape for "enumerate
  a published list and upsert each onion". `CachedFeed` physically cannot fetch a
  `.onion` (clearnet-only `http_pool`), which keeps the ingester honest: it
  consumes the clearnet-published list, it does not crawl onions.
- **A small dedicated ingester, not the feeds/ class.** Flagged per the brief:
  Ahmia's plain-text list and dark.fail's HTML don't fit `BlocklistFeed`'s
  entity-matching contract, so `seeds.py` follows the feeds/ *pattern* (a
  LICENSES-style provenance registry + `CachedFeed` fetch) with dedicated
  parsers.
- **Seed liveness is `unknown`.** List membership is not proof of life; a Tor
  probe / crawl (P3.3) promotes `unknown → alive/dead`. Usage-seeded onions are
  recorded `alive` (we just scraped them).
- **Seed index docs are placeholders** keyed by a synthetic per-onion id (not a
  content hash), with no `content_snapshot_ref` and title/category as searchable
  text. When the onion is actually scraped, a real content-hash-keyed page doc is
  added alongside. Ahmia entries (no title) are searchable by their address;
  dark.fail entries by title + category — the latter demonstrate breadth ("a
  query with no prior usage surfaces a seeded onion").
- **Shared-tier only.** This ingester targets the forward-looking `DiscoveredOnion`
  shared table, not the legacy `sources/data/onion_seeds.json` `SeedManager`
  (crawler seeds). We deliberately do not mirror into the JSON store.

## Requirement 1.2 — ahmia-crawler adopt/skip evaluation

**Decision: SKIP the continuous ahmia-crawler (Scrapy) stack. Adopt only Ahmia's
data asset — the known-onion list.**

Requirement 1.2 says "adopt Ahmia's crawler, don't build bespoke." Read together
with 1.4 (incremental, usage-seeded indexing — *"indexing volume scales with
usage, not with the size of Tor"*), running ahmia-crawler continuously would
contradict the very model 1.4 prescribes and add a heavy stack to the $0 box:

- **Cost/maintenance.** ahmia-crawler is a Scrapy application that expects an
  Elasticsearch/OnionElasticSearch backend and a running Tor with a large crawl
  budget. Standing that up alongside FastAPI + Postgres + Tor + Meilisearch on a
  single low-cost VM is exactly the heavyweight footprint the project's
  low-maintenance / $0 goal rejects (and it duplicates our Meilisearch index).
- **Marginal benefit over what we already do.** ahmia-crawler's unique value is
  *broad discovery*. But P3.1 already gets (a) Ahmia's discovered breadth for
  free by ingesting its **known-onion list** as data, and (b) relevance/depth
  from **usage-seeding** the onions our investigations actually touch. A
  continuous broad crawl would mostly index onions no user has asked about —
  precisely the exhaustive-crawl volume 1.4 tells us not to chase.
- **Legal/operational surface.** A broad autonomous crawler massively widens the
  content we fetch and must sanitize/store, for little targeted value.

**What we adopt instead:** Ahmia's highest-value asset, its `/onions/` list
(plus dark.fail), ingested as data — no Scrapy, no ES, no crawl budget.

**If broad discovery is ever wanted**, the extension points are already here:
`ingest_seed_sources` (add more published lists) and the **P3.3 freshness loop**
(re-crawl + liveness), which can be pointed at a wider frontier without adopting
a second crawler stack. Revisit adoption only if seed-list + usage-seeding
demonstrably under-cover real queries.

## Tests

```bash
pytest tests/test_index_population.py
```

Parsers are tested against canned Ahmia/dark.fail fixtures; ingestion is tested
against a file-backed SQLite DB (`Base.metadata.create_all`) with the network
fetch monkeypatched and a fake owned-index client — no Meilisearch, no Tor, no
cloud. Covers: seed breadth (a seeded onion is searchable), usage-seeding volume
scaling, the private-mode no-op, and the P4 tier boundary (no `global_entities`).
