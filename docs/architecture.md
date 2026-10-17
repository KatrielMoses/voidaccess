# VoidAccess Architecture and Technical Reference

This document describes the current state of the VoidAccess codebase. It is intended for community contributors, security researchers integrating VoidAccess into existing workflows, and developers building on top of the platform.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Investigation Pipeline](#2-investigation-pipeline)
3. [Intelligence Sources](#3-intelligence-sources)
4. [Entity Extraction](#4-entity-extraction)
5. [Enrichment Sources](#5-enrichment-sources)
6. [Graph System](#6-graph-system)
7. [Actor Intelligence Layer](#7-actor-intelligence-layer)
8. [Content Safety](#8-content-safety)
9. [Data Quality Features](#9-data-quality-features)
10. [Export Formats](#10-export-formats)
11. [Monitoring System](#11-monitoring-system)
12. [API Reference](#12-api-reference)
13. [Configuration Reference](#13-configuration-reference)
14. [Known Limitations](#14-known-limitations)

---

## 1. Architecture Overview

### 1.1 Docker Services

Four services compose the stack ([`docker-compose.yml`](../docker-compose.yml)):

| Service | Image / Build | Host Port | Role |
|---|---|---|---|
| `postgres` | postgres:16-alpine | 5433 → 5432 | Persistent storage for all investigation data |
| `tor` | custom Dockerfile.tor | 9050 → 9050 | SOCKS5 proxy for all `.onion` requests |
| `fastapi` | custom Dockerfile.fastapi | 8000 → 8000 | Python 3.11 backend; runs the investigation pipeline |
| `nextjs` | custom Dockerfile.nextjs | 3001 → 3000 | Next.js 14 frontend |

### 1.2 Service Communication

- **nextjs → fastapi**: HTTP via `NEXT_PUBLIC_API_URL` (set to `http://fastapi:8000` inside Docker). All requests carry a `Bearer` JWT.
- **fastapi → postgres**: SQLAlchemy 2.x via `DATABASE_URL`.
- **fastapi → tor**: all outbound `.onion` requests use `aiohttp-socks` SOCKS5 at `TOR_PROXY_HOST:TOR_PROXY_PORT`. Clearnet enrichment calls (OTX, abuse.ch, CISA, etc.) bypass Tor.
- **fastapi ↔ redis**: optional; used for JWT token blacklisting and rate-limit counters. Falls back gracefully when unavailable.
- `postgres` health check gates `fastapi` startup. `tor` health check gates `fastapi` startup. `fastapi` health check gates `nextjs` startup.

### 1.3 Database Schema

All tables are in `db/models.py`. Primary keys are UUID4 generated in Python (integer autoincrement for `users`, `monitor_alerts`, `actor_style_profiles`, `user_api_keys`, `content_safety_events`). DateTime columns are timezone-aware UTC. Enums are stored as `VARCHAR` for PostgreSQL/SQLite portability.

#### Tables

**`investigations`** — one row per pipeline run

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | pipeline run identifier |
| `run_id` | UUID unique | alternate lookup key |
| `query` | Text | original user query |
| `refined_query` | Text nullable | LLM-refined query |
| `model_used` | String(100) | LLM model ID used |
| `preset` | String(50) | summary preset name |
| `summary` | Text | final LLM-generated report |
| `status` | String(20) | `pending` / `processing` / `completed` / `completed_no_results` / `cancelled` / `failed` |
| `graph_status` | String(20) | `pending` / `built` / `skipped_overflow` / `no_data` |
| `current_step` | Integer | 0–9; progress counter |
| `current_step_label` | String(200) | human-readable step label |
| `entity_count` | Integer | count updated during extraction |
| `page_count` | Integer | scraped page count |
| `is_seed` | Boolean | marks seed-only investigations |
| `user_id` | Integer FK → users | owner (SET NULL on delete) |
| `created_at` | DateTime TZ | |

**`sources`** — canonical `.onion` domain registry (global, deduped by address)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `onion_address` | String(255) unique | bare `.onion` hostname |
| `status` | String(20) | `active` / `down` / `unknown` |
| `source_type` | String(30) | `search_result` / `crawled` / `seed` / `telegram` |
| `first_seen` | DateTime TZ | |
| `last_seen` | DateTime TZ | |

**`investigation_sources`** — many-to-many junction: investigations ↔ sources

| Column | Type |
|---|---|
| `investigation_id` | UUID FK (CASCADE) |
| `source_id` | UUID FK (CASCADE) |
| `added_at` | DateTime TZ |

**`pages`** — individual scraped pages (URL-level)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `source_id` | UUID FK → sources (SET NULL) | |
| `url` | Text unique | |
| `raw_content_hash` | String(64) | SHA-256 of raw content |
| `cleaned_text` | Text | trafilatura-extracted text |
| `scrape_timestamp` | DateTime TZ | when VoidAccess scraped it |
| `posted_at` | DateTime TZ nullable | content authored date (rarely available) |
| `language` | String(10) | detected language |
| `byte_size` | Integer | |
| `created_at` | DateTime TZ | |

**`entities`** — structured intelligence artifacts

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `page_id` | UUID FK → pages (CASCADE) | |
| `investigation_id` | UUID FK → investigations (SET NULL) | |
| `entity_type` | String(50) | see Section 4 for full list |
| `value` | Text | raw extracted value |
| `canonical_value` | String indexed | normalised value |
| `confidence` | Float | 0.0–1.0 |
| `context_snippet` | Text | surrounding text at extraction time |
| `historical_context` | Text | notes from enrichment sources |
| `extraction_method` | String(10) | `regex` / `ner` / `llm` |
| `source_count` | Integer | number of sources corroborating |
| `corroborating_sources` | Text | comma-separated source names |
| `first_seen` / `last_seen` | DateTime TZ | |
| `first_seen_at` / `last_seen_at` | DateTime TZ | DB-level timestamps |

> `Entity.context` is a Python property alias for `context_snippet` kept for backward compatibility. Do not remove.

**`entity_relationships`** — directed edges between two entities

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `entity_a_id` | UUID FK → entities (CASCADE) | source |
| `entity_b_id` | UUID FK → entities (CASCADE) | target |
| `relationship_type` | String(50) | see `RelationshipType` enum |
| `confidence` | Float | |
| `source_page_id` | UUID FK → pages (SET NULL) | page that produced this edge |
| `investigation_id` | UUID FK → investigations (SET NULL) | |
| `first_seen` | DateTime TZ | |

Relationship types: `CO_APPEARED_ON`, `POSTED_BY`, `LINKED_TO`, `PAID_TO`, `MEMBER_OF`, `USES`, `CLAIMED`, `LIKELY_SAME_ACTOR`, `CONFIRMED_SAME_ACTOR`, `FUNDED_BY`, `POSSIBLE_SAME_AUTHOR`

**`investigation_entity_links`** — cross-investigation entity deduplication junction

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `entity_id` | UUID FK → entities (CASCADE) | |
| `investigation_id` | UUID FK → investigations (CASCADE) | |
| `linked_at` | DateTime TZ | |

**`actor_style_profiles`** — aggregated stylometry fingerprints

| Column | Type |
|---|---|
| `id` | Integer PK autoincrement |
| `canonical_value` | String indexed |
| `entity_type` | String |
| `style_vector` | JSON |
| `sample_count` | Integer |
| `total_chars` | Integer |
| `last_updated` | DateTime TZ |

Unique constraint: `(canonical_value, entity_type)`

**`users`** — authentication and access control

| Column | Type |
|---|---|
| `id` | Integer PK autoincrement |
| `email` | String(255) unique |
| `hashed_password` | String (bcrypt) |
| `is_active` | Boolean |
| `must_reset_password` | Boolean |
| `created_at` | DateTime TZ |
| `last_login_at` | DateTime TZ nullable |

**`user_api_keys`** — per-user encrypted API key storage

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK autoincrement | |
| `user_id` | Integer FK → users (CASCADE) | |
| `key_name` | String(64) | e.g. `OTX_API_KEY` |
| `encrypted_value` | Text | Fernet (AES-128) |
| `created_at` / `updated_at` | DateTime TZ | |

Unique constraint: `(user_id, key_name)`

**`monitor_alerts`** — alert history from the monitoring system

| Column | Type |
|---|---|
| `id` | Integer PK autoincrement |
| `monitor_name` | String indexed |
| `triggered_at` | DateTime TZ indexed |
| `change_type` | String(50) |
| `summary` | Text |
| `diff_data` | JSON |
| `severity` | String(20): `info` / `warning` / `critical` |
| `entity_count_delta` | Integer |
| `delivered` | Boolean |
| `delivery_channels` | JSON |
| `acknowledged` | Boolean |
| `acknowledged_at` | DateTime TZ nullable |

**`content_safety_events`** — audit log for content safety blocks

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK autoincrement | |
| `event_type` | String(50) | `query_blocked` / `url_blocked` / `content_blocked` |
| `user_id` | Integer nullable | |
| `content_hash` | String(64) | SHA-256 prefix of blocked item; never actual content |
| `timestamp` | DateTime TZ | |

### 1.4 Redis Usage

Redis is optional (`REDIS_URL`). When present it stores:

- **JWT blacklist**: revoked tokens from `POST /auth/logout`. Behaviour on Redis availability is a deliberate decision: when `REDIS_URL` is unset the blacklist is disabled by design (fail-open); when `REDIS_URL` is set but Redis is unreachable the revocation check **fails closed** (authenticated requests get `503` with an operator warning) rather than silently passing. See §"JWT Blacklist" below.
- **Rate-limit counters**: `slowapi` uses Redis for distributed rate limiting. Falls back to in-memory counting when Redis is unavailable.

In-process Python dicts (`_infra_cluster_cache`, `_sources_used_cache`, `_cancel_flags`) are used for per-investigation state that does not need to survive restarts.

### 1.5 CLI Interface

VoidAccess also ships as a pip-installable CLI. The CLI uses a local SQLite database and config under `~/.voidaccess/`, and it shares the same search, scraping, extraction, and enrichment modules as the Docker stack.

#### Installation

```bash
pip install voidaccess
```

#### Configuration and Data Paths

| Path | Purpose |
|---|---|
| `~/.voidaccess/config.json` | Saved CLI config: LLM provider, model, API keys, Tor proxy, and output directory |
| `~/.voidaccess/investigations.db` | SQLite database used by `voidaccess list`, `show`, `export`, and `enrich` |
| `~/.voidaccess/results/` | Default output directory for JSON and Markdown reports |

#### Commands and Flags

| Command | Common flags | Notes |
|---|---|---|
| `voidaccess investigate "<query>"` | `--output`, `--model`, `--no-tor`, `--no-llm`, `--depth`, `--format`, `--quiet`, `--no-banner`, `--events-jsonl PATH` | Runs the full local pipeline and writes report files. `--quiet` prints nothing at all except fatal errors (which never echo the query); the output paths are in the `completed` event of `--events-jsonl`. SIGTERM cancels the run cleanly (exit 143, see 2.5). |
| `voidaccess show [target]` | `--no-tui` | Opens the entity browser, or prints a summary table for scripted use |
| `voidaccess export <target>` | `--format stix|misp|sigma|yara|snort|suricata|package|csv|md|json`, `--output`, `--tlp`, `--redact-credentials`, `--include-raw` | Exports a saved investigation or JSON report |
| `voidaccess package <target>` | `--output`, `--tlp`, `--redact-credentials`, `--include-raw` | Shortcut for `voidaccess export <target> --format package`; writes an IOC ZIP bundle |
| `voidaccess enrich <target>` | `--skip-ips`, `--skip-domains`, `--skip-hashes`, `--skip-emails` | Re-runs post-processing enrichment against current feeds |
| `voidaccess list` | `--limit`, `--json` | Lists saved investigations from the local SQLite DB |
| `voidaccess status` | `--engines`, `--cache`, `--seeds`, top-level `--no-banner` | Shows config, API key status, Tor reachability, spaCy status, search engine stats, cache stats, or seed pool status |
| `voidaccess actors` | `--limit`, `--search`, `--json` | Lists persistent actor profiles |
| `voidaccess actor <handle>` | `--json`, `--timeline`, `--event-types`, `--note` | Shows, timelines, or annotates one actor profile |
| `voidaccess timeline <handle>` | `--limit`, `--event-types`, `--json` | Shortcut for `voidaccess actor <handle> --timeline` |
| `voidaccess configure` | `llm`, `keys`, `tor` | First-run wizard and targeted configuration subcommands |

#### Tor Detection

The CLI checks for a local Tor SOCKS5 proxy in this order:

1. `127.0.0.1:9050`
2. `127.0.0.1:9150`
3. The configured `tor.host` / `tor.port` from `~/.voidaccess/config.json`

Use `--no-tor` for clearnet-only investigations.

#### Differences from Docker

- No built-in Tor; a local Tor install or Tor Browser proxy is required for dark web sources.
- SQLite is used instead of PostgreSQL.
- The entity browser is a terminal TUI rather than the sigma.js graph UI.
- Monitoring and scheduled alerts are not included.
- Multi-user auth and JWT-backed API routes are not included.
- spaCy (`en_core_web_sm`) auto-installs on first use if it is missing.

---

## 2. Investigation Pipeline

### 2.1 Triggering

`POST /investigations` — rate-limited to **3 requests per minute** per IP. Creates the DB row synchronously and returns immediately; the pipeline runs as a FastAPI `BackgroundTasks` coroutine.

Content safety check runs at intake: if the query matches `BLOCKED_TERMS` or `BLOCKED_PATTERNS`, the request is rejected with HTTP 400 and the event is logged to `content_safety_events`.

### 2.2 Step Labels (STEP_LABELS map)

The `current_step` field in the `investigations` table uses these labels. The UI displays `total_steps: 13` but the pipeline uses 9 numbered labels — several numbered steps contain multiple internal sub-steps that are not separately labeled in the DB.

| Step | Label |
|---|---|
| 1 | Refining query |
| 2 | Searching dark web |
| 3 | Filtering results |
| 4 | Scraping pages |
| 5 | Extracting entities |
| 6 | Enriching intelligence |
| 7 | Building graph |
| 8 | Generating summary |
| 9 | Finalizing results |

### 2.3 Full Pipeline Sequence

**Step 0 — Model selection and status init**
- Resolves the LLM model; marks investigation `processing`.

**Step 1 — LLM query refinement**
- Calls `refine_query()` to shorten the user query to ≤5 words optimised for Tor search engine indexing.
- Falls back to the original query if the LLM call fails.
- Persists `refined_query` to the DB.
- Cancellation checkpoint after this step.

**Step 1.5 — Multilingual query expansion**
- Calls `i18n.query_expand.expand_query()` to produce translated variants.
- Configured by `I18N_LANGUAGES` (default `en,ru,zh`).
- Falls back to English-only if the i18n module is unavailable.

**Seed URL injection (before search fan-out)**
- `SeedManager.get_relevant_seeds()` scores `data/onion_seeds.json` entries against the query by tag and name matching; returns up to 10 relevant seeds.
- Seed URLs are prepended to the scrape queue; they bypass the LLM filter.

**Steps 2-4 (parallel) - 7 concurrent tasks with a configurable hard cap**

All 7 tasks run simultaneously via `asyncio.gather(..., return_exceptions=True)`. One task failing never cancels the others. The group cap defaults to 300 seconds and is controlled by `VOIDACCESS_PARALLEL_SOURCES_TIMEOUT`; each task also has its own inner timeout.

| Task | Inner timeout | Description |
|---|---|---|
| Search + filter | 180s search, no separate filter cap | Fan-out to 16+ Tor search engines per language; LLM filter selects relevant URLs |
| Threat intel enrichment | 60s per query | OTX, MalwareBazaar, ThreatFox, URLhaus, ransomware.live, CISA, Shodan, VT (all parallel) |
| Recursive crawler | 120s | Optional; only runs when `run_crawler: true` in the request |
| Paste sites | 120s | Clearnet sweep of Pastebin, dpaste, paste.ee, Rentry |
| GitHub | 180s | Clearnet code search + repo READMEs |
| GitLab | 180s | Clearnet code search + project pages |
| RSS feeds | 120s | Curated security blog feed scraping; 1h per-URL cache |

After the parallel phase, enrichment-derived `.onion` seed URLs (e.g., ransomware.live leak sites) are appended to the scrape queue.

Cancellation checkpoint after this step.

**Step 4.5 — Vector cache lookup**
- `vector.store.bulk_check_cache()` checks ChromaDB for pages seen within the last 24 hours.
- Cache hits skip the Tor scrape. Misses go to Step 5.

**Step 5 — Tor scraping**
- `scraper.scrape.scrape_multiple()` — async `aiohttp-socks` scraper; 1 MB cap per page; `trafilatura` for text extraction; exponential backoff; max 12 concurrent workers.
- SSRF validation (`validate_urls_for_scraping`) blocks unsafe URLs before scraping.
- Paste, GitHub, GitLab, and RSS pages bypass this step entirely — they inject pre-fetched text directly into the extraction pool.

**Step 5.75 — Content safety scan (Layer 4)**
- `gate_pages()` scans every scraped/cached/shared page via `sanitize_content()` before vector cache writes, DB persistence, extraction, or summarization.
- Flagged pages are discarded entirely; their URLs are hashed (SHA-256 prefix) and logged to `content_safety_events`. The original text is never stored.

**Step 5.5 — Vector cache write**
- New pages with >100 characters are stored in ChromaDB with `source: "scraper"` metadata (only pages that passed Step 5.75).
- Cancellation checkpoint after scraping.

**Step 5.7 — Language detection**
- `i18n.detect.detect_language()` tags each page's detected language; results are logged but not stored in the DB.

**Step 6 — Entity extraction**
- `extract_entities_from_pages()` runs the 4-stage extraction pipeline (regex → NER → LLM → normalise) concurrently across all pages; max 5 concurrent pages.
- Confidence filter: entities below 0.80 are dropped before DB write.
- Entity cap: 400 per investigation (see Section 4).
- Cancellation checkpoint after extraction.

**Step 6.1 — IP reputation enrichment**
- `sources/ip_reputation.py` enriches `IP_ADDRESS` entities (up to 50 per investigation).
- **Feodo Tracker** (abuse.ch) and **C2IntelFeeds** (montysecurity/C2-Tracker, 6 frameworks): IPs on either list are tagged `C2` and their confidence is raised to 1.0. Both are public and require no key. Blocklists are cached in-memory and refreshed every `C2_FEED_CACHE_TTL` hours.
- **AbuseIPDB** (`ABUSEIPDB_API_KEY`): abuse confidence score and usage type. Skipped if key absent. Free tier: 1,000 checks/day.
- **GreyNoise** (`GREYNOISE_API_KEY`): classifies IPs as `benign_scanner`, `malicious`, or `unknown`. IPs classified `benign_scanner` are suppressed from the entity list before DB write. Skipped if key absent.
- `MALWARE_FAMILY` entities are auto-created from C2 feed framework names and linked to the source IP.

**Step 6.2 — Domain reputation enrichment**
- `sources/domain_reputation.py` enriches `DOMAIN` and `DOMAIN_NAME` entities (up to 30 per investigation). All three sources run concurrently per domain.
- **crt.sh**: certificate transparency log lookup; returns subdomains as new `DOMAIN` entities. No key required.
- **URLScan.io** (`URLSCAN_API_KEY`): fetches existing scan results, malicious verdict, and communicating IPs. Key is optional; public scan results are available without one. `URLSCAN_SUBMIT=true` submits a new scan (public — disabled by default for OPSEC).
- **Wayback Machine**: CDX API query for historical snapshots; tags domains with an `ARCHIVED` flag when historical content exists. No key required.
- Results are cached 24 h (crt.sh, Wayback) or 6 h (URLScan.io).

**Step 6.3 — Hash reputation enrichment**
- `sources/hash_reputation.py` enriches `FILE_HASH_MD5`, `FILE_HASH_SHA1`, `FILE_HASH_SHA256` entities (up to 50 per investigation; SHA-256 prioritised). All sources are queried concurrently. Cache TTL: 48 h.
- **MalwareBazaar** and **ThreatFox**: family classification and IOC confidence. Both free; `ABUSECH_API_KEY` optional (improves rate limits).
- **Hybrid Analysis** (`HYBRID_ANALYSIS_API_KEY`): behavioral verdict, AV detection ratio, and contacted IPs/domains from dynamic analysis. Skipped if key absent. Free tier available.
- **VirusTotal** (`VT_API_KEY`): AV detection data and sandbox network IOCs. Skipped if key absent.
- `MALWARE_FAMILY` entities are auto-created from confirmed family names and linked to the source hash.

**Step 6.4 — Email reputation enrichment**
- `sources/email_reputation.py` enriches `EMAIL_ADDRESS` entities (up to 30 per investigation).
- **Disposable domain blocklist**: refreshed daily from the `disposable-email-domains` public list; matched emails are tagged `DISPOSABLE`. No key required.
- **EmailRep** (`EMAILREP_API_KEY`): reputation score, suspicious flag, and platform presence (spam lists, data breaches). Works at reduced rate without a key. Cache TTL: 12 h.
- **HaveIBeenPwned** (`HIBP_API_KEY`): breach names, dates, and data classes. Skipped if key absent. Paid: $3.50/month. Cache TTL: 24 h.
- Custom-domain email addresses also produce new `DOMAIN` entities for downstream enrichment.

**Step 6.5 — Cross-reference with seed data**
- `db.queries.cross_reference_with_seeds()` links extracted entities against the `investigation_entity_links` table.

**Step 6.6 — Stylometry profiles**
- Builds actor writing-style vectors and upserts them in `actor_style_profiles`.

**Step 6.7 — Blockchain wallet enrichment**
- For up to 10 `BITCOIN_ADDRESS` / `ETHEREUM_ADDRESS` entities, queries BlockCypher (BTC/ETH) and Etherscan (ETH).
- Adds `PAID_TO` edges in the entity graph.
- Requires `BLOCKCYPHER_TOKEN` / `ETHERSCAN_API_KEY`; skipped if keys are absent.

**Step 6.8 — DNS/WHOIS enrichment**
- Calls `sources.dns_enrichment.enrich_with_dns()` on extracted IP and domain entities (up to 20 IPs, 20 domains).
- Queries CIRCL PDNS, CIRCL PSSL, and RDAP. Optionally queries SecurityTrails.
- Persists `infrastructure_clusters` and `sources_used` in investigation metadata while keeping in-process caches as the fast path.

**Step 6.9 - Persistent actor profiles**
- `sources.actor_profiles.ActorProfileManager` upserts extracted actor handles into `actor_profiles`.
- Co-occurring aliases and infrastructure are written to `actor_aliases` and `actor_infrastructure`.
- `run_alias_resolution()` adds likely or confirmed alias rows when the composite signal score is high enough.

**Step 7 — Graph construction**
- `graph.builder.build_graph_from_db()` builds a NetworkX `MultiDiGraph` from DB entities.
- `persist_graph_edges()` writes edges to `entity_relationships`.
- Edge overflow rules apply (see Section 6).
- Runs deterministic backend community detection for the graph API response.
- Sets `graph_status` to `built` or `skipped_overflow`.

**Step 8 — LLM summary**
- `generate_summary()` produces a structured threat intelligence briefing from all extracted pages and entities. The phase timeout defaults to 90 seconds and is controlled by `VOIDACCESS_SUMMARY_TIMEOUT`.
- Falls back to a plain count summary if the LLM call fails.

**Step 9 — Finalise**
- Marks investigation `completed`; updates `sources_used_cache`. The phase timeout defaults to 30 seconds and is controlled by `VOIDACCESS_FINALIZE_TIMEOUT`.
- On any unhandled exception, marks `failed` and stores the error message in `summary`.

### 2.4 Phase Timeouts and Recovery

The API and CLI wrap the major long-running phases in configurable timeouts:

| Phase | Env var | Default |
|---|---|---|
| Parallel collection sources | `VOIDACCESS_PARALLEL_SOURCES_TIMEOUT` | `300` seconds |
| Enrichment | `VOIDACCESS_ENRICHMENT_TIMEOUT` | `120` seconds |
| Graph build | `VOIDACCESS_GRAPH_TIMEOUT` | `60` seconds |
| Summary | `VOIDACCESS_SUMMARY_TIMEOUT` | `90` seconds |
| Finalize | `VOIDACCESS_FINALIZE_TIMEOUT` | `30` seconds |

On the CLI, the enrichment cap is applied only when `VOIDACCESS_ENRICHMENT_TIMEOUT` is set explicitly (partial results are kept); the 120 s default is not enforced there. The CLI summary phase splits its budget: the first attempt gets 67% of it; if that times out, one retry runs with a reduced context (top 4 pages, 4000 characters) in the remaining 33%. If that also fails, a deterministic fallback summary built from the top entities and sources is used and the report JSON carries `"summary_kind": "fallback"` (`"llm"` for a model summary, `"none"` for `--no-llm`).

`voidaccess.llm.generate_summary` never returns an error string: when the LLM fails (or there is no page content) it raises `SummaryUnavailable` (`.reason` is `llm_error` or `no_content`, the underlying exception is `__cause__`, and the message carries no provider text). The CLI and the API both go through `voidaccess.summary_fallback.summarize_with_fallback`, which treats a `SummaryUnavailable`, any other exception, a timeout and an empty answer identically: retry once with reduced context, then build the deterministic fallback. `summary_kind` is `llm` only when the model produced text. The API uses 90% of its `summary` phase cap for the two attempts so the helper, not the outer cap, ends the phase. No user-facing text (display line, summary, log line) contains a raw exception message.

Pipeline metadata that used to live only in process memory now survives restarts through the investigation metadata JSON column:

- `sources_used`
- `infrastructure_clusters`

At API startup, and every `VOIDACCESS_SWEEP_INTERVAL_SECONDS` seconds thereafter, the stuck-investigation sweep marks runs older than `VOIDACCESS_INVESTIGATION_HARD_TIMEOUT_MINUTES` as failed. Defaults are 300 seconds between sweeps and 30 minutes for the hard timeout.

### 2.5 Cancellation

`POST /investigations/{id}/cancel` sets `_cancel_flags[investigation_id] = True`.

Checkpoints (where the pipeline actually honours the flag): after Step 1, after the parallel phase, after Step 5, and after Step 6. Inside the long stages the same request is honoured between items through one shared helper, `utils/cancel.py` (a `CancelToken` plus `checkpoint()`, `is_cancelled()`, `wait_cancellable()` and `run_cancellable()`):

| Stage | In-stage checkpoint |
|---|---|
| Search fan-out (`search/search.py`) | between engines: an engine that has not started returns `cancelled`; in-flight engines get a grace period; cancelled engines are not recorded against the circuit breaker |
| Fetch and scrape (`scraper/scrape.py`) | between pages: a queued page never starts and a page mid-retry is not retried; the fetches already in flight finish |
| Enrichment (`sources/enrichment.py`, `historical_intel.py`, `feeds/`) | between sources, between the sequential enrichment sub-steps, and between entities in the historical and MITRE loops; sources that already finished keep their results |

The API binds a token per investigation (`_cancel_tokens`, set together with the flag in `_set_cancelled`); an in-stage loop sees it through a context variable, and a cancel recorded only in the database is picked up at the next stage boundary. A cancel never leaves a half-written state beyond what the checkpoint rules above already say.

**CLI.** `voidaccess investigate` routes SIGTERM to a token (installed in the CLI entry point only, never in `_run_investigation`, so an embedding runner keeps its own signal handling; `_run_investigation(..., cancel_token=...)` is the library hook). On a cancel the current item finishes (up to `VOIDACCESS_CANCEL_GRACE`, default 3 s, then the in-flight work is cancelled), the progress hook emits the terminal `cancelled` event with `stages_completed` listing only the stages that finished, the investigation row is marked `cancelled`, and the process exits 143 (130 for Ctrl-C). The JSON and Markdown outputs are written to dot-prefixed temp files and renamed into place after the last checkpoint, so a cancelled run leaves no output file, partial or otherwise.

When cancelled:
- The DB `status` is set to `cancelled`.
- All entities and pages written up to the checkpoint are preserved — partial results are available via the normal GET endpoints.
- The `_cancel_flags` entry is cleared.

> **Single-worker caveat**: cancellation works only when the HTTP cancel request reaches the same uvicorn worker process that is running the pipeline. In multi-worker deployments this is not guaranteed.

---

## 3. Intelligence Sources

### 3.1 Tor Search Fan-out

16+ `.onion` search engines are queried concurrently. Search is weighted by engine reliability (`ENGINE_WEIGHTS` in `search/search.py`). Queries are sent in all languages returned by the multilingual expansion step (default: English, Russian, Chinese).

Search results are deduplicated, sorted by engine weight, and passed to the LLM filter. The filter selects the most relevant URLs; up to 150 total URLs are passed to the scrape queue (filtered top results + remainder from raw search output).

**Current reality**: the Tor search engine landscape is highly volatile. As of the writing of this document, only 3 of the 16+ configured engines reliably return results. The others time out silently.

### 3.2 Clearnet Parallel Sources

These sources run in the same parallel phase as the Tor search and do not use Tor.

#### Paste Sites (`PASTE_SCRAPING_ENABLED`)

| Source | Search method |
|---|---|
| Pastebin | Search endpoint + raw paste fetch |
| dpaste.org | Search endpoint |
| paste.ee | Search endpoint |
| Rentry.co | Search endpoint |

Controlled by `PASTE_MAX_RESULTS` (default 15). Paste pages bypass the Tor scrape step and inject their pre-fetched text directly into the extraction pool.

#### GitHub (`GITHUB_SCRAPING_ENABLED`)

Queries the GitHub code search API. Without a token: 10 req/min. With `GITHUB_TOKEN`: 30 req/min. Returns file content and repository READMEs. Controlled by `GITHUB_MAX_RESULTS` (default 15). Bypasses the Tor scrape step.

#### GitLab (`GITLAB_SCRAPING_ENABLED`)

Queries the GitLab code search API. Without a token: ~15 req/min. With `GITLAB_TOKEN`: ~60 req/min. Controlled by `GITLAB_MAX_RESULTS` (default 15). Bypasses the Tor scrape step.

#### RSS Security Feeds (`RSS_FEEDS_ENABLED`)

Articles from curated threat intelligence blogs. Feed results are cached per-URL for 1 hour. Maximum article age: 90 days. Controlled by `RSS_MAX_ARTICLES` (default 20). Bypasses the Tor scrape step.

Configured feeds include: Krebs on Security, BleepingComputer, The Record by Recorded Future, Cisco Talos, Mandiant, CrowdStrike, Unit 42, CISA, and others.

#### Optional Clearnet Scraping Proxy

Paste sites and RSS feeds can be routed through ScrapingAnt to reduce blocking and rate-limiting from flaky upstreams. This is optional and only affects clearnet scraping.

##### Products

| Product | Credential(s) | Persistent config | One-shot CLI flag | Transport details |
|---|---|---|---|---|
| Web Scraping API | `SCRAPINGANT_API_KEY` | `VOIDACCESS_USE_PROXIES=true` | `--use-scraping-api` | POST to `https://api.scrapingant.com/v2/general`; billed in request credits. |
| Residential Proxy transport | `SCRAPINGANT_PROXY_USERNAME` + `SCRAPINGANT_PROXY_PASSWORD` | `VOIDACCESS_USE_PROXY=true` | `--use-proxies` | HTTP CONNECT via `residential.scrapingant.com:8080` or `:443`; billed in GB of traffic. |
| Datacenter Proxy transport | `SCRAPINGANT_PROXY_USERNAME` + `SCRAPINGANT_PROXY_PASSWORD` | `SCRAPINGANT_PROXY_TYPE=datacenter` plus `VOIDACCESS_USE_PROXY=true` | `--use-proxies` | Same proxy flow as Residential, but the datacenter pool is still live-unverified in this repo. |

##### Scope and exclusions

- Tor and `.onion` traffic are unaffected in every configuration.
- GitHub and GitLab scraping are excluded permanently because those requests carry `GITHUB_TOKEN` and `GITLAB_TOKEN`.
- If both the REST API and proxy transport are enabled, the proxy transport wins for that request and the chokepoint logs the choice once.
- There is no chained mode; each request uses exactly one transport and falls back to direct on failure.
- `SCRAPINGANT_PROXY_TYPE` selects the proxy pool and does not change the host.
- The storage surface follows the rest of the project: CLI config is plaintext in `~/.voidaccess/config.json`, `.env` and `setup.sh` are plaintext, and the Docker/web settings path stores secrets encrypted at rest via `UserApiKey`.

##### Environment variables

| Variable | Description |
|---|---|
| `SCRAPINGANT_API_KEY` | Credential exclusively for the Web Scraping API transport. |
| `SCRAPINGANT_PROXY_USERNAME` | Residential or datacenter proxy username from the ScrapingAnt dashboard; separate from `SCRAPINGANT_API_KEY`. |
| `SCRAPINGANT_PROXY_PASSWORD` | Residential or datacenter proxy password from the ScrapingAnt dashboard; used together with `SCRAPINGANT_PROXY_USERNAME`. |
| `SCRAPINGANT_PROXY_TYPE` | Selects `residential` or `datacenter` for the proxy transports. |
| `VOIDACCESS_USE_PROXIES` | Enables the REST API transport for clearnet scraping. |
| `VOIDACCESS_USE_PROXY` | Enables the proxy transport for clearnet scraping. |

### 3.3 Seed URLs

`data/onion_seeds.json` is a JSON catalogue of curated `.onion` addresses organised by category. The `SeedManager` scores entries against the query using tag and name matching and returns up to 10 relevant seeds. Seeds are injected before the search fan-out and bypass the LLM filter. The seed file refreshes weekly (Sunday 03:00 UTC) via the APScheduler job.

---

## 4. Entity Extraction

### 4.1 Extraction Pipeline

Four stages run per page in `extractor/pipeline.py`:

1. **Regex** (`extractor/regex_patterns.py`): pattern-based extraction for cryptographically structured types (wallet addresses, hashes, CVEs, onion URLs, IPs, emails, PGP blocks, phone numbers).
2. **NER** (`extractor/ner.py`): dictionary/heuristic named-entity recognition for actor handles, malware families, organisation names, person names.
3. **LLM** (`extractor/llm_extract.py`): optional; runs when regex/NER already found entities. Augments and contextualises the combined set.
4. **Normalisation** (`extractor/normalizer.py`): canonicalises values, deduplicates, resolves type conflicts, assigns confidence scores.

Regex results take precedence over NER results for shared entity types.

### 4.2 Entity Types

VoidAccess v1.7.1 recognises 55+ entity type strings. The `TYPE_PRIORITY` map controls conflict resolution when an entity's type is ambiguous.

#### Critical IOCs

| Entity type | Description |
|---|---|
| `CVE`, `CVE_NUMBER` | CVE identifiers |
| `IP_ADDRESS` | IPv4 address |
| `IPV6_ADDRESS` | IPv6 address |
| `DOMAIN`, `DOMAIN_NAME` | DNS names |
| `ONION_URL` | Tor onion URLs and hostnames |
| `FILE_HASH`, `FILE_HASH_MD5`, `FILE_HASH_SHA1`, `FILE_HASH_SHA256`, `FILE_HASH_SHA512` | File hashes |
| `MAC_ADDRESS` | Colon, hyphen, or Cisco-style MAC address |
| `IPFS_CID` | IPFS CIDv0/CIDv1 content identifiers |
| `COMBO_LIST_ENTRY` | Credential combo-list record |
| `YARA_RULE` | YARA rule name or rule block marker |
| `MITRE_TACTIC`, `MITRE_TECHNIQUE` | ATT&CK tactic or technique IDs |
| `EXPLOIT_DB_ID` | Exploit-DB identifier |
| `NUCLEI_TEMPLATE` | Nuclei template identifier |

#### Cryptocurrency

| Entity type | Description |
|---|---|
| `BITCOIN_ADDRESS` | Bitcoin address |
| `ETHEREUM_ADDRESS` | Ethereum address |
| `MONERO_ADDRESS` | Monero address |
| `LITECOIN_ADDRESS` | Litecoin address |
| `ZCASH_ADDRESS` | Zcash address |
| `DOGECOIN_ADDRESS` | Dogecoin address |
| `XRP_ADDRESS` | XRP classic address |
| `SOLANA_ADDRESS` | Solana address |
| `TRON_ADDRESS` | Tron address |
| `BITCOIN_CASH_ADDRESS` | Bitcoin Cash cashaddr |
| `DASH_ADDRESS` | Dash address |
| `ENS_DOMAIN` | Ethereum Name Service `.eth` name |
| `WALLET`, `CRYPTO_WALLET` | Generic wallet type |
| `CRYPTO_SEED_PHRASE` | Detected seed phrase marker |

#### Credentials

| Entity type | Description |
|---|---|
| `AWS_ACCESS_KEY` | AWS access key ID |
| `AWS_SECRET_KEY` | AWS secret key candidate |
| `GITHUB_TOKEN` | GitHub token |
| `SLACK_TOKEN` | Slack token |
| `DISCORD_TOKEN` | Discord bot/user token pattern |
| `JWT_TOKEN` | JWT bearer token |
| `GOOGLE_API_KEY` | Google API key |
| `STRIPE_KEY` | Stripe live/test key |
| `API_KEY` | Generic API key with context |
| `STEALER_LOG_ENTRY` | Stealer-log URL/login/password marker |

#### Messaging Handles

| Entity type | Description |
|---|---|
| `TELEGRAM_HANDLE` | Telegram username |
| `DISCORD_HANDLE` | Discord legacy username/discriminator |
| `XMPP_JID` | XMPP/Jabber ID |
| `TOX_ID` | Tox ID |
| `SESSION_ID` | Session messenger ID |
| `MATRIX_HANDLE` | Matrix user handle |
| `WIRE_HANDLE` | Wire handle |
| `ICQ_NUMBER` | ICQ number |
| `WICKR_ID` | Wickr handle |

#### Actors and Identity

| Entity type | Description |
|---|---|
| `MALWARE_FAMILY`, `RANSOMWARE_GROUP` | Malware or ransomware family/group names |
| `THREAT_ACTOR`, `THREAT_ACTOR_HANDLE` | Actor names and handles |
| `EMAIL_ADDRESS` | Email address |
| `PGP_KEY_BLOCK` | PGP public key block or fingerprint |
| `ORGANIZATION_NAME`, `PERSON_NAME` | Named organisations and people |
| `PHONE_NUMBER` | Phone number |
| `DATE` | Date mention |
| `PASTE_URL` | Paste-site URL |

### 4.3 Per-Type Sub-Caps

Applied before the global cap to prevent high-volume low-specificity types from crowding out high-value IOCs:

| Entity Type | Sub-cap |
|---|---|
| `ORGANIZATION_NAME` | 50 |
| `THREAT_ACTOR_HANDLE` | 80 |
| `PERSON_NAME` | 30 |
| `LOCATION` | 20 |

### 4.4 Global Entity Cap

- Confidence threshold: entities below **0.80** are dropped before any cap logic.
- Global cap: **400 entities** per investigation.
- Ranking when cap is applied (descending priority): confidence score → type priority (lower number = higher priority) → occurrence count across pages.
- Capped entities are logged with a warning; partial results are preserved.

### 4.5 Type Conflict Resolution

`resolve_entity_type_conflicts()` in `extractor/normalizer.py` resolves cases where the same value was extracted as two different entity types. The higher-priority type (lower `TYPE_PRIORITY` number) wins. If both types have the same priority, both records are kept.

---

## 5. Enrichment Sources

All enrichment runs during the parallel phase (Steps 2–4) and again after extraction for DNS. Each source wraps its HTTP calls in a 30-second `aiohttp.ClientTimeout`. The entire enrichment task has a 60-second per-query cap; the outer parallel phase has a 300-second hard cap.

### 5.1 Threat Intel Enrichment (parallel, Steps 2–4)

All six sources below run concurrently via a single `asyncio.gather()` inside `sources/enrichment.py`.

| Source | What it returns | Key required | Free tier |
|---|---|---|---|
| **AlienVault OTX** | Threat pulses: malware families, MITRE ATT&CK IDs, IOCs for top 5 pulses | `OTX_API_KEY` — skipped if absent | N/A; key required |
| **MalwareBazaar** | Malware samples by tag then by signature; SHA-256, MD5, family, first/last seen | `ABUSECH_API_KEY` — optional; improves rate limits | Yes |
| **ThreatFox** | IOCs by search term or last 24h feed; ioc_type, ioc_value, malware, confidence | `ABUSECH_API_KEY` — optional | Yes |
| **URLhaus** | Malicious URLs by tag; url_status, threat, reporter | `ABUSECH_API_KEY` — optional | Yes |
| **ransomware.live** | Group profiles, leak-site `.onion` addresses, recent victim claims; also injects `.onion` seeds into the scrape queue | None | Yes (public API) |
| **ransomlook.io** | Second ransomware-group tracker (different corpus) — group profiles, leak-site `.onion` addresses, recent victim posts; cross-validates ransomware.live. Onion seeds are URL-normalised to match ransomware.live so shared leak sites dedup to a single scrape seed | None | Yes (public API) |
| **Secondary enrichment** (`_enrich_new_sources`) | Calls CISA, NVD, Shodan, VirusTotal, and historical intel concurrently (55s cap) | Varies — see below | Varies |

The Phase-A fan-out preserves partial results: if the 59s (outer) or 55s (nested) deadline hits while some sources are still running, the results of sources that already finished are kept rather than discarding the whole batch (`_gather_with_partial_results`).

#### Secondary enrichment sources (nested, 55-second cap)

| Source | What it enriches | Key required |
|---|---|---|
| **CISA KEV** | CVE entities: vendor, product, exploitation date, description (only actively-exploited CVEs) | None |
| **CISA Advisories** | Advisory titles, URLs, dates correlated to the query | None |
| **NVD 2.0** | CVE entities: CVSS base score/severity/vector, CWE weaknesses, description, published/modified dates — for ANY CVE, not just KEV. Capped at 15 CVEs with a soft 45s budget | `NVD_API_KEY` — optional; raises rate limit 5→50 req/30s |
| **Shodan InternetDB** | IP entities: open ports, hostnames, tags, known CVEs | None (free public API) |
| **VirusTotal** | File hash entities: detection ratio, threat label, first/last seen | `VT_API_KEY` — skipped if absent; free tier: 4 req/min; max 20 hashes |
| **MITRE ATT&CK overlay** | Technique IDs (T-codes) for actors identified from OTX/ransomware.live | None (local lookup via `historical_intel.py`) |
| **Historical intel** | MITRE ATT&CK group profiles, FBI/DOJ press releases, CISA historical advisories | None |

### 5.2 DNS/WHOIS Enrichment (Step 6.8)

Runs after entity extraction using the extracted IP and domain entities. Capped at 20 IPs and 20 domains. 0.5-second delay between CIRCL requests.

| Source | What it enriches | Key required |
|---|---|---|
| **CIRCL PDNS** | Passive DNS history for IPs and domains | None |
| **CIRCL PSSL** | SSL certificate history | None |
| **RDAP (ARIN / rdap.org)** | WHOIS/registration data for IPs and domains | None |
| **SecurityTrails** | Detailed DNS history | `SECURITYTRAILS_API_KEY` — skipped if absent; free tier: 50 queries/month |

**Infrastructure cluster detection**: after CIRCL/RDAP results are processed, `_detect_infrastructure_clusters()` groups IPs and domains sharing the same ASN, CIDR block, or WHOIS registrant into clusters. Clusters are stored in `_infra_cluster_cache` and returned in the investigation detail endpoint as `infrastructure_clusters`.

### 5.3 Blockchain Enrichment (Step 6.7)

| Source | What it enriches | Key required |
|---|---|---|
| **BlockCypher** | BTC and ETH wallet addresses: balance, transaction count, related addresses | `BLOCKCYPHER_TOKEN` — skipped if absent |
| **Etherscan** | ETH wallet addresses: balance, transactions | `ETHERSCAN_API_KEY` — skipped if absent |

Creates `PAID_TO` edges in the entity graph between wallets that transacted. Limited to 10 wallets per investigation.

### 5.4 IP Reputation Enrichment (Step 6.1)

| Source | What it enriches | Key required | Free tier |
|---|---|---|---|
| **Feodo Tracker** | C2 IPs for banking trojans and ransomware loaders | None | Yes (public) |
| **C2IntelFeeds** | C2 IPs for Cobalt Strike, Sliver, Metasploit, Brute Ratel, PoshC2, Havoc | None | Yes (public) |
| **AbuseIPDB** | Abuse confidence score; usage type | `ABUSEIPDB_API_KEY` — skipped if absent | Yes; 1,000 checks/day |
| **GreyNoise** | Scanner classification; suppresses `benign_scanner` IPs before DB write | `GREYNOISE_API_KEY` — skipped if absent | Free tier available |

C2 feed blocklists are refreshed in-memory every `C2_FEED_CACHE_TTL` hours (default 24). IPs confirmed as C2 receive confidence 1.0 and a `C2` badge in the UI. `MALWARE_FAMILY` entities may be auto-created from C2 framework names.

### 5.5 Domain Reputation Enrichment (Step 6.2)

| Source | What it enriches | Key required | Free tier | Cache TTL |
|---|---|---|---|---|
| **crt.sh** | Subdomains from certificate transparency logs | None | Yes | 24 h |
| **URLScan.io** | Live scan data, malicious verdict, communicating IPs | `URLSCAN_API_KEY` — optional | Yes (public results) | 6 h |
| **Wayback Machine** | Historical snapshot availability; `ARCHIVED` tag | None | Yes | 24 h |

`URLSCAN_SUBMIT=false` (default): only retrieves existing scan results. When `true`, VoidAccess submits new scans — note that URLScan.io scans are publicly indexed and may reveal investigation targets to domain operators.

### 5.6 Hash Reputation Enrichment (Step 6.3)

| Source | What it enriches | Key required | Free tier |
|---|---|---|---|
| **MalwareBazaar** | Malware family, AV coverage, first/last seen | `ABUSECH_API_KEY` — optional | Yes |
| **ThreatFox** | Malware family, IOC confidence, associated IOCs | `ABUSECH_API_KEY` — optional | Yes |
| **Hybrid Analysis** | Behavioral verdict, AV detection ratio, contacted IPs/domains | `HYBRID_ANALYSIS_API_KEY` — skipped if absent | Yes (registration required) |
| **VirusTotal** | AV detection ratio, sandbox network IOCs | `VT_API_KEY` — skipped if absent | Yes (4 req/min) |

Cache TTL: 48 h (hashes are immutable). Up to 50 hashes per investigation; SHA-256 is prioritised over SHA-1 and MD5. `MALWARE_FAMILY` entities are auto-created from confirmed family names and linked to the source hash entity.

### 5.7 Email Reputation Enrichment (Step 6.4)

| Source | What it enriches | Key required | Free tier | Cache TTL |
|---|---|---|---|---|
| **Disposable domain blocklist** | Known throwaway email domains; `DISPOSABLE` tag | None | Yes (public list) | 24 h |
| **EmailRep** | Reputation score, suspicious flag, platform presence | `EMAILREP_API_KEY` — optional | Reduced rate without key | 12 h |
| **HaveIBeenPwned** | Breach names, dates, exposed data classes | `HIBP_API_KEY` — skipped if absent | No ($3.50/month) | 24 h |

Custom-domain email addresses (non-disposable, non-freemail) also produce new `DOMAIN` entities for downstream domain reputation enrichment.

### 5.7a Breach-Exposure Lookup (Step 6.5)

Complements HIBP (Step 6.4) with two additional breach corpora. HIBP, XposedOrNot, and LeakCheck draw from different corpora, so all three run and each surfaces things the others miss. Each reports its own `sources_used` status (`xposedornot`, `leakcheck`).

| Source | What it enriches | Key required | Free tier | Cache TTL |
|---|---|---|---|---|
| **XposedOrNot** | Breach names for an email, including stealer-log exposure (`stealer_log_exposure` tag) | `XPOSEDORNOT_API_KEY` — optional; free tier fully functional | Yes | 48 h |
| **LeakCheck** (public) | Breach-source names + exposed-data categories; lightweight corroboration signal | None (unauthenticated) | Yes | 48 h |

When an email appears in BOTH corpora the entity is tagged `breach_corroborated` (stronger signal than either alone). Pacing: XposedOrNot ≲2 req/s, LeakCheck gentle — both bound by a concurrency semaphore + per-request sleep. Up to 30 emails per investigation.

### 5.7b Infostealer Intelligence (Step 6.6)

| Source | What it enriches | Key required | Free tier | Cache TTL |
|---|---|---|---|---|
| **Hudson Rock Cavalier** | `EMAIL_ADDRESS`: whether the email appears in stealer logs and on how many compromised machines (`hudsonrock_infostealer` tag). `DOMAIN`: employee/user counts in stealer logs — org-level infostealer exposure | None | Yes (public API) | 24 h |

Higher-signal than breach dumps: reports machines actively infected by infostealer malware, not just old breach appearances. Runs for both `EMAIL_ADDRESS` (up to 30) and `DOMAIN` (up to 20, freemail domains skipped). Reports under `hudsonrock`.

### 5.8 Entity Enrichment Pipeline Summary

The following table maps all post-extraction enrichment steps to their pipeline position, entity types, and source modules.

| Step | Entity types enriched | Sources | Config |
|---|---|---|---|
| **6.1** IP reputation | `IP_ADDRESS` (up to 50) | Feodo Tracker, C2IntelFeeds, AbuseIPDB, GreyNoise | `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `C2_FEED_CACHE_TTL` |
| **6.2** Domain reputation | `DOMAIN`, `DOMAIN_NAME` (up to 30) | crt.sh, URLScan.io, Wayback Machine | `URLSCAN_API_KEY`, `URLSCAN_SUBMIT` |
| **6.3** Hash reputation | `FILE_HASH_MD5/SHA1/SHA256` (up to 50) | Hybrid Analysis, MalwareBazaar, ThreatFox, VirusTotal | `HYBRID_ANALYSIS_API_KEY`, `VT_API_KEY`, `ABUSECH_API_KEY` |
| **6.4** Email reputation | `EMAIL_ADDRESS` (up to 30) | HIBP, EmailRep, disposable blocklist | `HIBP_API_KEY`, `EMAILREP_API_KEY` |
| **6.5** Breach exposure | `EMAIL_ADDRESS` (up to 30) | XposedOrNot, LeakCheck | `XPOSEDORNOT_API_KEY` (optional) |
| **6.6** Infostealer | `EMAIL_ADDRESS` (up to 30), `DOMAIN` (up to 20) | Hudson Rock Cavalier | None |
| **6.7** Blockchain | `BITCOIN_ADDRESS`, `ETHEREUM_ADDRESS` (up to 10) | BlockCypher, Etherscan | `BLOCKCYPHER_TOKEN`, `ETHERSCAN_API_KEY` |
| **6.8** DNS/WHOIS | `IP_ADDRESS`, `DOMAIN` (up to 20 each) | CIRCL PDNS, CIRCL PSSL, RDAP, SecurityTrails | `SECURITYTRAILS_API_KEY`, `DNS_ENRICHMENT_ENABLED` |

All enrichment steps are wrapped in `try/except` with graceful fallback. A failing enrichment source never fails the investigation.

---

## 6. Graph System

### 6.1 Node Construction

`graph/builder.py` builds a NetworkX `MultiDiGraph`. Each entity maps to a node type:

| Entity type | Graph node type |
|---|---|
| `THREAT_ACTOR_HANDLE` | `threat_actor` |
| `BITCOIN_ADDRESS`, `ETHEREUM_ADDRESS`, `MONERO_ADDRESS` | `crypto_wallet` |
| `ONION_URL` | `onion_url` |
| `EMAIL_ADDRESS` | `email_address` |
| `PGP_KEY_BLOCK` | `pgp_key` |
| `CVE_NUMBER` | `vulnerability` |
| `PASTE_URL` | `paste` |
| `MALWARE_FAMILY` | `malware_family` |
| `RANSOMWARE_GROUP` | `ransomware_group` |
| `IP_ADDRESS` | `ip_address` |
| `PHONE_NUMBER` | `phone_number` |
| `ORGANIZATION_NAME` | `organization` |
| `FILE_HASH_MD5`, `FILE_HASH_SHA1`, `FILE_HASH_SHA256` | `file_hash` |
| `MITRE_TECHNIQUE` | `technique` |
| `DATE` | `date` |

Entity types not in this mapping are skipped (they generate no graph node).

**Node ID disambiguation**: `THREAT_ACTOR_HANDLE` nodes are keyed as `handle@forum-domain` so the same handle on two different forums produces two distinct nodes, enabling the `LIKELY_SAME_ACTOR` inference pass.

**Node size**: base 10; boosted by 5 for each additional page the entity appears on (cap 40).

### 6.2 Edge Construction

Three passes during `build_graph_from_db()`:

1. **Intra-page edges**: for every page with 2+ entities, `CO_APPEARED_ON` edges are created between all pairs (confidence 1.0).
2. **Cross-page edges**: entities shared across multiple pages bridge those pages' unique-entity sets with `CO_INVESTIGATION` edges (confidence 0.3–0.4).
3. **Persisted relationship edges**: explicit `entity_relationships` rows written during enrichment (e.g., `PAID_TO` from blockchain) are loaded and added.

### 6.3 Relationship Inference

`infer_relationships()` adds two types of derived edges:

- **PGP key reuse** (`CONFIRMED_SAME_ACTOR`, confidence 0.95): if a PGP key node is adjacent to 2+ threat actor nodes, those actors likely share an identity.
- **Handle similarity** (`LIKELY_SAME_ACTOR`, confidence 0.6): two threat actor nodes with the same handle value (case-insensitive) but different forum domains.

### 6.4 Edge Overflow Behaviour

Applied by `persist_graph_edges()` before writing to the DB:

| Edge count | Behaviour |
|---|---|
| ≤ 10,000 | All edges written |
| 10,001 – 50,000 | **Pruning**: edges where either entity has confidence < 0.85 are dropped |
| > 50,000 | **Overflow skip**: all edges skipped; `graph_status` set to `skipped_overflow` |

Return statuses: `written`, `pruned`, `skipped_overflow`.

### 6.5 `graph_status` Values

| Value | Meaning |
|---|---|
| `pending` | Graph not yet built |
| `built` | Graph written successfully (may have been pruned) |
| `skipped_overflow` | Edge count exceeded 50,000; graph skipped |
| `no_data` | Investigation completed with no results |

### 6.6 Backend Community Detection

The graph API computes communities server-side before returning the graph payload. The response includes:

- `communities`: map of `node_id` to deterministic community ID
- `community_count`: number of detected communities

The frontend uses backend communities as the preferred partition and falls back to client-side Louvain only when the backend field is absent.

### 6.7 Path Between Nodes

`GET /investigations/{id}/graph/path?from=entity&to=entity&max_hops=6` finds the shortest path between two entity values inside one investigation graph.

The response includes `found`, `path_length`, ordered `nodes`, ordered `edges`, `from_entity`, `to_entity`, `max_hops`, `directed`, and `message`. The backend first attempts a directed path and then uses an undirected fallback. The CLI browser `[P]` path finder and the frontend Find Path button both use this endpoint and highlight the returned subgraph.

---

## 7. Actor Intelligence Layer

### 7.1 Data Model

Persistent actor intelligence uses three tables:

| Table | Purpose |
|---|---|
| `actor_profiles` | One row per canonical handle, with first/last seen timestamps, investigation count, confidence, and analyst notes |
| `actor_aliases` | Alternate handles, PGP fingerprints, emails, wallets, domains, and manually confirmed aliases |
| `actor_infrastructure` | IPs, IPv6 addresses, domains, onion URLs, PGP keys, wallets, and credential-related infrastructure linked to an actor |

Profiles are populated from `THREAT_ACTOR`, `THREAT_ACTOR_HANDLE`, `RANSOMWARE_GROUP`, and related entities during investigations. Handles below the actor-profile confidence threshold are skipped to reduce noisy profiles.

### 7.2 Cross-Alias Resolution

`sources.actor_profiles.run_alias_resolution()` scores candidate actor merges using five signals:

| Signal | Meaning |
|---|---|
| Shared infrastructure | Both profiles link to the same IP, domain, onion URL, wallet, or other infrastructure |
| Shared PGP | Both profiles link to the same PGP key or fingerprint |
| String similarity | Canonical handles or aliases are similar |
| Temporal co-activity | Profiles were observed within the same activity window |
| Co-investigation | Both profiles appeared in at least one shared investigation |

Candidates at or above 0.75 become `likely_same_actor`; candidates at or above 0.90 become `confirmed_same_actor`. Manual alias additions default to confirmed confidence.

### 7.3 Timeline Derivation

Actor timelines are computed from existing data rather than stored as a separate table. Events include first seen, investigation appearances, new aliases, new infrastructure, and analyst notes. CLI and API callers can limit event count and filter by event type.

### 7.4 API Endpoints

```
GET  /actors
GET  /actors/{handle}
GET  /actors/{handle}/investigations
GET  /actors/{handle}/timeline
GET  /actors/{handle}/aliases
POST /actors/{handle}/aliases
POST /actors/{handle}/notes
```

### 7.5 CLI Commands

```bash
voidaccess actors
voidaccess actors --search lockbit
voidaccess actor lockbit
voidaccess actor lockbit --timeline
voidaccess actor lockbit --note "Observed reuse of leak-site infrastructure"
voidaccess timeline lockbit
```

---

## 8. Content Safety

Six mandatory layers. None can be disabled via configuration.

| Layer | Where | What is checked | Action on match |
|---|---|---|---|
| 1 — Query intake | `POST /investigations` handler | `BLOCKED_TERMS` list + `BLOCKED_PATTERNS` regexes | HTTP 400; event logged |
| 2 — URL pre-scan | `is_blocked_url()` before any scraping | `BLOCKED_URL_TERMS` (pedo, loli, jailbait, csam, hurtcore, bestgore, etc.) | URL silently dropped |
| 3 — Paste/RSS content | `sanitize_content()` in paste and RSS scrapers | `CONTENT_BLOCKLIST` | Page silently dropped |
| 4 — Scraped content | `gate_pages()` / `scan_page_text()` in Step 5.75 (CLI + API) and inside `scrape_multiple` before DB write | `CONTENT_BLOCKLIST` | Page discarded; URL hash logged |
| 5 — Post-extraction entity values | `is_blocked_entity_value()` in `extract_entities_from_pages()` | `ENTITY_VALUE_BLOCKLIST` against `_TEXT_ENTITY_TYPES` only | Entity silently dropped |
| 6 — Audit logging | All block events | SHA-256 prefix of blocked item | Written to `content_safety_events` |

**`_TEXT_ENTITY_TYPES`** (Layer 5 applies only to these):
`ORGANIZATION_NAME`, `THREAT_ACTOR_HANDLE`, `PERSON_NAME`, `MALWARE_FAMILY`

Technical IOC types (hashes, IPs, CVEs, wallet addresses, onion URLs) are intentionally excluded from Layer 5. They cannot contain prohibited content by definition.

**Log hygiene**: actual prohibited text is never logged anywhere in the system. Only event type, user ID, and a hash prefix are stored.

---

## 9. Data Quality Features

### 9.1 IOC Freshness Decay

`utils/ioc_freshness.py` assigns a `FreshnessTag` to entities based on `last_seen_at` and entity type:

| Entity type | Fresh (days) | Aging (days) | Stale (days) | Expired |
|---|---|---|---|---|
| `IP_ADDRESS` | ≤ 14 | ≤ 30 | ≤ 90 | > 90 |
| `DOMAIN` | ≤ 30 | ≤ 90 | ≤ 180 | > 180 |
| `ONION_URL` | ≤ 60 | ≤ 180 | ≤ 365 | > 365 |
| `FILE_HASH_MD5`, `FILE_HASH_SHA256` | ≤ 365 | ≤ 730 | ≤ 1825 | > 1825 |
| `CVE` | ≤ 365 | ≤ 730 | ≤ 1825 | > 1825 |
| `BITCOIN_ADDRESS` | ≤ 90 | ≤ 180 | ≤ 365 | > 365 |
| `THREAT_ACTOR` | ≤ 90 | ≤ 365 | ≤ 730 | > 730 |
| Default (all others) | ≤ 30 | ≤ 90 | ≤ 180 | > 180 |

Tags: `fresh`, `aging`, `stale`, `expired`, `unknown`

### 9.2 Cross-Source Confidence

`Entity.source_count` tracks how many distinct sources corroborated an entity. `Entity.corroborating_sources` stores the source names. Higher source counts increase effective confidence during triage.

### 9.3 Defanged Output

`utils/defang.py` provides:

- `defang_url()`: `http://` → `hxxp://`, dots in hostname → `[.]`
- `defang_ip()`: last octet → `[.]x`
- `defang_email()`: `@` → `[@]`, dots → `[.]`
- `defang_value(entity_type, value)`: dispatches by type
- `defang_text(text)`: defangs all URLs and IPs in free text

Defanging is applied to the frontend display when the `defang` toggle is enabled (`defangEnabled` state in the investigation page, defaulting to `true`). It is not applied to DB storage.

### 9.4 Sources Panel

The investigation detail endpoint returns `sources_used` — a dict showing which intelligence sources ran and what they found:

```json
{
  "otx": "ok_3_results",
  "virustotal": "skipped_no_key",
  "malwarebazaar": "ok_7_results",
  "threatfox": "ok_12_results",
  "urlhaus": "ok_0_results",
  "ransomware_live": "ok_1_results",
  "cisa": "ok_2_results",
  "shodan": "ok_0_results",
  "tor_search": "ok_45_pages",
  "github": "ok_8_results",
  "gitlab": "ok_3_results",
  "paste_sites": "ok_5_results",
  "rss_feeds": "ok_12_results",
  "ip_reputation": "ok_6_enrichments",
  "greynoise": "ok_2_suppressed",
  "abuseipdb": "ok_6_enrichments",
  "domain_reputation": "ok_4_enrichments",
  "urlscan": "ok_3_enrichments",
  "hash_reputation": "ok_3_enrichments",
  "hybrid_analysis": "skipped_no_key",
  "email_reputation": "ok_2_enrichments",
  "hibp": "skipped_no_key",
  "emailrep": "ok_2_enrichments",
  "circl_pdns": "ok_4_enrichments",
  "securitytrails": "skipped_no_key"
}
```

Possible status values: `ok_N_results`, `ok_N_pages`, `ok_N_enrichments`, `skipped_no_key`, `skipped_disabled`, `error`, `pending`.

### 9.5 Infrastructure Cluster Detection

After DNS enrichment, entities sharing the same ASN, CIDR block, or WHOIS registrant are grouped into clusters. Clusters appear in `investigation.infrastructure_clusters` and are surfaced in the `InfrastructureClusters` UI component.

The cluster data is persisted in investigation metadata and mirrored in the in-process `_infra_cluster_cache` dict for fast reads. Completed investigations keep `infrastructure_clusters` and `sources_used` after container restart.

---

## 10. Export Formats

All export endpoints are at `/export/{id}/{format}` and require a valid JWT.

### 10.1 STIX 2.1

`export/stix.py` produces a STIX 2.1 Bundle containing:

- `Indicator` objects for technical IOCs (IPs, domains, hashes, onion URLs)
- `ThreatActor` objects for extracted threat actor handles
- `Malware` objects for malware families
- `Relationship` objects derived from `entity_relationships`
- `Report` object with the investigation summary and referenced objects

### 10.2 MISP JSON

`export/misp.py` produces a MISP-compatible event JSON:

- One MISP Event per investigation
- Attributes mapped from entity types to MISP attribute categories
- Galaxy clusters for malware families and threat actors
- Tags from OTX pulse tags and MITRE ATT&CK technique IDs

### 10.3 Sigma Rules

`export/sigma.py` auto-generates Sigma YAML detection rules from extracted IOCs:

- Network-level rules for IP addresses and domains
- File-level rules for hashes
- One rule per high-confidence indicator

### 10.4 CSV

Flat entity dump with columns:

`entity_type`, `value`, `canonical_value`, `confidence`, `first_seen`, `last_seen`, `source_count`, `corroborating_sources`, `context_snippet`

### 10.5 YARA Rules

`export/yara_export.py` generates `.yar` output from investigation entities. Rule generation covers malware-family strings, file hashes, credential markers, infrastructure strings, and high-confidence IOC content. Credential-like values are escaped and bounded for rule safety; use the IOC package when raw text lists are required.

API:

```
GET /export/{id}/yara
```

CLI:

```bash
voidaccess export <file-or-id> --format yara
```

### 10.6 Snort and Suricata Rules

`export/snort_export.py` generates `.rules` output for both Snort and Suricata. Rule types include IP, domain, URL, hash/string, and credential-oriented content matches where a network signature can be expressed safely.

API:

```
GET /export/{id}/snort?format=snort
GET /export/{id}/snort?format=suricata
```

CLI:

```bash
voidaccess export <file-or-id> --format snort
voidaccess export <file-or-id> --format suricata
```

### 10.7 IOC Package Export

`export/ioc_package.py` builds a ZIP bundle with 21 standard files:

| Path | Contents |
|---|---|
| `README.md` | Package overview and file index |
| `metadata.json` | Package metadata, TLP, counts, and source summary |
| `iocs/hashes.txt` | MD5, SHA1, and SHA256 values |
| `iocs/ip_addresses.txt` | IPv4 indicators |
| `iocs/ipv6_addresses.txt` | IPv6 indicators |
| `iocs/domains.txt` | Domain indicators |
| `iocs/onion_urls.txt` | Onion URLs |
| `iocs/email_addresses.txt` | Email indicators |
| `iocs/urls.txt` | URL indicators |
| `iocs/crypto_wallets.txt` | Crypto wallet indicators |
| `iocs/credentials.txt` | Partially redacted credential indicators |
| `iocs/cve_identifiers.txt` | CVE IDs |
| `iocs/mitre_techniques.txt` | MITRE ATT&CK IDs |
| `threat_intel/stix.json` | STIX 2.1 bundle |
| `threat_intel/misp.json` | MISP event JSON |
| `detections/sigma.yml` | Sigma rules |
| `detections/yara.yar` | YARA rules |
| `detections/snort.rules` | Snort rules |
| `detections/suricata.rules` | Suricata rules |
| `reports/summary.md` | Investigation summary |
| `reports/entities.csv` | Full entity CSV |

Credential redaction is enabled by default for package exports. Use `--no-redact-credentials` only when the operator explicitly needs raw credential values in the bundle. Raw scraped page content is excluded by default and only added when `--include-raw` is passed.

API:

```
GET /export/{id}/package
```

CLI:

```bash
voidaccess package <file-or-id>
voidaccess export <file-or-id> --format package
```

---

## 11. Monitoring System

### 11.1 How Monitors Work

Monitors are defined in `data/monitors.yaml`. Each monitor has:

- `name`: unique identifier and APScheduler job ID
- `type`: `keyword` or `url`
- `interval_hours`: how often the watch runs
- `enabled`: boolean toggle

**Keyword watches** (`monitor/jobs.py:run_keyword_watch`): run a new investigation for the monitor's keyword; diff the entity list against the previous run; fire alerts on new entities.

**URL watches** (`monitor/jobs.py:run_url_watch`): scrape a specific URL over Tor; diff the extracted text using `monitor/diff.py`; fire alerts on significant changes.

### 11.2 Scheduling

`monitor/scheduler.py` starts an `apscheduler.schedulers.asyncio.AsyncIOScheduler` at API startup. Jobs:

- One `IntervalTrigger(hours=N)` job per enabled watch
- `weekly_seed_refresh`: `CronTrigger(day_of_week="sun", hour=3, minute=0)` — refreshes `data/onion_seeds.json`
- `seed_validation`: `CronTrigger(day_of_week="sun", hour=2, minute=0)` — validates `.onion` seed reachability over Tor

`max_instances=1` and `coalesce=True` prevent overlapping runs of the same watch.

### 11.3 Alert Delivery

`monitor/alerts.py` dispatches alerts through configured channels:

- **Telegram bot**: sends formatted alert messages to a chat ID
- **SMTP email**: sends HTML alert emails

Alert records are persisted to `monitor_alerts`. The `delivered` field tracks whether delivery succeeded; `acknowledged` tracks operator review.

---

## 12. API Reference

All routes except `/auth/*`, `/health`, `/healthz/*` require `Authorization: Bearer <token>`.

### 12.1 Authentication

```
POST /auth/login        — { email, password } → { access_token, token_type }
POST /auth/logout       — blacklists the current token
POST /auth/register     — create account (admin only in default config)
```

### 12.2 Investigations

```
POST   /investigations                         — trigger investigation (3/min rate limit)
GET    /investigations                         — list investigations (paginated)
GET    /investigations/{id}                    — investigation detail + sources_used + clusters
GET    /investigations/{id}/entities           — entity list (filterable by type, confidence)
GET    /investigations/{id}/graph              — graph JSON (nodes + edges + communities)
GET    /investigations/{id}/graph/path         — shortest path between two entity values
POST   /investigations/{id}/cancel             — request cancellation
DELETE /investigations/{id}                    — delete investigation and all associated data
```

### 12.3 Entities

```
GET    /entities                               — global entity search
GET    /entities/{id}                          — entity detail
```

### 12.4 Export

```
GET    /export/{id}/stix                       — STIX 2.1 JSON bundle
GET    /export/{id}/misp                       — MISP event JSON
GET    /export/{id}/sigma                      — Sigma YAML rules (zip)
GET    /export/{id}/yara                       — YARA rules
GET    /export/{id}/snort?format=snort         — Snort rules
GET    /export/{id}/snort?format=suricata      — Suricata rules
GET    /export/{id}/package                    — IOC package ZIP
GET    /export/{id}/csv                        — entity CSV
```

### 12.5 Actors

```
GET    /actors                                 — list or search actor profiles
GET    /actors/{handle}                        — full actor profile
GET    /actors/{handle}/investigations         — investigations linked to actor
GET    /actors/{handle}/timeline               — derived actor activity timeline
GET    /actors/{handle}/aliases                — alias candidates grouped by confidence tier
POST   /actors/{handle}/aliases                — manually add or confirm alias
POST   /actors/{handle}/notes                  — append analyst note
```

### 12.6 Monitors

```
GET    /monitors                               — list configured watches + job status
POST   /monitors/{name}/trigger                — trigger a watch immediately
GET    /monitors/alerts                        — list alerts (filterable by severity, monitor)
PATCH  /monitors/alerts/{id}/acknowledge       — mark alert acknowledged
```

### 12.7 Admin

```
GET    /admin/users                            — list users
POST   /admin/users                            — create user
DELETE /admin/users/{id}                       — delete user
GET    /admin/enrichment-cache/stats           — cache backend, hit/miss, size, and TTL stats
POST   /admin/enrichment-cache/invalidate      — invalidate one cached enrichment entry
```

### 12.8 Health

```
GET    /health                                 — DB + Tor connectivity check (no auth)
GET    /healthz/live                           — liveness probe (no auth)
GET    /healthz/ready                          — readiness probe (no auth)
GET    /debug/tor-test                         — test Tor connectivity (JWT required)
GET    /debug/search-test                      — test search engine (JWT required)
```

### 12.9 Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /investigations` | 3 per minute per IP |
| All other protected routes | No per-route limit configured (global middleware present but not enforcing per-route) |

`DISABLE_RATE_LIMIT=true` bypasses all rate limiting (development only).

---

## 13. Configuration Reference

### 13.0 Optional vector embeddings

PyTorch and sentence-transformers are optional. Without them, the embedding
pipeline logs a one-time notice and uses a deterministic SHA-256 fallback
encoder. Install the full vector stack with:

```bash
pip install "voidaccess[nlp]"
```

Copy `.env.example` to `.env`. The API reads all values at startup via `config.py`, which strips accidentally-quoted values and provides typed defaults.

### 13.1 Required

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL connection string. Format: `postgresql://user:pass@host:port/db` |
| `JWT_SECRET` | — | Minimum 32-byte hex string. Auto-generated by `setup.sh`; **must be set in production**. |

### 13.2 LLM Providers

At least one LLM provider key is needed for query refinement, result filtering, and summary generation. If no key is present, the pipeline falls back to unfiltered top-100 search results and skips the summary.

| Variable | Default | Notes |
|---|---|---|
| `DEFAULT_MODEL` | `openrouter/deepseek/deepseek-chat` | Model ID used when the request does not specify one. Format: `provider/model-name` |
| `OPENAI_API_KEY` | — | Enables GPT-4o, GPT-4o Mini, etc. |
| `ANTHROPIC_API_KEY` | — | Enables Claude models |
| `GOOGLE_API_KEY` | — | Enables Gemini models |
| `OPENROUTER_API_KEY` | — | Enables all OpenRouter-proxied models |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | Override for self-hosted OpenRouter |
| `GROQ_API_KEY` | — | Enables Groq fast inference |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Enables local Ollama models |
| `LLAMA_CPP_BASE_URL` | `http://127.0.0.1:8080` | Enables llama.cpp server |
| `VOIDACCESS_SAFETY_BYPASS_PROMPT` | `on` | When `off`, omits the LLM authorization preamble from refine, filter, and summary prompts (cloud runners). Mandatory content-safety gates are unchanged. |

### 13.3 Threat Intelligence Enrichment

| Variable | Default | Notes |
|---|---|---|
| `OTX_API_KEY` | — | AlienVault OTX. Required; skipped if absent. |
| `VT_API_KEY` | — | VirusTotal. Required; skipped if absent. Free tier: 4 req/min. |
| `ABUSECH_API_KEY` | — | abuse.ch (MalwareBazaar, ThreatFox, URLhaus). Optional; improves rate limits. |

### 13.4 Blockchain Enrichment

| Variable | Default | Notes |
|---|---|---|
| `BLOCKCYPHER_TOKEN` | — | BlockCypher for BTC/ETH wallet lookups. Optional. |
| `ETHERSCAN_API_KEY` | — | Etherscan for ETH wallet lookups. Optional. |

### 13.5 Clearnet Scrapers

| Variable | Default | Notes |
|---|---|---|
| `PASTE_SCRAPING_ENABLED` | `true` | Set `false` to disable paste site scraping |
| `PASTE_MAX_RESULTS` | `15` | Max pastes to fetch per investigation |
| `GITHUB_SCRAPING_ENABLED` | `true` | Set `false` to disable GitHub scraping |
| `GITHUB_TOKEN` | — | Personal access token. No scopes needed. Increases rate limit from 10 to 30 req/min |
| `GITHUB_MAX_RESULTS` | `15` | Max GitHub results per investigation |
| `GITLAB_SCRAPING_ENABLED` | `true` | Set `false` to disable GitLab scraping |
| `GITLAB_TOKEN` | — | Personal access token. No scopes needed. Increases rate limit from ~15 to ~60 req/min |
| `GITLAB_MAX_RESULTS` | `15` | Max GitLab results per investigation |
| `RSS_FEEDS_ENABLED` | `true` | Set `false` to disable RSS feed scraping |
| `RSS_MAX_ARTICLES` | `20` | Max RSS articles per investigation |
| `SCRAPINGANT_API_KEY` | — | Optional. Credential exclusively for the Web Scraping API transport. Routes paste site and RSS feed fetches through ScrapingAnt to improve reliability on flaky upstreams. Affects clearnet scraping only — never Tor, `.onion`, GitHub, or GitLab (those two carry auth tokens and are permanently excluded). Any transport failure (timeout, auth, 5xx, malformed response) silently falls back to a direct request. See §3.2 for the routing mechanism. |
| `SCRAPINGANT_PROXY_TYPE` | `residential` | Pool type for the proxy transports. `residential` (default; harder to detect, slightly higher latency) or `datacenter` (faster, cheaper, easier to fingerprint). Selects the proxy pool and does not change the host. Env-var-only; not a secret. Ignored when neither transport is active. |
| `VOIDACCESS_USE_PROXIES` | `false` | **REST API transport.** Set to `true` to route paste sites and RSS feeds through the ScrapingAnt Web Scraping API (`POST https://api.scrapingant.com/v2/general`). Without `SCRAPINGANT_API_KEY`, this is a no-op. Legacy pre-1.6.2 toggle; CLI: also set by `voidaccess configure proxy --enable / --disable` or the `--use-scraping-api` flag on `voidaccess investigate`. Mutually exclusive with `VOIDACCESS_USE_PROXY`; if both are set, the proxy transport wins for that request. |
| `VOIDACCESS_USE_PROXY` | `false` | **Proxy transport.** Set to `true` to route requests through the configured ScrapingAnt proxy pool. Requires the proxy username/password pair and uses `SCRAPINGANT_PROXY_TYPE` to select the pool. Mutually exclusive with `VOIDACCESS_USE_PROXIES` — if both are set, the proxy transport wins for that request. CLI: `voidaccess configure proxy --enable-proxy / --disable-proxy`. New in v1.6.0. |

### 13.6 DNS/WHOIS Enrichment

| Variable | Default | Notes |
|---|---|---|
| `DNS_ENRICHMENT_ENABLED` | `true` | Set `false` to skip CIRCL/RDAP enrichment |
| `SECURITYTRAILS_API_KEY` | — | Optional. Provides richer DNS history. Free tier: 50 queries/month |

### 13.7 Caching and Rate Limiting

| Variable | Default | Notes |
|---|---|---|
| `REDIS_URL` | — | Redis connection string. Optional. When absent, JWT blacklist is disabled by design (tokens valid to expiry) and rate-limit counters are in-memory. When **set** but Redis is unreachable, authenticated requests fail closed with `503` until Redis recovers (see "JWT Blacklist" in Known Behaviors) |
| `ENRICHMENT_REDIS_URL` | — | Optional Redis override used by the enrichment cache when `REDIS_URL` is not set |
| `DISABLE_RATE_LIMIT` | `false` | Set `true` to bypass all rate limiting (development only) |

Enrichment cache backend selection:

1. Redis when `REDIS_URL` or `ENRICHMENT_REDIS_URL` is set and reachable.
2. SQLite when Redis is unavailable or unset. CLI cache path defaults to `~/.voidaccess/cache.db`.
3. In-memory dict as the last-resort fallback.

Per-source TTL defaults:

| Source | TTL |
|---|---|
| AbuseIPDB | 24h |
| GreyNoise | 6h |
| Hybrid Analysis | 7d |
| HIBP | 48h |
| crt.sh | 72h |
| URLScan | 12h |
| Wayback | 7d |
| CIRCL PDNS | 24h |
| CIRCL PSSL | 24h |
| RDAP WHOIS | 72h |
| MalwareBazaar | 48h |
| ThreatFox | 24h |
| EmailRep | 24h |
| VirusTotal | 24h |

Stats endpoint:

```
GET /admin/enrichment-cache/stats
```

### 13.8 Tor

| Variable | Default | Notes |
|---|---|---|
| `TOR_PROXY_HOST` | `127.0.0.1` | SOCKS5 host. Docker Compose sets this to `tor` (the service name) |
| `TOR_PROXY_PORT` | `9050` | SOCKS5 port |

### 13.9 Internationalisation

| Variable | Default | Notes |
|---|---|---|
| `DEEPL_API_KEY` | — | DeepL translation. Optional; falls back to Helsinki-NLP local models |
| `I18N_LANGUAGES` | `en,ru,zh` | Comma-separated language codes for multilingual query expansion |

### 13.10 Playwright

| Variable | Default | Notes |
|---|---|---|
| `PLAYWRIGHT_ENABLED` | `true` | Enables JS-rendered `.onion` page scraping. Set `false` to save memory (~400 MB) |

### 13.11 IP Reputation Enrichment

| Variable | Default | Notes |
|---|---|---|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB community abuse reports. Optional; skipped if absent. Free tier: 1,000 checks/day |
| `GREYNOISE_API_KEY` | — | GreyNoise scanner classification. Optional; skipped if absent. IPs classified `benign_scanner` are removed from entity results before DB write |
| `C2_FEED_CACHE_TTL` | `24` | Hours between in-memory refreshes of the Feodo Tracker and C2IntelFeeds blocklists |

### 13.12 Domain Reputation Enrichment

| Variable | Default | Notes |
|---|---|---|
| `URLSCAN_API_KEY` | — | URLScan.io scan data. Optional; public scan results are available without a key at reduced rate |
| `URLSCAN_SUBMIT` | `false` | When `true`, VoidAccess submits new URLScan.io scans for domains with no existing result. Scans are **publicly indexed** — keep `false` for OPSEC-sensitive investigations |

### 13.13 Hash Reputation Enrichment

| Variable | Default | Notes |
|---|---|---|
| `HYBRID_ANALYSIS_API_KEY` | — | Hybrid Analysis behavioral sandbox. Optional; skipped if absent. Free tier available at hybrid-analysis.com |

### 13.14 Email Reputation Enrichment

| Variable | Default | Notes |
|---|---|---|
| `HIBP_API_KEY` | — | HaveIBeenPwned breach history. Optional; skipped if absent. Paid: $3.50/month individual plan |
| `EMAILREP_API_KEY` | — | EmailRep reputation scoring. Optional; works at reduced rate without a key |

### 13.15 Pipeline Timeouts and Recovery

| Variable | Default | Notes |
|---|---|---|
| `VOIDACCESS_PARALLEL_SOURCES_TIMEOUT` | `300` | Seconds allowed for the parallel collection phase |
| `VOIDACCESS_ENRICHMENT_TIMEOUT` | `120` | Seconds allowed for enrichment phases |
| `VOIDACCESS_GRAPH_TIMEOUT` | `60` | Seconds allowed for graph building |
| `VOIDACCESS_SUMMARY_TIMEOUT` | `90` | Seconds allowed for summary generation |
| `VOIDACCESS_FINALIZE_TIMEOUT` | `30` | Seconds allowed for final metadata/status persistence |
| `VOIDACCESS_INVESTIGATION_HARD_TIMEOUT_MINUTES` | `30` | Age after which a stuck processing investigation is marked failed |
| `VOIDACCESS_SWEEP_INTERVAL_SECONDS` | `300` | How often the stuck-investigation sweep runs |

### 13.16 Enrichment Source Allowlist

| Variable | Default | Notes |
|---|---|---|
| `VOIDACCESS_ENRICHMENT_SOURCES` | unset | Comma-separated list of enrichment source ids (table below). When set, only the named sources may make network calls during enrichment. Ids are case-insensitive and whitespace is ignored. |

**Unset or blank: behaviour is unchanged.** Every enrichment source runs exactly as before, subject to its own key and feature checks.

**Set: restricts, never widens.** A source in the list still needs its own API key (where it has one). A source not in the list is never called: no HTTP request, no cache read, and no coroutine is created for it. It contributes the same empty result the code already returns when a key is missing or a call fails. In the CLI report an allowlisted-off source reads `skipped_by_allowlist` in `sources_used` (never `ok`; see 13.18). The modules' own stats still say `disabled` internally (`hudsonrock`, `xposedornot`, `leakcheck`, blocklist feeds, Pwned Passwords); the CLI translates them.

The gate sits inside the `sources/` modules (and `feeds/`, `credential_presence/`), so it applies on every path that runs enrichment: `voidaccess investigate`, `voidaccess enrich`, the API, and the monitor seed refresh. Search-stage sources (onion engines, paste sites, GitHub/GitLab, RSS, Telegram, proxy) are not enrichment sources and are not affected by the allowlist; switch those off with the deny-list in 13.18.

**Unknown id: hard error.** A typo never silently enables or disables a source. The process raises `EnrichmentAllowlistError` (a `ValueError`) naming the unknown id(s) and listing every valid id, for example `VOIDACCESS_ENRICHMENT_SOURCES contains unknown source id(s): nvdd. Valid ids: ...`. The CLI validates the variable at startup; library callers hit the same error on the first enrichment call.

**Recommended cloud value** (the licence-table "fine on our keys" sources that are enrichment sources, exported as `sources.enrichment_allowlist.CLOUD_ENRICHMENT_SOURCES`; not applied by default):

```
VOIDACCESS_ENRICHMENT_SOURCES=rdap,crtsh,wayback,cisa_kev,nvd,mitre_attack
```

With that value, CVE fusion (`sources/cve_intel.py`) still runs on NVD and CISA KEV. EPSS and Exploit-DB are skipped with no request, the unified CVE page says which feeds were not queried, and the stored priority tags gain `cve_priority_partial` because the band is a lower bound (no EPSS or public-exploit uplift). If every fusion feed is off, no CVE page is emitted and nothing is written back, so an unknown CVE is never labelled `low`. The `blocklists` feeds (including Ransomwhere), Pwned Passwords and the justice.gov press feed are off under this value.

The licence column is the verdict in `platform/docs/baseline/E0-LICENCE-TABLE.md` (2026-10-11). It is an audit aid, not legal advice. "not in table" means the source is called by the pipeline but was not audited, so its terms need a human check before it is enabled for paying customers.

| id | What it queries | Module | Licence-table verdict |
|---|---|---|---|
| `otx` | AlienVault OTX pulse search | `sources/enrichment.py` | off |
| `malwarebazaar` | abuse.ch MalwareBazaar (recent samples; hash lookup) | `sources/enrichment.py`, `sources/hash_reputation.py` | off (BYO) |
| `threatfox` | abuse.ch ThreatFox IOC search; hash lookup | `sources/enrichment.py`, `sources/hash_reputation.py` | off (BYO) |
| `urlhaus` | abuse.ch URLhaus tag search | `sources/enrichment.py` | off (BYO) |
| `ransomware_live` | ransomware.live API v2 group/victim data | `sources/enrichment.py` | off |
| `ransomlook` | RansomLook group/victim data | `sources/enrichment.py` | off |
| `cisa_kev` | CISA KEV catalogue and CISA advisories feed | `sources/cisa.py`, `sources/historical_intel.py` | on our keys |
| `nvd` | NIST NVD 2.0 CVE data and CPE product lookup | `sources/nvd.py` | on our keys |
| `epss` | FIRST EPSS exploit-probability scores (CVE fusion) | `sources/epss.py` | conditional (confirm with FIRST) |
| `exploitdb` | Exploit-DB CVE-to-EDB-ID CSV (CVE fusion) | `sources/exploitdb.py` | conditional (read repo licence) |
| `shodan_internetdb` | Shodan InternetDB open ports/vulns per IP | `sources/shodan.py` | off |
| `virustotal` | VirusTotal file-hash lookups (entity enrichment and hash reputation) | `sources/virustotal.py`, `sources/hash_reputation.py` | BYO |
| `mitre_attack` | MITRE ATT&CK STIX actor-to-technique mapping and the technique overlay | `sources/historical_intel.py`, `sources/enrichment.py` | on our keys |
| `fbi_doj_press` | justice.gov press-release RSS matched against actors | `sources/historical_intel.py` | not in table (cf. row 39, RSS feeds) |
| `blocklists` | Umbrella id: enables `sslbl`, `openphish`, `phishtank` and `ransomwhere` together | `feeds/__init__.py` | not in table |
| `sslbl` | abuse.ch SSL Blacklist | `feeds/__init__.py` | not in table (abuse.ch terms, cf. row 12) |
| `openphish` | OpenPhish community feed | `feeds/__init__.py` | not in table |
| `phishtank` | PhishTank bulk feed | `feeds/__init__.py` | not in table |
| `ransomwhere` | Ransomwhere BTC ransom-wallet list | `feeds/__init__.py` | not in table |
| `feodo_tracker` | abuse.ch Feodo Tracker C2 IP list | `sources/ip_reputation.py` | off |
| `c2_tracker` | C2-Tracker / C2IntelFeeds GitHub lists | `sources/ip_reputation.py` | off |
| `abuseipdb` | AbuseIPDB IP check | `sources/ip_reputation.py` | BYO |
| `greynoise` | GreyNoise Community IP check | `sources/ip_reputation.py` | off (BYO) |
| `crtsh` | crt.sh certificate-transparency subdomains | `sources/domain_reputation.py` | on our keys |
| `wayback` | Wayback Machine CDX snapshot history | `sources/domain_reputation.py` | on our keys |
| `urlscan` | urlscan.io search and submit | `sources/domain_reputation.py` | BYO |
| `hybrid_analysis` | Hybrid Analysis hash search | `sources/hash_reputation.py` | BYO |
| `hibp` | HIBP v3 breached-account lookup | `sources/email_reputation.py` | conditional (paid key + attribution, else BYO) |
| `emailrep` | EmailRep.io reputation | `sources/email_reputation.py` | BYO |
| `disposable_email` | Disposable-email-domain list download | `sources/email_reputation.py` | conditional (read repo licence) |
| `xposedornot` | XposedOrNot breach lookup | `sources/breach_lookup.py` | BYO |
| `leakcheck` | LeakCheck public API | `sources/breach_lookup.py` | off |
| `hudsonrock` | Hudson Rock Cavalier infostealer OSINT (email and domain) | `sources/infostealer.py` | off |
| `rdap` | RDAP via rdap.org and rdap.arin.net | `sources/dns_enrichment.py` | on our keys |
| `circl` | CIRCL passive DNS and passive SSL | `sources/dns_enrichment.py` | off |
| `securitytrails` | SecurityTrails DNS history (key is configured but no code path calls it today) | `sources/dns_enrichment.py` | BYO |
| `blockcypher` | BlockCypher Bitcoin address lookup | `sources/blockchain.py` | BYO |
| `etherscan` | Etherscan Ethereum address lookup | `sources/blockchain.py` | off (BYO) |
| `hibp_pwned_passwords` | HIBP Pwned Passwords k-anonymity range API (5-char hash prefix only) | `credential_presence/__init__.py` | not in table |

---

## 14. Known Limitations

### CLI Requires Local Tor

The CLI probes `127.0.0.1:9050`, then `127.0.0.1:9150`, then the configured Tor proxy. If none respond, dark web investigations stop unless `--no-tor` is used for clearnet-only runs.

### spaCy Auto-Installs on First Use

The CLI installs `en_core_web_sm` automatically if it is missing. First run can stall on locked-down machines or on hosts without network access to PyPI.

### Tor Search Engine Coverage

Only 3 of the 16+ configured `.onion` search engines reliably return results. The others time out silently. Queries that depend on dark web search surface area will return far fewer results than the engine count implies.

### Tor Circuit Saturation

Concurrent investigations share the same Tor SOCKS5 proxy. Performance degrades significantly with 2–3 simultaneous investigations. The 1 MB per-page scrape cap limits individual circuit load, but concurrent queries to different search engines can exhaust the circuit pool.

### OpenRouter Free Tier Rate Limits

Free-tier models on OpenRouter enforce per-minute rate limits. The pipeline has exponential backoff with up to 4 retries per LLM call, parsing the `X-RateLimit-Reset` header to determine wait time. Investigations involving many LLM calls (refinement + filter + summary) can stall for several minutes under rate limiting.

### JWT Blacklist: Fail-Open by Design, Fail-Closed on Outage

`POST /auth/logout` writes revoked tokens to Redis. Behaviour depends on whether revocation was opted into (a deliberate decision, not an accident of implementation):

- **`REDIS_URL` unset** — the blacklist is disabled by design. `POST /auth/logout` returns success but is a no-op; tokens remain valid until their 8-hour expiry. Fail-open, for operators who choose not to run Redis.
- **`REDIS_URL` set, Redis reachable** — revocation is enforced. `POST /auth/logout` blacklists the token; a failed write returns `503`.
- **`REDIS_URL` set, Redis unreachable** — revocation was opted into, so it is a required control. `is_token_revoked()` raises `BlacklistUnavailableError` and `get_current_user` **fails closed**, rejecting every authenticated request with `503 Service Unavailable` plus an operator warning log, rather than silently honouring a possibly-revoked token. Enforcement resumes automatically once Redis recovers (per-request retry, no restart).

Rationale: single-operator self-hosted tool with 8-hour (not short-lived) tokens — silently accepting revoked tokens during an outage would make logout/session-invalidation unreliable when it matters most, and an attacker could induce an outage to bypass revocation. Operators who prefer availability over revocation can unset `REDIS_URL`.

### Temporal Analysis Uses Scrape Time, Not Content Time

`Page.scrape_timestamp` records when VoidAccess visited a page — not when the content was authored. `Page.posted_at` exists for authored dates but is rarely populated (paste sites and RSS feeds populate it; `.onion` scrapes almost never do). Temporal analysis panels are therefore based on VoidAccess scrape time, which can skew activity histograms for old content.

### `detect_pgp_reuse()` Not Called

`analysis/opsec.py` implements `detect_pgp_reuse()` but `run_full_opsec_analysis()` never calls it. PGP key reuse detection at the graph level (via `infer_relationships()`) is still functional; the OPSEC-panel method is dead code.

### Debug Endpoints Are Unauthenticated at Network Level

`GET /debug/tor-test` and `GET /debug/search-test` require a JWT since the audit (they are behind `Depends(get_current_user)`), but they expose internal connectivity status. Consider removing them before public deployment.

### Single-Worker Cancellation Only

`_cancel_flags` is an in-process dict. Cancellation works only when the HTTP cancel request and the pipeline background task run in the same uvicorn worker process. Multi-worker deployments (e.g., `--workers 4`) break cancellation for investigations running on a different worker.

### proxy transport Over Plain HTTP Can Return 502

When `VOIDACCESS_USE_PROXY=true` is set and the target URL is plain HTTP (not HTTPS), the ScrapingAnt proxy transport endpoint occasionally returns HTTP 502 instead of the target's content. HTTPS targets succeed reliably. Because real-world paste sites and the curated RSS feed list are nearly universally HTTPS, this only surfaces against an unusual plain-HTTP target and the silent fallback to direct (`sources/proxy_client.py::_fetch_via_proxy_mode` returns `None` on `resp.status >= 500`, then the chokepoint retries without the proxy) still returns usable content. The REST API transport (`VOIDACCESS_USE_PROXIES=true`) is not affected — the same chokepoint has no observed flakiness on plain HTTP via the `/v2/general` endpoint. If a future investigation produces unexpectedly few results from a plain-HTTP source, the cause is this; switching to REST API or to direct is a workaround.

### 13.17 Opt-in Speed Controls and Progress Events

All of these are unset by default and change nothing for self-hosters. Each overrides one built-in value.

| Env var / flag | Default (unset) | Effect |
|---|---|---|
| `VOIDACCESS_PACE=aggressive` | `normal` (or the persisted `configure pace` value) | Existing pacing profile; scales every search and scrape timeout, retry backoff and politeness delay (`pacing/`). Third-party quota delays never shrink below their published interval. |
| `VOIDACCESS_SEARCH_WORKERS` | `DEPTH_PRESETS[depth].max_workers` (3 / 5 / 8) | Concurrent Tor search engines. Engines queued behind this limit spend their per-engine timeout waiting, so a low value causes spurious timeouts. |
| `VOIDACCESS_SCRAPE_WORKERS` | `DEPTH_PRESETS[depth].max_workers` | Concurrent page fetches. |
| `VOIDACCESS_EXTRACT_CONCURRENCY` | `DEPTH_PRESETS[depth].extract_concurrency` (3 / 5 / 6) | Pages extracted concurrently. |
| `VOIDACCESS_LLM_CHUNK_CONCURRENCY` | `1` | LLM extraction splits a long page into 12,000-character chunks and sends them one after another. A value above 1 sends a page's chunks concurrently (results are merged in the same order, so output is identical). |
| `VOIDACCESS_LLM_CHUNK_TIMEOUT` | none | Seconds. Caps one LLM extraction chunk call; a stalled call then contributes nothing instead of holding the extraction stage (one measured run spent 759 s there). |
| `VOIDACCESS_SEARCH_DEADLINE` | none (wait for the slowest engine) | Seconds. When it passes, the search stage returns the engines that have answered and cancels the rest (reported as `deadline`, not counted against the circuit breaker). |
| `VOIDACCESS_CONCURRENT_COLLECT` | off | `1` runs the side sources (paste, GitHub, GitLab, RSS, Torch/Haystack, Telegram) concurrently with the Tor engine fan-out instead of after it. |
| `VOIDACCESS_ENRICHMENT_TIMEOUT` | not enforced on the CLI | Seconds; caps the whole enrichment cluster on the CLI and keeps partial results. |
| `VOIDACCESS_ENRICHMENT_SOURCES` | all | See 13.16. |
| `MAX_LLM_PAGES_PER_INV` | `10` | Pages that get an LLM extraction call. The CLI now honours it (as the API already did). |
| `--events-jsonl PATH` | off | Writes one JSON progress event per line; see `progress/README.md`. The `completed` event's `metrics` carry `source_requests`, `source_requests_by_step`, `sources_status`, `summary_kind` and the output paths. |
| `VOIDACCESS_DISABLED_SOURCES` | none | Cloud deny-list; see 13.18. |
| `VOIDACCESS_CANCEL_GRACE` | `3` | Seconds an in-flight item may keep running after a cancel before it is stopped (see 2.5). |
| `VOIDACCESS_CANCEL_POLL_INTERVAL` | `0.25` | Seconds between looks at the cancel token while a stage waits. |

Why enrichment is not run concurrently with scraping or extraction: the query-only fetchers (OTX, abuse.ch, ransomware.live, RansomLook) have no data dependency and could overlap scraping, but they are exactly the sources a licence-restricted deployment turns off, and the remaining sources (NVD, CISA KEV, RDAP, crt.sh, Wayback, MITRE) are driven by entities that only exist after extraction. The entity enrichers share and rewrite the extraction result list and the entity rows, so they stay sequential.

### 13.18 Source Deny-List and Source Status

| Variable | Default | Notes |
|---|---|---|
| `VOIDACCESS_DISABLED_SOURCES` | unset | Comma-separated source ids (tables below and in 13.16). Ids are case-insensitive and whitespace is ignored. The named sources make no network call in any stage. |
| `VOIDACCESS_RSS_SNIPPET_ONLY` | unset | Set to `1` to retain only feed headline/link/date/summary and never fetch full RSS-linked article bodies. Unset preserves full-body behavior. Works alongside the E1C deny-list. |

**Unset or blank: behaviour is unchanged.** Setting it only removes sources.

**Every stage is covered.** The deny-list is applied inside the modules, so it holds on the CLI, the API and `voidaccess enrich`: the Tor engine fan-out (`tor_search`, `torch`, `haystack`), the paste, GitHub, GitLab, RSS and Telegram scrapers, the blocklist feed matchers, historical intel (justice.gov press), credential presence (Pwned Passwords) and every enrichment source. A denied source is not called, not read from its cache, and no coroutine is created for it. It composes with the allowlist in 13.16: a source runs only if the deny-list does not name it **and** the allowlist (when set) permits it. When both exclude a source, `disabled` wins.

**Unknown id: hard error**, like the allowlist, because a typo would leave a source running that the operator meant to switch off. The CLI validates it at startup (exit code 2); the API validates it when an investigation starts (`SourceControlError`, a `ValueError`).

**Umbrella ids.** `paste_sites` denies `pastebin`, `paste_ee`, `dpaste` and `rentry`; `blocklists` denies `sslbl`, `openphish`, `phishtank` and `ransomwhere`; `rss` denies every RSS feed including the FBI and DOJ ones. `fbi_doj_press` on its own denies both the justice.gov press-release lookup in historical intel and the two FBI/DOJ feeds in the RSS scraper.

Search-stage source ids (enrichment ids are in 13.16):

| id | What it is | Module | Licence-table verdict (E0, 2026-10-11) |
|---|---|---|---|
| `tor_search` | the 16-engine Tor onion search fan-out | `search/search.py` | on our keys (row 36; needs a legal and abuse-handling decision) |
| `torch` | Torch onion search engine | `sources/engines.py` | on our keys (row 36) |
| `haystack` | Haystack onion search engine | `sources/engines.py` | on our keys (row 36) |
| `paste_sites` | umbrella for the four clearnet paste sites | `sources/paste_scraper.py` | off (row 38) |
| `pastebin` | Pastebin search and raw fetch | `sources/paste_scraper.py` | off (row 38) |
| `paste_ee` | paste.ee search and fetch | `sources/paste_scraper.py` | off (row 38) |
| `dpaste` | dpaste.org search and fetch | `sources/paste_scraper.py` | off (row 38) |
| `rentry` | Rentry raw fetch (no search endpoint) | `sources/paste_scraper.py` | off (row 38) |
| `github` | GitHub code and repository search | `sources/github_scraper.py` | on our keys with one token and caching (row 31) |
| `gitlab` | GitLab snippet and project search | `sources/gitlab_scraper.py` | BYO only until terms are read (row 32) |
| `rss` | umbrella for the 21 security RSS and press feeds | `sources/rss_scraper.py` | conditional: headline, link and short snippet only (row 39) |
| `telegram` | Telegram channels through Telethon (needs `TELEGRAM_API_ID`/`TELEGRAM_API_HASH`) | `sources/telegram.py` | off (row 40) |

**Recommended cloud value** (exported as `sources.source_control.CLOUD_DISABLED_SOURCES`; not applied by default). It denies every source whose commercial terms are unverified or non-commercial on the licence table and that the allowlist in 13.16 does not already remove:

```
VOIDACCESS_DISABLED_SOURCES=openphish,sslbl,phishtank,ransomwhere,hibp_pwned_passwords,fbi_doj_press,pastebin,paste_ee,dpaste,rentry,gitlab,telegram
```

Use it together with `VOIDACCESS_ENRICHMENT_SOURCES=rdap,crtsh,wayback,cisa_kev,nvd,mitre_attack`. Still running under both values, and not on the licence table's "fine on our keys" list: `rss` (conditional: the scraper also fetches each matching article's body and passes it to extraction and the summary, which is more than "headline, link and short snippet"), `github` (fine only with one token and caching, never token pooling), `torch`/`haystack`/`tor_search` (no terms, a legal decision), and the non-source services ScrapingAnt (a paid proxy, resale terms unread) and DeepL (a free key is off; only a paid plan is fine).

**`sources_used` (CLI JSON and the `sources_status` metric).** Each entry is `{"status", "count", "requests"}` (plus `"error"` carrying an exception class name, never its message):

| status | Meaning |
|---|---|
| `ok` | the source ran; `count` is the pages or matches it produced (zero is a real zero) |
| `error` | it raised, or every HTTP call it made failed (an exception, 401, 403, 429 or 5xx) |
| `timed_out` | the stage or call hit its cap |
| `skipped_by_allowlist` | `VOIDACCESS_ENRICHMENT_SOURCES` excludes it |
| `disabled` | `VOIDACCESS_DISABLED_SOURCES` names it, or its own off switch is set (`PASTE_SCRAPING_ENABLED=false` and friends) |
| `no_key` | it needs an API key that is not set and it made no request |
| `skipped` | not run in this mode, for example the onion engines under `--no-tor` |

`requests` is the number of HTTP calls the source actually made (a cache hit is zero). It is counted at the shared HTTP chokepoints by mapping the URL to a source id (`sources/source_control.py::SOURCE_URL_RULES`), so no module keeps its own tally. The same counts are in the `completed` progress event: `metrics.source_requests` (total per source id) and `metrics.source_requests_by_step` (per pipeline step, so a runner can report `enrichment_calls` per source). In the API, `sources_used` keeps its flat string form and gains the strings `disabled` and `skipped_by_allowlist` for those sources.

```json
"sources_used": {
  "nvd":          {"status": "ok", "count": 3, "requests": 2},
  "otx":          {"status": "no_key", "count": 0, "requests": 0},
  "openphish":    {"status": "disabled", "count": 0, "requests": 0},
  "pastebin":     {"status": "disabled", "count": 0, "requests": 0},
  "ransomlook":   {"status": "skipped_by_allowlist", "count": 0, "requests": 0},
  "github":       {"status": "error", "count": 0, "requests": 4, "error": "ClientConnectorError"},
  "tor_search":   {"status": "skipped", "count": 0, "requests": 0}
}
```

### 13.19 Trace Events (progress schema 2)

Opt-in. With neither switch set, a run produces exactly the events, files and terminal output it did before; the only change is the added `schema: 2` field on every progress event.

| Env var / flag | Default | Effect |
|---|---|---|
| `voidaccess investigate --trace` | off | Writes `trace` events to the `--events-jsonl` file. Without `--events-jsonl` it warns and keeps nothing. |
| `VOIDACCESS_TRACE_EVENTS=1` | off | The same, for any caller of `_run_investigation` (the cloud runner sets it and receives traces through its `CallbackSink`). |
| `VOIDACCESS_TRACE_CAPS` | `url.found=600,url.kept=600,url.dropped=600,page.fetched=400,entity.found=300`, 200 for every other kind | Per-kind caps, e.g. `url.found=300,entity.found=100`. |
| `VOIDACCESS_TRACE_MAX_EVENTS` | `3000` | Total trace events per run, including the truncation markers. |

**Event.** `{type: "trace", schema: 2, run_id, seq, at, stage, kind, data}`. `seq` is shared with the schema-1 events, so it is monotonic across both. The kinds and their `data` are in `progress/README.md`; `progress/schema/progress-v2.schema.json` validates every event a run writes.

**Where they come from.** The hooks are module functions in `progress/trace.py`, called from the search fan-out (`search/search.py`), the scraper (`scraper/scrape.py`) and the CLI orchestrator. They find the run's emitter the way `utils/cancel.py` finds the cancel token (a context variable, then a process-wide default for the search stage's thread-isolated loop), and are no-ops when no traced emitter is bound. The API pipeline shares the search and scrape functions but never binds one, so it emits nothing and behaves as before.

**Guarantees.**

- *Never slows or breaks a run.* A trace is O(1) to emit, goes through the emitter's bounded queue (raised to 4,096 when tracing is on), and is the first thing dropped when the queue is full; `stage`, `refined` and terminal events never are. On close, if a slow sink is still behind after half the flush budget, queued traces are shed so the terminal event is delivered. Any exception while building a trace is swallowed. Inline sinks (the Rich display) never receive traces.
- *No new work.* No LLM calls and no extra database queries. The safety checks the hooks use are the pure ones (`is_blocked_url`, `is_blocked_query`, `is_blocked_entity_value`), not `url_is_blocked`, which writes an audit event.
- *Caps.* Beyond a kind's cap the events are counted, not sent; just before the terminal event the emitter sends one `trace.truncated {kind, dropped}` per capped kind with the final count. The `counts` events keep counting everything.

**What a trace may contain.** A URL appears only as `host`: an onion as the first 8 and last 4 characters of its label plus `[.]onion` (`lockbit3…xyz7[.]onion`), a clearnet host or IP with every `.` and `:` bracketed (`example[.]com`). No scheme, port, path, query or user info. Vanity onion prefixes and hostnames can name what a site is (a live run surfaced prefixes naming child-abuse and murder-for-hire sites that pass the URL check), so when the part shown, or the search result's title, contains a child-abuse, sexual or violence-for-hire term (`progress/trace.py::_DISPLAY_DENY_TERMS`, plus the content-safety lists) the name is masked: `********…fcid[.]onion`, `********[.]com`. The id still follows the URL; the title is used only for this check and never emitted. False positives only hide a harmless name. Entities go through `progress.trace.mask_entity`: public threat-intel identifiers (CVE, hashes, malware and group names, wallet addresses, MITRE ids, actor handles) are shown; IPs, domains and URLs are defanged to their host; emails become `n***[@]domain[.]com`; phones, locations, personal names and key or rule blobs become placeholders; credentials and secrets keep only a well-known public prefix (`AKIA[REDACTED]`, `ghp_[REDACTED]`) or nothing; any type not on those lists is `[REDACTED]`. Never page text, titles, raw credentials, API keys or file paths.

**Content safety.** A URL that `is_blocked_url` rejects is never shown: it gets `url.dropped {url_id, reason: "safety"}` and nothing else, ever. A page the content scan drops gets `page.fetched {url_id, outcome: "safety_dropped"}` with no size, timing or status, and no `page.entities` or `entity.found` follow. Successful scraper fetches are reported only after `scrape_multiple`'s per-page scan, so a dropped page is never first announced as fetched. The host of such a page was already shown by its `url.found` (the URL itself passed the URL check before the fetch), so a consumer should hide that node's host once it sees `safety_dropped`. A query that `is_blocked_query` rejects produces no trace at all, whoever calls `_run_investigation`.

**Following one URL.** `url_id` (`u1`, `u2`, ...) is allocated once per URL string per run, so `url.found` → `url.kept` / `url.dropped` → `page.fetched` → `page.entities` share it. `entity_id` (`e1`, ...) is allocated once per (type, value); `entity.found` is sent on the first sighting with the `url_id` of that page. Entities extracted from enrichment pages carry no `url_id` (those pages have no `url.found`).

**Known limits.** `too_large` is in the vocabulary but the scraper truncates at 1 MB and keeps the page, so such a page reports `ok`. Successful fetches arrive together at the end of the scrape batch (after the safety scan); failures arrive live. Pages whose content duplicates another page are reported `url.dropped {reason: "duplicate"}` at the fetch stage after their `page.fetched`. The search stage's alternative queries (asked of the LLM when the first query finds fewer than 5 results) are `query.refined` events with `index` 1 and 2 in the `collect` stage.

