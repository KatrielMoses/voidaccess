# P1→P3 Batched Live Validation Gate — Report

Executed: 2026-09-06. Environment: Windows 11, native PostgreSQL 18.2 on
`localhost:5432`, Meilisearch v1.11.3 (local binary, `:7700`), Redis **down**
(used deliberately to prove the no-Redis path), Tor installed but not running,
no Oracle/VPS target reachable.

Scope split agreed with the owner before execution:
- **Runnable here (real infra):** environment + Meili, live Postgres migrations,
  no-Redis auth + rate limiting, the two legal lines, durable-queue
  restart-survival, the ranking four-point items, the ransomwhe.re endpoint.
- **Operator-driven (live dark-web Tor egress / deploy):** items requiring real
  `.onion` crawls or a remote box. Validators are provided so the operator runs
  them and gets a deterministic pass/fail.

---

## Results

| Test | Result | Notes |
|---|---|---|
| **G-ENV1** real-Meili integration | **PASS** | Upsert → keyword + hybrid-semantic round-trip → dedup, against real Meili 1.11.3. **Caught + fixed** two crashes: a cold-index delete (FIX-1) and a non-idempotent `ensure_index` that crashed on the 2nd-ever startup against a persistent index (FIX-5). Passes repeatably. |
| **G-ENV2** no-Redis boot serves JWT auth | **PASS** | Standalone uvicorn with `REDIS_URL` unset boots; `/health`=200; auth served with no 503 (DB-backed revocation). |
| **G-P2a** `alembic upgrade head` on live Postgres | **PASS** | 0026→0030 applied clean; all artifacts (discovered_onions, page_snapshots, global_entities, jobs, revoked_tokens, consecutive_dead) present; idempotent re-run. **Caught + fixed a critical migration bug** (see FIX-2). |
| **G-P2b** restart-survival (durable queue) | **PASS** | Live PG jobs table: worker-A's in-flight `running` job survived a simulated API restart (`requeue_orphans(all_running=True)`) and was resumed by worker-B (attempts=2), not orphaned; lease-lapse reaper also reclaims. |
| **G-P2c** rate limiting + login-not-500 | **PASS** | Malformed login → 422 (never 500 — the standalone-uvicorn 500 is fixed); burst of logins → attempts 1–4 = 422, **5+ = 429** (in-process limiter, no Redis). |
| **G-P2d** `migrate-to-vps.sh` review + dry-run | **PASS (reviewed)** | `--dry-run` added; confirmed it carries state incl. QUEUED jobs (Postgres volume). **Fixed a gap:** `meili_data` (owned index) was not in the bundle — added (FIX-4). Execution against a real target: operator-driven (no VPS here). |
| **RV-F4a** defang legal line | **PASS** | Real API round-trip (`GET /investigations/{id}/entities?defang=true`): URL/PASTE_URL returned defanged (`hxxp`, `[.]`); wallet returned raw with `defanged:false`; invariant `defanged:true ⇒ value changed` holds for all rows. Live-crawl sourcing of URLs: operator-driven (validator provided). |
| **RV-C3** ransomwhe.re endpoint | **PASS (live)** | `/export` reachable → **11,186 wallets** (matches tester figure). A real wallet (Netwalker) flagged `ransom_wallet` + `feed:ransomwhere` + family tag + `ransomwhe.re` provenance; base58 case preserved. Graceful-degradation path unchanged. |
| **G-P3c** sanitizer legal line | **PASS** | `test_sanitizer.py` green here (creds/prose-creds/token-secrets/PII/fail-closed). Real-Meili end-to-end: content laced with a credential combo + AWS secret + victim name/email/phone upserted through the normal gate → **none survive** in the stored index doc. Spot-check of live-crawl R2 objects: operator-driven (validator provided). |
| **FP-1** survive engine death | **PASS (live)** | `merge_and_rank(query, external_links=[])` (all engines dead) still returned the owned-index hit from real Meili. Unit coverage `test_survives_all_engines_failing` also green. |
| **FP-4** semantic rank beats static weight | **PASS (mechanism) / BLOCKED (real embeddings here)** | Ranking mechanism proven: `test_semantic_rank_beats_static_weight` (relevant/low-weight beats irrelevant/high-weight) green. **Live drift:** the real MiniLM model does not load in this env (numpy 2.x — see DRIFT-1), so semantic ranking ran on the non-semantic deterministic fallback and cannot demonstrate semantic superiority on real embeddings here. **Caught + fixed a fallback bug** (FIX-3). Re-verify FP-4 on real embeddings on a box where the model loads. |
| **FP-2** serve-from-cache (partial) | **PARTIAL (as noted)** | Persistent shared cache-serve is P4 (read-from-shared). Today's partial: the 24h vector cache skips a re-scrape of an already-cached page. Not separately re-demonstrated live this pass. |
| **FP-3** freshness re-crawl + diff | **OPERATOR** | Part of G-P3d; needs a live crawl + the freshness durable-queue loop. Runs on operator infra with Tor; queue mechanics validated via G-P2b. |
| **RV-REG** one API + one CLI e2e | **OPERATOR** | Needs live Tor to complete a real investigation end-to-end. |
| **INT-C7** keyed second pass | **OPERATOR** | Needs the free API keys (OTX/NVD/abuse.ch/PhishTank). |
| **G-P3a** seed ingestion returns a seeded onion | **OPERATOR** | Clearnet ingestion (Ahmia/dark.fail) + a query returning a seeded onion; needs Meili populated on operator infra. |
| **G-P3b** usage-seeding auto-index | **OPERATOR** | Needs a live `.onion` investigation to index the pages it touched. |
| **G-P3d** freshness dead→drop loop | **OPERATOR** | Needs live re-crawl over Tor. |
| Oracle box deploy | **OPERATOR** | No target reachable here. |

**Exit criteria:** the two non-negotiable legal lines (**RV-F4a**, **G-P3c**) —
PASS. Live Postgres migration (**G-P2a**), restart-survival (**G-P2b**),
real-Meili (**G-ENV1**) — PASS. Four-point standard: FP-1 fully (live), FP-4
mechanism (real-embeddings blocked by DRIFT-1), FP-2 partial-as-noted, FP-3
operator. No legal-line failures. The remaining items are operator-driven (live
dark-web egress / deploy), each with a ready validator.

---

## Live drift vs mocked assumptions (the point of the gate)

- **DRIFT-1 — the real embedding model does not load in this environment.**
  `sentence-transformers` fails to import against **numpy 2.2.6**
  (`cannot import name 'ComplexWarning' from 'numpy.core.numeric'`). The system
  silently degrades to the deterministic (non-semantic) fallback. Impact: hybrid
  *semantic* search and semantic ranking (FP-4) are degraded wherever this
  dependency state exists. **Action:** pin `numpy<2` (or a
  sentence-transformers/scipy build compatible with numpy 2.x) in the deploy
  image, and verify at startup that the real model loaded — do not assume it did.
- **DRIFT-2 — the migration path silently did not commit on real Postgres.**
  See FIX-2: `alembic upgrade head` reported success (exit 0, "Running upgrade…"
  logs) but committed nothing on PostgreSQL under SQLAlchemy 2.0. Invisible on
  the SQLite test path. This means auto-migrate-at-startup was a no-op on a real
  box — P2/P3 tables would never be created. Highest-value catch of the gate.
- **DRIFT-3 — `.env` has `REDIS_URL` set to a Redis that is down.** With
  `REDIS_URL` set, revocation is the opt-in Redis backend and fails **closed**
  when unreachable (by design). The supported no-Redis single-box mode is
  `REDIS_URL` **unset** (DB-backed). For a single box without Redis, unset
  `REDIS_URL` rather than leaving it pointed at a dead endpoint.
- **DRIFT-4 — `db.session`/alembic autobegin.** Any code that runs a read on an
  alembic connection before `context.begin_transaction()` will re-trigger
  DRIFT-2; see the guard comment now in `env.py`.

## Fixes applied during the gate

- **FIX-1** `owned_index/client.py` — `delete_all_documents()` is now idempotent
  on a cold (not-yet-created) index; it previously crashed a fresh-deploy reset.
- **FIX-2** `db/migrations/env.py` — commit the connection after the
  version-column capacity check so alembic's transaction actually commits on
  PostgreSQL/SQLAlchemy-2.0 (was silently rolled back).
- **FIX-3** `vector/model_singleton.py` — the deterministic-fallback
  `embed_batch` returned one identical vector for every input; now per-text.
- **FIX-4** `scripts/migrate-to-vps.sh` — carry `meili_data` (owned index) and
  add `--dry-run`.
- **FIX-5** `owned_index/client.py` — `ensure_index()` is now truly idempotent.
  Meili's create-index is async (202 + task even when the index exists), so
  "already exists" arrives as a FAILED task, not a synchronous 409; the guard
  only handled the sync path, so the 2nd-ever `ensure_ready()` against a
  persistent index crashed. Only reproducible live (mocks don't model the async
  task lifecycle) and only on a re-run — caught when the two gated real-Meili
  tests ran in the same suite.
- Also: added the Meilisearch service to `docker-compose.yml`.

## Committed artifacts

- This report.
- Regression tests: `tests/test_defang_api_integration.py` (RV-F4a API),
  `tests/test_owned_index.py::test_real_meili_g_p3c_no_creds_or_pii_in_index`
  (G-P3c real-Meili). Gate scripts kept in the session scratchpad
  (migrations, RV-C3, FP demos, restart-survival) — portable, DB/feed-backed.

## Operator runbook (the live-Tor / deploy remainder)

1. Start Tor; set the free API keys for the keyed pass (INT-C7).
2. Run one API + one CLI investigation to completion (RV-REG); export entities;
   confirm defang honesty on the real URLs (RV-F4a live tail).
3. Confirm no creds/PII in the stored R2 objects + index docs for that run (G-P3c
   live tail).
4. Seed ingestion (Ahmia/dark.fail) → query returns a seeded onion (G-P3a);
   usage-seeding indexes touched pages (G-P3b); freshness dead→drop loop (G-P3d,
   FP-3).
5. On a box where the MiniLM model loads (DRIFT-1 resolved), re-verify FP-4 on
   real embeddings and real queries.
6. `migrate-to-vps.sh user@host --dry-run`, then for real against the target.
