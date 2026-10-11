# VoidAccess — Engineering Requirements Spec

*Handoff spec for the Solutions Architect. Derived from the strategy audit
(`docs/STRATEGY.md`) and owner decisions on 2026-09-04. This is a **what-must-be-true**
document, not an implementation plan — the SA owns sequencing and design within these
constraints. Requirements are written to be individually testable.*

**Owner decisions locked in:**
- Standard = **beat all OSS peers**, not just most. Primary rivals to surpass on the
  dark-web-collection axis: **AIL Framework**; interoperate with (not beat) OpenCTI/MISP.
- Budget: single modest always-on service, **$10–20/mo** ceiling.
- Shared corpus is **live and automated** (no human-in-the-loop git PRs). Anti-poisoning
  is an **automated trust gate**, not human review.
- Persistence is **two-tier**: private investigations never leak across users; observed
  artifacts (sites/pages/IOCs) are shared to accelerate the next investigation.
- Legal lines are hard (no raw creds, no PII) — enforced in code, not policy.

---

## EPIC 1 — Search foundation overhaul

**Goal:** stop depending on flaky third-party engines; own a persistent, self-refreshing,
semantically-ranked onion index that survives any external engine dying.

- **1.1 Engine health audit + cull.** Build a repeatable live probe that runs the full
  fan-out over Tor and records per-engine success rate, result count, latency over a
  sample of queries. *Acceptance:* a report table of all 18 engines; any engine at 0%
  over the sample is removed or quarantined. **`darksearch.io` is to be confirmed defunct
  and removed** (engine entry in `search/engine_catalog.py` **and** the dedicated module
  `sources/engines.py`).
- **1.2 Adopt an existing crawler/index rather than building from scratch.** Evaluate and
  deploy **Ahmia's open-source stack** (`ahmia-crawler` Scrapy onion crawler +
  `ahmia-index`) as the base onion crawler and known-onion seed source. *Constraint:* do
  **not** build a bespoke crawler if Ahmia's covers it; extend it.
- **1.3 Owned persistent index.** Stand up a self-hosted full-text + semantic index over
  crawled/observed onions. *Backend constraint:* use a **lightweight** engine
  (Meilisearch or Typesense on the app box, **or Quickwit backed by R2 object storage**) —
  **not** a heavy Elasticsearch cluster. Index must store: URL, title, content snapshot
  ref, first_seen, last_seen, liveness, language, category, content_hash.
- **1.4 Incremental, usage-seeded indexing (cost control).** The index grows from
  (a) curated seeds (Ahmia known-onion list + dark.fail), and (b) every onion any
  investigation touches. **No exhaustive dark-web crawl.** *Acceptance:* indexing volume
  scales with usage, not with the size of Tor.
- **1.5 Hybrid retrieval.** Keep the live external fan-out for breadth, but merge results
  with the owned index so coverage degrades gracefully when external engines are down.
  *Acceptance:* with all external engines forced to fail, search still returns results
  from the owned index.
- **1.6 Freshness loop.** Scheduled re-crawl of previously-seen onions for liveness +
  content-diff; update `last_seen`/liveness; feed diffs to the monitor subsystem.
- **1.7 Semantic ranking.** Rank merged results by semantic relevance to the query
  (reuse the existing vector/embedding layer), not raw keyword order. *This is a
  capability no OSS peer has and is the explicit differentiator.*
- **1.8 The four-point standard (definition of done for the whole epic):** search must
  (1) survive any single external engine's death, (2) serve previously-seen sites from
  cache with zero re-scrape, (3) re-crawl seen sites on a freshness schedule,
  (4) rank by semantic relevance. All four demonstrable.

---

## EPIC 2 — Two-tier persistence model

**Goal:** private investigations never appear for other users; observed sites/pages/IOCs
persist to a shared corpus that accelerates future investigations.

- **2.1 Formalize the tiers in the schema.**
  - *Private tier:* investigation, query, report, user linkage. Access-controlled to the
    owning user. **Never** exposed to other users or the shared corpus.
  - *Shared tier:* `discovered_onions`, `page_snapshots` (content cache), `global_entities`/
    IOCs — all stripped of user identity and query framing.
- **2.2 Read-from-shared on every investigation.** Pipeline must, before scraping, check
  the shared tier for: cached page content (skip re-scrape), known seeds to expand,
  pre-extracted entities. *Acceptance:* a second user searching an overlapping topic gets
  measurably faster results and cache hits from the first user's run — **without seeing
  the first user's investigation or report.**
- **2.3 Write-to-shared as a byproduct of normal use.** After scraping/extraction, observed
  artifacts flow to the shared tier **through the trust gate (Epic 3)**. Contribution
  requires **no separate user action**.
- **2.4 Consent + opt-out.** Contribution to the shared corpus is **opt-in by default-on
  with a clear opt-out** (self-hosters can run fully private). *Acceptance:* a private-mode
  install reads nothing from and writes nothing to the central corpus.
- **2.5 Page-snapshot store.** Page content snapshots live in **object storage (R2)**, DB
  holds refs + content_hash. Dedup by content_hash. TTL/refresh policy defined.
- **2.6 Reuse existing dedup.** Global entity identity goes through `extractor/identity.py`
  and the existing `(entity_type, canonical_value)` dedup — do not fork a second identity path.

---

## EPIC 3 — Shared corpus service + automated trust gate

**Goal:** a central, live, writable corpus that installs contribute to automatically, with
poisoning prevented by an automated gate — no human review.

- **3.1 Central ingest API.** Authenticated, rate-limited, opt-in endpoint that installs
  POST observed artifacts to. Owner retains a kill-switch (per-key revocation, global
  pause). *Constraint:* keep it centralized on the single owned service; installs do not
  write to each other.
- **3.2 The trust gate (pure, deterministic, pre-write function).** Every artifact passes,
  in order:
  1. **Sanitization** — strip PII (personal names/emails/addresses of victims); **never
     store raw credentials or passwords** — presence-hash (HIBP-style k-anonymity) only;
     defang IOCs.
  2. **Schema + structural validation** — reject malformed; reuse shape-aware NER
     (`extractor/entity_shape.py` + `gazetteer.py`) to reject noise.
  3. **Provenance stamping** — source onion, capture timestamp, scraper version; every
     record attributable to its origin.
  4. **Quarantine-by-default** — new artifacts enter `unconfirmed`; they do **not** affect
     scoring/triage until corroborated by ≥N independent sources **or** cross-validated
     against a trusted feed (abuse.ch/KEV/etc.).
  5. **Corroboration → promotion** — confidence tier is raised only by independent
     confirmation; **never auto-trusted.**
  6. **Source reputation** — per-onion/per-key reliability score; sources that repeatedly
     produce contradicted or anomalous data are downweighted or blocked.
  7. **Anomaly/flood detection** — per-source rate limits; detect entity-stuffing,
     templated injection, mass-identical submissions.
  8. **Dedup/canonicalize** — via `identity.py`.
  *Acceptance:* a red-team test that stands up an attacker onion feeding false IOCs cannot
  influence scoring without sustained multi-source corroboration; single-source claims stay
  quarantined; the gate is unit-tested against each attack class above.
- **3.3 Confidence tiers are first-class.** Every shared artifact carries a tier
  (`unconfirmed` / `corroborated` / `feed-validated`). Consumers (search ranking, reports,
  triage) must respect the tier. Unconfirmed data is visible but clearly weighted/labeled.
- **3.4 Provenance is queryable.** Any shared record can be traced to its sources and
  first-seen. Required for trust, disputes, and takedown.
- **3.5 Legal enforcement in code.** The sanitizer is the single choke point that
  guarantees no raw creds / no PII ever land in the store or object storage. *Acceptance:*
  automated tests assert credential/PII patterns are rejected/hashed at ingest.

---

## EPIC 4 — Noise reduction + autonomous triage brain

**Goal:** turn the accumulating corpus into a self-triaging, low-noise engine — the direct
answer to the incumbents' #1 complaint.

- **4.1 Low-noise-by-default output.** Lean on existing confidence scoring
  (`extractor/confidence.py`) + shape-aware NER so reports surface high-signal entities
  first and suppress junk. *Acceptance:* measurable reduction in low-value entities in
  output vs. current baseline on a fixed query set.
- **4.2 Corpus-informed triage.** Prioritization/scoring must consult the shared corpus:
  prior sightings, corroboration count, feed cross-hits, actor/infra linkage, recency.
  An IOC seen across many prior investigations + a trusted feed ranks above a one-off.
- **4.3 Autonomous pre-triage.** On a new investigation, the system auto-classifies and
  ranks findings (severity/relevance/novelty) from corpus history **before** the LLM
  summary — the "brain triages on its own," analyst confirms rather than sifts.
- **4.4 Feedback signal (optional, later).** Capture implicit signals (which findings users
  act on/dismiss) to tune ranking — **as anonymized aggregate weights only**, never private
  investigation content into the shared tier.

---

## EPIC 5 — Data-source integrations

**Goal:** maximize coverage/quality using free sources; observe the hard legal lines.
Ranked by value ÷ effort. Each source normalizes into the existing `enrichment.py`
page/entity model and flows through the Epic 3 trust gate where it contributes shared data.

- **5.1** ransomware.live v2 API (no-auth). *(already partially present — confirm/extend.)*
- **5.2** RansomLook API + RSS (CC BY 4.0 — attribute). *(already partially present — confirm/extend.)*
- **5.3** CISA KEV + FIRST EPSS + ExploitDB (git bulk CSVs) — CVE prioritization.
- **5.4** Ahmia `/onions/` list + dark.fail — onion-corpus expansion (ties to Epic 1).
- **5.5** abuse.ch SSLBL + Feodo; OpenPhish; PhishTank — round out feeds.
- **5.6** ransomwhe.re — BTC-address ransom labeling (enriches wallet entities).
- **5.7** NVD API 2.0 (free key); AbuseIPDB / GreyNoise Community / Censys free tiers.
- **5.8** HIBP **Pwned Passwords** (free, unlimited) — k-anonymity credential *presence*
  checks only.
- **5.9 (gated/later)** CrimeBB (Cambridge) — needs an academic data-sharing agreement.
- **5.L Legal guardrails (blocking, apply to all):**
  - **Never** ingest/host raw credential corpora (COMB/breach-parse/combolists) — presence
    flags/hashes only.
  - Strip PII; publish only defanged IOCs + org-level entities.
  - Respect per-source licenses: store **derived indicators**, not verbatim feeds, where a
    feed's ToS restricts commercial/redistribution (abuse.ch/OpenPhish). Confirm ToS before
    republishing any feed content into the shared corpus.

---

## EPIC 6 — Interoperability (surpass AIL; integrate OpenCTI/MISP)

**Goal:** match/exceed AIL's dark-web collection depth with AI on top; plug into the
platforms above you rather than competing with them.

- **6.1 AIL parity checklist.** Enumerate AIL's dark-web ingestion features (Tor/I2P/
  Telegram crawl, decoding/OCR/QR, correlation, YARA tracking, forum crawling) and define
  which VoidAccess matches, exceeds (via AI/semantic layer), or explicitly de-scopes.
  *Acceptance:* a documented feature-parity matrix with a plan to close the gaps that matter.
- **6.2 OpenCTI connector.** Publish VoidAccess entities/reports as STIX2 bundles into
  OpenCTI via its connector framework; optionally pull enrichment back.
- **6.3 MISP feed publisher.** Emit findings as MISP events/feed (you already generate MISP
  output — extend to a subscribable feed). Consume free MISP/CIRCL feeds for enrichment.
- **6.4 Keep standards exports current** — STIX 2.1 / MISP / Sigma remain first-class output.

---

## Cross-cutting requirements

- **CC-1 Security (single-maintainer threat model).** Central ingest API is the main attack
  surface — authenticated keys, per-key rate limits + revocation, global pause, input
  validation at the boundary, and the trust gate as the only write path to the shared store.
  No unauthenticated writes anywhere.
- **CC-2 Cost guardrails.** Cloudflare R2 (zero egress) for bulk/snapshots. Billing alerts +
  hard request caps on any metered surface. Prefer static snapshot serving for bulk reads;
  reserve the live DB/API for point lookups. Do **not** use Supabase as the primary
  always-on store (7-day idle pause).
- **CC-3 Preserve the existing pipeline.** New capabilities are parallel modules; the
  current investigation flow must keep working (project rule). Every new module gets
  `__init__.py`, a `README.md`, and `tests/test_<module>.py`.
- **CC-4 Pacing discipline.** No hardcoded timeouts/retries/backoff/delays — all through the
  `pacing` module (existing project rule); Tor safety for all `.onion` traffic.
- **CC-5 Observability.** The shared corpus needs health/quality metrics: ingest rate,
  quarantine vs. promotion ratio, source-reputation distribution, index size/freshness,
  cache-hit rate. So the owner can see poisoning/abuse and coverage at a glance.

---

## Suggested sequencing (SA may revise)
1. **Epic 1 (search foundation)** + **Epic 5.1–5.6** (fast data wins) — fixes the crumbling
   base and improves output immediately.
2. **Epic 2 (two-tier persistence)** — the schema/data-model change everything else builds on.
3. **Epic 3 (shared corpus + trust gate)** — the moat; depends on 2.
4. **Epic 4 (triage brain)** — compounds once the corpus has data.
5. **Epic 6 (interoperability)** — ongoing, once core is stable.

*Distribution/README work is explicitly deferred to after integration (owner's call).*
