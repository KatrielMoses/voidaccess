# Changelog

All notable changes to VoidAccess are documented here.

## Unreleased

### Default changes (self-hosters will notice these)

- **Packaging:** `pip install voidaccess` now ships 13 packages it previously
  omitted (`shared_corpus`, `trust_gate`, `netpool`, `jobqueue`, `hygiene`,
  `sanitizer`, `ratelimit`, `observability`, `snapshot_store`,
  `credential_presence`, `feeds`, `ingest`, `benchmark`) plus the new
  `progress` package. A wheel install used to crash on import. `tests/test_packaging.py`
  builds a wheel and checks it from a clean venv.
- **CLI page cap:** `voidaccess investigate` now honours `MAX_LLM_PAGES_PER_INV`
  (default unchanged at 10); it was silently ignored before.
- **Summary loss:** the CLI summary phase now retries once with a reduced context
  after a timeout, then falls back to a deterministic non-LLM summary. The first
  attempt gets 67% of `VOIDACCESS_SUMMARY_TIMEOUT` (60 of 90 s by default) so the
  retry fits in the same budget. The report JSON gains `summary_kind`
  (`llm` | `fallback` | `none`). The CLI also passes `preset="threat_intel"` by
  keyword; it was being passed in the `entities` position.
- **Search engines:** `OSS` and `TorNet` are quarantined (excluded from the
  fan-out, retained for re-probe). Live Tor probe, 4 samples each: p90 latency
  48.6 s / 76.1 s and unique-result share 0% / 7.2%
  (`benchmark/artifacts/E1B_engine_probe.json`). Kaizer, Anima, Tornado and
  Find Tor were already quarantined and probed at 0% success again.
- **Tests:** `tests/test_setup.sh` no longer contains a real-looking OpenRouter
  key or admin password.
- **`generate_summary` raises (library API):** it now raises
  `voidaccess.llm.SummaryUnavailable` (with the cause chained) when the LLM fails
  or there is no page content, instead of returning the string
  `"Summary unavailable — LLM error: …"` or `"… No extractable content found."`.
  A failed LLM could therefore be stored as, and reported as, a real summary.
  Callers must catch it; the CLI and the API do.
- **Summary retry and fallback on every failure, in both entry points:** the CLI
  retried only after a timeout; now any failure (`SummaryUnavailable`, another
  exception, an empty answer) retries once with reduced context and then falls
  back to the deterministic summary. The API now does the same through the shared
  `voidaccess.summary_fallback.summarize_with_fallback` (it used to store the
  error text). `summary_kind` is `llm` only when the model produced text. No
  user-facing text contains a raw exception message any more: the API's stored
  summary no longer ends in `summary generation failed: <exception>`, the CLI
  display line shows a generic message, and `sources_used[...].error` is the
  exception class name rather than its message.
- **`--quiet` is now silent:** it used to print a `VoidAccess — <query>` header,
  every step line, and then the full result panel. It now prints nothing at all
  except fatal errors, and those never echo the query (a too-short query used to
  be quoted back). Library warnings, the startup banner (on a terminal) and the
  optional-keys configuration warning are suppressed too. Output files are still
  written; their paths are in the `completed` event of `--events-jsonl` (file
  names embed the query, so they are not printed). JSONL and callback sinks are
  unaffected.
- **`sources_used` is honest and richer (CLI JSON):** statuses are now `ok`,
  `error`, `timed_out`, `skipped_by_allowlist`, `disabled`, `no_key` (plus
  `skipped` for "not run in this mode", e.g. `--no-tor`). Renames: `fail` ->
  `error`, `skipped_no_key` -> `no_key`. A source switched off by
  `VOIDACCESS_ENRICHMENT_SOURCES` or by its own off switch
  (`PASTE_SCRAPING_ENABLED=false`, `GITHUB_SCRAPING_ENABLED=false`, ...) no longer
  reads `ok` with zero results; a source whose every HTTP call failed reads
  `error`; a side source that raised reads `error` (it used to read `ok`). Every
  entry gains `requests` (HTTP calls actually made), and any source that made
  calls but was not reported before now appears. The summary panel's "Sources"
  count counts `ok` sources only. The API's flat string statuses are unchanged
  apart from the new `disabled` and `skipped_by_allowlist` strings.
- **SIGTERM cancels `voidaccess investigate` cleanly:** it used to kill the
  process with no event and no cleanup. Now the current item finishes (up to
  `VOIDACCESS_CANCEL_GRACE`, 3 s), the progress hook emits `cancelled` with an
  accurate `stages_completed`, the investigation row is marked `cancelled`, and the
  process exits 143 without writing any output file. Ctrl-C (exit 130) also marks
  the row `cancelled` (it used to stay `running` until the stuck-run sweep failed
  it).
- **Output files are written atomically:** the JSON and Markdown reports are
  staged as dot-prefixed temp files and renamed into place after the last cancel
  checkpoint, so a cancelled or killed-at-the-wrong-moment run can no longer leave
  a truncated report.
- **Cancel checkpoints inside the long stages** (API and CLI): a cancel request is
  now honoured between engines in the search fan-out, between pages in fetch and
  scrape, and between sources in enrichment, not only at stage boundaries. With no
  cancel requested nothing changes.
- **Tests:** `tests/test_progress.py::test_rich_display_output_unchanged` compares
  the live display (not `quiet=True`, which is now silent).

### New, opt-in (no change unless set)

- Official progress hook (`progress/`): 8-stage events with numeric counts, Rich /
  JSONL / callback sinks, `voidaccess investigate --events-jsonl PATH`.
- `VOIDACCESS_ENRICHMENT_SOURCES` allowlist for enrichment sources.
- `VOIDACCESS_DISABLED_SOURCES`: a cloud deny-list. The named sources make no
  network call in any stage (Tor engines, paste sites, GitHub, GitLab, RSS,
  Telegram, blocklist feeds, historical intel, Pwned Passwords, enrichment) and
  report `disabled`. Unknown ids are a hard error. Recommended cloud value:
  `openphish,sslbl,phishtank,ransomwhere,hibp_pwned_passwords,fbi_doj_press,pastebin,paste_ee,dpaste,rentry,gitlab,telegram`
  (`sources.source_control.CLOUD_DISABLED_SOURCES`). Source ids are listed in
  docs/architecture.md section 13.18.
- `VOIDACCESS_CANCEL_GRACE` and `VOIDACCESS_CANCEL_POLL_INTERVAL` tune the cancel
  helper (`utils/cancel.py`); `_run_investigation(..., cancel_token=...)` lets an
  embedding runner cancel cooperatively.
- Per-source HTTP request counts: `sources_used[...].requests`, and
  `source_requests`, `source_requests_by_step`, `sources_status` and the output
  paths in the `completed` progress event's `metrics`.
- `VOIDACCESS_ENRICHMENT_SOURCES` allowlist for enrichment sources.
- `VOIDACCESS_SEARCH_WORKERS`, `VOIDACCESS_SCRAPE_WORKERS`,
  `VOIDACCESS_EXTRACT_CONCURRENCY`, `VOIDACCESS_LLM_CHUNK_CONCURRENCY`, `VOIDACCESS_LLM_CHUNK_TIMEOUT`, `VOIDACCESS_SEARCH_DEADLINE`,
  `VOIDACCESS_CONCURRENT_COLLECT`; `VOIDACCESS_ENRICHMENT_TIMEOUT` is now applied
  on the CLI path when set. See docs/architecture.md section 13.17.
- `benchmark probe` artifacts report `latency_p90_ms` and `unique_result_share`
  per engine.

### Earlier unreleased changes

- Align CLI and API content-safety gates: Tor and side-source page text is
  scanned via shared `gate_pages()` before persistence, vector cache, extraction,
  or summarization; URL and entity gates fail closed on errors.
- Add `VOIDACCESS_SAFETY_BYPASS_PROMPT` (`on` default, `off` for cloud runners)
  to omit the LLM authorization preamble from refine, filter, and summary prompts
  without disabling mandatory content filters.

## [2.0.3] - 2026-08-04

- Enforce owner-only permissions on the project `.env` in both CLI configure
  and setup flows, using the same protection path as `~/.voidaccess/config.json`.
- Add a one-time legacy-data backfill for typed relationship page provenance
  and persisted community partitions.
- Re-verify typed-relationship yield on five fresh real investigations and
  record the measured baseline in the release audit.

## [1.9.4] - 2026-07-27

- Version bump.

## [1.9.3] - 2026-07-24

- STIX malware exports classify ransomware groups as `ransomware` and use
  available malware metadata/family-name signals for additional STIX malware
  types; unknown families retain the valid generic type rather than receiving
  a speculative label.
- Deterministic embedding fallback selection and its operator notice now occur
  before the small-investigation page-selection shortcut, so missing torch is
  visible on the first applicable run.
- Modernized stale test fixtures for canonical values and calibrated
  confidence output, and made null `DISABLE_RATE_LIMIT` lookups safe.
- Cross-process optional-configuration warning suppression is explicitly
  **won't-fix**: the existing process-scoped guard is sufficient for the
  operator warning, while a persistent marker would add filesystem state,
  expiry/race handling, and cleanup complexity for a minor UX issue.

## [1.9.2] - 2026-07-24

- Preserve typed graph relationships in MISP object references and map
  organization targets to STIX `targets` relationships.
- Prevent export output collisions, document the optional vector dependency,
  surface deterministic embedding fallback use, and warn once for dropped or
  legacy configuration keys.
- Warning deduplication remains process-scoped: separate CLI invocations are
  separate processes, so repeating a warning across invocations is expected
  and does not justify persistent state for this minor UX case.

## [1.9.1] - 2026-07-23

- Defer CLI/runtime configuration until after environment injection.
- Preserve configured LLM credentials through all CLI model construction paths.
- Surface graph-build row and edge metrics in the live CLI display.
- Correct rejected-query exit codes and relationship counts in summaries.
- Restore once-per-process optional-configuration warning behavior.
- Keep LockBit/LockBit4 observations distinct unless evidence supports a
  conservative relationship, avoiding unsafe automatic entity merges.

## [1.9.0] - 2026-07-23

### Changed
- Entity identity is now derived through a single shared module,
  `extractor/identity.py` (`entity_graph_id` / `entity_canonical_id` /
  `entity_display_id`). The graph builder (`_make_node_id`), the STIX / MISP /
  Sigma / IOC-package exporters, and the entity API were migrated off their own
  independent identity logic onto it, so a graph node key and an exporter's
  lookup key can no longer silently diverge (the recurring STIX threat-actor
  "silently dropped relationships" bug class). `NormalizedEntity.canonical_value`
  now returns the genuine canonical form instead of the raw value.

### Fixed
- Confidence now follows one monotonic, max-based rule across extraction,
  corroboration boosts, database upserts, and consumers; relationship type
  definitions are sourced from `graph/model.py`; and `merge_with_db` now
  records the page host in `corroborating_sources` for every persisted entity.
  This resolves the three-times-carried corroboration bug from 1.6.4, 1.7.0,
  and 1.7.1.

- Consolidated confidence consistency and edge-type vocabulary across
  extraction, persistence, graph construction, and exports; fixed
  `corroborating_sources`, closing a three-cycle-old known issue.
- Completed the seven-phase identity-drift remediation through the canonical
  identity module and migrated graph, STIX, MISP, IOC package, Snort, YARA,
  CLI browser, `show`, and investigation consumers.
- Improved CLI honesty with 500-character query validation, live graph-build
  progress, explicit zero-relationship distinctions, visible degraded
  community-detection states, expanded completion metrics, and per-source
  outcome tables.
- Verified mixed-case and EIP-55 identity behavior with repo-wide sweeps.

## [1.8.2] - 2026-07-23

- Preserve `page_id` in the CLI's lightweight `pages_scraped` manifest so
  typed relationship provenance resolves to the source page.
- Add prompt-level and post-LLM endpoint-type compatibility validation for
  typed relationships; structurally invalid pairs are excluded.

## [1.8.1] - 2026-07-22
### Fixed
- `--no-tor` now generates **zero** Tor traffic for the entire run. Previously the flag only skipped the primary Tor search branch; the Torch/Haystack onion search engines still ran and fed real `.onion` result URLs into the scrape list, which were then routed back through Tor. The onion search engines are now skipped when `--no-tor` is set, and any `.onion` link from any source is stripped before the scraper sees it — so no outbound connection to the Tor SOCKS proxy is ever attempted and no onion-sourced pages appear in the output.
- Typed relationship extraction now works against the real LLM adapter. The call built a silent client with `llm.bind(callbacks=[])`, which LangChain forwarded to `agenerate_prompt` as a keyword while `ainvoke` also passed `callbacks` explicitly, raising `got multiple values for keyword argument 'callbacks'` on every page and silently degrading to zero typed relationships. It now uses `with_config({"callbacks": []})` (matching the entity-extraction path), and a failed relationship LLM call logs a visible warning distinct from a call that genuinely found no relationship.
- Step-cost metrics (`investigation_step_metrics`) are no longer written all-zero from the CLI. The CLI created the metrics collector but never started/finished steps or recorded scraping, so `duration_ms`, `llm_calls`, and the page-fetch counters stayed zero even though work was happening (and `record_llm_call` only credits an *active* step). The CLI pipeline is now instrumented per step like the API path, so durations, per-step LLM-call counts, and page-fetch counters reflect real values.
- Empty, whitespace-only, and trivially short (< 3 character) investigation queries are now rejected up front with a clear message, before any network activity — instead of silently proceeding to produce a full, confident-looking report from generic noise.
- Non-actionable IP addresses are now filtered alongside the existing RFC 5737 documentation ranges: `0.0.0.0`, the broadcast address, and well-known public DNS resolvers (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, Quad9, OpenDNS, Level3). They no longer appear in the persisted entity store or the exported `ip_addresses.txt`, so a user importing that file into a blocklist can't accidentally block a legitimate resolver or a null route.
- ransomlook.io and ransomware.live group matching is now token-based. The old logic required the entire query string to appear literally in a tracked group name, so realistic analyst queries like `"LockBit ransomware leak site"` matched nothing even though `lockbit3` exists. Generic words are stripped and the meaningful token(s) are matched against group names (`lockbit` → `lockbit`, `lockbit2`, `lockbit3`); a genuine no-match still reports `ok_0_results` honestly.

### Changed
- The typed-relationship vocabulary term `USED` was renamed to **`USES`** for a consistent, externally-visible name across the LLM prompt/parser, the internal storage type (`RelationshipType`/`EDGE_TYPES`), the API response, and the STIX export mapping (`USES` → STIX `uses`).
- Version bumped to 1.8.1 (`pyproject.toml`, `voidaccess_cli.__version__`, IOC package `PACKAGE_VERSION`).

## [1.8.0] - 2026-07-22
### Added
- Five new free (key-optional) intelligence sources, each reporting honestly into `sources_used`:
  - **XposedOrNot** (`sources/breach_lookup.py`) — email breach-exposure lookup, complements HIBP with a different corpus; free tier includes stealer-log exposure.
  - **LeakCheck** public tier (`sources/breach_lookup.py`) — breach-source corroboration; an email surfacing in both XposedOrNot and LeakCheck is tagged `breach_corroborated`.
  - **Hudson Rock Cavalier** (`sources/infostealer.py`) — infostealer intelligence (30M+ malware-infected machines) queried by email AND domain; one of the few sources giving domain-level infostealer exposure.
  - **NVD 2.0** (`sources/nvd.py`) — full CVE metadata (CVSS, CWE, description, dates) for any extracted CVE, complementing CISA KEV's actively-exploited subset. Optional `NVD_API_KEY` raises the rate limit.
  - **ransomlook.io** (`sources/enrichment.py`) — second ransomware-group tracker that cross-validates ransomware.live; shared leak-site `.onion` seeds are URL-normalised to dedup across the two trackers.
- First pytest test suite (`tests/`), covering the parsers for the five new sources with mocked HTTP (`aioresponses`).

### Fixed
- Phase-A threat-intel enrichment now preserves the results of sources that finished before the deadline instead of discarding the entire batch when the 59s/55s cap is hit (`_gather_with_partial_results`).
- CLI `investigate` reputation steps (domain/hash/email) no longer clobber the threaded `extraction_results` list into a `(results, stats)` tuple, which had silently starved subsequent steps and actor-profile aggregation of entities.
- Typed relationship edges. A distinct LLM relationship-extraction pass (`extractor/relationship_extract.py`) runs after entity extraction and asks, for the entities already found on a page, which specific typed relationship (if any) connects them — `USED`, `DROPS`, `CONTROLS`, `TARGETS`, `EXPLOITS`, `COMMUNICATES_WITH`. Each relationship carries its own claim confidence, separate from the confidence of the two entities it connects. The vocabulary is bounded: anything the LLM cannot map cleanly is dropped and the pair keeps its plain co-occurrence edge.
- The pass is additive — co-occurrence edge generation is unchanged; typed edges sit alongside it. Bounded by `MAX_REL_PAGES_PER_INV` (default 10; one LLM call per selected page) so it can never scale unbounded with page count, mirroring the existing `MAX_LLM_PAGES_PER_INV` entity-extraction cap. Disable with `ENABLE_RELATIONSHIP_EXTRACTION=false`.

### Fixed
- STIX export keyed its entity→object map only by raw entity value, so graph edges whose node id is disambiguated (e.g. `THREAT_ACTOR_HANDLE` as `handle@forum`) were silently dropped from the bundle. The map now also registers the graph node id, so relationships with a threat-actor endpoint — including the new typed relationships — survive into the bundle.

### Changed
- STIX `Relationship` SROs now carry the edge's confidence (STIX 2.1 `confidence`, 0–100), and the new typed edge types map to documented STIX relationship types (`uses`, `drops`, `targets`, `exploits`, `communicates-with`); `CONTROLS` has no standard STIX verb and degrades to `related-to`. `CO_INVESTIGATION` now has an explicit mapping instead of relying on the default.

## [1.7.2] - 2026-07-08
### Fixed
- STIX relationship generation now avoids near-quadratic same-page edge explosions by emitting bounded semantic co-occurrence edges instead of every pair on a page.
- Persistent relationship loading now skips malformed non-UUID endpoints before graph hydration, preventing UUID coercion crashes during STIX export.
- THREAT_ACTOR_HANDLE and ORGANIZATION_NAME NER noise from repeated audits is filtered before persistence, including the confirmed generic security/programming vocabulary false positives.
- MISP, Sigma, API, and shared DB query paths now use explicit SQLAlchemy select constructs instead of passing subquery objects into `.in_()`.
- Optional configuration warnings are summarized once per process instead of printing a repeated warning wall.
- Refined query persistence now strips labelled/chatty LLM responses down to the actual short search query.

### Changed
- Tor result-count variance was reassessed as environmental network/search-engine flakiness for this pass; no code change was made for that item.

## [1.7.1] - 2026-07-07
### Fixed
- STIX export was silently producing an empty 82-byte bundle (regression from 1.6.3's working fix); now produces real bundles with entities and relationships
- Entity extraction quality had regressed on queries containing CVE/financial terms, returning only organization-name noise; CVE extraction now works correctly
- Confidence scores were clustered at 1-2 discrete values across an entire investigation; now show genuine multi-value spread reflecting source quality, extraction method, and corroboration
- Source-quality scoring (previously claimed but not actually implemented) is now genuinely present on extracted entities and contributes to confidence
- Fixed a CLI readback bug where entities were successfully extracted and persisted but the final displayed/exported count could read as zero, because the query only checked direct investigation_id matches and ignored entities linked via InvestigationEntityLink
- Fixed duplicate canonical entities appearing in results when the same entity existed in both the direct-match and linked-match branches of the entity query; results are now deduped after the union, not before

### Known Issues
- corroborating_sources field still not populated (carried over from 1.6.4, tracked separately)

## [1.7.0] - 2026-07-07
### Fixed
- --version now works as a top-level flag
- config.json now written with 0600 permissions
- Entities from Tor/.onion pages now persist to the entity store
- RFC 5737/2606 placeholder IPs/domains/emails filtered or flagged instead of treated as high-confidence threat intel
- Source-quality scoring added for low-trust sources (GitHub README docs)
- Stale OPENROUTER_API_KEY warning fixed
- Stuck 'running' investigation rows now cleaned up
- DATE entity extraction capped
- IOC package email export no longer drops emails
- STIX export SQLAlchemy warning fixed
- Non-interactive `voidaccess configure` input now detected and handled

### Changed
- sentence-transformers, torch, transformers, telethon, playwright moved to optional extras (`voidaccess[nlp]`, `[telegram]`, `[js]`, `[all]`)
- Added VOIDACCESS_NO_BANNER for session-level banner suppression

### Known Issues
- corroborating_sources not populated for any entity (tracked for next release)
- LLM may under-tag malware names present in summary but not in structured extraction

## [1.6.4] - 2026-07-07
### Fixed
- STIX relationship export now declares and installs its graph dependency, and export commands visibly warn when relationships cannot be built.
- Added missing third-party dependency declarations for imported libraries across the codebase.
- Entity store `corroborating_sources` field is silently null for all entities because `merge_with_db` in `extractor/normalizer.py` never calls `update_entity_source_count` after the initial upsert. Every entity — from tor_search, RSS, GitHub, or enrichment — has `source_count=1` and `corroborating_sources=null` instead of the source name (e.g. `["tor_search"]`). Fix requires calling `update_entity_source_count` in `merge_with_db` after each upsert, passing the page's source label derived from the page URL. Tracked as a separate fix cycle — do not treat as a footnote.

## [1.6.3] - 2026-07-07
### Fixed
- LLM entity extraction no longer streams raw JSON fragments to stdout during investigations with LLM enabled.
- STIX export no longer writes an empty bundle silently when `stix2` is missing; `stix2` is now a declared dependency and the export produces a real bundle.
- `click` is now a declared dependency, so the first-run spaCy model download triggered by `voidaccess configure` no longer fails silently and leave NER disabled.
- `use_proxies` and `use_proxy` config flags have been renamed to `rest_api_transport_enabled` and `residential_proxy_enabled`, with automatic migration for existing config files and a fix for BOM-prefixed JSON loading.

### Known Issues
- (Resolved in v1.6.4) Entity extraction and persistence from Tor/.onion pages is now confirmed working end-to-end.

## [1.6.2] - 2026-07-03
### Added
- Clarified the final release state after the residential proxy fallback QA pass and the `--use-scraping-api` transport reintroduction.
- Confirmed the six live-verified safety guarantees from the verification arc, including silent fallback behavior when proxy credentials are invalid.

### Fixed
- Residential proxy credential handling and release metadata alignment.

## [1.6.0] - 2026-07-02
### Added
- Optional clearnet ScrapingAnt integration for paste sites and RSS feeds.
- Three independent ScrapingAnt products are now documented and supported separately: Web Scraping API, Residential Proxy transport, and Datacenter Proxy transport.
- Web Scraping API transport uses `VOIDACCESS_USE_PROXIES=true` and `SCRAPINGANT_API_KEY`.
- Residential Proxy transport uses `VOIDACCESS_USE_PROXY=true` with `SCRAPINGANT_PROXY_USERNAME` and `SCRAPINGANT_PROXY_PASSWORD`.
- Datacenter Proxy transport is configured with `SCRAPINGANT_PROXY_TYPE=datacenter` and the same proxy credentials, but live verification is still open.
- The transport selection model is mutually exclusive per request; if both transports are enabled, the proxy transport wins for that request and the chokepoint logs the choice once.
- Tor, `.onion`, GitHub, and GitLab traffic remain unaffected by the integration.

### Fixed
- Corrected earlier documentation and configuration drift that conflated the Web Scraping API credential with the proxy credentials and described the wrong host model.
- Clarified that there is no chained transport mode.
