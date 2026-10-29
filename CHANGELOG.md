# Changelog

All notable changes to VoidAccess are documented here.

## 2.2.1 (2026-10-29)

### Security

- Prompt-injection fencing. Scraped page text, search-result titles and links, URLs and page-derived entity values
  now reach the LLM only inside a data fence with a random per-call boundary (`voidaccess/fence.py`), in the
  summary, relevance filter, entity and relationship extraction, and Sigma enrichment prompts. Invisible and
  control characters are scrubbed, and fake fence markers, chat-template tokens and the boundary itself are
  defanged inside the data. Each prompt states that fenced text is data and that instructions in it must be
  ignored. Measured overhead: about 3% of a typical summary prompt's tokens.
- Pages whose text looks like a prompt-injection attempt are still summarised but labelled for the model as
  suspect; the CLI `completed` progress metrics carry `prompt_injection_suspects` (count of flagged pages).
- The LLM query rewrite now keeps every identifier in the query exactly (e-mail, phone with its `+`, domain, IP,
  CVE, crypto wallet, onion address, hash, @handle); if the rewrite drops or alters one, the original query is
  used.

### Crawling and safety

- Onion addresses written in page text, not only in links, are found, including defanged forms (`[.]onion`,
  `(dot)onion`, ` dot onion`, `hxxp://`, spaces or zero-width characters inside the address). Only v3 addresses
  with a valid checksum count. Each one passes the URL safety gate first, then joins the crawl frontier behind
  every real link and inside the same page budget, and is reported as an `ONION_URL` entity.
- Near-identical pages fetched from different onion hosts are merged into the best-ranked one. The investigate
  JSON adds `mirror_count` and `mirrors` (hosts) to each `pages_scraped` entry and a top-level
  `mirror_hosts_merged` count. The crawler result adds `text_urls_discovered`.
- Optional Ahmia banned-host list as a second CSAM defence: point `VOIDACCESS_AHMIA_BANNED_MD5` at a file of
  MD5 hashes of banned onion hosts (or place it at `data/ahmia_banned.md5`) and those hosts are blocked like the
  built-in host blocklist. The list is not shipped and is never fetched by the engine.

### Search engines

- Engine cull: Torgle (down), Torgol (answers with 0 links), Amnesia and Torland (the same fixed links for every
  query, gibberish included) are quarantined, and so are the Torch and Haystack side-source engines (down, or page
  chrome only). Evidence in `search/ENGINE_CULL.md`. The fan-out is now 7 engines (was 11 plus 2 side engines).
- Per-engine outcome: every engine attempt ends `ok`, `empty`, `unreachable`, `rate_limited` or `error`. The
  investigate JSON has a new `search_engines` block (per-engine status, result count, attempts, ms; counts per
  outcome; `nothing_found`: `no_results` / `engines_unreachable` / `engines_failed`; a one-line `message`), the
  terminal and Markdown report say "N of M engines unreachable" or "engines answered but found nothing", and
  `get_last_search_summary()` gains `engines`, `engine_status_counts` and `engines_attempted`. Trace
  `search.result` gains an optional `outcome` field; `status` is unchanged.
- Cleaner results before ranking: links to search-engine hosts (every catalog engine, the side engines and other
  known onion search engines) are dropped; redirect-wrapped links (`l=`, `u=`, `url=`, `redirect_url=`, ... and `q=`
  on a redirect path, double-encoded too) are unwrapped; tracking and session parameters (`utm_*`, `ref`,
  `fbclid`, session ids) and fragments are stripped. Exact duplicates merge into one candidate that records
  `found_by` / `engine_count`; ranking gives a small capped bonus for multi-engine agreement.
- More results per engine: Onionway (pages 2-3), Excavator and The Deep Searches (page 2) are read concurrently
  when page 1 was full, within 1.5x page 1's time and never past the engine's own deadline or the search
  deadline. On 4 probe queries: 70/72/62/76 -> 130/106/116/136 unique results; direct results 18 -> 51 for
  LockBit, unchanged on the other three; the slowest engine (OnionLand, not paged) still sets the fan-out time.
  `VOIDACCESS_SEARCH_PAGES=0` turns paging off.
- Diversified alternative queries go only to engines that answered in this run (most results first), never to
  one that was just unreachable.

## 2.2.0 (2026-10-29)

### Search and sources

- Search results that name the query (title, snippet or URL) are fetched first, and the exact query (or its selector)
  is sent to every search engine next to the refined one. The fetch count and time budget are unchanged.
- GitHub searches the exact query, uses `GITHUB_TOKEN` when set, skips code search without one, and reports
  `rate_limited` (a new source and trace status) instead of "ok, 0 results" when GitHub throttles it.
- RansomLook (data CC BY 4.0) joins the cloud enrichment allowlist. Its answers are cached with a stale fallback,
  leak-site seeds are capped at 10 per group, and ordinary-word group names need a threat word in the query.

### Added

- Relevance tiers. Every page, entity and relationship in the investigate JSON now carries `relevance`
  (`direct`, `related` or `background`); pages and entities also carry `relevance_reason`, and pages a
  `page_kind`. A top-level `relevance` object gives the query type, per-tier counts, the removal counts,
  `feed_items_capped`, `filter_fallback` and `refined_query_restored`. Fields are only added; see
  `docs/architecture.md` section 13.20.
- The summary leads with direct findings, labels related material, and never presents background material as a
  finding about the query. With no direct page it opens with "No collected page mentions <query> directly."
- The Markdown report groups entities into Direct and Related and collapses Background into a short list at the
  end; `voidaccess show` has a Tier column.
- A `filter_fallback` trace event (counts only) when the LLM filter returns nothing usable.
- `scripts/eval_relevance.py` scores runs per query and per tier; `scripts/build_relevance_data.py` regenerates
  `data/ambiguous_threat_names.txt` and `data/threat_relations.json`.

### Fixed

- The query's selector is never lost: when the LLM rewrite drops or changes an e-mail, phone, domain, IP, CVE,
  hash, onion address, wallet, @handle, threat name or person name, the original query is searched.
- RSS: an article is relevant only when a query term or alias is in its title or summary. Recency orders results;
  at most 5 recent unmatched articles are kept per run, as background feed items.
- Common words in the threat gazetteer ("play", "royal", "snake", ...) are typed as threat names only with a threat
  cue within about 8 tokens, or when the query names them; platform words ("php", "tor", "android") only when the
  query names them. The removals are counted.
- An organisation that is the page's own site or publisher, or a protocol, CMS or link-directory brand ("oauth",
  "wordpress", "onionland"), is no longer extracted. Agencies such as the FBI are kept and marked background unless
  they sit next to a direct match.
- The content-safety rule in the LLM prompts is reworded so an echo of it can no longer trip the content-safety
  detector on a summary, and the model is told never to restate it.

## [2.1.1] - 2026-10-28

A security release. Upgrade promptly.

### Security

- Security: stronger content-safety detection for page text, titles, URLs and entities.
- A response without a `Content-Type` header is kept only when its body looks like text.

## [2.1.0] - 2026-10-18

A security release for multi-user self-hosted installs, plus everything built since 2.0.3: a shared knowledge
tier and owned page index, new intelligence sources, safety parity between the CLI and the web app, an official
progress hook, a cloud-ready source deny-list, and many reliability fixes.

**Upgrade:** read `docs/SECURITY-ADVISORY-2026-10.md`, install 2.1.0, rebuild the web UI, and run
`alembic upgrade head` (migrations `0027` to `0036`). Rotate `JWT_SECRET` if you want to end sessions issued before
the upgrade. Multi-user installs should upgrade promptly.

**Privacy:** nothing leaves your install. The new "shared" tier is shared between the users of one install, in your
own database, and only ever holds sanitized observations, never who searched for what. The cross-install ingest API
is off unless you set `VOIDACCESS_INGEST_ENABLED=true` on a corpus service you run yourself.

### Security

- Fix self-hosted multi-user data exposure: shared ownership dependencies return
  404 for foreign investigation, entity, graph, analysis, export, actor and monitor resources.
- Add owned entity link context, investigation-scoped pages, private actor notes
  and aliases, database monitors and alerts, and user-filtered Chroma search.
- Add the `user`/`admin` role and `voidaccess admin promote --email`; administrative
  routes now require an administrator. Existing first users bootstrap as admin.
- Make forwarded-IP trust opt-in and add authenticated-user request limits.
- Move web sessions to httpOnly cookies; server proxies forward authentication,
  and logout revokes backend JWTs. Database revocation errors fail closed.
- Add opt-in `VOIDACCESS_RSS_SNIPPET_ONLY=1` to avoid fetching article bodies.
- Add migration `0036_multiuser_security`, idempotent YAML/vector import, two-user
  API tests, migration tests, route enumeration and browser-session tests.
- See `docs/SECURITY-ADVISORY-2026-10.md` for upgrade and attribution limitations.

### Breaking changes

- Database: run `alembic upgrade head` (migrations `0027` to `0036`). The ownership migration has no destructive
  downgrade; back up first (see the advisory).
- Administrative routes require the `admin` role.
- `voidaccess.llm.generate_summary` raises `SummaryUnavailable` instead of returning an error string.
- CLI JSON `sources_used` statuses renamed: `fail` -> `error`, `skipped_no_key` -> `no_key`; new `disabled`,
  `skipped_by_allowlist`, `timed_out`.
- `voidaccess investigate --quiet` prints nothing except fatal errors.

### New: shared tier and owned page index (local to your install)

- **Shared corpus tier** (`shared_corpus/`): discovered onions, page snapshots, canonical IOCs and source reputation,
  kept apart from private investigation data, so one investigation's observations speed up the next (cache hits,
  seed expansion, pre-extracted entities) without revealing who searched for what. Migrations `0027`, `0028`,
  `0030` to `0032`, `0034`, `0035`.
- **One sanitizer for every shared write** (`sanitizer/`): content-safety drop, credential redaction and personal
  data redaction before anything reaches the shared tier; it fails closed (stores nothing) when it can't guarantee
  redaction. Plus a page-snapshot object store (`snapshot_store/`) and IOC hygiene helpers (`hygiene/`).
- **Anti-poisoning trust gate** (`trust_gate/`): deterministic quarantine, corroboration, source reputation and
  anomaly checks for the shared tier, with corpus-health views for the maintainer (`observability/`).
- **Cross-install ingest API with Sybil-resistant corroboration** (`ingest/`, `api/routes/ingest.py`, migration
  `0033`). Off by default (`VOIDACCESS_INGEST_ENABLED=false`).
- **Owned, semantically ranked page index** (`owned_index/`), filled from investigations and seeds
  (`index_population/`) and kept fresh by a background loop (`freshness/`) on a durable DB-backed job queue
  (`jobqueue/`, migration `0029`), with an in-process rate limiter (`ratelimit/`).
- **New sources and search improvements:** CVE intelligence, EPSS exploit-probability scores and Exploit-DB; a much
  larger curated onion seed list; search result ranking and an engine cull (`search/ENGINE_CULL.md`); a reusable
  blocklist-feed matcher (`feeds/`); presence-only HIBP Pwned Passwords checks via k-anonymity
  (`credential_presence/`); a shared clearnet connection pool (`netpool/`).
- **Benchmark tooling** (`benchmark/`): engine probes with latency and unique-result share.

### Changed defaults (self-hosters will notice these)

- **More distinct onion pages per run.** Onion links are now picked one per site and
  at most two per mirror family (sites whose addresses share their first seven
  characters), with real search-result links ahead of addresses a results page
  only mentions. The number fetched follows `--depth`: 15 (shallow), 25 (normal),
  40 (deep), overridable with `VOIDACCESS_ONION_TOP_N` (5-60). When failed fetches
  or mirrored copies leave slots empty, one extra batch backfills them from the
  next-ranked links; `normal` and `deep` also follow up to 10 / 20 links found on
  the fetched pages. Every extra fetch goes through the same URL and content
  safety gates.
- **Source status can read `partial`:** some of the source's requests worked and
  some failed. In the `enrich.source` trace event a partial source reads `error`
  (the trace vocabulary has no `partial`).

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
- `VOIDACCESS_SEARCH_WORKERS`, `VOIDACCESS_SCRAPE_WORKERS`,
  `VOIDACCESS_EXTRACT_CONCURRENCY`, `VOIDACCESS_LLM_CHUNK_CONCURRENCY`, `VOIDACCESS_LLM_CHUNK_TIMEOUT`, `VOIDACCESS_SEARCH_DEADLINE`,
  `VOIDACCESS_CONCURRENT_COLLECT`; `VOIDACCESS_ENRICHMENT_TIMEOUT` is now applied
  on the CLI path when set. See docs/architecture.md section 13.17.
- `benchmark probe` artifacts report `latency_p90_ms` and `unique_result_share`
  per engine.
- Trace events (progress schema 2): `voidaccess investigate --trace --events-jsonl PATH`
  or `VOIDACCESS_TRACE_EVENTS=1` adds a `trace` event for each refined query,
  search engine call, URL found/kept/dropped (with the reason), page fetch outcome,
  page entity counts, entity found (masked), enrichment source, graph progress and
  summary status, so a dashboard can animate a live run. Hosts are shown only in a
  shortened or defanged form, with names that spell out abuse content masked; no
  page text, paths, credentials or personal data,
  and anything the content-safety filter dropped is reported as an id and a reason
  only. Volume is capped per kind (`VOIDACCESS_TRACE_CAPS`, at most 3,000 per run),
  and traces are dropped first when a sink falls behind. JSON Schema:
  `progress/schema/progress-v2.schema.json`; docs/architecture.md section 13.19.
- Every progress event now carries `schema: 2` (an added field; nothing else in the
  schema-1 events changed).

### Safety

- Align CLI and API content-safety gates: Tor and side-source page text is
  scanned via shared `gate_pages()` before persistence, vector cache, extraction,
  or summarization; URL and entity gates fail closed on errors.
- Add `VOIDACCESS_SAFETY_BYPASS_PROMPT` (`on` default, `off` for cloud runners)
  to omit the LLM authorization preamble from refine, filter, and summary prompts
  without disabling mandatory content filters.

### Fixed

- **A failed fetch is no longer counted or stored as a page.** The scraper used to
  return the search result's title as the text of a page it could not fetch (or
  that had no text), so those titles were stored, extracted and counted in
  `pages_fetched`. Now only a fetch that returned content is a page; the failure
  shows only as its `page.fetched` outcome.
- **Source status is honest for fixed endpoints.** Any non-2xx answer from a feed
  or a fixed API (ransomware.live, CISA advisories, justice.gov, the MITRE
  bundle, the blocklists) is a failure; a per-item lookup's 404 (Shodan
  InternetDB, HIBP, VirusTotal, NVD and similar) still means "no record". Calls
  made as `await session.get(...)` are counted too, and a feed that failed is not
  requested again in the same run. Sources that silently read `ok` while every
  call 404'd now read `error`.
- **Dead endpoints replaced:** ransomware.live groups and victim posts now come
  from its data feed (`data.ransomware.live/groups.json` and `victims.json`; the
  API's `/groups`, `/group/{name}` and `/v2` victim endpoints are gone), CISA advisories from `cybersecurity-advisories/all.xml`, and
  justice.gov press releases from `/news/rss`. The last two are RSS and are now
  parsed as such (the justice.gov feed had never parsed).
- **MITRE ATT&CK techniques are attributed only to a group the run found, by
  exact name or alias.** Matching was by substring, so "Tor", "royal" or "bert"
  pulled in unrelated groups' techniques. Now a name must equal an intrusion
  set's name or alias (after a built-in alias table that now holds only names
  ATT&CK itself lists for the group; brand mappings such as REvil, GandCrab or
  Conti to Wizard Spider and DarkSide to FIN7, and the tool "Cobalt Strike",
  were removed); an alias that is also an ATT&CK software name is
  ambiguous and matches nothing; revoked sets are ignored. The overlay counts
  `THREAT_ACTOR_HANDLE` as an actor, runs only when the run has no
  `MITRE_TECHNIQUE` yet (it used to check a misspelt CVE type), adds one page per
  group, and tags every technique with its group.
- **MITRE output now needs a corroborated actor.** An actor drives the ATT&CK
  overlay and historical intel only if a pattern or the gazetteer extractor found
  it, it was seen on at least two different hosts, or the query names it. One
  entity-recognition hit on one page (a common word that is also an ATT&CK group
  name) used to add that group's techniques to most reports. The actor entity
  itself is still reported.
- **ransomware.live and RansomLook group names match whole words only.** A group
  name or listed alias must appear as a whole word in the query (at least three
  characters, case-insensitive); versioned names such as `lockbit3` also match
  their stem ("LockBit"). Substring matching let a one-letter group name match
  unrelated queries and add its pages. ransomware.live is off in the hosted
  profile, so this affects self-hosted runs.
- **Organisation names drop link-directory and markup noise.** Values such as
  "Name - description" titles, markdown residue, slash lists, `.onion` names,
  directory words, base64 runs and dark-market listing words are removed before
  they are stored or sent to the NVD CPE lookup; truncated parentheses, link
  tails and leak-listing status words are trimmed first. On 379 labelled values
  from the regression runs: 97.8% precision, 75.9% recall.
- **Enrichment no longer throws away finished work at its 59 s deadline.** The
  CISA KEV / NVD / Shodan / VirusTotal / historical-intel (MITRE) / CVE-fusion
  group ran its steps one after another behind NVD, so it usually missed the
  deadline and all of its results were discarded (MITRE techniques, the CVE
  view and many relationships were lost). Now historical intel starts as soon as
  CISA, Shodan and VirusTotal are done, the CVE fusion as soon as NVD and KEV
  are (bounded at 8 s, falling back to the plain NVD/KEV pages), NVD stops
  starting new lookups after 35 s and keeps what it fetched, and the group
  returns its finished parts 2 s before the phase deadline. A slow source loses
  only its own results; the phase still ends by 59 s. The constants are in
  `sources/enrichment.py` (`ENRICHMENT_DEADLINE_S`, `NVD_BUDGET_S`, ...).
- **A source a deadline cut off now reads `timed_out`, one that failed `error`,**
  in `sources_used` and in the `enrich.source` trace events, including the
  sources inside that group (`cisa_kev`, `nvd`, `cve_intel`, `epss`,
  `exploitdb`, `shodan_internetdb`, `virustotal`, `mitre_attack`) and the
  other enrichment feeds. Before, a dropped source read `ok` with 0 results.

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
