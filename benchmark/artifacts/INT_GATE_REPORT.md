# P1 End-to-End Integration Gate — Test Report

**Date:** 2026-09-05 · **Tester:** QA (senior) · **Build:** working tree at git `be276d12` (v2.0.3, P1 delta uncommitted)
**Environment:** Windows 11, Python 3.10.6, live Tor 0.4.9.6 on `127.0.0.1:9050` (system tor), CLI/SQLite `$0` path (`~/.voidaccess/`), **enrichment keys 0/20 (keyless primary pass)**.

> **How the working tree was exercised.** The installed `voidaccess` package is a stale **v1.9.0** and does *not* contain the P1 modules. All runs use the working tree via `PYTHONPATH=C:/void.access/voidaccess python -m voidaccess_cli.main …`, verified to resolve `voidaccess_cli __version__ == 2.0.3`.

---

## Verdict

**NOT a clean pass — P2 is blocked by one Group-F failure until fixed.** Three defects found (one in the non-negotiable F group). All are bounded, low-risk fixes; none is a credential or PII leak. The core P1 collection + low-noise + invariant machinery is otherwise working on live data.

| Blocking? | ID | Finding | Fix |
|---|---|---|---|
| **YES (F group)** | INT-F4 | `URL` / `PASTE_URL` entity types are **not** defanged, yet `GET /entities/{id}` returns them with `"defanged": true` — a live clearnet URL can render to the user. | One-line: add `URL`/`PASTE_URL` to `defang_value` dispatch |
| No (Group C) | INT-C3 | ransomwhe.re feed 403s — configured endpoint has a stale `/v1/` path (`/v1/export` → should be `/export`). No ransom wallet flagged on a cold cache. | One-line URL fix |
| No (Group D) | INT-D3 | Headline low-noise metric `junk_ratio − visible_junk_ratio` is structurally 0.0 (confidence-junk tier is empty post-extraction); real suppression = **16.4%** is invisible to it. | Redefine metric onto the priority axis / expose `suppression_rate` |

Blocked / not executed: **INT-C7** (keyed second pass — no free keys available in env).

---

## Results by test case

| ID | Result | Notes |
|---|---|---|
| **A1** Baseline capture | **PASS** | 12/12 `completed`, 180/180 pages, **1950 entities**; artifact has per-type, junk_ratio, `visible_junk_ratio`, entities_suppressed, cache-hit, per-phase wall-clock. |
| **A2** Determinism | **PASS** | Re-run 1982 entities; schema key-set **byte-identical** to A1; 12/12 completed. |
| **B1** Live probe | **PASS** | 17-engine table over Tor; Tor genuinely working (13 engines 100%); **darksearch absent**; 4 engines flagged 0% (Anima, Find Tor, Kaizer, Tornado). |
| **B2** Cull dispositions | **PASS** | All four 0% engines → `quarantined`; darksearch = only `removed` (out-of-band); Torgol 25% stays active; each disposition traces to an artifact row. |
| **B3** Survives engine failure | **PASS** | Fan-out predicate excludes non-`active`; **applied** the 4 quarantines to `engine_catalog.py` (fan-out now **13**), verified excluded. |
| **C1** CVE fusion | **PASS** | Log4Shell keyless: CVSS 10.0 CRITICAL (NVD) + KEV+ransomware (CISA) + EPSS 0.97 (FIRST) + Exploit-DB EDB-IDs — single `cve_intel` page, no NVD/KEV double-fetch. |
| **C2** ExploitDB one-fetch | **PASS** | CSV fetched **exactly once** across 1 fusion + 2×5-CVE calls; zero per-CVE calls. |
| **C3** Ransom wallet | **FAIL** | `api.ransomwhe.re/v1/export` → **HTTP 403** (API-Gateway MissingAuthenticationToken = dead route). Correct endpoint is `/export` (verified 11,186 wallets; flagging + case-preservation all correct there). Cold cache ⇒ no wallet flagged. |
| **C4** Phishing feeds | **PASS** | OpenPhish index 247 (non-empty); a live member flagged `phishing`+`feed:openphish`+provenance. PhishTank → `skipped_no_key` (keyless, correct). |
| **C5** SSLBL | **PASS** | Index 10,632; a listed SHA-1 flagged `malicious_cert`+`feed:sslbl`+provenance (CC0-1.0). |
| **C6** Pwned credential presence | **PASS** | `check("password")` → present, breach_count 52,372,427; presence-only summary; no raw value in output. |
| **C7** Keyed second pass | **BLOCKED** | No OTX/NVD/ABUSECH/PhishTank keys in env (0/20). Not executable; keyless primary pass is green. |
| **D1** Ranking order | **PASS** | Corroborated IOC (0.63) outranks all junk; deterministic flags exempt low entities & win ties **without** changing `priority_score` (0.1675 == 0.1675). |
| **D2** Non-destructive suppression | **PASS** | All inputs retained; suppressed rows flagged with reason, ranked last, reachable. |
| **D3** The 4.1 number | **FAIL** | `junk_ratio − visible_junk_ratio = 0.0` (metric measures empty confidence-junk tier). Real suppression **319/1950 = 16.4%**. Metric gap, not a suppression failure. See `INT-D3_junk_reduction.md`. |
| **D4** Floor lever | **PASS** | On real data suppressed count 32→157 monotonically as `VOIDACCESS_PRIORITY_FLOOR` rises; high-signal never suppressed. |
| **F1** Raw credential never persisted | **PASS** | Not on the wire, not in payload, not in DB (entity values/context/pages), not in `pages` (stores `raw_content_hash`, not raw HTML). |
| **F2** Only 5-char prefix leaves | **PASS** | Every outbound request = `…/range/5BAA6`; full SHA-1 and local suffix never leave. |
| **F3** PII stripped | **PASS** | Email → `joh***@corp.com`, phone → `[redacted-phone]`, CVE id preserved. |
| **F4** IOCs defanged on display | **FAIL** | `defang_value` handles ONION_URL/DOMAIN/IP/EMAIL only; `URL` & `PASTE_URL` pass through **live** while API sets `"defanged": true`. (PASTE_URL is produced even on the no-LLM path.) |
| **F5** Tor isolation invariant | **PASS** | Clearnet pool refuses `.onion` with `ValueError`; clearnet URLs pass. |
| **F6** Provenance/license on feed artifacts | **PASS** | Each emitted feed page carries license+attribution; RansomLook CC-BY registered. |
| **G1** Connection reuse | **PASS** | 5 same-host GETs → **1** TCP connection (keep-alive); shared singleton session. |
| **G2** Feed-down degradation | **PASS** | Cold-cache outage: SSLBL `unavailable`, others unaffected, no crash. |
| **G3** Missing-key honesty | **PASS** | PhishTank `skipped_no_key` (not fake ok_0); keyless CVE view still renders. |
| **H1** Ranked/suppressed list | **PASS** | API list orders by shared `rank`, computes `suppressed_count`, hides suppressed by default, `include_suppressed` reveals all (non-destructive). |
| **H2** Temporal panel post-fix | **PASS** | No `z_score`/`Z_SCORE_THRESHOLD`; `POISSON_ALPHA=0.01`; emits `poisson_p_value`/`expected_rate`/`type`; frontend TS type matches. |
| **H3** API↔CLI parity | **PASS** | Same 173-entity investigation: identical ID ordering and identical suppressed flags (both surfaces call shared `rank_map`). |
| **I1** Full pipeline, API | **PASS** | API pipeline task `_run_investigation_task` (what `POST /investigations` schedules) ran end-to-end: **completed**, 315 entities, 457 graph edges, summary present. HTTP+auth wrapper blocked only by missing Redis (token_blacklist fails closed → 503; out of P1 scope). |
| **I2** Full pipeline, CLI | **PASS** | 24/24 CLI investigations `completed` (A1+A2) with entities + pages. |

---

## Live response-format drift vs mocked assumptions (the headline of this gate)

1. **ransomwhe.re endpoint moved** — `/v1/export` (mocked green in unit tests) now 403s; live route is `/export`. **Caught only live.** (INT-C3)
2. **NVD 2.0 / CISA KEV / FIRST EPSS / Exploit-DB CSV formats all still parse** — no drift; `base_score`, `cwes`, `entity_value`, `{"result":[…]}` etc. matched the code's expectations against live endpoints.
3. **The gate's own success metric is mis-instrumented** — `visible_junk_ratio` can never move because extraction pre-filters the confidence-junk tier; the real P1.6 win (priority-based suppression, 16.4%) is not what the metric measures. (INT-D3)

## Out-of-scope observation (not a gate result)
Against a standalone `uvicorn` process, `POST /auth/login` returned HTTP 500, but the **same code returns 200 via TestClient and direct call** — points to a rate-limiter wiring issue when the process runs without `DISABLE_RATE_LIMIT`. Auth is explicitly out of P1 scope; flagged only as an aside for the owners.

## Committed artifacts (gate record)
- `INT-A1_metrics_baseline.json`, `INT-A2_metrics_rerun.json` — live baseline + determinism.
- `INT-B1_probe.json`, `INT-B2_cull_dispositions.md` — 17-engine probe + applied cull ledger.
- `INT-D3_junk_reduction.md` — the recorded junk-ratio number + root cause.
- `INT_GATE_REPORT.md` — this report.
- Applied change: `search/engine_catalog.py` — 4 engines quarantined from committed evidence.
