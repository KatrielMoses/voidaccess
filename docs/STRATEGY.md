# VoidAccess — Competitive Strategy & Growth Roadmap

*Prepared 2026-09-04. Audit of the live codebase cross-referenced with live market
research on commercial vendors, the open-source ecosystem, free data sources, and
low-cost infrastructure. Every external claim is attributed; unverified items are
flagged. This is a living document — supersede sections as reality changes.*

---

## 0. The one-sentence thesis

> **You will never out-collect Recorded Future's data lake. Don't try. Win the
> uncontested middle of the market: the only *free* dark-web tool that is
> simultaneously AI-native, persistent/continuously-monitoring, and
> standards-interoperable — and let the whole community's investigations compound
> into a shared corpus that no free tool has.**

The research is unambiguous on where the seam is (§3). Your architecture is already
sitting in it. The gap between where you are and where you're perceived is a
*distribution and packaging* problem far more than a *technology* problem.

---

## 1. Where you actually stand (the harsh audit)

### 1a. The docs undersell the product by a full generation
`CLAUDE.md` and the README describe a "13-step pipeline, 16 engines, 4 threat feeds."
The live code is dramatically more capable. The real pipeline in
`api/routes/investigations.py` runs **~25 sub-steps**, and `sources/enrichment.py`
already federates:

- **abuse.ch suite** — MalwareBazaar, URLhaus, ThreatFox
- **AlienVault OTX** (pulses + indicators)
- **Ransomware leak-site feeds** — `ransomware.live` **and** `ransomlook.io`
- **CISA KEV, NVD, Shodan, VirusTotal**
- **Hudson Rock Cavalier** infostealer intelligence
- **Breach exposure** — XposedOrNot + LeakCheck
- **DNS, blockchain-wallet, IP/domain/email/hash reputation** enrichment
- **Stylometry, actor profiling, cross-alias resolution, multilingual query
  expansion, content-safety scanning**

**Finding:** the single highest-ROI action in this entire document is *rewriting the
public-facing story to match the code that already exists.* You are marketing a 2024
prototype. See §6.

### 1b. Engineering quality is high — this is a real asset
- Per-engine **Tor circuit isolation** (`search/tor_isolation.py`) — 16 engines land
  on 16 circuits; correlation-resistant, better than most OSS peers.
- **Circuit breaker + priority scoring** per engine (`search/search.py`).
- **Pacing profiles** as the single source of truth for every timeout/retry/backoff.
- **Query diversification** fallback when results are thin.
- Every external call is `try/except` with graceful degradation.

### 1c. The three real weaknesses

1. **The dark-web *search* layer rests on a crumbling foundation.**
   `search/engine_catalog.py` lists 18 engines, but `darksearch.io` is almost
   certainly defunct (shut down years ago) yet still ships as an engine *and* a
   dedicated module (`sources/engines.py`). The onion search engines (Torch,
   Haystack, Ahmia, Tor66…) are chronically unreliable — "gracefully handling" a
   dead engine still means zero coverage from it. **Action:** run a live engine
   health probe, delete dead weight, and expand the onion corpus from free indexes
   (Ahmia `/onions/`, dark.fail) — see §5.

2. **Collection is ephemeral — the tool has no memory.** Every investigation
   re-scrapes the live dark web from scratch. Discovered onions land in a local
   44-entry JSON (`sources/data/onion_seeds.json`) that lives and dies on one disk.
   There is no growing, persistent, shared index.

3. **Every install is an island.** User A's investigation teaches User B's install
   nothing. Intelligence never compounds. This is both the biggest gap *and* the
   biggest opportunity (§4).

---

## 2. The market you're actually entering

### 2a. Commercial vendors — the price umbrella you sit under
*(All figures reported/third-party; this market is overwhelmingly quote-based.)*

| Vendor | Moat | Reported price |
|---|---|---|
| Recorded Future (Mastercard, acq. $2.65B) | Breadth + Insikt human analysts | $40k–60k single module; $250k–500k+ enterprise |
| DarkOwl | ~1B indexed docs; ~60% auth-gated sources | ~$60k/seat/yr *(single source)* |
| Intel 471 | HUMINT personas inside closed forums | ~$80k–300k+/yr |
| Cybersixgill (now Bitsight) | ~10M items/day automated + deep archive | "cheaper than RF", unpublished |
| SpyCloud | Recaptured creds+cookies, 105+ malware families | quote-based |
| Constella | 1T+ breach records | unpublished |
| Searchlight/Cerberus | LE focus; safe live-access Stealth Browser; 475B points | unpublished |
| **Flare** | Identity-first, SMB-friendly | **~$417/mo billed annually (the clearest floor)**; free trial, no CC |

**Enterprise floor: $40k–60k/yr. SMB floor: ~$50–500/mo.** Genuine free *continuous*
monitoring is rare — Flare's no-CC trial is the notable exception.

### 2b. The analyst pain points that are your wedge
- **Noise is the #1 complaint.** One Recorded Future user: the identity module
  surfaced ~8,000 compromised credentials of which **11** were actual colleagues.
- **Opaque, escalating pricing** — hidden API overages, TAM fees, custom-research
  fees, 5–7% renewal escalation.
- **Commoditization.** Forrester: vendor intel has "considerable overlap… networks
  are commoditized" — which undercuts the premium-data narrative and is *your best
  argument*.
- **Tools dump data; humans must triage.** Useless without an analyst team.

### 2c. The OSS field — your *real* competitor has a name
- **Robin** (`github.com/apurvsinghgautam/robin`, ~7.0k stars, MIT, active) is a
  near-identical AI-dark-web assistant: LLM refine → fan-out → scrape over Tor → LLM
  summary. **But it is single-run:** no persistent DB, no entity graph, no
  monitoring, no STIX/MISP/Sigma export, no threat-feed enrichment, no
  stylometry/OPSEC. **You already have all of these.** Robin has ~10x your mindshare
  with a fraction of the depth. *This is the head-to-head to win.*
- **AIL Framework** (CIRCL, ~1.4k stars, very active) — the serious pure dark-web
  collection platform, but analyst-driven, **not** LLM-native. Complementary bar to
  measure depth against.
- **OpenCTI (~9.9k), MISP (~6.5k), IntelOwl (~4.7k)** — the aggregation layer above
  you. **Integrate, don't compete:** you already emit STIX/MISP/Sigma; becoming an
  *OpenCTI connector* is the natural next step.
- **ransomware.live, RansomLook, Ahmia** — free feeds/indexes to consume.

---

## 3. Positioning: own the uncontested middle

The research found the market splits cleanly, with an empty center:

```
                     AI / LLM-native
                           ▲
                  Robin ●  │  ◄── EMPTY: AI-native + persistent
                           │        + interoperable  ← VoidAccess
        ephemeral ─────────┼───────────────────────► persistent / monitoring
                           │
                           │  ● AIL   ● OpenCTI/MISP  ● Recorded Future
                           ▼        (deep but not AI-native / paid)
                     analyst-driven
```

**Nobody owns "AI-native + continuous + interoperable + free."** That is precisely
your architecture. The tagline writes itself:

> **"Robin's AI ergonomics + AIL's persistence + OpenCTI's interoperability — free,
> self-hosted, and transparent."**

Message to the buyer priced out of / frustrated by the incumbents: *cheap,
transparent, tunable, self-hostable, low-noise — for teams the $40k–500k/yr vendors
ignore, over data that is (per Forrester) commoditized anyway.*

---

## 4. The moat: a shared community intelligence corpus

The one thing commercial vendors sell that OSS "can't match" is a **historical data
lake**. You reproduce it not by owning petabytes but by **letting every user's
investigation compound into a shared, public, queryable corpus** — crowdsourced
intelligence, the way abuse.ch and ransomware.live already work.

### 4a. Architecture — target **$0–5/month**, hard-capped under $20
Copy the proven pattern (abuse.ch/ransomware.live/RansomLook all serve millions with
*no heavy live DB*): **precompute static snapshots, serve immutable files from a
zero-egress CDN, put a thin read API in front.**

```
 Contributors ──PR──►  GitHub repo (contrib/*.json, CI schema-validated)
                              │
        Your backend/CI  ─────┤  nightly GitHub Action: extract, sanitize, normalize
                              ▼
                 Snapshots (JSON / Parquet)
                   ├──► Cloudflare R2  (10GB free, $0 egress)   ◄── canonical
                   ├──► Hugging Face Dataset (free, TB-scale)   ◄── community mirror
                   └──► GitHub Releases (versioned provenance)
                              │
              Cloudflare Worker + D1 / Turso (read-only /search API)
                   free tiers cover it; $5/mo Workers Paid removes ceilings
```

- **Contributions = git PRs to `contrib/`**, not an open write API. Gives you free
  moderation, history, rollback — *and* is your data-poisoning defense.
- **Cost control:** Cloudflare egress is $0 (the key guardrail). Serve bulk as static
  files; reserve the live API for point lookups; set billing alerts + hard request
  caps on the Worker. Avoid Supabase as primary store — it **pauses after 7 days
  idle**, silently breaking an always-on service.

### 4b. Poisoning defense (non-negotiable for crowdsourced intel)
An open write API invites false-IOC injection (poison a rival's IP/domain into the
blocklist) and spam. Mitigate with: **PR-based contributions + CI schema validation +
provenance/source-attribution on every record + reputation weighting + human review
of first-time contributors + a confidence tier.** Never auto-trust community
submissions in scoring.

---

## 5. Data sources to add — ranked by (value ÷ effort)

*All free unless noted. Effort is rough.*

| # | Source | Adds | License / limit | Effort |
|---|---|---|---|---|
| 1 | **ransomware.live v2 API** | Victim/gang DLS intel, no-auth | Public domain | hours |
| 2 | **RansomLook API + RSS** | 620+ groups, screenshots | **CC BY 4.0 (cleanest)** | hours |
| 3 | **CISA KEV + FIRST EPSS + ExploitDB** | CVE prioritization (git bulk CSVs) | free/open | low |
| 4 | **Ahmia `/onions/` + dark.fail** | Free onion-corpus expansion + mirror verification — *directly fixes §1c-1* | free | low |
| 5 | **abuse.ch SSLBL + Feodo; OpenPhish; PhishTank** | Round out feeds you partly have | free bulk (non-commercial ToS) | low |
| 6 | **ransomwhe.re** | BTC addresses tied to ransom payments | free JSON + bulk | low |
| 7 | **NVD API 2.0 (free key)**, AbuseIPDB, GreyNoise Community, Censys free | Steady enrichment | modest rate limits | low-med |
| 8 | **HIBP Pwned Passwords** | k-anonymity credential *presence* checks | free, unlimited | low |
| 9 | *(later, needs academic partner)* **CrimeBB** (Cambridge) | ~110M underground-forum posts | data-sharing agreement | high/gated |

### 5a. Hard legal line — do not cross
- **Do NOT host raw credential corpora** (COMB, breach-parse, combolists). Possession/
  redistribution is illegal in many jurisdictions. Use HIBP-style *presence flags /
  k-anonymity hashes* only.
- **Strip PII / no doxxing content** (doxbin, victim personal data). Publish only
  defanged IOCs and org-level entities → GDPR/CCPA exposure otherwise.
- **License compliance:** RansomLook is CC BY (attribute). abuse.ch/OpenPhish restrict
  commercial use — a public community DB may count as redistribution, so store
  *derived indicators* rather than verbatim feeds, and confirm ToS before republishing.

---

## 6. The road to 10k stars — quality *and* distribution

Quality alone doesn't move stars; Robin proves distribution wins. Do both.

### Phase A — Truth in advertising (weeks, highest ROI)
- Rewrite README/docs to match the real ~25-step pipeline and full source list.
- A comparison table: **VoidAccess vs Robin** (persistence, graph, monitoring,
  exports, enrichment) and **vs commercial** (price, transparency, self-host).
- A 60-second demo GIF/video of one investigation → graph → STIX export.
- Purge dead weight (darksearch.io) so first-run experience isn't full of failures.

### Phase B — Fix the foundation + quick data wins (weeks)
- Live engine-health probe; drop/replace dead engines; expand corpus from Ahmia +
  dark.fail (§5 #4).
- Ship §5 #1–3, #6 (ransomware.live, RansomLook, KEV/EPSS/ExploitDB, ransomwhe.re) —
  all hours-to-low effort, all visible output-quality gains.
- Attack the **noise** complaint: lean into your existing confidence scoring / shape-
  aware NER so output is *low-noise by default* — that's the anti-Recorded-Future pitch.

### Phase C — The moat (1–2 months)
- Ship the shared-corpus MVP (§4): nightly snapshot → R2 + HF mirror → read-only
  `/search` → PR-based `contrib/`. Sanitization + poisoning defenses first-class.
- "Query the community corpus" becomes a headline feature no free tool has.

### Phase D — Interoperate upward (ongoing)
- Ship an **OpenCTI connector** and **MISP feed publisher**. This puts VoidAccess
  inside the workflows of every SOC already running OpenCTI/MISP — distribution into
  the professional audience, for free.

### Distribution mechanics (do in parallel)
- Write-ups on r/cybersecurity, r/OSINT, the DFIR/CTI communities framed as
  "free alternative to $40k CTI tools" + the Robin comparison.
- Submit to awesome-osint / awesome-threat-intelligence lists.
- A recurring public artifact (e.g., a weekly auto-generated ransomware-victim digest
  built *by VoidAccess itself* from the shared corpus) — proves the product and earns
  inbound links every week.

---

## 7. Open decisions (need owner input)
1. **Moat vs. quick wins first?** Recommend Phase A+B immediately (low risk, fast),
   Phase C in parallel once the data model for shareable artifacts is settled.
2. **How public is "public"?** Fully-open corpus vs. authenticated read. Recommend
   open read (static files) + PR-gated write.
3. **Legal posture on shared data** — confirm the sanitization schema (defanged IOCs +
   org entities only, no PII, no raw creds) before *any* data is published.
4. **Commercial ToS review** for abuse.ch/OpenPhish before re-hosting their feeds vs.
   storing only derived indicators.

---

## Appendix — verification flags
- Vendor coverage numbers are self-reported marketing claims, not independently audited.
- Firm pricing: Recorded Future (Vendr/aggregators), Flare (~$417/mo), DarkOwl
  (~$60k/seat, single source). Indicative-only: Intel 471, SpyCloud, Cybersixgill.
  Not found: KELA, Searchlight, Constella, DarkTracer.
- Star counts approximate where noted (Ahmia repos, Photon, OnionScan).
- `darksearch.io` defunct status is high-confidence but should be confirmed by the
  live engine-health probe (Phase B).
- Exact 2026 HIBP Core price and Shodan free-tier limits unconfirmed.
