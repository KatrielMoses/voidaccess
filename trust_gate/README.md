# trust_gate — automated, deterministic anti-poisoning gate (P4.0)

The shared corpus is **live and automatically contributed to**. Poisoning must
therefore be stopped by an automated, deterministic gate, not human review. This
module is the **scoring half** of the Epic-3 trust gate (spec 3.2 steps 4–8),
composed on top of the P2.2 **blocking half** (`sanitizer/`, steps 1–3) into a
single ordered choke point:

```
sanitize → validate → provenance → quarantine → corroborate → reputation → anomaly → dedup
   1           2           3            4            5             6           7        8
   └────────── P2.2 sanitizer ──────────┘   └──────────────── P4.0 trust_gate ─────────────┘
```

`trust_gate(artifact, corpus_state, config) -> GateDecision` is a **pure,
deterministic** function. Identical inputs always yield an identical decision. It
performs **no I/O** — no network, no LLM, no clock, no randomness. Time comes from
`artifact.observed_at`; every threshold comes from a `TrustGateConfig` snapshot.

It is the **only** thing in the system that assigns or raises a `ConfidenceTier`.

## Confidence tiers (first-class — spec 3.3)

| Tier | How it is reached | Influences scoring? |
|---|---|---|
| `unconfirmed` | default for every new artifact (quarantine) | **no** |
| `corroborated` | ≥ N independent sources (default N=2) | yes |
| `feed_validated` | a trusted-feed cross-hit (abuse.ch / KEV / …) | yes |

Quarantine-by-default is load-bearing: a new, single-source, non-feed artifact is
`unconfirmed` and **cannot influence scoring or triage** (`GateDecision.
influences_scoring is False`) until it earns promotion. Never auto-trusted.

## The eight steps

1. **sanitize** — `sanitizer.sanitize_entity` (drop PII types / raw secrets / noise).
2. **validate** — `sanitizer.is_valid_shape` (drop malformed / prose).
3. **provenance** — `sanitizer.provenance_stamp` (attribute to source + capture time).
4. **quarantine** — enter `unconfirmed`; influences nothing.
5. **corroborate** — promote only on ≥ N *independent* sources or a trusted-feed
   cross-hit. A feed cross-hit is source-independent → `feed_validated` outright.
6. **reputation** — a source's contribution counts toward corroboration only if
   its reputation clears the bar. *Contradicted* data (conflicting with an
   entity's established, corroborated disposition) downweights and can block the
   source, and holds the artifact in quarantine.
7. **anomaly** — reject + downweight on any attack pattern: single-source flood,
   entity-stuffing, templated injection, mass-identical (one test per class).
8. **dedup / canonicalize** — via `extractor.identity.entity_canonical_id`, the
   **single** identity path the shared corpus already uses (grep-provable: it is
   the only canonicalization in `gate.py`).

Steps 1, 2 and 7 can terminate early (`REJECTED`). Steps 4–6 and 8 refine the
tier. The composition is the ordered `GATE_STEPS` tuple.

## Why an attacker cannot fabricate trust

- **`feed_hits` is platform-verified.** It is computed by *our* feed matcher
  (`feeds/`), never copied from untrusted submission metadata. Unknown/claimed
  feed names are filtered against the tunable allowlist, so a single attacker
  source can never reach `feed_validated`.
- **Independent-source counting is a set of source ids.** One source resubmitting
  (even thousands of times, even under an alias id it controls) appears once and
  can never reach the ≥ N threshold alone.
- **Reputation is monotonic-down on bad behavior.** Contradictions and anomalies
  decay a source's score; below the block threshold its contributions stop
  counting entirely.
- **Flood/stuffing/templated/mass-identical are rate-limited and rejected**, and
  the offending source is downweighted.

## Purity and state

The gate never mutates `CorpusState`. It reads counters and **emits**
`CounterDeltas` (quarantine/promotion + the updated per-source
`SourceReputationView`). Callers advance state explicitly via
`CorpusState.apply(decision)` — the deterministic bridge the red-team harness uses
to simulate *sustained* corroboration, and the shape the P4.1 write path mirrors
against the shared-tier tables.

`CorpusState` is projected from:

- `shared_corpus.GlobalEntity.corroboration_count` — corroboration counts;
- `shared_corpus.SourceReputation` — the per-source reputation store (new in P4.0,
  migration `0031`), a **shared-tier** table (a source's reliability is
  corpus-wide, carries no private framing).

## Tunable thresholds (CC-4)

All defaults live in `config.py` (`TRUST_GATE_*`) and are read into
`TrustGateConfig`. Defaults per the P4.0 brief: ≥ 2 independent sources OR ≥ 1
trusted-feed cross-hit; source-reputation decay/block; per-source rate limit;
entity-stuffing / templated / mass-identical bounds. The red-team suite constructs
configs directly to calibrate in isolation.

## Scope boundary

**In P4.0:** the pure gate, the reputation store schema + migration, tunable
config, and the red-team acceptance suite (`tests/test_trust_gate.py`).

**Not in P4.0 (later phases):** wiring the gate into the pipeline write path
(P4.1), read-from-shared (P4.2), the cross-install ingest API (P4.3), and
observability dashboards (P4.4 — the gate *emits* the counters those dashboards
consume). The pipeline is untouched (CC-3).
