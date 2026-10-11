# Engine cull ledger (requirement 1.1)

One place to see why each search engine is `active` / `quarantined` / `removed`.
Statuses are declared inline in [`engine_catalog.py`](engine_catalog.py); this
ledger records the *evidence* behind each disposition.

## The rule

Applied by [`benchmark/engine_cull.py`](../benchmark/engine_cull.py) against a
committed P1.0 engine-health-probe artifact
(`benchmark/artifacts/engine-health-latest.json`):

| Condition (over the full benchmark sample) | Disposition |
|---|---|
| 0% success | `quarantined` |
| `0 < success_rate < 10%` (borderline) | `quarantined` |
| Independently confirmed defunct (dead domain / sunset API) | `removed` |
| otherwise | `active` |

`quarantined` engines are excluded from the fan-out but **retained** so a P3
freshness re-probe can revive them. `removed` requires out-of-band confirmation
of death — it is never inferred from the probe alone.

## Regenerating this table

Once a live-Tor baseline is committed, regenerate the dispositions:

```bash
python -m benchmark.engine_cull benchmark/artifacts/engine-health-latest.json
```

Then apply any `quarantined` results by setting `"status": "quarantined"` on the
matching entries in `engine_catalog.py`.

## Current dispositions (18 originally probed)

**Applied now — independent of the baseline:**

| Engine | Status | Evidence |
|---|---|---|
| DarkSearch (API) — `darksearch.io` | **removed** | Confirmed defunct (service sunset years ago). Physically deleted from `engine_catalog.py` **and** the standalone `sources/engines.py::search_darksearch`. |

**Pending the committed live-Tor baseline (all currently `active`):**

The remaining 17 catalog engines — Ahmia (Clearnet Proxy), Ahmia, OnionLand,
Torgle, Amnesia, Kaizer, Anima, Tornado, TorNet, Torland, Find Tor, Excavator,
Onionway, Tor66, OSS, Torgol, The Deep Searches — stay `active` until the
end-stage live-Tor baseline lands. At that point run the command above; every 0%
or borderline engine (the P1.0 probe is expected to flag several of the chronically
unreliable onion engines) moves to `quarantined`, each traceable to its row in the
committed artifact.
