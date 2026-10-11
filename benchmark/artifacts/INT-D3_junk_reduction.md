# INT-D3 — Low-noise reduction number (P1 end-to-end gate)

Baseline artifact: `INT-A1_metrics_baseline.json` (git `be276d12`, 12-query set,
live Tor, `--no-llm`, pace `normal`).

## The literal D3 metric

| Metric | Value |
|---|---|
| `junk_ratio` (stored) | **0.0000** |
| `visible_junk_ratio` (visible after suppression) | **0.0000** |
| **`junk_ratio − visible_junk_ratio`** | **0.0000** |

Per the brief's D3 acceptance ("a positive, non-trivial reduction"), the literal
number **fails** (delta = 0).

## Why the literal number is 0 — and why suppression is nonetheless working

`junk` here is a **confidence tier** (effective confidence < 0.42). That 0.42 cut
is the same "reject" boundary the extractor applies *before storage*
(`extractor.entity_shape`), so no sub-0.42 entity is ever persisted. On the live
baseline the confidence-tier breakdown is:

```
high=242  medium=1506  low=202  junk=0     (total 1950)
```

`junk = 0`, so both `junk_ratio` and `visible_junk_ratio` are structurally 0 and
their difference can never be positive. The metric cannot express the P1.6 win.

The **actual** P1.6 low-noise mechanism is *priority-based* suppression
(`priority_floor` / `per_type_display_cap` in `utils.entity_priority`), which is
alive and biting on the same baseline:

| Real suppression signal | Value |
|---|---|
| `entities_suppressed` | **319** |
| `total_entities` | 1950 |
| **suppression rate** | **16.4 %** |
| visible-by-default | 1631 (83.6 %) |

Confirmed on real data (INT-D4): raising `VOIDACCESS_PRIORITY_FLOOR` monotonically
increases the suppressed count (32 → 157 on a 173-entity investigation), and
high-signal entities are never suppressed.

## Verdict

- **Literal D3 (junk_ratio − visible_junk_ratio): 0.0 → FAIL as specified.**
- **Root cause: measurement gap, not a suppression failure.** The `visible_junk_ratio`
  metric measures the confidence-junk tier (always empty post-extraction) instead of
  priority-based suppression. The true low-noise reduction is **16.4 %**
  (`entities_suppressed / total_entities`).
- Filed for fix: redefine the low-noise metric onto the priority axis / expose
  `suppression_rate` (see gate report).
