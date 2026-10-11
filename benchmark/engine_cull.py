"""Evidence-driven engine cull decision rule (P1.1, requirement 1.1).

Turns a committed P1.0 engine-health-probe artifact into a per-engine disposition
(`active` / `quarantined` / `removed`) via a single documented rule, so every
engine's status is *traceable to a row in the baseline artifact* rather than a
hand-wave. The dev runs this against the committed live-Tor baseline at end-stage
and applies the resulting quarantine list to ``search/engine_catalog.py``.

The rule (see the module constants):
  * 0% success over the sample                     -> quarantined
  * 0 < success_rate < BORDERLINE_SUCCESS_RATE      -> quarantined (borderline)
  * name in ``confirmed_defunct`` (dead domain / sunset API) -> removed
  * otherwise                                       -> active

``removed`` is never inferred from the probe alone — it requires an out-of-band
confirmation of death, per the brief. ``darksearch.io`` was the known case and is
already physically removed from the catalog; pass it in ``confirmed_defunct`` only
if it is still present in an older artifact you are reconciling.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional, Union

from benchmark import artifact as _artifact

# A non-zero success rate at or below this over the full sample is "borderline"
# and quarantined rather than trusted. Documented threshold (brief latitude).
BORDERLINE_SUCCESS_RATE = 0.10

Disposition = tuple[str, str]  # (status, reason)


def _load(artifact: Union[dict, Path, str]) -> dict:
    if isinstance(artifact, dict):
        return artifact
    return json.loads(Path(artifact).read_text(encoding="utf-8"))


def dispositions_from_baseline(
    artifact: Union[dict, Path, str],
    confirmed_defunct: Iterable[str] = (),
) -> dict[str, Disposition]:
    """Map each engine in a probe artifact to ``(status, reason)`` per the rule."""
    data = _load(artifact)
    defunct = set(confirmed_defunct)
    out: dict[str, Disposition] = {}
    for row in data.get("engines", []):
        name = row.get("name", "")
        attempts = int(row.get("attempts", 0) or 0)
        rate = float(row.get("success_rate", 0.0) or 0.0)
        if name in defunct:
            out[name] = ("removed", "confirmed defunct (dead domain / sunset API)")
        elif attempts == 0:
            out[name] = ("active", "no probe attempts recorded — no evidence to cull")
        elif rate == 0.0:
            out[name] = ("quarantined", f"0% success over {attempts} probe attempts")
        elif rate < BORDERLINE_SUCCESS_RATE:
            out[name] = (
                "quarantined",
                f"borderline {rate * 100:.1f}% < {BORDERLINE_SUCCESS_RATE * 100:.0f}% "
                f"over {attempts} probe attempts",
            )
        else:
            out[name] = ("active", f"{rate * 100:.1f}% success over {attempts} probe attempts")
    return out


def format_ledger(
    artifact: Union[dict, Path, str],
    confirmed_defunct: Iterable[str] = (),
    extra_removed: Optional[dict[str, str]] = None,
) -> str:
    """Render a Markdown disposition ledger from a baseline artifact.

    ``extra_removed`` records engines already physically deleted from the catalog
    (so they won't appear in a fresh artifact) as ``{name: reason}`` — e.g.
    ``{"DarkSearch (API)": "darksearch.io confirmed defunct"}``.
    """
    data = _load(artifact)
    dispositions = dispositions_from_baseline(data, confirmed_defunct)
    run = data.get("run", {})
    lines = [
        "| Engine | Status | Success rate | Evidence |",
        "|---|---|---|---|",
    ]
    for name, reason in (extra_removed or {}).items():
        lines.append(f"| {name} | removed | (deleted) | {reason} |")
    by_name = {r.get("name"): r for r in data.get("engines", [])}
    for name in sorted(dispositions):
        status, reason = dispositions[name]
        row = by_name.get(name, {})
        rate = row.get("success_rate")
        rate_s = f"{float(rate) * 100:.1f}%" if rate is not None else "—"
        lines.append(f"| {name} | {status} | {rate_s} | {reason} |")
    header = (
        f"Baseline: `{run.get('git_commit', 'unknown')}` "
        f"queries={run.get('queries_used', [])} "
        f"tor={run.get('tor_source', 'unknown')} "
        f"threshold={BORDERLINE_SUCCESS_RATE * 100:.0f}%"
    )
    return header + "\n\n" + "\n".join(lines) + "\n"


def _main(argv: Optional[list[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Print engine cull dispositions from a baseline artifact.")
    ap.add_argument(
        "artifact",
        nargs="?",
        default=str(_artifact.DEFAULT_ARTIFACT_DIR / "engine-health-latest.json"),
        help="Path to an engine-health-probe artifact.",
    )
    ap.add_argument("--confirmed-defunct", nargs="*", default=[], help="Engine names confirmed dead.")
    ns = ap.parse_args(argv)
    print(format_ledger(ns.artifact, confirmed_defunct=ns.confirmed_defunct))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
