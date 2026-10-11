"""Canonical, git-diffable artifact helpers shared by both harnesses.

P1.0 exists to produce a *ruler*: a metric artifact whose schema is fixed so that
P1.2 / P4 / P5 can assert deltas run-over-run. Two runs on an unchanged codebase
must produce structurally identical JSON (same keys, same order); only the measured
*values* may move with live data. That guarantee comes from:

  * enumerating every entity-type bucket, confidence tier, and pipeline phase up
    front (zero-filled) so a sparse run still emits the full key set; and
  * serializing with ``sort_keys=True`` and a trailing newline so ordering never
    depends on dict insertion order or Python version.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"

DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"

# The 8 fixed pipeline step names ``utils.investigation_metrics.InvestigationMetrics``
# pre-seeds. Kept in sync with that module (the single source of per-phase timing).
PIPELINE_PHASES: tuple[str, ...] = (
    "query_refinement",
    "source_gathering",
    "scraping",
    "entity_extraction",
    "enrichment",
    "graph_build",
    "summary_generation",
    "finalization",
)

# Confidence tiers on the persisted *effective* confidence (0..1). The junk cut at
# 0.42 reuses the shape "reject" boundary in
# ``extractor.entity_shape._tier_from_score`` so "junk" here means exactly what the
# extractor already treats as sub-threshold noise.
CONFIDENCE_TIERS: tuple[str, ...] = ("high", "medium", "low", "junk")
_TIER_HIGH = 0.90
_TIER_MEDIUM = 0.72
_TIER_LOW = 0.42


def entity_type_keys() -> list[str]:
    """All entity-type bucket keys, sorted. Uses the ``EntityType`` member *names*
    (UPPERCASE, e.g. ``IP_ADDRESS``) which match the uppercased ``entity_type`` the
    CLI's ``get_entities()`` returns. Falls back to a static list if the model
    can't import, so the harness stays usable in a minimal env."""
    try:
        from db.models import EntityType

        return sorted(m.name for m in EntityType)
    except Exception:
        return sorted([
            "CRYPTO_WALLET", "EMAIL", "PGP_KEY", "ONION_URL", "CVE", "IP_ADDRESS",
            "PHONE", "HANDLE", "MALWARE", "RANSOMWARE_GROUP", "DOMAIN", "OTHER",
            "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256", "MITRE_TECHNIQUE",
        ])


def confidence_tier(confidence: Any) -> str:
    c = float(confidence or 0.0)
    if c >= _TIER_HIGH:
        return "high"
    if c >= _TIER_MEDIUM:
        return "medium"
    if c >= _TIER_LOW:
        return "low"
    return "junk"


def empty_type_counts() -> dict[str, int]:
    return {k: 0 for k in entity_type_keys()}


def empty_tier_counts() -> dict[str, int]:
    return {t: 0 for t in CONFIDENCE_TIERS}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def git_commit() -> str:
    """Short HEAD hash for artifact provenance. 'unknown' if git is unavailable."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(Path(__file__).resolve().parent),
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def canonical_json(obj: Any) -> str:
    """Deterministic serialization: sorted keys, 2-space indent, UTF-8 preserved
    (so multilingual queries stay readable in a diff), trailing newline."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_artifact(obj: Any, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(obj), encoding="utf-8")
    return path
