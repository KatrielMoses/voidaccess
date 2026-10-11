"""Metrics harness — runs the benchmark set through the REAL SQLite pipeline and
captures a diffable metrics artifact.

Reuses the existing instrumentation rather than forking one. The CLI pipeline
(``voidaccess_cli.commands.investigate._run_investigation``) already persists
per-phase timing + page/cache counters to the ``investigation_step_metrics`` table
and writes a result JSON carrying entities + sources_used + pages. This harness
drives that pipeline unchanged, then reads both back and derives the entity-type /
confidence-tier / junk-ratio / per-source views the ruler needs.

Default is $0 and deterministic: ``use_llm=False`` ⇒ ``no_llm=True`` (regex/NER
extraction only — no query refinement or LLM summary). Pass ``use_llm=True`` for a
realistic-but-paid run. The metrics *schema* is identical either way.
"""
from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

from benchmark import artifact as _artifact
from benchmark.queries import QuerySet, load_query_set

logger = logging.getLogger(__name__)

# Matches the CLI's default --depth preset (DEPTH_PRESETS["normal"]).
INVESTIGATION_DEPTH = "normal"


def _load_result_json(out_dir: Path) -> Optional[dict]:
    files = list(out_dir.glob("*.json"))
    if not files:
        return None
    newest = max(files, key=lambda p: p.stat().st_mtime)
    try:
        return json.loads(newest.read_text(encoding="utf-8"))
    except Exception:
        return None


def _step_metrics_for(investigation_id: str) -> dict[str, dict]:
    """Read persisted per-phase counters for one investigation from SQLite."""
    try:
        from db.models import InvestigationStepMetric
        from db.session import get_session

        inv_uuid = uuid.UUID(investigation_id)
        out: dict[str, dict] = {}
        with get_session() as session:
            rows = (
                session.query(InvestigationStepMetric)
                .filter(InvestigationStepMetric.investigation_id == inv_uuid)
                .all()
            )
            for r in rows:
                out[r.step_name] = {
                    "duration_ms": float(r.duration_ms or 0.0),
                    "llm_calls": int(r.llm_calls or 0),
                    "extraction_llm_pages": int(r.extraction_llm_pages or 0),
                    "extraction_cache_hits": int(r.extraction_cache_hits or 0),
                    "pages_attempted": int(r.pages_attempted or 0),
                    "pages_fetched": int(r.pages_fetched or 0),
                    "pages_failed": int(r.pages_failed or 0),
                    "pages_cache_hits": int(r.pages_cache_hits or 0),
                    "pages_fresh": int(r.pages_fresh or 0),
                }
        return out
    except Exception as exc:
        logger.warning("could not read step metrics for %s: %s", investigation_id, exc)
        return {}


def summarize_query_result(result_json: dict, step_metrics: dict[str, dict]) -> dict[str, Any]:
    """Pure aggregation of one investigation's outputs into the fixed schema.

    Separated from the run loop so it is unit-testable without a live pipeline.
    Always emits every entity-type bucket, every confidence tier, and every
    pipeline phase (zero-filled) — that is what makes the artifact schema
    deterministic across runs.
    """
    entities = result_json.get("entities") or []
    type_counts = _artifact.empty_type_counts()
    tier_counts = _artifact.empty_tier_counts()
    for e in entities:
        etype = (e.get("entity_type") or "OTHER").upper()
        if etype not in type_counts:
            etype = "OTHER"
        type_counts[etype] += 1
        tier_counts[_artifact.confidence_tier(e.get("confidence"))] += 1

    total_entities = len(entities)
    junk = tier_counts["junk"]
    junk_ratio = (junk / total_entities) if total_entities else 0.0

    # P1.6 low-noise view: the *default-visible* junk ratio, i.e. after the
    # non-destructive suppression the ranking applies. ``suppressed`` is emitted
    # by ``utils.entity_priority.rank_entities`` (present on CLI/API entity
    # dicts); a run predating P1.6 has no such key, so a missing key counts as
    # visible and ``visible_junk_ratio`` degrades to ``junk_ratio``. The gap
    # between the two is exactly the measurable low-value-entity reduction 4.1
    # asks for.
    suppressed = sum(1 for e in entities if e.get("suppressed"))
    visible_entities = [e for e in entities if not e.get("suppressed")]
    visible_junk = sum(
        1 for e in visible_entities
        if _artifact.confidence_tier(e.get("confidence")) == "junk"
    )
    visible_count = len(visible_entities)
    visible_junk_ratio = (visible_junk / visible_count) if visible_count else 0.0

    # P1.6 headline low-noise number. The confidence-junk axis (``junk_ratio`` /
    # ``visible_junk_ratio``) is structurally ~0 because extraction strips the
    # low-confidence tier before storage, so there is no confidence-junk left to
    # suppress. The measurable P1.6 win is priority-based display suppression:
    # ``entities_suppressed / total``. It moves with ``VOIDACCESS_PRIORITY_FLOOR``
    # because ``suppressed`` is written by ``utils.entity_priority.rank_entities``,
    # which honors that floor.
    suppression_rate = (suppressed / total_entities) if total_entities else 0.0

    scraping = step_metrics.get("scraping", {})
    extraction = step_metrics.get("entity_extraction", {})
    pages_attempted = int(scraping.get("pages_attempted", 0))
    pages_fetched = int(scraping.get("pages_fetched", 0))
    pages_cache_hits = int(scraping.get("pages_cache_hits", 0))
    pages_empty = max(0, pages_attempted - pages_fetched)
    page_cache_hit_rate = (pages_cache_hits / pages_attempted) if pages_attempted else 0.0

    extr_hits = int(extraction.get("extraction_cache_hits", 0))
    extr_llm = int(extraction.get("extraction_llm_pages", 0))
    extr_total = extr_hits + extr_llm
    extraction_cache_hit_rate = (extr_hits / extr_total) if extr_total else 0.0

    per_source: dict[str, dict] = {}
    for name, info in (result_json.get("sources_used") or {}).items():
        if isinstance(info, dict):
            per_source[name] = {
                "status": str(info.get("status", "")),
                "count": int(info.get("count", 0) or 0),
            }

    phase_ms = {
        p: round(float(step_metrics.get(p, {}).get("duration_ms", 0.0)), 1)
        for p in _artifact.PIPELINE_PHASES
    }

    return {
        "total_entities": total_entities,
        "entity_counts_by_type": type_counts,
        "entity_counts_by_confidence_tier": tier_counts,
        "junk_ratio": round(junk_ratio, 4),
        "suppression_rate": round(suppression_rate, 4),
        "entities_suppressed": suppressed,
        "visible_entity_count": visible_count,
        "visible_junk_count": visible_junk,
        "visible_junk_ratio": round(visible_junk_ratio, 4),
        "pages_attempted": pages_attempted,
        "pages_fetched": pages_fetched,
        "pages_empty": pages_empty,
        "pages_cache_hits": pages_cache_hits,
        "page_cache_hit_rate": round(page_cache_hit_rate, 4),
        "extraction_cache_hits": extr_hits,
        "extraction_llm_pages": extr_llm,
        "extraction_cache_hit_rate": round(extraction_cache_hit_rate, 4),
        "per_source_contribution": {k: per_source[k] for k in sorted(per_source)},
        "phase_wall_clock_ms": phase_ms,
    }


def _build_artifact(query_set: QuerySet, per_query: list[dict], use_llm: bool, tor_source: str) -> dict:
    agg_type = _artifact.empty_type_counts()
    agg_tier = _artifact.empty_tier_counts()
    agg_phase = {p: 0.0 for p in _artifact.PIPELINE_PHASES}
    agg_source: dict[str, dict] = {}

    total_entities = 0
    total_suppressed = 0
    total_visible = 0
    total_visible_junk = 0
    total_pages_attempted = 0
    total_pages_fetched = 0
    total_pages_empty = 0
    total_pages_cache_hits = 0
    total_extr_hits = 0
    total_extr_llm = 0

    for rec in per_query:
        total_entities += rec["total_entities"]
        total_suppressed += rec.get("entities_suppressed", 0)
        total_visible += rec.get("visible_entity_count", rec["total_entities"])
        total_visible_junk += rec.get("visible_junk_count", rec["entity_counts_by_confidence_tier"]["junk"])
        total_pages_attempted += rec["pages_attempted"]
        total_pages_fetched += rec["pages_fetched"]
        total_pages_empty += rec["pages_empty"]
        total_pages_cache_hits += rec["pages_cache_hits"]
        total_extr_hits += rec["extraction_cache_hits"]
        total_extr_llm += rec["extraction_llm_pages"]
        for k, v in rec["entity_counts_by_type"].items():
            agg_type[k] += v
        for k, v in rec["entity_counts_by_confidence_tier"].items():
            agg_tier[k] += v
        for p in _artifact.PIPELINE_PHASES:
            agg_phase[p] += rec["phase_wall_clock_ms"].get(p, 0.0)
        for name, info in rec["per_source_contribution"].items():
            slot = agg_source.setdefault(name, {"queries": 0, "count": 0})
            slot["queries"] += 1
            slot["count"] += int(info.get("count", 0))

    junk_ratio = (agg_tier["junk"] / total_entities) if total_entities else 0.0
    visible_junk_ratio = (total_visible_junk / total_visible) if total_visible else 0.0
    suppression_rate = (total_suppressed / total_entities) if total_entities else 0.0
    page_cache_rate = (total_pages_cache_hits / total_pages_attempted) if total_pages_attempted else 0.0
    extr_total = total_extr_hits + total_extr_llm
    extr_cache_rate = (total_extr_hits / extr_total) if extr_total else 0.0

    return {
        "artifact_type": "pipeline_metrics",
        "schema_version": _artifact.SCHEMA_VERSION,
        "run": {
            "generated_at": _artifact.now_iso(),
            "pace_profile": _pace_profile(),
            "llm_enabled": bool(use_llm),
            "tor_source": tor_source,
            "depth": INVESTIGATION_DEPTH,
            "query_set_version": query_set.version,
            "query_count": len(per_query),
            "git_commit": _artifact.git_commit(),
        },
        "totals": {
            "total_entities": total_entities,
            "entity_counts_by_type": agg_type,
            "entity_counts_by_confidence_tier": agg_tier,
            "junk_ratio": round(junk_ratio, 4),
            "suppression_rate": round(suppression_rate, 4),
            "entities_suppressed": total_suppressed,
            "visible_entity_count": total_visible,
            "visible_junk_ratio": round(visible_junk_ratio, 4),
            "pages_attempted": total_pages_attempted,
            "pages_fetched": total_pages_fetched,
            "pages_empty": total_pages_empty,
            "page_cache_hit_rate": round(page_cache_rate, 4),
            "extraction_cache_hit_rate": round(extr_cache_rate, 4),
            "phase_wall_clock_ms": {p: round(agg_phase[p], 1) for p in _artifact.PIPELINE_PHASES},
            "per_source_contribution": {k: agg_source[k] for k in sorted(agg_source)},
        },
        "per_query": per_query,
    }


def _pace_profile() -> str:
    try:
        import pacing

        return pacing.get_profile()
    except Exception:
        return "normal"


def _render_summary(console, artifact: dict) -> None:
    from rich.table import Table

    t = artifact["totals"]
    table = Table(title="Pipeline metrics (benchmark run)")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Queries", str(artifact["run"]["query_count"]))
    table.add_row("LLM enabled", str(artifact["run"]["llm_enabled"]))
    table.add_row("Total entities", str(t["total_entities"]))
    table.add_row("Junk ratio (stored)", f"{t['junk_ratio'] * 100:.1f}%")
    table.add_row(
        "Junk ratio (visible)",
        f"{t.get('visible_junk_ratio', t['junk_ratio']) * 100:.1f}%",
    )
    table.add_row("Entities suppressed", str(t.get("entities_suppressed", 0)))
    table.add_row(
        "Suppression rate (low-noise)",
        f"{t.get('suppression_rate', 0.0) * 100:.1f}%",
    )
    table.add_row("Pages fetched / attempted", f"{t['pages_fetched']} / {t['pages_attempted']}")
    table.add_row("Page cache-hit rate", f"{t['page_cache_hit_rate'] * 100:.1f}%")
    table.add_row("Extraction cache-hit rate", f"{t['extraction_cache_hit_rate'] * 100:.1f}%")
    console.print(table)


def run_metrics(
    query_set: Optional[QuerySet] = None,
    *,
    use_llm: bool = False,
    no_tor: bool = False,
    out_path: Optional[Path] = None,
    console=None,
) -> dict:
    """Run the benchmark set through the real SQLite pipeline and write a canonical
    metrics artifact. Returns the artifact."""
    query_set = query_set or load_query_set()

    from voidaccess_cli import config as cli_config
    from voidaccess_cli.adapters import sqlite as sqlite_adapter

    cli_config.apply_env()
    sqlite_adapter.init_db()

    if no_tor:
        tor_source = "disabled"
    else:
        from voidaccess_cli.tor_detect import detect_tor, tor_unavailable_message
        import os

        status = detect_tor()
        if not status.proxy_url:
            raise RuntimeError(tor_unavailable_message())
        os.environ["TOR_PROXY_HOST"] = status.host or "127.0.0.1"
        os.environ["TOR_PROXY_PORT"] = str(status.port or 9050)
        tor_source = status.source

    from voidaccess_cli.commands import investigate

    per_query: list[dict] = []
    for q in query_set.queries:
        with tempfile.TemporaryDirectory(prefix="va-bench-") as tmp:
            tmp_dir = Path(tmp)
            try:
                asyncio.run(
                    investigate._run_investigation(
                        query=q.query,
                        out_dir=tmp_dir,
                        model=None,
                        no_tor=no_tor,
                        no_llm=not use_llm,
                        depth=INVESTIGATION_DEPTH,
                        fmt="json",
                        quiet=True,
                    )
                )
            except Exception as exc:
                logger.warning("investigation failed for %s: %s", q.id, exc)

            result_json = _load_result_json(tmp_dir) or {}
            inv_id = result_json.get("id")
            step_metrics = _step_metrics_for(inv_id) if inv_id else {}
            summary = summarize_query_result(result_json, step_metrics)
            per_query.append({
                "query_id": q.id,
                "category": q.category,
                "lang": q.lang,
                "investigation_id": inv_id or "",
                "status": result_json.get("status", "no_result"),
                **summary,
            })
        if console is not None:
            console.print(f"  [dim]ran[/dim] {q.id}")

    artifact = _build_artifact(query_set, per_query, use_llm, tor_source)
    path = Path(out_path) if out_path else (_artifact.DEFAULT_ARTIFACT_DIR / "metrics-latest.json")
    _artifact.write_artifact(artifact, path)

    if console is not None:
        _render_summary(console, artifact)
    return artifact
