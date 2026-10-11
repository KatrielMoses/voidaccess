"""Offline tests for the P1.0 measurement module.

Everything here runs with no Tor, no LLM, and no network by exercising the pure
functions directly and by monkeypatching the two probe seams (``_fetch_engine``
and ``tor_isolation.acquire/release_engine_session``). The live pipeline is never
invoked; the metrics aggregation is tested against injected result JSON + fake
step-metric rows.
"""
from __future__ import annotations

import uuid

import pytest

from benchmark import artifact
from benchmark import engine_probe
from benchmark.metrics import _build_artifact as build_metrics_artifact
from benchmark.metrics import summarize_query_result
from benchmark.queries import VALID_CATEGORIES, load_query_set


# --------------------------------------------------------------------------- #
# Query set
# --------------------------------------------------------------------------- #
def test_query_set_loads_and_spans_categories():
    qs = load_query_set()
    assert qs.version
    assert len(qs) >= 8
    cats = {q.category for q in qs.queries}
    assert cats <= VALID_CATEGORIES
    # The brief requires multilingual coverage specifically.
    assert "multilingual" in cats
    langs = {q.lang for q in qs.queries}
    assert langs - {"en"}, "expected at least one non-English query"
    # ids unique
    ids = [q.id for q in qs.queries]
    assert len(ids) == len(set(ids))


def test_query_set_rejects_unknown_category(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"version":"1","queries":[{"id":"x","query":"q","category":"nope"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_query_set(bad)


# --------------------------------------------------------------------------- #
# Artifact helpers
# --------------------------------------------------------------------------- #
def test_confidence_tier_boundaries():
    assert artifact.confidence_tier(0.95) == "high"
    assert artifact.confidence_tier(0.90) == "high"
    assert artifact.confidence_tier(0.899) == "medium"
    assert artifact.confidence_tier(0.72) == "medium"
    assert artifact.confidence_tier(0.719) == "low"
    assert artifact.confidence_tier(0.42) == "low"
    assert artifact.confidence_tier(0.419) == "junk"
    assert artifact.confidence_tier(0.0) == "junk"
    assert artifact.confidence_tier(None) == "junk"


def test_canonical_json_is_deterministic_and_sorted():
    obj = {"b": 1, "a": {"z": 2, "y": 3}}
    j = artifact.canonical_json(obj)
    assert j == artifact.canonical_json(obj)
    assert j.endswith("\n")
    assert j.index('"a"') < j.index('"b"')  # sorted keys


# --------------------------------------------------------------------------- #
# Metrics aggregation (pure)
# --------------------------------------------------------------------------- #
def test_summarize_emits_full_fixed_schema_on_sparse_input():
    result_json = {
        "id": str(uuid.uuid4()),
        "entities": [
            {"entity_type": "IP_ADDRESS", "confidence": 0.95},   # high
            {"entity_type": "domain", "confidence": 0.5},        # lowercase -> DOMAIN, low
            {"entity_type": "WEIRD_UNKNOWN", "confidence": 0.3},  # -> OTHER, junk
        ],
        "sources_used": {"tor_search": {"status": "ok", "count": 4}},
    }
    step_metrics = {
        "scraping": {"pages_attempted": 10, "pages_fetched": 7, "pages_cache_hits": 3},
        "entity_extraction": {"extraction_cache_hits": 2, "extraction_llm_pages": 5},
        "query_refinement": {"duration_ms": 12.0},
    }
    s = summarize_query_result(result_json, step_metrics)

    # Every entity-type bucket and every phase present regardless of sparse data.
    assert set(s["entity_counts_by_type"]) == set(artifact.entity_type_keys())
    assert set(s["phase_wall_clock_ms"]) == set(artifact.PIPELINE_PHASES)
    assert set(s["entity_counts_by_confidence_tier"]) == set(artifact.CONFIDENCE_TIERS)

    assert s["entity_counts_by_type"]["IP_ADDRESS"] == 1
    assert s["entity_counts_by_type"]["DOMAIN"] == 1
    assert s["entity_counts_by_type"]["OTHER"] == 1  # unknown type folded into OTHER
    assert s["entity_counts_by_confidence_tier"] == {"high": 1, "medium": 0, "low": 1, "junk": 1}
    assert s["junk_ratio"] == round(1 / 3, 4)

    assert (s["pages_attempted"], s["pages_fetched"], s["pages_empty"]) == (10, 7, 3)
    assert s["page_cache_hit_rate"] == round(3 / 10, 4)
    assert s["extraction_cache_hit_rate"] == round(2 / 7, 4)
    assert s["per_source_contribution"]["tor_search"]["count"] == 4
    assert s["phase_wall_clock_ms"]["query_refinement"] == 12.0


def test_visible_junk_ratio_reflects_non_destructive_suppression():
    """P1.6: suppression is non-destructive, so ``junk_ratio`` (all stored) is
    unchanged, but ``visible_junk_ratio`` (default-visible) drops when the junk is
    suppressed. The gap is the measurable low-value-entity reduction."""
    result_json = {
        "id": str(uuid.uuid4()),
        "entities": [
            {"entity_type": "IP_ADDRESS", "confidence": 0.95, "suppressed": False},
            {"entity_type": "IP_ADDRESS", "confidence": 0.30, "suppressed": True},   # junk, hidden
            {"entity_type": "DOMAIN", "confidence": 0.20, "suppressed": True},        # junk, hidden
        ],
        "sources_used": {},
    }
    s = summarize_query_result(result_json, {})

    # Stored view still sees both junk entities.
    assert s["junk_ratio"] == round(2 / 3, 4)
    # Visible view: only the one high-confidence entity remains → zero junk.
    assert s["entities_suppressed"] == 2
    assert s["visible_entity_count"] == 1
    assert s["visible_junk_ratio"] == 0.0
    assert s["visible_junk_ratio"] < s["junk_ratio"]


def test_suppression_rate_is_suppressed_over_total():
    """INT-D3: the headline low-noise metric is priority-based suppression,
    ``entities_suppressed / total`` — non-zero even when confidence-junk is 0."""
    result_json = {
        "id": str(uuid.uuid4()),
        "entities": [
            {"entity_type": "IP_ADDRESS", "confidence": 0.95, "suppressed": False},
            {"entity_type": "IP_ADDRESS", "confidence": 0.92, "suppressed": True},
            {"entity_type": "DOMAIN", "confidence": 0.91, "suppressed": True},
        ],
        "sources_used": {},
    }
    s = summarize_query_result(result_json, {})
    # All three entities are high-confidence, so confidence-junk is zero...
    assert s["junk_ratio"] == 0.0
    # ...but the low-noise metric still moves off zero.
    assert s["suppression_rate"] == round(2 / 3, 4)
    assert s["suppression_rate"] == round(
        s["entities_suppressed"] / s["total_entities"], 4
    )


def test_suppression_rate_tracks_priority_floor_monotonically():
    """RV-D3b: raising ``VOIDACCESS_PRIORITY_FLOOR`` raises ``suppression_rate``.

    Drives the real ranking (``rank_entities``) at two floors and feeds each
    ranked output through the metric, proving the artifact's headline number
    responds to the lever P1.6 actually acts on."""
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from utils.entity_priority import rank_entities

    now = datetime.now(timezone.utc)

    def _e(eid, confidence):
        return SimpleNamespace(
            id=eid,
            entity_type="IP_ADDRESS",
            confidence=confidence,
            source_count=1,
            investigation_count=1,
            last_seen_at=now,
            first_seen_at=now,
            corroborating_sources=None,
        )

    entities = [_e(f"e{i}", c) for i, c in enumerate((0.30, 0.45, 0.60, 0.75, 0.90))]

    def _rate_at(floor):
        import os

        prev = os.environ.get("VOIDACCESS_PRIORITY_FLOOR")
        os.environ["VOIDACCESS_PRIORITY_FLOOR"] = str(floor)
        try:
            ranked = rank_entities(entities)
        finally:
            if prev is None:
                os.environ.pop("VOIDACCESS_PRIORITY_FLOOR", None)
            else:
                os.environ["VOIDACCESS_PRIORITY_FLOOR"] = prev
        s = summarize_query_result(
            {"id": str(uuid.uuid4()), "entities": ranked, "sources_used": {}}, {}
        )
        return s["suppression_rate"]

    low = _rate_at(0.10)
    high = _rate_at(0.70)
    assert high > low, f"suppression_rate did not rise with the floor: {low} -> {high}"


def test_visible_junk_ratio_degrades_to_junk_ratio_without_suppressed_key():
    """A pre-P1.6 run has no ``suppressed`` key; everything counts as visible."""
    result_json = {
        "id": str(uuid.uuid4()),
        "entities": [
            {"entity_type": "IP_ADDRESS", "confidence": 0.95},
            {"entity_type": "DOMAIN", "confidence": 0.20},
        ],
        "sources_used": {},
    }
    s = summarize_query_result(result_json, {})
    assert s["entities_suppressed"] == 0
    assert s["visible_junk_ratio"] == s["junk_ratio"] == 0.5


def test_metrics_artifact_repeatable_structure():
    qs = load_query_set()
    rec = summarize_query_result({"id": "x", "entities": [], "sources_used": {}}, {})
    per_query = [{
        "query_id": "q1", "category": "ransomware", "lang": "en",
        "investigation_id": "x", "status": "completed", **rec,
    }]
    a1 = build_metrics_artifact(qs, per_query, False, "system_tor")
    a2 = build_metrics_artifact(qs, per_query, False, "system_tor")
    # Neutralize the intentionally-volatile provenance fields.
    for a in (a1, a2):
        a["run"]["generated_at"] = "X"
        a["run"]["git_commit"] = "X"
    assert artifact.canonical_json(a1) == artifact.canonical_json(a2)
    # Fixed top-level schema present.
    assert set(a1["totals"]["entity_counts_by_type"]) == set(artifact.entity_type_keys())
    assert set(a1["totals"]["phase_wall_clock_ms"]) == set(artifact.PIPELINE_PHASES)


# --------------------------------------------------------------------------- #
# Engine probe
# --------------------------------------------------------------------------- #
def test_classify_error_mapping():
    assert engine_probe.classify_error(None) == "ok"
    assert engine_probe.classify_error("timeout") == "timeout"
    assert engine_probe.classify_error("HTTP 503") == "http_error"
    assert engine_probe.classify_error("JSON parse: boom") == "parse_error"
    assert engine_probe.classify_error("max retries") == "max_retries"
    assert engine_probe.classify_error("Cannot connect to host via proxy") == "connection_error"
    assert engine_probe.classify_error("circuit_open") == "circuit_open"
    assert engine_probe.classify_error("something odd") == "other"


def test_probe_is_read_only_and_flags_zero(monkeypatch, tmp_path):
    """The probe must (a) never touch circuit-breaker state and (b) flag every
    engine that returns 0% over the sample. Both fetch and Tor isolation are
    mocked, so no network or Tor is used."""
    from search.engine_catalog import SEARCH_ENGINES
    from search.search import EngineResult

    ok_engine = SEARCH_ENGINES[0]["name"]

    async def fake_fetch(engine, query, session, sem):
        if engine["name"] == ok_engine:
            return EngineResult(name=engine["name"], links=[{"title": "t", "link": "http://x.onion"}])
        return EngineResult(name=engine["name"], links=[], error="timeout")

    # Poison the stats-mutating functions: if the probe calls them, fail loudly.
    import db.search_engine_stats as stats

    def _boom(*a, **k):  # pragma: no cover - only fires on regression
        raise AssertionError("probe touched circuit-breaker state")

    monkeypatch.setattr(stats, "record_engine_attempt", _boom, raising=False)
    monkeypatch.setattr(stats, "should_skip_engine", _boom, raising=False)

    monkeypatch.setattr(engine_probe, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(engine_probe.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(engine_probe.tor_isolation, "release_engine_session", lambda key: None)

    out = tmp_path / "engine-health.json"
    art = engine_probe.probe_engines(sample_size=2, no_tor=True, out_path=out)

    assert out.exists()
    assert art["summary"]["engines_total"] == len(SEARCH_ENGINES)
    by_name = {e["name"]: e for e in art["engines"]}
    assert len(by_name) == len(SEARCH_ENGINES)  # every engine reported
    assert by_name[ok_engine]["flagged_zero"] is False
    assert by_name[ok_engine]["success_rate"] == 1.0
    # All non-ok engines flagged.
    assert art["summary"]["engines_flagged_zero"] == len(SEARCH_ENGINES) - 1
    assert ok_engine not in art["summary"]["flagged_engine_names"]


def test_engine_ceiling_scales_and_is_positive():
    assert engine_probe.engine_ceiling_seconds() > 0


def test_probe_report_carries_engine_status(monkeypatch, tmp_path):
    from search.search import EngineResult

    async def fake_fetch(engine, query, session, sem):
        return EngineResult(name=engine["name"], links=[])

    monkeypatch.setattr(engine_probe, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(engine_probe.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(engine_probe.tor_isolation, "release_engine_session", lambda key: None)
    art = engine_probe.probe_engines(sample_size=1, no_tor=True, out_path=tmp_path / "e.json")
    assert all("status" in e for e in art["engines"])


# --------------------------------------------------------------------------- #
# P1.1 — engine cull decision rule (benchmark/engine_cull.py)
# --------------------------------------------------------------------------- #
def test_cull_dispositions_from_baseline():
    from benchmark.engine_cull import BORDERLINE_SUCCESS_RATE, dispositions_from_baseline

    artifact_obj = {
        "engines": [
            {"name": "Healthy", "attempts": 12, "success_rate": 0.75},
            {"name": "Dead", "attempts": 12, "success_rate": 0.0},
            {"name": "Borderline", "attempts": 12, "success_rate": BORDERLINE_SUCCESS_RATE / 2},
            {"name": "AtThreshold", "attempts": 12, "success_rate": BORDERLINE_SUCCESS_RATE},
            {"name": "NoData", "attempts": 0, "success_rate": 0.0},
            {"name": "OldDefunct", "attempts": 12, "success_rate": 0.9},
        ]
    }
    disp = dispositions_from_baseline(artifact_obj, confirmed_defunct=["OldDefunct"])
    assert disp["Healthy"][0] == "active"
    assert disp["Dead"][0] == "quarantined"
    assert disp["Borderline"][0] == "quarantined"
    # At exactly the threshold it is NOT borderline (rule is strict `<`).
    assert disp["AtThreshold"][0] == "active"
    assert disp["NoData"][0] == "active"  # no evidence to cull on
    assert disp["OldDefunct"][0] == "removed"  # confirmed defunct overrides the rate


def test_cull_format_ledger_includes_extra_removed():
    from benchmark.engine_cull import format_ledger

    artifact_obj = {"run": {"git_commit": "abc123"}, "engines": [{"name": "E1", "attempts": 3, "success_rate": 0.0}]}
    md = format_ledger(artifact_obj, extra_removed={"DarkSearch (API)": "darksearch.io defunct"})
    assert "DarkSearch (API)" in md and "removed" in md
    assert "E1" in md and "quarantined" in md


# --------------------------------------------------------------------------- #
# P1.1 — metrics-table ensure regression (voidaccess_cli/adapters/sqlite.py)
# --------------------------------------------------------------------------- #
def test_step_metrics_table_ensured_on_preexisting_db(monkeypatch, tmp_path):
    """A DB file that is missing investigation_step_metrics must get it back after
    init_db(), so a baseline metrics run can persist rows (regression for the
    P1.0 baseline-integrity concern)."""
    import sqlalchemy as sa

    db_path = tmp_path / "preexisting.db"
    monkeypatch.setenv("VOIDACCESS_DB_PATH", str(db_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    from db.session import get_engine

    sqlite_adapter.init_db()
    eng = get_engine(f"sqlite:///{db_path.as_posix()}")
    assert "investigation_step_metrics" in sa.inspect(eng).get_table_names()

    # Simulate a pre-existing DB that predates the model: drop the table, then
    # the defensive ensure must recreate it on the next init_db().
    with eng.connect() as c:
        c.execute(sa.text("DROP TABLE investigation_step_metrics"))
        c.commit()
    assert "investigation_step_metrics" not in sa.inspect(get_engine(f"sqlite:///{db_path.as_posix()}")).get_table_names()

    sqlite_adapter.init_db()
    assert "investigation_step_metrics" in sa.inspect(get_engine(f"sqlite:///{db_path.as_posix()}")).get_table_names()

    # And a row actually persists + reads back (via the ORM, exactly as
    # utils.investigation_metrics.persist does — the int counters use Python-side
    # defaults, so a raw INSERT omitting them would violate NOT NULL).
    from benchmark.metrics import _step_metrics_for
    from db.models import InvestigationStepMetric
    from db.session import get_session

    inv_id = str(uuid.uuid4())
    with get_session() as s:
        s.add(InvestigationStepMetric(
            investigation_id=uuid.UUID(inv_id), step_name="scraping", duration_ms=5.0,
        ))
        s.commit()
    rows = _step_metrics_for(inv_id)
    assert "scraping" in rows and rows["scraping"]["duration_ms"] == 5.0


def test_probe_artifact_reports_p90_latency_and_unique_share():
    from benchmark.engine_probe import _build_artifact, _percentile, _unique_contribution
    from benchmark.queries import load_query_set

    assert _percentile([], 0.9) == 0.0
    assert _percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0.9) == pytest.approx(4.6)

    def o(urls, lat):
        return {"success": True, "result_count": len(urls), "latency_ms": lat, "error_class": "ok", "urls": urls}

    per = {e["name"]: [] for e in __import__("search.engine_catalog", fromlist=["x"]).SEARCH_ENGINES}
    names = list(per)
    per[names[0]] = [o(["a", "b"], 100), o(["c"], 300)]
    per[names[1]] = [o(["b"], 200), o(["d"], 200)]
    unique, distinct = _unique_contribution(per)
    assert unique[names[0]] == (2, 3) and unique[names[1]] == (1, 2) and distinct == 4
    qs = load_query_set()
    art = _build_artifact(qs, list(qs.queries)[:2], per, "test")
    e0 = next(e for e in art["engines"] if e["name"] == names[0])
    assert e0["unique_result_count"] == 2 and e0["unique_result_share"] == 0.5
    assert e0["latency_p90_ms"] == pytest.approx(280.0)
