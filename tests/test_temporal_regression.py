"""P1.6 regression: the temporal-anomaly path was left calling the pre-Poisson
API — it imported a ``Z_SCORE_THRESHOLD`` that no longer exists (an ImportError
that killed the whole endpoint) and read a ``z_score`` key the new detector no
longer emits.  These tests lock the path to the current Poisson API and prove it
runs end-to-end.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def test_temporal_module_exposes_poisson_not_zscore():
    import analysis.temporal as temporal

    assert hasattr(temporal, "POISSON_ALPHA")
    assert not hasattr(temporal, "Z_SCORE_THRESHOLD")


def test_no_zscore_threshold_reference_remains_in_caller():
    # grep-equivalent guard against re-introduction (acceptance criterion).
    source = Path("api/routes/investigations.py").read_text(encoding="utf-8")
    assert "Z_SCORE_THRESHOLD" not in source
    assert "POISSON_ALPHA" in source


async def test_temporal_endpoint_runs_end_to_end(db_engine):
    from db.session import get_session
    from db.models import Investigation, Page, Entity
    from api.routes.investigations import get_temporal_analysis

    inv_id = uuid.uuid4()
    base = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)

    # 10 quiet days (one page each) then a 6-page spike day → a Poisson anomaly
    # over an 11-point timeline (detector needs >= 10 points).
    day_counts = [(i, 1) for i in range(10)] + [(20, 6)]

    with get_session() as session:
        session.add(Investigation(
            id=inv_id, query="q", status="completed", created_at=base,
        ))
        for day_offset, count in day_counts:
            for _ in range(count):
                page_id = uuid.uuid4()
                posted = base + timedelta(days=day_offset)
                session.add(Page(
                    id=page_id, url=f"http://{page_id}.onion",
                    cleaned_text="x", scrape_timestamp=base,
                    posted_at=posted, created_at=base,
                ))
                session.add(Entity(
                    id=uuid.uuid4(), page_id=page_id, investigation_id=inv_id,
                    entity_type="IP_ADDRESS", value="1.2.3.4",
                    canonical_value="1.2.3.4", confidence=0.9,
                    extraction_method="regex", created_at=base,
                ))
        session.commit()

    result = await get_temporal_analysis(str(inv_id))

    # The path completed (no ImportError → analysis_failed, no insufficient_data).
    assert "error" not in result, result
    assert result["data_points"] >= 10
    assert result["anomalies"], "expected the spike day to be flagged"

    anomaly = result["anomalies"][0]
    # New Poisson shape — not the removed z_score key.
    assert "z_score" not in anomaly
    assert "poisson_p_value" in anomaly
    assert "expected_rate" in anomaly
    assert anomaly["type"] in {"spike", "drop"}
    assert 0.0 <= anomaly["poisson_p_value"] <= 1.0
