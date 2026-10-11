"""P1.6 — low-noise-by-default ranking + non-destructive suppression.

Uses only the existing signals (priority_score = confidence + corroboration +
freshness, plus a per-type display cap and the deterministic P1.3–P1.5 flags as a
surfacing hint).  Every input entity survives ranking — suppression marks and
deprioritizes, it never deletes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from utils.entity_priority import (
    DEFAULT_PRIORITY_FLOOR,
    order_and_filter_for_summary,
    rank_entities,
    rank_map,
)


def _entity(
    entity_id,
    *,
    confidence,
    entity_type="IP_ADDRESS",
    source_count=1,
    investigation_count=1,
    days_ago=0,
    corroborating_sources=None,
):
    seen = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return SimpleNamespace(
        id=entity_id,
        entity_type=entity_type,
        confidence=confidence,
        source_count=source_count,
        investigation_count=investigation_count,
        last_seen_at=seen,
        first_seen_at=seen,
        corroborating_sources=corroborating_sources,
    )


def test_high_signal_entities_rank_above_low_signal():
    entities = [
        _entity("low", confidence=0.20, source_count=1, days_ago=300),
        _entity("high", confidence=0.96, source_count=6, days_ago=0),
        _entity("mid", confidence=0.70, source_count=2, days_ago=10),
    ]
    ranked = rank_entities(entities)
    order = [r["id"] for r in ranked]
    assert order == ["high", "mid", "low"]
    assert [r["rank"] for r in ranked] == [1, 2, 3]


def test_suppression_is_non_destructive_and_flagged():
    entities = [
        _entity("keep", confidence=0.95, source_count=5, days_ago=0),
        _entity("junk", confidence=0.05, source_count=1, days_ago=400),
    ]
    ranked = rank_entities(entities)
    by_id = {r["id"]: r for r in ranked}

    # The low-signal entity is still present (reachable), just flagged + last.
    assert set(by_id) == {"keep", "junk"}
    assert by_id["junk"]["priority_score"] < DEFAULT_PRIORITY_FLOOR
    assert by_id["junk"]["suppressed"] is True
    assert by_id["junk"]["suppression_reason"] == "below_priority_floor"
    assert by_id["keep"]["suppressed"] is False
    assert by_id["keep"]["suppression_reason"] is None
    assert by_id["keep"]["rank"] < by_id["junk"]["rank"]


def test_deterministic_flags_exempt_low_score_entity_from_suppression():
    # Same weak signals as "junk" above, but it carries a KEV flag → surfaced.
    entities = [
        _entity(
            "kev-cve",
            confidence=0.05,
            source_count=1,
            days_ago=400,
            corroborating_sources=json.dumps(["dark_web_scrape", "kev"]),
        ),
    ]
    (record,) = rank_entities(entities)
    assert record["priority_score"] < DEFAULT_PRIORITY_FLOOR
    assert record["high_signal"] is True
    assert record["suppressed"] is False


def test_high_signal_only_breaks_ties_never_reorders_priority():
    # A plain entity with a *higher* priority_score must still outrank a flagged
    # entity with a lower score — the flag is a tie-break hint, not a score input.
    entities = [
        _entity("plain-strong", confidence=0.95, source_count=6, days_ago=0),
        _entity(
            "flagged-weak",
            confidence=0.30,
            source_count=1,
            days_ago=200,
            corroborating_sources=["ransom_wallet"],
        ),
    ]
    ranked = {r["id"]: r for r in rank_entities(entities)}
    assert ranked["plain-strong"]["priority_score"] > ranked["flagged-weak"]["priority_score"]
    assert ranked["plain-strong"]["rank"] < ranked["flagged-weak"]["rank"]

    # But with equal scores, the flag surfaces the high-signal one first.
    tied = [
        _entity("tied-plain", confidence=0.80, source_count=2, days_ago=5),
        _entity(
            "tied-flagged",
            confidence=0.80,
            source_count=2,
            days_ago=5,
            corroborating_sources=["phishing"],
        ),
    ]
    ranked_tied = {r["id"]: r for r in rank_entities(tied)}
    assert ranked_tied["tied-plain"]["priority_score"] == ranked_tied["tied-flagged"]["priority_score"]
    assert ranked_tied["tied-flagged"]["rank"] < ranked_tied["tied-plain"]["rank"]


def test_per_type_display_cap_suppresses_the_tail():
    # 12 equally-strong DATE entities; the DATE display cap is 10, so exactly two
    # are suppressed by cap (all are above the floor).
    entities = [
        _entity(f"d{i:02d}", confidence=0.90, entity_type="DATE", days_ago=0)
        for i in range(12)
    ]
    ranked = rank_entities(entities)
    suppressed = [r for r in ranked if r["suppressed"]]
    assert len(suppressed) == 2
    assert all(r["suppression_reason"] == "per_type_display_cap" for r in suppressed)
    # Non-destructive: all 12 still present.
    assert len(ranked) == 12


def test_tags_read_from_json_string_and_from_list():
    as_string = _entity("s", confidence=0.05, days_ago=400,
                         corroborating_sources=json.dumps(["kev"]))
    as_list = _entity("l", confidence=0.05, days_ago=400,
                      corroborating_sources=["exploit_public"])
    ranked = {r["id"]: r for r in rank_entities([as_string, as_list])}
    assert ranked["s"]["high_signal"] is True
    assert ranked["l"]["high_signal"] is True


def test_prefixed_flags_count_as_high_signal():
    e = _entity("w", confidence=0.05, days_ago=400,
                corroborating_sources=["ransom_wallet_conti_ransomware"])
    (record,) = rank_entities([e])
    assert record["high_signal"] is True
    assert record["suppressed"] is False


def test_rank_map_is_keyed_by_id():
    entities = [
        _entity("a", confidence=0.9, source_count=4),
        _entity("b", confidence=0.5),
    ]
    mapping = rank_map(entities)
    assert set(mapping) == {"a", "b"}
    assert mapping["a"]["rank"] == 1


def test_summary_feed_drops_suppressed_by_default_and_is_reversible():
    strong = _entity("strong", confidence=0.95, source_count=5, days_ago=0)
    weak = _entity("weak", confidence=0.05, source_count=1, days_ago=400)

    default = order_and_filter_for_summary([weak, strong])
    assert [e.id for e in default] == ["strong"]  # suppressed weak dropped, ordered

    full = order_and_filter_for_summary([weak, strong], include_suppressed=True)
    assert [e.id for e in full] == ["strong", "weak"]  # reachable, still ranked

    limited = order_and_filter_for_summary(
        [weak, strong], include_suppressed=True, limit=1
    )
    assert [e.id for e in limited] == ["strong"]


def test_env_floor_override_changes_suppression(monkeypatch):
    weak = _entity("weak", confidence=0.35, source_count=1, days_ago=30)
    # Default floor 0.25: this entity is above it → visible.
    (base,) = rank_entities([weak])
    assert base["suppressed"] is False
    # Raise the floor above its score → suppressed, deterministically.
    monkeypatch.setenv("VOIDACCESS_PRIORITY_FLOOR", "0.99")
    (raised,) = rank_entities([weak])
    assert raised["suppressed"] is True
    assert raised["suppression_reason"] == "below_priority_floor"
