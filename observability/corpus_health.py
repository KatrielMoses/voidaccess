"""
observability/corpus_health.py — the CC-5 corpus-health view (P4.4).

A single low-ops aggregation over the counters the gate / promote / read paths
**already emit** — there is no parallel metrics pipeline, no time-series store, no
Prometheus. Every number is a point-in-time SELECT over existing tables:

* ``global_entities`` (confidence_tier, first_seen, corroboration_count) — the
  quarantine:promotion ratio (the primary poisoning signal) + ingest rate.
* ``source_reputations`` (score, blocked, contributed, contradicted, anomalies,
  last_seen) — contributor-reputation distribution + flagged abusers + flood signal.
* ``global_entity_sources`` (source=origin, contributor) — distinct origins /
  contributors.
* ``discovered_onions`` (status) + ``page_snapshots`` (captured_at) — index size +
  freshness (fresh/stale/dead).
* ``investigation_step_metrics`` (pages_cache_hits / pages_attempted) — the
  read-from-shared cache-hit rate.

Every section is independently guarded, so a missing/empty table (the $0/local
install with no central corpus) yields zeros, never a crash.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import sqlalchemy as sa

logger = logging.getLogger(__name__)

_DEFAULT_WINDOW_SECONDS = 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe(fn, default):
    try:
        return fn()
    except Exception as exc:  # a failing section must not crash the whole view
        logger.debug("corpus_health: section failed (non-fatal): %s", exc)
        return default


def _tier_section(session, now, window) -> dict:
    from shared_corpus.models import ConfidenceTier, GlobalEntity

    rows = session.execute(
        sa.select(GlobalEntity.confidence_tier, sa.func.count()).group_by(
            GlobalEntity.confidence_tier
        )
    ).all()
    counts = {t.value: 0 for t in ConfidenceTier}
    for tier, n in rows:
        counts[tier] = counts.get(tier, 0) + int(n)
    total = sum(counts.values())
    unconfirmed = counts.get(ConfidenceTier.UNCONFIRMED.value, 0)
    promoted = (
        counts.get(ConfidenceTier.CORROBORATED.value, 0)
        + counts.get(ConfidenceTier.FEED_VALIDATED.value, 0)
    )
    return {
        "total": total,
        "unconfirmed": unconfirmed,
        "corroborated": counts.get(ConfidenceTier.CORROBORATED.value, 0),
        "feed_validated": counts.get(ConfidenceTier.FEED_VALIDATED.value, 0),
        # The primary poisoning signal: a spike toward 1.0 means a flood of
        # single-source/uncorroborated (likely poisoned) artifacts.
        "quarantine_ratio": round(unconfirmed / total, 4) if total else 0.0,
        "promotion_ratio": round(promoted / total, 4) if total else 0.0,
    }


def _reputation_section(session, now, window) -> dict:
    from shared_corpus.models import SourceReputation

    total = int(session.execute(sa.select(sa.func.count()).select_from(SourceReputation)).scalar() or 0)
    blocked = int(
        session.execute(
            sa.select(sa.func.count()).select_from(SourceReputation).where(SourceReputation.blocked.is_(True))
        ).scalar()
        or 0
    )
    agg = session.execute(
        sa.select(
            sa.func.avg(SourceReputation.score),
            sa.func.min(SourceReputation.score),
            sa.func.sum(SourceReputation.anomalies),
            sa.func.sum(SourceReputation.contradicted),
            sa.func.sum(SourceReputation.contributed),
        )
    ).one()
    mean_score, min_score, anomalies, contradicted, contributed = agg

    # Distribution buckets.
    def _bucket(lo, hi):
        q = sa.select(sa.func.count()).select_from(SourceReputation)
        if lo is not None:
            q = q.where(SourceReputation.score >= lo)
        if hi is not None:
            q = q.where(SourceReputation.score < hi)
        return int(session.execute(q).scalar() or 0)

    buckets = {
        "low_<0.5": _bucket(None, 0.5),
        "mid_0.5-0.8": _bucket(0.5, 0.8),
        "high_>=0.8": _bucket(0.8, None),
    }

    # Flagged contributors — abuse is visible here: high anomalies/contradictions
    # or blocked. Ordered most-abusive first.
    flagged_rows = session.execute(
        sa.select(SourceReputation)
        .where(
            sa.or_(
                SourceReputation.blocked.is_(True),
                SourceReputation.anomalies > 0,
                SourceReputation.contradicted > 0,
            )
        )
        .order_by(
            (SourceReputation.anomalies + SourceReputation.contradicted).desc(),
            SourceReputation.score.asc(),
        )
        .limit(20)
    ).scalars().all()
    flagged = [
        {
            "source": r.source,
            "score": round(r.score, 4),
            "blocked": r.blocked,
            "contributed": r.contributed,
            "anomalies": r.anomalies,
            "contradicted": r.contradicted,
        }
        for r in flagged_rows
    ]

    return {
        "contributors": total,
        "blocked": blocked,
        "mean_score": round(float(mean_score), 4) if mean_score is not None else None,
        "min_score": round(float(min_score), 4) if min_score is not None else None,
        "score_buckets": buckets,
        # Cumulative flood/abuse signal across all contributors.
        "total_anomalies": int(anomalies or 0),
        "total_contradictions": int(contradicted or 0),
        "total_contributions": int(contributed or 0),
        "flagged": flagged,
    }


def _origins_section(session, now, window) -> dict:
    from shared_corpus.models import GlobalEntitySource

    distinct_origins = int(
        session.execute(sa.select(sa.func.count(sa.func.distinct(GlobalEntitySource.source)))).scalar() or 0
    )
    distinct_contributors = int(
        session.execute(
            sa.select(sa.func.count(sa.func.distinct(GlobalEntitySource.contributor)))
        ).scalar()
        or 0
    )
    return {"distinct_origins": distinct_origins, "distinct_contributors": distinct_contributors}


def _index_section(session, now, window) -> dict:
    from shared_corpus.models import DiscoveredOnion, PageSnapshot

    onion_rows = session.execute(
        sa.select(DiscoveredOnion.status, sa.func.count()).group_by(DiscoveredOnion.status)
    ).all()
    onions = {"alive": 0, "dead": 0, "dropped": 0, "unknown": 0}
    for status, n in onion_rows:
        onions[status] = onions.get(status, 0) + int(n)
    onions["total"] = sum(v for k, v in onions.items() if k != "total")

    snap_total = int(session.execute(sa.select(sa.func.count()).select_from(PageSnapshot)).scalar() or 0)
    try:
        import config

        stale_secs = int(getattr(config, "FRESHNESS_STALE_AFTER_SECONDS", 24 * 3600))
    except Exception:
        stale_secs = 24 * 3600
    cutoff = now - timedelta(seconds=stale_secs)
    stale = int(
        session.execute(
            sa.select(sa.func.count()).select_from(PageSnapshot).where(PageSnapshot.captured_at < cutoff)
        ).scalar()
        or 0
    )
    return {
        "onions": onions,
        "snapshots": {"total": snap_total, "stale": stale, "fresh": max(0, snap_total - stale)},
    }


def _cache_section(session, now, window) -> dict:
    from db.models import InvestigationStepMetric

    agg = session.execute(
        sa.select(
            sa.func.sum(InvestigationStepMetric.pages_cache_hits),
            sa.func.sum(InvestigationStepMetric.pages_attempted),
        )
    ).one()
    hits, attempted = int(agg[0] or 0), int(agg[1] or 0)
    return {
        "pages_cache_hits": hits,
        "pages_attempted": attempted,
        "hit_rate": round(hits / attempted, 4) if attempted else 0.0,
    }


def _ingest_section(session, now, window) -> dict:
    """Recent-window activity from emitted first_seen / last_seen timestamps."""
    from shared_corpus.models import GlobalEntity, GlobalEntitySource, SourceReputation

    cutoff = now - window
    new_entities = int(
        session.execute(
            sa.select(sa.func.count()).select_from(GlobalEntity).where(GlobalEntity.first_seen >= cutoff)
        ).scalar()
        or 0
    )
    new_origins = int(
        session.execute(
            sa.select(sa.func.count()).select_from(GlobalEntitySource).where(GlobalEntitySource.first_seen >= cutoff)
        ).scalar()
        or 0
    )
    active_contributors = int(
        session.execute(
            sa.select(sa.func.count()).select_from(SourceReputation).where(SourceReputation.last_seen >= cutoff)
        ).scalar()
        or 0
    )
    return {
        "window_seconds": int(window.total_seconds()),
        "new_entities": new_entities,
        "new_origins": new_origins,
        "active_contributors": active_contributors,
    }


def corpus_health(
    session: Any, *, window_seconds: int = _DEFAULT_WINDOW_SECONDS, now: Optional[datetime] = None
) -> dict:
    """Aggregate the corpus-health vital signs. Never raises — sections degrade to zeros."""
    now = now or _now()
    window = timedelta(seconds=window_seconds)
    return {
        "generated_at": now.isoformat(),
        "ingest": _safe(lambda: _ingest_section(session, now, window), {}),
        "tiers": _safe(lambda: _tier_section(session, now, window), {}),
        "reputation": _safe(lambda: _reputation_section(session, now, window), {}),
        "origins": _safe(lambda: _origins_section(session, now, window), {}),
        "index": _safe(lambda: _index_section(session, now, window), {}),
        "cache": _safe(lambda: _cache_section(session, now, window), {}),
    }
