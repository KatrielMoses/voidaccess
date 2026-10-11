"""
shared_corpus/read.py — read-from-shared before scraping (P4.2 / spec 2.2).

The write path (P4.1) fills the shared tier; this is the *read* half that makes it
pay off. Before the pipeline scrapes anything over Tor it consults the shared tier
— populated by *other users' runs* — for three things:

* **Cached content** (``page_snapshots``): if we already captured this URL's
  content recently and the source onion is alive, serve it and **skip the Tor
  re-scrape** (point 2 of the four-point standard: serve-from-cache, zero
  re-scrape). Respects the P3.3 freshness/liveness policy — a dead/dropped onion
  or a stale snapshot is never served; it falls through to a live re-scrape.
* **Known seeds** (``discovered_onions``): onions relevant to the query, added to
  the scrape/consider queue (complements P1.5 seed injection + owned-index
  retrieval).
* **Pre-extracted entities** (``global_entities``): canonical IOCs relevant to the
  query, reused **carrying their confidence tier** so consumers weight/label
  ``unconfirmed`` data and never silently trust it (spec 3.3).

Privacy boundary (the 2.2 acceptance) — airtight by construction
----------------------------------------------------------------
Every query here hits **only** the user-agnostic shared tables
(``page_snapshots`` / ``discovered_onions`` / ``global_entities``) + the object
store. It never reads ``investigations`` / ``entities`` / ``pages`` / ``users`` or
any other private-tier table, so a second user's run can be accelerated by the
first's observations without ever seeing that user's investigation, query, or
report. ``tests/test_shared_read.py`` asserts the SQL touches no private table.

Consent-gated (P2.4): a private-mode install reads nothing central — every entry
point returns empty (and ``skipped_private=True``) so the pipeline runs live-only.
Graceful on the $0/CLI path: no object store / no rows → nothing served, no crash.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional

import sqlalchemy as sa
from sqlalchemy.orm import Session

from freshness.recrawl import ALIVE, DEAD, DROPPED
from shared_corpus.consent import contribution_enabled
from shared_corpus.models import (
    ConfidenceTier,
    DiscoveredOnion,
    GlobalEntity,
    PageSnapshot,
)
from snapshot_store import is_stale, read_snapshot

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Confidence-tier consumption policy (spec 3.3)
# ---------------------------------------------------------------------------

_TIER_RANK: dict[str, int] = {
    ConfidenceTier.UNCONFIRMED.value: 0,
    ConfidenceTier.CORROBORATED.value: 1,
    ConfidenceTier.FEED_VALIDATED.value: 2,
}

#: Weight a consumer (ranking / report) should apply to shared data by tier.
#: unconfirmed is visible but down-weighted — never silently trusted.
_TIER_WEIGHT: dict[str, float] = {
    ConfidenceTier.UNCONFIRMED.value: 0.3,
    ConfidenceTier.CORROBORATED.value: 0.7,
    ConfidenceTier.FEED_VALIDATED.value: 1.0,
}


def tier_weight(tier: Optional[str]) -> float:
    """Consumer weight for a shared-tier confidence level (default: unconfirmed)."""
    return _TIER_WEIGHT.get(tier or ConfidenceTier.UNCONFIRMED.value, 0.3)


def is_trusted_tier(tier: Optional[str]) -> bool:
    """True for corroborated / feed_validated — data that may be ranked/trusted."""
    return _TIER_RANK.get(tier or "", 0) >= 1


def tier_label(tier: Optional[str]) -> str:
    """Human-facing label; unconfirmed is explicitly marked unverified."""
    t = tier or ConfidenceTier.UNCONFIRMED.value
    return {
        ConfidenceTier.UNCONFIRMED.value: "unconfirmed (unverified)",
        ConfidenceTier.CORROBORATED.value: "corroborated",
        ConfidenceTier.FEED_VALIDATED.value: "feed-validated",
    }.get(t, "unconfirmed (unverified)")


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

@dataclass
class SharedContentResult:
    served: dict[str, str] = field(default_factory=dict)
    remaining: list = field(default_factory=list)
    hits: int = 0
    skipped_private: bool = False


@dataclass
class SharedReadBundle:
    """Everything the shared tier offered before scraping."""

    served: dict[str, str] = field(default_factory=dict)
    remaining: list = field(default_factory=list)
    served_count: int = 0
    seeds: list[dict] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    skipped_private: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

Reader = Callable[[str], Awaitable[Optional[bytes]]]


def _url_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("link") or item.get("url") or "")
    return str(item or "")


def _serve_ttl() -> timedelta:
    """The freshness window for *serving* cached content — the P3.3 staleness policy.

    A snapshot older than ``FRESHNESS_STALE_AFTER_SECONDS`` (default 24h) is due for
    a freshness re-crawl and must not be served as a fresh cache hit; it falls
    through to a live scrape.
    """
    try:
        import config

        secs = int(getattr(config, "FRESHNESS_STALE_AFTER_SECONDS", 24 * 3600))
    except Exception:
        secs = 24 * 3600
    return timedelta(seconds=secs)


def _onion_url(address: str) -> str:
    addr = (address or "").strip()
    if not addr:
        return ""
    return addr if addr.startswith("http") else f"http://{addr}"


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(query: Optional[str], *, min_len: int = 3, cap: int = 12) -> list[str]:
    if not query:
        return []
    seen: list[str] = []
    for tok in _TOKEN_RE.findall(query.lower()):
        if len(tok) >= min_len and tok not in seen:
            seen.append(tok)
        if len(seen) >= cap:
            break
    return seen


# ---------------------------------------------------------------------------
# 1) Cached content — serve without re-scraping (respecting freshness + liveness)
# ---------------------------------------------------------------------------

async def serve_shared_snapshots(
    session: Session,
    urls: Iterable[Any],
    *,
    now: Optional[datetime] = None,
    ttl: Optional[timedelta] = None,
    reader: Reader = read_snapshot,
) -> SharedContentResult:
    """Serve shared cached content for *urls*, skipping the Tor re-scrape.

    For each URL: take the most-recent ``PageSnapshot``; serve it only if it is
    **fresh** (within the P3.3 staleness window) and its source onion is **alive**
    (never dead/dropped — spec constraint), then read the bytes from the object
    store. Any miss falls through to ``remaining`` for a live scrape. Reads only the
    shared ``page_snapshots`` / ``discovered_onions`` tables. Consent-gated.

    Batched: one query for the snapshots, one for their onions, then concurrent
    object reads — no per-URL DB round-trip.
    """
    items = list(urls)
    if not contribution_enabled():
        return SharedContentResult(served={}, remaining=items, hits=0, skipped_private=True)

    url_pairs = [(_url_of(u), u) for u in items]
    url_strings = [u for u, _ in url_pairs if u]
    if not url_strings:
        return SharedContentResult(served={}, remaining=items, hits=0)

    now = now or datetime.now(timezone.utc)
    ttl = ttl or _serve_ttl()

    snaps = (
        session.execute(
            sa.select(PageSnapshot).where(PageSnapshot.url.in_(set(url_strings)))
        )
        .scalars()
        .all()
    )
    # Latest snapshot per URL.
    latest: dict[str, PageSnapshot] = {}
    for snap in snaps:
        cur = latest.get(snap.url)
        if cur is None or _captured(snap) > _captured(cur):
            latest[snap.url] = snap

    onion_ids = {s.onion_id for s in latest.values() if s.onion_id is not None}
    onions: dict[Any, DiscoveredOnion] = {}
    if onion_ids:
        onions = {
            o.id: o
            for o in session.execute(
                sa.select(DiscoveredOnion).where(DiscoveredOnion.id.in_(onion_ids))
            ).scalars()
        }

    servable: list[tuple[str, str]] = []  # (url, storage_ref)
    for url, snap in latest.items():
        if is_stale(snap, now=now, ttl=ttl):
            continue  # stale → re-scrape, never a stale serve
        if snap.onion_id is not None:
            onion = onions.get(snap.onion_id)
            # Alive only: dead / dropped / unknown liveness never served.
            if onion is None or onion.status != ALIVE:
                continue
        if not snap.storage_ref:
            continue
        servable.append((url, snap.storage_ref))

    served: dict[str, str] = {}
    for url, ref in servable:
        try:
            data = await reader(ref)
        except Exception as exc:  # object-store hiccup → fall through to scrape
            logger.debug("shared read: snapshot read failed for %s (non-fatal): %s", url, exc)
            data = None
        if data:
            served[url] = data.decode("utf-8", "replace")

    remaining = [orig for (u, orig) in url_pairs if u not in served]
    return SharedContentResult(served=served, remaining=remaining, hits=len(served))


def _captured(snap: PageSnapshot) -> datetime:
    ts = snap.captured_at
    if ts is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 2) Known seeds relevant to the query
# ---------------------------------------------------------------------------

def relevant_seeds(
    session: Session, query: Optional[str], *, limit: int = 20
) -> list[dict]:
    """Query-relevant, *alive* discovered onions to add to the scrape queue.

    Excludes dead/dropped onions (P3.3). Matches query tokens against the onion
    address / title / category; with no query, returns the most-recently-seen
    alive onions. Reads only ``discovered_onions``. Consent-gated.
    """
    if not contribution_enabled():
        return []

    stmt = sa.select(DiscoveredOnion).where(
        DiscoveredOnion.status.notin_([DEAD, DROPPED])
    )
    tokens = _tokens(query)
    if tokens:
        conds = []
        for tok in tokens:
            like = f"%{tok}%"
            conds.append(DiscoveredOnion.onion_address.ilike(like))
            conds.append(sa.func.coalesce(DiscoveredOnion.title, "").ilike(like))
            conds.append(sa.func.coalesce(DiscoveredOnion.category, "").ilike(like))
        stmt = stmt.where(sa.or_(*conds))
    stmt = stmt.order_by(DiscoveredOnion.last_seen.desc()).limit(limit)

    rows = session.execute(stmt).scalars().all()
    return [
        {
            "onion_address": r.onion_address,
            "link": _onion_url(r.onion_address),
            "url": _onion_url(r.onion_address),
            "via": "shared_seed",
            "status": r.status,
            "category": r.category,
            "title": r.title,
        }
        for r in rows
        if r.onion_address
    ]


# ---------------------------------------------------------------------------
# 3) Pre-extracted entities relevant to the query — carrying their tier
# ---------------------------------------------------------------------------

def relevant_entities(
    session: Session,
    query: Optional[str],
    *,
    observed_values: Optional[Iterable[str]] = None,
    limit: int = 100,
) -> list[dict]:
    """Query-relevant shared entities, each carrying its ``confidence_tier``.

    Ranked trusted-first (feed_validated > corroborated > unconfirmed, then by
    corroboration count) and tagged with a ``trust_weight`` + ``trusted`` flag so
    consumers respect the tier — ``unconfirmed`` is returned (visible) but
    down-weighted and labeled, never silently trusted. Reads only
    ``global_entities``. Consent-gated.
    """
    if not contribution_enabled():
        return []

    tokens = _tokens(query)
    values = {v.strip() for v in (observed_values or []) if v and v.strip()}
    if not tokens and not values:
        return []

    conds = []
    for tok in tokens:
        like = f"%{tok}%"
        conds.append(GlobalEntity.canonical_value.ilike(like))
        conds.append(sa.func.coalesce(GlobalEntity.display_value, "").ilike(like))
    if values:
        conds.append(GlobalEntity.canonical_value.in_(values))

    rows = (
        session.execute(sa.select(GlobalEntity).where(sa.or_(*conds)).limit(limit * 3))
        .scalars()
        .all()
    )
    rows.sort(
        key=lambda e: (
            _TIER_RANK.get(e.confidence_tier, 0),
            e.corroboration_count or 0,
        ),
        reverse=True,
    )
    out = []
    for e in rows[:limit]:
        out.append(
            {
                "entity_type": e.entity_type,
                "value": e.display_value or e.canonical_value,
                "canonical_value": e.canonical_value,
                "confidence_tier": e.confidence_tier,
                "corroboration_count": e.corroboration_count,
                "trust_weight": tier_weight(e.confidence_tier),
                "trusted": is_trusted_tier(e.confidence_tier),
                "tier_label": tier_label(e.confidence_tier),
                "shared": True,
                "via": "shared_corpus",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Orchestrator — the single pre-scrape shared-read call (API/CLI parity)
# ---------------------------------------------------------------------------

async def read_shared_before_scrape(
    session: Session,
    query: Optional[str],
    urls: Iterable[Any],
    *,
    seed_limit: int = 20,
    entity_limit: int = 100,
    now: Optional[datetime] = None,
    reader: Reader = read_snapshot,
) -> SharedReadBundle:
    """The one call the API and CLI pipelines make before scraping.

    Consent-gated + non-fatal end to end. Serves cached content (skipping the Tor
    re-scrape), and gathers query-relevant seeds and tier-carrying pre-extracted
    entities — all from user-agnostic shared tables only.
    """
    items = list(urls)
    if not contribution_enabled():
        return SharedReadBundle(
            served={}, remaining=items, served_count=0, seeds=[], entities=[],
            skipped_private=True,
        )

    content = await serve_shared_snapshots(session, items, now=now, reader=reader)
    try:
        seeds = relevant_seeds(session, query, limit=seed_limit)
    except Exception as exc:
        logger.debug("shared read: seed lookup failed (non-fatal): %s", exc)
        seeds = []
    try:
        entities = relevant_entities(session, query, limit=entity_limit)
    except Exception as exc:
        logger.debug("shared read: entity lookup failed (non-fatal): %s", exc)
        entities = []

    return SharedReadBundle(
        served=content.served,
        remaining=content.remaining,
        served_count=content.hits,
        seeds=seeds,
        entities=entities,
        skipped_private=False,
    )
