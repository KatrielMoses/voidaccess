"""
ingest/service.py — turn an authenticated ingest payload into gate-promoted data.

The single job here is to build ``EntityObservation``s from the submitted artifacts
and hand them to the **one and only write path** — P4.1's ``promote_entities`` (the
full P4.0 eight-step gate). The ingest endpoint is just another producer; there is
no second write path (grep-provable: this module never calls ``upsert_global_entity``
or touches ``global_entities`` directly).

Two things the ingest boundary enforces here:

* **Contributor vs origin (the Sybil split).** Every observation's ``contributor``
  is the authenticated ``key_id`` (the reputation/rate unit); its ``origin`` is the
  onion/host the submitter claims to have observed it on (the corroboration unit).
  A fresh key is low-rep, so its claimed origins don't count — a thousand keys or a
  thousand fabricated origins promote nothing.
* **Server-side feed_hits.** Any submitter-supplied ``feed_hits`` are **discarded**;
  they are re-derived from the platform's own ``feeds/`` matching, so a forged feed
  hit can never yield ``feed_validated``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Sequence

from shared_corpus.promote import EntityObservation, PromotionReport, promote_entities
from trust_gate import TrustGateConfig

FeedMatcher = Callable[[list[dict]], Awaitable[dict]]


async def _default_feed_matcher(entities: list[dict]) -> dict:
    from feeds import derive_feed_hits

    return await derive_feed_hits(entities)


async def promote_ingest(
    session: Any,
    key_id: str,
    artifacts: Sequence[dict],
    *,
    config: Optional[TrustGateConfig] = None,
    feed_matcher: Optional[FeedMatcher] = None,
    now: Optional[datetime] = None,
) -> PromotionReport:
    """Promote an authenticated key's submitted *artifacts* through the trust gate.

    *artifacts* is a list of ``{entity_type, value, origin, disposition?}`` dicts —
    any ``feed_hits`` on them are ignored. Returns the P4.1 ``PromotionReport``.
    """
    now = now or datetime.now(timezone.utc)
    matcher = feed_matcher or _default_feed_matcher

    # Re-derive feed_hits server-side from the platform's own feeds (never trust
    # submitter-supplied values).
    match_input = [{"entity_type": a.get("entity_type"), "value": a.get("value")} for a in artifacts]
    try:
        feed_hits_map = await matcher(match_input)
    except Exception:
        feed_hits_map = {}

    observations = []
    for a in artifacts:
        etype = a.get("entity_type")
        value = a.get("value")
        if not etype or not value:
            continue
        observations.append(
            EntityObservation(
                entity_type=etype,
                value=value,
                origin=(a.get("origin") or "unknown"),
                contributor=key_id,  # the authenticated contributor — the rep unit
                feed_hits=feed_hits_map.get((str(etype).upper(), value), frozenset()),
                disposition=a.get("disposition"),
                observed_at=now,
            )
        )

    return promote_entities(session, observations, config=config, now=now)
