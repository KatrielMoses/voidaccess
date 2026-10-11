"""
freshness/recrawl.py — the re-crawl worker job (P3.3 / requirement 1.6).

Given one previously-seen onion, re-fetch it over Tor via the existing scrape
path and update the shared corpus:

* **Liveness.** Update ``DiscoveredOnion.status`` (alive/dead) + ``last_seen``.
  The dead→drop policy: ``consecutive_dead`` counts consecutive dead re-crawls
  (reset on any live one); at ``FRESHNESS_DEAD_DROP_THRESHOLD`` the onion is marked
  ``dropped`` — it stops surfacing in retrieval and stops being re-crawled.
* **Content change.** Sanitize the fetched text once; hash-compare against the
  stored snapshot's ``content_hash``. Unchanged → stop. Changed → store a new
  sanitized snapshot + re-index by reusing the P3.1 ``index_sanitized_page`` path
  (so the single-NER-pass + provenance + dedup all apply — nothing rebuilt).
* **Diff → monitor.** On a significant change, feed a diff (via ``monitor/diff.py``)
  to the existing monitor/alert subsystem (``evaluate_and_dispatch_alerts``).

Everything is consent-gated and a graceful no-op when the index/store is
unconfigured. Never raises into the worker loop — the queue handles retries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from monitor.diff import compute_diff, is_significant_change
from owned_index import OwnedIndex
from sanitizer import sanitize_page
from shared_corpus import DiscoveredOnion, PageSnapshot, contribution_enabled
from snapshot_store import content_hash, read_snapshot
from index_population import index_sanitized_page

logger = logging.getLogger(__name__)

_UNSET: Any = object()

# Liveness values excluded from active retrieval / re-crawl scheduling.
DEAD = "dead"
DROPPED = "dropped"
ALIVE = "alive"


@dataclass
class RecrawlOutcome:
    status: str = "skipped"
    changed: bool = False
    indexed: bool = False
    alerted: bool = False


def _dead_drop_threshold() -> int:
    import config

    return int(getattr(config, "FRESHNESS_DEAD_DROP_THRESHOLD", 3) or 3)


def _url_for(onion: DiscoveredOnion, session: Any) -> str:
    """Best URL to re-fetch: the most recent snapshot's URL, else ``http://<addr>/``."""
    latest = (
        session.query(PageSnapshot)
        .filter(PageSnapshot.onion_id == onion.id)
        .order_by(PageSnapshot.captured_at.desc())
        .first()
    )
    if latest is not None and latest.url:
        return latest.url
    return f"http://{onion.onion_address}/"


async def _default_fetch(url: str) -> str:
    """Fetch one onion's current text over Tor via the existing scrape path."""
    from scraper import scrape

    scraped = await scrape.scrape_multiple([{"link": url, "title": ""}], max_workers=1)
    return scraped.get(url, "") or ""


async def _feed_monitor(url: str, onion: DiscoveredOnion, diff: dict) -> bool:
    """Feed a significant content diff to the existing monitor/alert subsystem."""
    try:
        from monitor.alerts import evaluate_and_dispatch_alerts

        watch = {"name": f"freshness:{onion.onion_address}", "url": url}
        job_result = {
            "name": watch["name"],
            "url": url,
            "changed": True,
            "change_ratio": diff.get("change_ratio", 0.0),
            "lines_added": diff.get("lines_added", 0),
            "lines_removed": diff.get("lines_removed", 0),
            "diff_summary": diff.get("diff_summary", ""),
            "new_entities": 0,
            "is_first_scrape": False,
        }
        await evaluate_and_dispatch_alerts(watch, job_result)
        return True
    except Exception as exc:  # monitor delivery must never fail the re-crawl
        logger.debug("freshness monitor feed failed for %s (non-fatal): %s", url, exc)
        return False


async def recrawl_onion(
    session: Any,
    onion_address: str,
    *,
    fetch: Optional[Callable[[str], Awaitable[str]]] = None,
    index: Any = _UNSET,
    now: Optional[datetime] = None,
) -> RecrawlOutcome:
    """Re-crawl one onion: refresh liveness, and re-index + alert on change.

    ``fetch`` (async ``url -> text``) and ``index`` are injectable for tests;
    they default to the real Tor scrape path and ``OwnedIndex.from_config()``.
    """
    if not contribution_enabled():
        return RecrawlOutcome(status="skipped")

    onion = (
        session.query(DiscoveredOnion)
        .filter(DiscoveredOnion.onion_address == onion_address)
        .one_or_none()
    )
    if onion is None or onion.status == DROPPED:
        return RecrawlOutcome(status=(onion.status if onion else "missing"))

    now = now or datetime.now(timezone.utc)
    fetch = fetch or _default_fetch
    url = _url_for(onion, session)

    try:
        text = await fetch(url)
    except Exception as exc:
        logger.debug("freshness fetch failed for %s (non-fatal): %s", url, exc)
        text = ""

    # --- Dead: no content came back ---------------------------------------
    if not (text and text.strip()):
        onion.consecutive_dead = (onion.consecutive_dead or 0) + 1
        onion.status = DROPPED if onion.consecutive_dead >= _dead_drop_threshold() else DEAD
        onion.last_seen = now
        session.flush()
        return RecrawlOutcome(status=onion.status, changed=False)

    # --- Alive ------------------------------------------------------------
    onion.status = ALIVE
    onion.consecutive_dead = 0
    onion.last_seen = now

    sanitized = sanitize_page(text)
    if not sanitized:
        session.flush()
        return RecrawlOutcome(status=ALIVE, changed=False)

    new_hash = content_hash(sanitized.encode("utf-8"))
    latest = (
        session.query(PageSnapshot)
        .filter(PageSnapshot.onion_id == onion.id)
        .order_by(PageSnapshot.captured_at.desc())
        .first()
    )
    changed = latest is None or latest.content_hash != new_hash
    if not changed:
        session.flush()
        return RecrawlOutcome(status=ALIVE, changed=False)

    # Read the previous sanitized content for the diff (empty on first capture).
    old_text = ""
    if latest is not None and latest.storage_ref:
        old_bytes = await read_snapshot(latest.storage_ref)
        if old_bytes:
            old_text = old_bytes.decode("utf-8", "ignore")

    if index is _UNSET:
        index = OwnedIndex.from_config()

    # Re-index via the P3.1 path (single NER pass already spent on `sanitized`).
    _snap, indexed = await index_sanitized_page(
        session,
        url,
        sanitized,
        index=index,
        onion=onion,
        title=onion.title,
        language=onion.language,
        category=onion.category,
        liveness=ALIVE,
        now=now,
    )

    # Feed a significant diff to the monitor subsystem.
    alerted = False
    diff = compute_diff(old_text, sanitized)
    if is_significant_change(diff):
        alerted = await _feed_monitor(url, onion, diff)

    session.flush()
    return RecrawlOutcome(status=ALIVE, changed=True, indexed=indexed, alerted=alerted)


async def recrawl_handler(payload: dict) -> None:
    """Durable-queue handler for a single re-crawl job."""
    import os

    if not os.getenv("DATABASE_URL"):
        return
    onion_address = (payload or {}).get("onion_address")
    if not onion_address:
        return
    from db.session import get_session

    with get_session() as session:
        await recrawl_onion(session, onion_address)
        session.commit()
