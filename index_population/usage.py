"""
index_population/usage.py — usage-seeded auto-indexing (requirement 1.4).

Every ``.onion`` page an investigation on *this* instance actually touches flows
— via the existing scrape path, not a parallel fetcher — into the shared corpus:
the ``discovered_onions`` registry (P2.0), the page-snapshot store (P2.1), and
the owned index (P3.0). This is the *depth/relevance* half of population; the
breadth half is ``index_population.seeds``.

Bounded by construction — "no exhaustive crawl"
-----------------------------------------------
This module never fetches anything. It is handed the pages the pipeline already
scraped and indexes exactly those. Indexing volume therefore scales with usage
(the onions investigations visit), not with the size of Tor — the 1.4 acceptance.

The legal + tier invariants (non-negotiable)
--------------------------------------------
* **Consent gate.** If ``contribution_enabled()`` is false (private mode), this
  no-ops entirely — nothing reaches the shared tier. Checked once up front, and
  again inside ``store_snapshot``.
* **Single sanitization gate.** Each page's content is run through
  ``sanitizer.sanitize_page`` exactly once here; the same sanitized text is fed
  to both the snapshot store and the index (``presanitized=True``), so there is
  no double NER pass and no path by which raw creds/PII reach the shared tier.
* **Provenance stamp** on every ``discovered_onions`` row.
* **Unconfirmed tier only.** Writes go to ``discovered_onions`` / ``page_snapshots``
  / owned-index docs — none of which carry a trust tier. This module never calls
  ``upsert_global_entity`` and never assigns a confidence tier: entity promotion
  and trust scoring are P4.
* **Graceful no-op.** With the snapshot store and/or index unconfigured, those
  writes simply no-op; the pipeline (API + CLI) is unaffected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from sanitizer import provenance_stamp, sanitize_page
from shared_corpus import contribution_enabled, record_discovered_onion
from snapshot_store import content_hash, store_snapshot
from owned_index import OwnedIndex

logger = logging.getLogger(__name__)

#: Provenance class for onions discovered by this instance's own investigations
#: (contrast ``"seed"`` for the curated seed lists). See ``DiscoveredOnion``.
DISCOVERY_SOURCE = "investigation"

#: Sentinel so callers can pass ``index=None`` (force no index) distinctly from
#: "not provided" (resolve from config). Tests inject a fake index this way.
_UNSET: Any = object()


@dataclass
class UsageIngestReport:
    """What a usage-seeding pass wrote (for logging / the pipeline report)."""

    considered: int = 0
    onions: int = 0
    snapshots: int = 0
    indexed: int = 0
    skipped_private: bool = False


def _onion_host(url: Optional[str]) -> Optional[str]:
    """Return the ``.onion`` host for *url*, or ``None`` for non-onion/empty.

    Usage-seeding targets onions only; clearnet side-sources (paste sites,
    GitHub, RSS) are not part of the onion corpus and are skipped here.
    """
    if not url:
        return None
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return None
    return host if host.endswith(".onion") else None


async def index_investigation_pages(
    session: Any,
    pages: Iterable[dict],
    *,
    index: Any = _UNSET,
) -> UsageIngestReport:
    """Auto-index the ``.onion`` pages an investigation touched.

    *pages* is the pipeline's finalized, content-safety-scanned page list — dicts
    with at least ``url`` and ``content``/``text``. For each onion page: record
    the discovered onion, store a sanitized snapshot (P2.1), and upsert an owned-
    index document (P3.0), all sanitized once and provenance-stamped at the
    unconfirmed tier. Never raises into the pipeline — per-page failures are
    swallowed (CC-3). The caller owns the transaction (commit after).
    """
    report = UsageIngestReport()

    if not contribution_enabled():
        report.skipped_private = True
        return report  # private mode: nothing reaches the shared tier

    if index is _UNSET:
        index = OwnedIndex.from_config()  # None when Meilisearch is unconfigured

    now = datetime.now(timezone.utc)

    for page in pages:
        report.considered += 1
        url = page.get("url") or page.get("link")
        raw = page.get("content") or page.get("text") or ""
        host = _onion_host(url)
        if not host or not raw or not raw.strip():
            continue

        try:
            # THE single gate, applied once; reused for both stores below.
            sanitized = sanitize_page(raw)
            if not sanitized:
                continue  # dropped by the sanitizer (content-safety / fail-closed)

            language = page.get("language")
            stamp = provenance_stamp(source=host)

            # 1) Shared onion registry (unconfirmed; alive — we just scraped it).
            onion, created = record_discovered_onion(
                session,
                host,
                discovery_source=DISCOVERY_SOURCE,
                status="alive",
                language=language,
                provenance=stamp,
            )
            if created:
                report.onions += 1

            # 2) Page snapshot (P2.1) — presanitized so the gate runs only once.
            snap = await store_snapshot(
                session,
                url,
                raw,
                presanitized=sanitized,
                onion_id=onion.id,
                language=language,
                source=host,
            )
            if snap is not None:
                report.snapshots += 1

            # 3) Owned index (P3.0) — content-hash dedup; ref ties back to R2.
            if index is not None:
                digest = (
                    snap.content_hash
                    if snap is not None
                    else content_hash(sanitized.encode("utf-8"))
                )
                ok = await index.upsert_document(
                    content_hash=digest,
                    url=url,
                    content=sanitized,
                    presanitized=True,
                    content_snapshot_ref=(snap.storage_ref if snap is not None else None),
                    title=page.get("title"),
                    liveness="alive",
                    language=language,
                    category=page.get("category"),
                    first_seen=now,
                    last_seen=now,
                )
                if ok:
                    report.indexed += 1
        except Exception as exc:  # never let population break the pipeline (CC-3)
            logger.debug("usage-seeding failed for %s (non-fatal): %s", url, exc)

    return report


async def index_sanitized_page(
    session: Any,
    url: str,
    sanitized: str,
    *,
    index: Any,
    onion: Any = None,
    title: Optional[str] = None,
    language: Optional[str] = None,
    category: Optional[str] = None,
    liveness: Optional[str] = "alive",
    now: Optional[datetime] = None,
) -> tuple[Any, bool]:
    """Store + index content that has *already* been through ``sanitize_page``.

    The re-index primitive the P3.3 freshness loop reuses so a re-crawl runs the
    sanitizer exactly once (in the worker) and feeds the same text to both the
    snapshot store and the owned index via ``presanitized=`` — no second NER pass,
    no reimplemented store/index/provenance logic. Unlike
    ``index_investigation_pages`` this does not touch ``discovered_onions``: the
    caller owns the onion row and its liveness. Consent-gated; returns
    ``(snapshot_or_None, indexed_bool)``.
    """
    if not contribution_enabled() or not sanitized:
        return None, False

    now = now or datetime.now(timezone.utc)
    source = _onion_host(url) or url

    snap = await store_snapshot(
        session,
        url,
        sanitized,
        presanitized=sanitized,
        onion_id=getattr(onion, "id", None),
        language=language,
        source=source,
    )

    indexed = False
    if index is not None:
        digest = snap.content_hash if snap is not None else content_hash(sanitized.encode("utf-8"))
        indexed = await index.upsert_document(
            content_hash=digest,
            url=url,
            content=sanitized,
            presanitized=True,
            content_snapshot_ref=(snap.storage_ref if snap is not None else None),
            title=title,
            liveness=liveness,
            language=language,
            category=category,
            first_seen=now,
            last_seen=now,
        )
    return snap, indexed
