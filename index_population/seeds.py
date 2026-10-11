"""
index_population/seeds.py — curated seed ingestion (requirements 1.4 breadth, 5.4).

Pulls two clearnet-published onion directories **as data** (not by crawling) and
normalizes them into the shared corpus, so a brand-new query still surfaces
owned-index results before this instance has investigated anything:

* **Ahmia known-onion list** (``https://ahmia.fi/onions/``) — a plain-text list
  of ``.onion`` URLs. Breadth: which onions exist. No titles/categories.
* **dark.fail** (``https://dark.fail/``) — a curated, categorized HTML directory
  of named services. Depth: titles + categories for searchable bootstrap docs.

Why "as data", not the ahmia-crawler
------------------------------------
See ``index_population/README.md`` for the requirement-1.2 adopt/skip evaluation.
Short version: we ingest Ahmia's highest-value *asset* — the known-onion list —
rather than standing up its continuous Scrapy stack on the $0 box. Broad
discovery, if ever wanted, extends through here + the P3.3 freshness loop.

Reuse
-----
Fetching reuses ``sources.cache.CachedFeed`` (the feeds/ fetch+TTL+clearnet-guard
primitive) with ``parse="text"``. ``CachedFeed`` physically cannot fetch a
``.onion`` (it goes through the clearnet-only ``http_pool``), which keeps this
ingester honest: it consumes the clearnet-published *list*, never crawls onions.
Liveness of the listed onions stays ``unknown`` until a later Tor probe / crawl
(P3.3) promotes it — a list membership is not proof of life.

Invariants
----------
Seeds are shared-tier writes, so the same rules as usage-seeding apply: gated on
``contribution_enabled()`` (private mode ingests nothing), provenance-stamped,
written at the unconfirmed tier (``discovered_onions`` + owned-index docs, never
``global_entities``), and a graceful no-op when the index is unconfigured.

Bootstrap index docs
---------------------
A seed has no page snapshot yet, so its index document is a *placeholder*: keyed
by a synthetic per-onion id (not a content hash), ``liveness="unknown"``, no
``content_snapshot_ref``, and searchable text built from the title/category (or
the onion address as a fallback). When the onion is later actually scraped
(usage-seeding / freshness), a real content-hash-keyed page document is added
alongside it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sanitizer import provenance_stamp
from shared_corpus import contribution_enabled, record_discovered_onion
from sources.cache import CachedFeed
from owned_index import OwnedIndex

logger = logging.getLogger(__name__)

# --- sources -----------------------------------------------------------------

AHMIA_ONIONS_URL = "https://ahmia.fi/onions/"
DARKFAIL_URL = "https://dark.fail/"

# `normal` refresh cadences (seconds). Seed lists change slowly; a stale list is
# harmless (it only affects breadth), so long TTLs keep the $0 box quiet.
AHMIA_TTL = 24 * 3600
DARKFAIL_TTL = 12 * 3600

_AHMIA_CACHE = os.path.join(tempfile.gettempdir(), "voidaccess_ahmia_onions.txt")
_DARKFAIL_CACHE = os.path.join(tempfile.gettempdir(), "voidaccess_darkfail.html")

# Attribution / licensing, mirroring the feeds/ LICENSES provenance registry.
_LICENSES: dict[str, dict[str, str]] = {
    "ahmia": {
        "license": "public-list",
        "attribution": "Ahmia (ahmia.fi) known-onion list",
        "url": AHMIA_ONIONS_URL,
    },
    "dark.fail": {
        "license": "public-list",
        "attribution": "dark.fail verified onion directory",
        "url": DARKFAIL_URL,
    },
}

# v3 (56) and legacy v2 (16) onion hosts.
_ONION_RE = re.compile(r"\b((?:[a-z2-7]{56}|[a-z2-7]{16})\.onion)\b", re.IGNORECASE)

# Status/verification noise stripped from dark.fail entry titles.
_TITLE_NOISE = ("online", "offline", "verified", "official", "status")


@dataclass(frozen=True)
class SeedEntry:
    onion_address: str
    url: str
    title: Optional[str] = None
    category: Optional[str] = None
    language: Optional[str] = None


@dataclass
class SeedIngestReport:
    considered: int = 0
    onions: int = 0
    indexed: int = 0
    skipped_private: bool = False


def _seed_doc_id(onion_address: str) -> str:
    """Stable synthetic index id for a seed placeholder (no content hash yet).

    Deterministic per onion so re-ingesting the same seed replaces its
    placeholder rather than duplicating it (Meili dedup by primary key).
    """
    return hashlib.sha256(f"seed:{onion_address.lower()}".encode("utf-8")).hexdigest()


def _license_extra(source: str) -> Optional[dict[str, str]]:
    return dict(_LICENSES[source]) if source in _LICENSES else None


# --- parsers (pure; unit-tested against canned fixtures) ---------------------

def parse_ahmia(text: str) -> list[SeedEntry]:
    """Parse Ahmia's plain-text onion list into de-duplicated seed entries."""
    seen: dict[str, SeedEntry] = {}
    for match in _ONION_RE.finditer(text or ""):
        addr = match.group(1).lower()
        if addr not in seen:
            seen[addr] = SeedEntry(onion_address=addr, url=f"http://{addr}/")
    return list(seen.values())


def parse_darkfail(html: str) -> list[SeedEntry]:
    """Best-effort parse of dark.fail's categorized HTML directory.

    dark.fail publishes no machine-readable list, so this scrapes the rendered
    structure: heading tags establish the current category; a leaf element whose
    short text contains an onion address is one entry, its remaining text the
    title. Robust to markup drift by degrading (fewer entries), never crashing.
    """
    if not html:
        return []
    try:
        from bs4 import BeautifulSoup
    except Exception:  # bs4 unavailable — degrade to address-only extraction
        return parse_ahmia(html)

    soup = BeautifulSoup(html, "html.parser")
    results: dict[str, SeedEntry] = {}
    current_category: Optional[str] = None

    for el in soup.find_all(True):
        name = getattr(el, "name", "") or ""
        if name in ("h1", "h2", "h3", "h4", "h5"):
            heading = el.get_text(" ", strip=True)
            if heading:
                current_category = heading
            continue

        text = el.get_text(" ", strip=True)
        if not text or len(text) > 2000:
            continue
        # An entry node contains exactly ONE onion address; a section/body
        # wrapping several entries contains many and is skipped. This picks the
        # entry container (title + address together) over both the page body and
        # the bare address span.
        matches = _ONION_RE.findall(text)
        if len(matches) != 1:
            continue
        addr = matches[0].lower()
        if addr in results:
            continue

        title = re.sub(re.escape(matches[0]), "", text, flags=re.IGNORECASE)
        for junk in _TITLE_NOISE:
            title = re.sub(junk, "", title, flags=re.IGNORECASE)
        title = title.strip(" -–—|:•\t\n") or None

        results[addr] = SeedEntry(
            onion_address=addr,
            url=f"http://{addr}/",
            title=title,
            category=current_category,
        )
    return list(results.values())


# --- fetchers (seams; monkeypatched in tests) --------------------------------

async def _fetch_ahmia() -> Optional[str]:
    return await CachedFeed(AHMIA_ONIONS_URL, _AHMIA_CACHE, AHMIA_TTL, parse="text").fetch()


async def _fetch_darkfail() -> Optional[str]:
    return await CachedFeed(DARKFAIL_URL, _DARKFAIL_CACHE, DARKFAIL_TTL, parse="text").fetch()


# --- orchestrator ------------------------------------------------------------

async def ingest_seed_sources(
    session: Any,
    *,
    index: Any = None,
    sources: tuple[str, ...] = ("ahmia", "dark.fail"),
    _resolve_index: bool = True,
) -> SeedIngestReport:
    """Ingest the seed directories into ``discovered_onions`` + owned-index docs.

    Fetches each source once (clearnet, TTL-cached), normalizes to seed entries,
    and writes each onion at the unconfirmed tier with a provenance stamp. Returns
    a report. Private mode / consent-off ingests nothing. The caller owns the
    transaction (commit after). Never raises — per-entry failures are swallowed.
    """
    report = SeedIngestReport()

    if not contribution_enabled():
        report.skipped_private = True
        return report

    if index is None and _resolve_index:
        index = OwnedIndex.from_config()  # None when Meilisearch is unconfigured

    collected: list[tuple[SeedEntry, str]] = []
    if "ahmia" in sources:
        try:
            text = await _fetch_ahmia()
            if text:
                collected += [(e, "ahmia") for e in parse_ahmia(text)]
        except Exception as exc:
            logger.debug("Ahmia seed fetch failed (non-fatal): %s", exc)
    if "dark.fail" in sources:
        try:
            html = await _fetch_darkfail()
            if html:
                collected += [(e, "dark.fail") for e in parse_darkfail(html)]
        except Exception as exc:
            logger.debug("dark.fail seed fetch failed (non-fatal): %s", exc)

    now = datetime.now(timezone.utc)

    for entry, src in collected:
        report.considered += 1
        try:
            stamp = provenance_stamp(source=src, extra=_license_extra(src))
            _onion, created = record_discovered_onion(
                session,
                entry.onion_address,
                discovery_source="seed",
                status="unknown",  # liveness unverified until crawled
                title=entry.title,
                category=entry.category,
                language=entry.language,
                provenance=stamp,
            )
            if created:
                report.onions += 1

            if index is not None:
                descriptor = " ".join(
                    p for p in (entry.title, entry.category) if p
                ) or entry.onion_address
                ok = await index.upsert_document(
                    content_hash=_seed_doc_id(entry.onion_address),
                    url=entry.url,
                    content=descriptor,
                    title=entry.title,
                    liveness="unknown",
                    language=entry.language,
                    category=entry.category,
                    content_snapshot_ref=None,
                    first_seen=now,
                    last_seen=now,
                )
                if ok:
                    report.indexed += 1
        except Exception as exc:
            logger.debug("seed ingest failed for %s (non-fatal): %s", entry.onion_address, exc)

    return report
