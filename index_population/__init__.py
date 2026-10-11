"""
index_population — P3.1: fill the owned index from two sources (requirement 1.4).

P3.0 built an empty index; P3.1 populates it, from:

* **Curated seeds** (``index_population.seeds``) — Ahmia's known-onion list +
  dark.fail, ingested *as data* (not by crawling). Breadth: a brand-new query
  still gets owned-index results.
* **Usage-seeding** (``index_population.usage``) — every ``.onion`` page this
  instance's own investigations touch, via the existing scrape path. Depth:
  indexing volume scales with usage, not with the size of Tor (no exhaustive
  crawl).

Both write sanitized, consent-gated, provenance-stamped artifacts to the shared
tier (``discovered_onions``, ``page_snapshots``, owned-index docs) at the
**unconfirmed** confidence tier only. Neither promotes ``global_entities`` nor
assigns trust tiers — that is P4.

The requirement-1.2 ahmia-crawler adopt/skip evaluation lives in
``index_population/README.md``.
"""

from index_population.seeds import (
    SeedEntry,
    SeedIngestReport,
    ingest_seed_sources,
    parse_ahmia,
    parse_darkfail,
)
from index_population.usage import (
    UsageIngestReport,
    index_investigation_pages,
    index_sanitized_page,
)

__all__ = [
    "SeedEntry",
    "SeedIngestReport",
    "ingest_seed_sources",
    "parse_ahmia",
    "parse_darkfail",
    "UsageIngestReport",
    "index_investigation_pages",
    "index_sanitized_page",
]
