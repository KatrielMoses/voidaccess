"""
owned_index — the P3.0 owned, self-refreshing, semantically-ranked index.

The differentiator epic (requirement 1.3 / 1.8): today search depends entirely on
third-party onion engines, so when they die coverage dies. This module stands up
an *owned* keyword + semantic index over sanitized page snapshots, on
Meilisearch, that survives any external engine's death. P3.0 is the index and its
primitives (schema, upsert/read/hybrid-search, dedup, the sanitized-only
invariant, graceful no-op); population (P3.1), search-path wiring (P3.2) and the
freshness loop (P3.3) build on top.

It is a central-service / shared-tier component: it lives on the Oracle box
alongside the shared corpus. A local/$0 install or a private-mode install that
does not configure Meilisearch simply falls back to live fan-out — the index
no-ops cleanly and the tool never crashes.

Reuse, not reinvention:

* embeddings come from the existing ``vector`` layer (MiniLM + SHA-256 fallback),
  fed to Meilisearch as user-provided vectors — no new embedding service;
* content is sanitized by the single shared ``sanitizer`` gate before it can be
  indexed — raw creds/PII can never enter the index (the legal invariant);
* ``content_hash`` (P2.0/P2.1) is the Meili primary key, so dedup is automatic;
* a hit resolves back to its R2 snapshot through the existing
  ``snapshot_store.read_snapshot``.

See ``owned_index/README.md``.
"""

from owned_index.client import MeiliClient, MeiliConfig, MeiliError
from owned_index.index import (
    DEFAULT_SEARCH_LIMIT,
    DEFAULT_SEMANTIC_RATIO,
    OwnedIndex,
    SearchHit,
    ensure_index,
    index_snapshot,
    read_hit_content,
    search_index,
)
from owned_index.schema import (
    EMBEDDER_NAME,
    EMBEDDING_DIMENSIONS,
    FILTERABLE_ATTRIBUTES,
    PRIMARY_KEY,
    SEARCHABLE_ATTRIBUTES,
    SORTABLE_ATTRIBUTES,
    build_document,
    document_from_snapshot,
)

__all__ = [
    "MeiliClient",
    "MeiliConfig",
    "MeiliError",
    "OwnedIndex",
    "SearchHit",
    "DEFAULT_SEARCH_LIMIT",
    "DEFAULT_SEMANTIC_RATIO",
    "ensure_index",
    "index_snapshot",
    "search_index",
    "read_hit_content",
    "build_document",
    "document_from_snapshot",
    "PRIMARY_KEY",
    "SEARCHABLE_ATTRIBUTES",
    "FILTERABLE_ATTRIBUTES",
    "SORTABLE_ATTRIBUTES",
    "EMBEDDER_NAME",
    "EMBEDDING_DIMENSIONS",
]
