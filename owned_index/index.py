"""
owned_index/index.py — the high-level owned-index surface.

``OwnedIndex`` wraps a ``MeiliClient`` and owns the write/read/search primitives
the rest of VoidAccess uses:

* ``upsert_document`` / ``upsert_snapshot`` — build a sanitized document (dedup
  by ``content_hash``) and add it to the index.
* ``get`` — read one document back by content hash.
* ``search`` — a hybrid (keyword + semantic) query returning ranked hits.

Vectors are **user-provided from the existing embedder**: ``OwnedIndex`` calls
``vector.embed_text`` (MiniLM, with the SHA-256 fallback) to embed both indexed
documents and the query. No new embedding service or dependency is introduced —
grep for ``embed_text`` shows the single reuse point is right here.

Unconfigured = graceful no-op
-----------------------------
``OwnedIndex.from_config()`` returns ``None`` when Meilisearch is not configured.
The module-level helpers (``index_snapshot`` / ``search_index`` / ``ensure_index``)
fold that check in: with no index, ``search_index`` returns ``[]`` and the caller
falls back to live fan-out — the CLI/$0-local path and private-mode installs run
unaffected, never crashing.

Resolving a hit back to its R2 snapshot
---------------------------------------
A hit carries ``content_snapshot_ref``; ``read_hit_content`` resolves it via the
existing ``snapshot_store.read_snapshot`` (which already accepts a ref or a bare
content hash) — no duplicate ref→content lookup is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from vector import embed_text  # the ONE embedding reuse point (no new service)

from owned_index import schema
from owned_index.client import MeiliClient

# Default hybrid mix: half keyword, half semantic. 0.0 = pure keyword, 1.0 = pure
# semantic. Sets up requirement 1.7 (semantic ranking) without hardcoding it into
# callers, which can override per-query.
DEFAULT_SEMANTIC_RATIO = 0.5
DEFAULT_SEARCH_LIMIT = 20


#: Max characters of snapshot text carried back on a hit as a ranking snippet.
_SNIPPET_MAX = 1000


@dataclass
class SearchHit:
    """One ranked search result, projected to the 1.3 schema fields + score."""

    content_hash: str
    url: Optional[str] = None
    title: Optional[str] = None
    content_snapshot_ref: Optional[str] = None
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    liveness: Optional[str] = None
    language: Optional[str] = None
    category: Optional[str] = None
    score: Optional[float] = None
    # A query-centered excerpt of the sanitized snapshot text, carried so downstream
    # consumers (e.g. P3.2 semantic ranking) have text to embed without a second
    # round-trip to R2. Truncated to keep hit payloads small.
    snippet: Optional[str] = None

    @classmethod
    def from_meili_hit(cls, hit: dict[str, Any]) -> "SearchHit":
        return cls(
            content_hash=hit.get("content_hash"),
            url=hit.get("url"),
            title=hit.get("title"),
            content_snapshot_ref=hit.get("content_snapshot_ref"),
            first_seen=hit.get("first_seen"),
            last_seen=hit.get("last_seen"),
            liveness=hit.get("liveness"),
            language=hit.get("language"),
            category=hit.get("category"),
            # Meili exposes the ranking score as ``_rankingScore`` when requested.
            score=hit.get("_rankingScore"),
            snippet=((hit.get("_formatted") or {}).get("content") or hit.get("content") or "")[:_SNIPPET_MAX] or None,
        )


def _build_filter(filters: Union[str, dict, None]) -> Optional[str]:
    """Turn a filter spec into a Meilisearch filter string.

    A raw string passes through (advanced use). A dict is treated as equality on
    the filterable attributes: string values are quoted, numbers are not, and a
    list/tuple value becomes an ``IN [...]`` set. Clauses are AND-joined.
    """
    if filters is None:
        return None
    if isinstance(filters, str):
        return filters or None

    clauses: list[str] = []
    for key, value in filters.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            rendered = ", ".join(_render_scalar(v) for v in value)
            clauses.append(f"{key} IN [{rendered}]")
        else:
            clauses.append(f"{key} = {_render_scalar(value)}")
    return " AND ".join(clauses) if clauses else None


def _render_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace('"', '\\"')
    return f'"{escaped}"'


class OwnedIndex:
    """Write/read/search over the owned Meilisearch index."""

    def __init__(
        self,
        client: MeiliClient,
        *,
        embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
    ):
        self._client = client
        # Injected for tests; defaults to the shared MiniLM embedder. This is the
        # only place a query/document embedding is produced for the index.
        self._embedder = embedder or embed_text

    @classmethod
    def from_config(
        cls,
        *,
        embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
    ) -> Optional["OwnedIndex"]:
        """Return an index handle, or ``None`` when Meilisearch is not configured."""
        client = MeiliClient.from_config()
        return cls(client, embedder=embedder) if client is not None else None

    @property
    def client(self) -> MeiliClient:
        return self._client

    async def ensure_ready(self) -> None:
        """Provision the index + schema settings (idempotent)."""
        await self._client.ensure_index()

    # -- writes ------------------------------------------------------------

    async def upsert_document(self, **fields: Any) -> bool:
        """Build (sanitize + embed) and upsert one document. False if dropped.

        Pass ``presanitized=True`` when ``content`` is already the output of
        ``sanitizer.sanitize_page`` (the usage-seeding path), to skip a redundant
        second sanitization pass — see ``schema.build_document``.
        """
        doc = schema.build_document(embedder=self._embedder, **fields)
        if doc is None:
            return False
        await self._client.add_documents([doc])
        return True

    async def upsert_snapshot(
        self, snapshot: Any, content: str, *, onion: Any = None, presanitized: bool = False
    ) -> bool:
        """Upsert a ``PageSnapshot`` (+ its onion) as a document. False if dropped."""
        doc = schema.document_from_snapshot(
            snapshot, content, onion=onion, embedder=self._embedder, presanitized=presanitized
        )
        if doc is None:
            return False
        await self._client.add_documents([doc])
        return True

    # -- reads -------------------------------------------------------------

    async def get(self, content_hash: str) -> Optional[SearchHit]:
        raw = await self._client.get_document(content_hash)
        return SearchHit.from_meili_hit(raw) if raw is not None else None

    async def search(
        self,
        query: str,
        *,
        filters: Union[str, dict, None] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        semantic_ratio: float = DEFAULT_SEMANTIC_RATIO,
        keyword_only: bool = False,
    ) -> list[SearchHit]:
        """Hybrid keyword+semantic search, returning ranked hits.

        The query is embedded with the same MiniLM embedder used for documents
        and supplied as a user-provided vector alongside the keyword ``q``; Meili
        fuses them by ``semantic_ratio``. Set ``keyword_only`` (or leave the
        embedder unavailable) to skip the vector and rank by keywords alone.
        """
        body: dict[str, Any] = {
            "q": query or "",
            "limit": limit,
            "showRankingScore": True,
            # Let later passages reach the downstream semantic ranker instead
            # of always embedding the first 1,000 characters of a document.
            "attributesToCrop": ["content"],
            "cropLength": 120,
            "cropMarker": "",
        }
        filter_str = _build_filter(filters)
        if filter_str:
            body["filter"] = filter_str

        if not keyword_only and query:
            try:
                vector = self._embedder(query)
            except Exception:
                vector = None
            if vector:
                body["vector"] = list(vector)
                body["hybrid"] = {
                    "semanticRatio": semantic_ratio,
                    "embedder": schema.EMBEDDER_NAME,
                }

        result = await self._client.search(body)
        hits = result.get("hits", []) if isinstance(result, dict) else []
        return [SearchHit.from_meili_hit(h) for h in hits]


# ---------------------------------------------------------------------------
# Module-level helpers: fold the "unconfigured → no-op" check in one place, so
# every caller gets graceful fallback to live fan-out for free.
# ---------------------------------------------------------------------------

async def ensure_index() -> bool:
    """Provision the index if configured. Returns False (no-op) when it isn't."""
    idx = OwnedIndex.from_config()
    if idx is None:
        return False
    await idx.ensure_ready()
    return True


async def index_snapshot(snapshot: Any, content: str, *, onion: Any = None) -> bool:
    """Index a snapshot if the owned index is configured; no-op (False) otherwise."""
    idx = OwnedIndex.from_config()
    if idx is None:
        return False
    return await idx.upsert_snapshot(snapshot, content, onion=onion)


async def search_index(query: str, **kwargs: Any) -> list[SearchHit]:
    """Search the owned index; returns ``[]`` (falls back to fan-out) if unconfigured."""
    idx = OwnedIndex.from_config()
    if idx is None:
        return []
    return await idx.search(query, **kwargs)


async def read_hit_content(hit: Union[SearchHit, str, None]) -> Optional[bytes]:
    """Resolve a hit back to its sanitized R2 snapshot bytes via the existing
    ``snapshot_store.read_snapshot`` (no duplicate ref→content lookup)."""
    ref = hit.content_snapshot_ref if isinstance(hit, SearchHit) else hit
    if not ref:
        return None
    from snapshot_store import read_snapshot

    return await read_snapshot(ref)
