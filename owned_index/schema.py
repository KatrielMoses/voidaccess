"""
owned_index/schema.py — the requirement-1.3 index schema and the document
builder that is the index's half of the legal sanitization invariant.

Index schema (requirement 1.3, exact stored fields)
---------------------------------------------------
Every indexed document carries::

    url, title, content_snapshot_ref, content_hash,
    first_seen, last_seen, liveness, language, category

plus one field the 1.3 metadata list does not name but search requires: the
``content`` field — the *sanitized* snapshot text that is actually searched.
The canonical bytes live in R2 (``page_snapshots`` / snapshot_store); the index
holds a searchable projection of them and the ``content_snapshot_ref`` that ties
a hit back to that R2 object.

Attribute roles (mapped onto Meilisearch by ``owned_index.client``):

* **primary key** = ``content_hash`` — this is what makes dedup fall out for
  free: re-indexing byte-identical content produces the same content hash, hence
  the same document id, hence a replace rather than a duplicate (P2.0/P2.1's
  hash is reused verbatim; no second hashing path here).
* **searchable** = ``title`` + ``content``.
* **filterable** = ``liveness`` / ``language`` / ``category`` / ``first_seen`` /
  ``last_seen`` (dates stored as epoch seconds so range filters work).
* **vectors** = user-provided, from the existing MiniLM embedder — see
  ``owned_index.index``; this module stays embedder-agnostic and takes the
  embedding function by injection so there is no new embedding dependency here.

The legal invariant (index ingests only sanitized content)
----------------------------------------------------------
``build_document`` routes the page text through the *single* shared sanitization
choke point ``sanitizer.sanitize_page`` before it can become a document — the
same gate the snapshot store uses. If the gate drops the text (empty,
content-safety-flagged, or — fail-closed — NER unavailable so name/location
redaction cannot be guaranteed) this returns ``None`` and nothing is indexed.
The title, a short metadata string, additionally has structured credentials
redacted (``redact_credentials`` needs no NER). Raw creds/PII therefore cannot
enter the index even if an upstream caller forgot to sanitize.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Optional

from sanitizer import redact_credentials, sanitize_page

# ---------------------------------------------------------------------------
# Attribute configuration (consumed by owned_index.client when it provisions
# the Meilisearch index settings).
# ---------------------------------------------------------------------------

#: Dedup key. Reusing the P2.0/P2.1 content hash as the Meili primary key is
#: what makes "re-indexing identical content never duplicates a doc" automatic.
PRIMARY_KEY = "content_hash"

#: title + snapshot text (requirement 1.3).
SEARCHABLE_ATTRIBUTES: tuple[str, ...] = ("title", "content")

#: liveness / language / category / first_seen / last_seen (requirement 1.3).
FILTERABLE_ATTRIBUTES: tuple[str, ...] = (
    "liveness",
    "language",
    "category",
    "first_seen",
    "last_seen",
)

#: Freshness-oriented ordering (P3.3 will lean on this); harmless now.
SORTABLE_ATTRIBUTES: tuple[str, ...] = ("first_seen", "last_seen")

#: The user-provided embedder handle configured on the index. Documents attach
#: their vector under this name; searches reference it in the ``hybrid`` block.
EMBEDDER_NAME = "default"

#: MiniLM (all-MiniLM-L6-v2) output width — must match ``vector.embed_text``.
EMBEDDING_DIMENSIONS = 384

#: The 1.3 stored-metadata fields, in schema order (the searchable ``content``
#: and the ``_vectors`` payload are added on top of these).
SCHEMA_FIELDS: tuple[str, ...] = (
    "url",
    "title",
    "content_snapshot_ref",
    "content_hash",
    "first_seen",
    "last_seen",
    "liveness",
    "language",
    "category",
)


def to_epoch(value: Any) -> Optional[int]:
    """Coerce a datetime (or epoch-ish value) to UTC epoch seconds, or ``None``.

    Meilisearch filters/sorts numerically, so ``first_seen``/``last_seen`` are
    stored as integer epoch seconds rather than ISO strings.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    if isinstance(value, (int, float)):
        return int(value)
    return None


def searchable_text(title: Optional[str], content: str) -> str:
    """The text embedded for semantic search: title + sanitized snapshot text."""
    return "\n".join(part for part in (title, content) if part)


def build_document(
    *,
    content_hash: str,
    url: str,
    content: str,
    title: Optional[str] = None,
    content_snapshot_ref: Optional[str] = None,
    first_seen: Any = None,
    last_seen: Any = None,
    liveness: Optional[str] = None,
    language: Optional[str] = None,
    category: Optional[str] = None,
    embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
    presanitized: bool = False,
) -> Optional[dict[str, Any]]:
    """Build a Meilisearch document for a page snapshot, or ``None`` to skip it.

    The ``content`` argument is routed through ``sanitizer.sanitize_page`` (the
    single shared gate) before it can become the searchable ``content`` field;
    if the gate drops it, this returns ``None`` and the page is not indexed.
    ``title`` has structured credentials redacted as defense-in-depth.

    Set ``presanitized=True`` only when ``content`` is *already* the output of
    ``sanitizer.sanitize_page`` (e.g. the usage-seeding path sanitizes once and
    feeds the same text to both the snapshot store and the index). This skips a
    redundant second NER pass without weakening the invariant — the gate still
    ran, just at the caller. The default (``False``) applies the gate here.

    When an ``embedder`` is supplied it is called with ``title + content`` and
    its 384-dim vector is attached as a user-provided ``_vectors`` payload. The
    embedder is injected (rather than imported here) so this module adds no
    embedding dependency — the caller wires ``vector.embed_text``.
    """
    if not content_hash or not url:
        return None

    # THE legal gate: only sanitized content may enter the index. ``presanitized``
    # certifies the caller already ran the identical gate (sanitize_page), so the
    # invariant holds; otherwise it is applied here (idempotent defense-in-depth).
    sanitized = content if presanitized else sanitize_page(content)
    if not sanitized:
        return None

    clean_title = redact_credentials(title) if title else None

    doc: dict[str, Any] = {
        "content_hash": content_hash,
        "url": url,
        "title": clean_title,
        "content_snapshot_ref": content_snapshot_ref,
        "content": sanitized,
        "first_seen": to_epoch(first_seen),
        "last_seen": to_epoch(last_seen),
        "liveness": liveness,
        "language": language,
        "category": category,
    }

    if embedder is not None:
        try:
            vector = embedder(searchable_text(clean_title, sanitized))
        except Exception:
            vector = None
        if vector:
            doc["_vectors"] = {EMBEDDER_NAME: list(vector)}

    return doc


def document_from_snapshot(
    snapshot: Any,
    content: str,
    *,
    onion: Any = None,
    embedder: Optional[Callable[[str], Optional[list[float]]]] = None,
    presanitized: bool = False,
) -> Optional[dict[str, Any]]:
    """Build an index document from a ``PageSnapshot`` row and its onion.

    ``url``/``content_hash``/``content_snapshot_ref``/``first_seen``/
    ``last_seen``/``language`` come from the snapshot; ``title``/``category``/
    ``liveness`` (= ``DiscoveredOnion.status``) come from the associated onion
    (passed explicitly, or ``snapshot.onion`` if a session is attached). The
    ``content`` is the sanitized snapshot text (e.g. from
    ``snapshot_store.read_snapshot``); it still passes the gate in
    ``build_document``.
    """
    onion = onion if onion is not None else getattr(snapshot, "onion", None)

    return build_document(
        content_hash=getattr(snapshot, "content_hash", None),
        url=getattr(snapshot, "url", None),
        content=content,
        title=getattr(onion, "title", None) if onion is not None else None,
        content_snapshot_ref=getattr(snapshot, "storage_ref", None),
        first_seen=getattr(snapshot, "first_seen", None),
        last_seen=getattr(snapshot, "last_seen", None),
        liveness=getattr(onion, "status", None) if onion is not None else None,
        language=(
            getattr(snapshot, "language", None)
            or (getattr(onion, "language", None) if onion is not None else None)
        ),
        category=getattr(onion, "category", None) if onion is not None else None,
        embedder=embedder,
        presanitized=presanitized,
    )
