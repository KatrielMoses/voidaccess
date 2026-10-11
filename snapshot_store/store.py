"""
snapshot_store/store.py — write/read sanitized page snapshots to object storage.

The high-level P2.1 surface:

* ``store_snapshot(session, url, content, …)`` — sanitize → content-address →
  dedup → upload → record the ``page_snapshots`` ref row. The one write path.
* ``read_snapshot(ref)`` — fetch stored bytes back by ref (or content hash).
* ``is_stale`` / ``stale_snapshots`` — the TTL/refresh policy's staleness marker.

Content addressing + dedup
---------------------------
The object key is derived from the SHA-256 of the *sanitized* bytes (what is
actually stored), sharded by the first two hex chars for bucket hygiene. Because
the key is the content hash, identical content is uploaded once: ``store_snapshot``
HEADs the key first and skips the PUT when the object already exists, reusing the
ref. The DB dedup is the P2.0 ``uq_page_snapshot_content_hash`` constraint.

Unconfigured = graceful no-op
-----------------------------
With no S3 store configured (``S3ObjectStore.from_config()`` → ``None``:
CLI $0 path, or a private-mode install), ``store_snapshot`` uploads nothing and
records nothing — it returns ``None`` and never raises. Object storage is never
required for the tool to run.

TTL / refresh policy
--------------------
Every snapshot carries ``captured_at``; ``SNAPSHOT_TTL`` (default 14 days) is the
refresh cadence. ``is_stale(snapshot)`` is the *programmatic staleness marker*
and ``stale_snapshots(session)`` enumerates rows due for refresh. This is a
deliberate contrast with the ChromaDB page cache (``vector/store.py``), whose
24h TTL is checked only on read and which never evicts — an audit finding of
unbounded growth. Here the growth story is explicit:

* **Dedup bounds writes** — content-hash addressing means re-observed content
  never adds a row or an object.
* **Staleness is queryable now** — ``stale_snapshots`` identifies refresh
  candidates; the actual re-crawl/eviction *enforcement* lands in P3's freshness
  loop (re-capture updated content, or delete object + row for a dead onion).
  The marker and the query exist now so the sweeper is a thin consumer, not a
  redesign.

The two stores serve different tiers (local per-URL scrape cache vs. shared
content-hash corpus) and are intentionally kept separate; see README.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from shared_corpus import PageSnapshot, contribution_enabled, record_page_snapshot
from sanitizer import provenance_stamp, sanitize_page
from snapshot_store.s3 import S3ObjectStore

#: Object-key prefix for page snapshots within the bucket.
SNAPSHOT_KEY_PREFIX = "snapshots"

#: Refresh cadence: a snapshot older than this is considered stale and due for
#: a P3 freshness re-crawl. Not an eviction deadline — content is refreshed or
#: removed by the freshness loop, not silently dropped on read.
SNAPSHOT_TTL = timedelta(days=14)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def content_hash(data: bytes) -> str:
    """SHA-256 hex of the (sanitized) bytes that will be stored."""
    return hashlib.sha256(data).hexdigest()


def content_key(digest: str) -> str:
    """Object key for a content hash: ``snapshots/<ab>/<hash>`` (sharded)."""
    shard = digest[:2] if len(digest) >= 2 else "00"
    return f"{SNAPSHOT_KEY_PREFIX}/{shard}/{digest}"


def _source_from_url(url: str) -> str:
    """Best-effort source-onion host for a provenance stamp."""
    from urllib.parse import urlparse

    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


async def store_snapshot(
    session: Session,
    url: str,
    content: str,
    *,
    onion_id=None,
    language: Optional[str] = None,
    source: Optional[str] = None,
    content_type: str = "text/plain; charset=utf-8",
    presanitized: Optional[str] = None,
) -> Optional[PageSnapshot]:
    """Sanitize, content-address, dedup-upload, and record a page snapshot.

    Returns the ``PageSnapshot`` row on success, or ``None`` when the page was
    dropped by the sanitizer (empty / content-safety-flagged / NER-unavailable),
    when object storage is not configured, or when the install is in private mode
    (consent opt-out) — all graceful no-ops.

    ``presanitized`` is an optimization for callers that have *already* run this
    module's gate (``sanitize_page``) on the same content and want to avoid a
    second NER pass — e.g. P3.1 usage-seeding, which sanitizes once and feeds the
    result to both this store and the owned index. When supplied it is used
    verbatim as the sanitized bytes (it MUST be the output of ``sanitize_page``);
    the single-gate invariant holds because the gate still ran, just at the
    caller. When ``None`` (the default) the gate is applied here as before.
    """
    # Consent / private-mode: a private install writes nothing to the shared
    # corpus, independent of whether S3 is configured.
    if not contribution_enabled():
        return None

    sanitized = presanitized if presanitized is not None else sanitize_page(content)
    if not sanitized:
        return None  # dropped by the mandatory sanitization gate

    store = S3ObjectStore.from_config()
    if store is None:
        return None  # unconfigured — snapshot writes no-op cleanly

    data = sanitized.encode("utf-8")
    digest = content_hash(data)
    key = content_key(digest)

    # Dedup: identical content is never re-uploaded — reuse the existing object.
    if not await store.object_exists(key):
        await store.put_object(key, data, content_type=content_type)

    captured = _now()
    stamp = provenance_stamp(source=source or _source_from_url(url), captured_at=captured)
    row, _created = record_page_snapshot(
        session,
        content_hash=digest,
        url=url,
        onion_id=onion_id,
        provenance=stamp,
        storage_ref=key,
        byte_size=len(data),
        language=language,
    )
    return row


async def read_snapshot(ref: str) -> Optional[bytes]:
    """Fetch stored snapshot bytes by ``storage_ref`` (object key) or content hash.

    Returns the bytes, or ``None`` if the object is missing, no store is
    configured, or the install is in private mode (reads nothing central).
    """
    if not contribution_enabled():
        return None
    store = S3ObjectStore.from_config()
    if store is None:
        return None
    # A bare 64-hex content hash is accepted and mapped to its sharded key; an
    # already-sharded key (contains "/") is used as-is.
    key = ref if "/" in ref else content_key(ref)
    return await store.get_object(key)


def is_stale(
    snapshot: PageSnapshot,
    *,
    now: Optional[datetime] = None,
    ttl: timedelta = SNAPSHOT_TTL,
) -> bool:
    """True if *snapshot* is older than *ttl* and due for a freshness re-crawl."""
    captured = snapshot.captured_at
    if captured is None:
        return True
    if captured.tzinfo is None:
        captured = captured.replace(tzinfo=timezone.utc)
    return (now or _now()) - captured > ttl


def stale_snapshots(
    session: Session,
    *,
    now: Optional[datetime] = None,
    ttl: timedelta = SNAPSHOT_TTL,
    limit: Optional[int] = None,
) -> list[PageSnapshot]:
    """Return snapshots past their TTL — the refresh candidates for P3's sweeper."""
    cutoff = (now or _now()) - ttl
    query = (
        session.query(PageSnapshot)
        .filter(PageSnapshot.captured_at < cutoff)
        .order_by(PageSnapshot.captured_at.asc())
    )
    if limit is not None:
        query = query.limit(limit)
    return query.all()
