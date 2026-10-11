"""
snapshot_store — the P2.1 page-snapshot object store (shared corpus).

Sanitized page content lives in S3-compatible object storage (Cloudflare R2 in
production, MinIO/local in dev, any S3 store — same code); the DB
``page_snapshots`` row (P2.0) holds the ref + content_hash. Content is
content-addressed and deduped by hash; every write passes the mandatory
sanitization gate first, so no raw credential/PII ever reaches object storage.
An unconfigured store degrades to a graceful no-op.

See ``snapshot_store/README.md``.
"""

from sanitizer import sanitize_page
from snapshot_store.s3 import S3Config, S3ObjectStore
from snapshot_store.store import (
    SNAPSHOT_KEY_PREFIX,
    SNAPSHOT_TTL,
    content_hash,
    content_key,
    is_stale,
    read_snapshot,
    stale_snapshots,
    store_snapshot,
)

__all__ = [
    "S3Config",
    "S3ObjectStore",
    "sanitize_page",
    "SNAPSHOT_KEY_PREFIX",
    "SNAPSHOT_TTL",
    "content_hash",
    "content_key",
    "is_stale",
    "read_snapshot",
    "stale_snapshots",
    "store_snapshot",
]
