"""
ChromaDB persistence for page embeddings (collection: voidaccess_pages).
"""

# If you migrate from an older collection name, delete ./chroma_db (or CHROMA_PERSIST_DIR)
# and re-run ingestion so the collection is recreated with the new name.

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

import config

from . import embedder

logger = logging.getLogger(__name__)

_COLLECTION: Any = None
_CLIENT: Any = None

DEFAULT_PERSIST_DIR = "./chroma_db"
COLLECTION_NAME = "voidaccess_pages"
ACTOR_PROFILE_COLLECTION = "actor_style_profiles"

# Issue 2: a cached page must go through the SAME size cap that a freshly
# scraped page does before extraction, otherwise the exact same URL yields a
# different number of entities purely depending on whether it was cached.  The
# fresh path truncates to scraper.scrape.MAX_RETURN_CHARS before extraction, so
# we mirror that here instead of the old, silently smaller 8 000-char cap.
_FALLBACK_CACHE_DOCUMENT_CHARS = 15_000


def _cache_document_cap() -> int:
    """Character cap for stored cache documents — kept in lockstep with the
    fresh-scrape return cap so cached and fresh content are identical inputs
    to the extractor.  Read lazily to avoid importing the scraper at module
    load; falls back to the known fresh cap if the import is unavailable."""
    try:
        from scraper.scrape import MAX_RETURN_CHARS
        return int(MAX_RETURN_CHARS)
    except Exception:
        return _FALLBACK_CACHE_DOCUMENT_CHARS

_ACTOR_COLLECTION: Any = None


def _persist_dir() -> str:
    v = getattr(config, "CHROMA_PERSIST_DIR", None) or os.getenv(
        "CHROMA_PERSIST_DIR", DEFAULT_PERSIST_DIR
    )
    return (v or DEFAULT_PERSIST_DIR).strip() or DEFAULT_PERSIST_DIR


def _page_id_str(page_id: int | None) -> str | None:
    if page_id is None:
        return None
    return str(page_id)


def get_collection():
    """
    Singleton persistent Chroma collection, or None if chromadb is unavailable.
    Never raises.
    """
    global _COLLECTION, _CLIENT
    if _COLLECTION is not None:
        return _COLLECTION
    try:
        import chromadb  # noqa: PLC0415
    except ImportError:
        logger.warning("chromadb not installed; vector store disabled")
        return None
    try:
        path = os.path.abspath(_persist_dir())
        os.makedirs(path, exist_ok=True)
        _CLIENT = chromadb.PersistentClient(path=path)
        _COLLECTION = _CLIENT.get_or_create_collection(name=COLLECTION_NAME)
    except Exception as exc:
        logger.warning("Failed to open ChromaDB: %s", exc)
        _COLLECTION = None
        _CLIENT = None
    return _COLLECTION


def get_actor_collection():
    """
    Singleton Chroma collection for actor style profiles.
    Uses cosine similarity (L2 normalized).
    """
    global _ACTOR_COLLECTION, _CLIENT
    if _ACTOR_COLLECTION is not None:
        return _ACTOR_COLLECTION
    try:
        import chromadb  # noqa: PLC0415
    except ImportError:
        logger.warning("chromadb not installed; actor vector store disabled")
        return None
    try:
        path = os.path.abspath(_persist_dir())
        os.makedirs(path, exist_ok=True)
        if _CLIENT is None:
            _CLIENT = chromadb.PersistentClient(path=path)
        _ACTOR_COLLECTION = _CLIENT.get_or_create_collection(
            name=ACTOR_PROFILE_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )
    except Exception as exc:
        logger.warning("Failed to open actor ChromaDB collection: %s", exc)
        _ACTOR_COLLECTION = None
    return _ACTOR_COLLECTION


def _stable_id(page_url: str) -> str:
    return hashlib.sha256(page_url.encode("utf-8")).hexdigest()


def _normalize_url(url: str) -> str:
    """
    Normalize URL for consistent cache lookups.

    Uses crawler.utils.normalize_url for consistency with scraper.
    Falls back to basic normalization if crawler.utils unavailable.
    """
    try:
        from crawler.utils import normalize_url
        return normalize_url(url)
    except ImportError:
        pass
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path and path != "/":
            path = path.rstrip("/")
        elif path == "/":
            path = ""
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    except Exception:
        return url


def _flatten_metadata(
    url: str,
    page_id: int | None,
    ts: str,
    extra: dict | None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "url": url,
        "timestamp": ts,
    }
    ps = _page_id_str(page_id)
    if ps is not None:
        meta["page_id"] = ps
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                meta[str(k)] = v
            else:
                meta[str(k)] = str(v)
    for key in ("user_id", "investigation_id"):
        if key in meta:
            meta[key] = str(meta[key])
    return meta


def upsert_page(
    page_url: str,
    text: str,
    metadata: dict | None = None,
    page_id: int | None = None,
) -> bool:
    """
    Embed *text* and upsert into Chroma. id = SHA-256 of page_url.
    Returns False on any failure or missing deps. Never raises.
    """
    col = get_collection()
    if col is None:
        return False
    emb = embedder.embed_text(text)
    if emb is None:
        return False
    try:
        metadata = dict(metadata or {})
        if metadata.get("investigation_id") and "user_id" not in metadata:
            from db.session import get_session
            from db.models import Investigation
            import uuid
            with get_session() as session:
                inv = session.get(Investigation, uuid.UUID(str(metadata["investigation_id"])))
                if inv and inv.user_id is not None:
                    metadata["user_id"] = str(inv.user_id)
        pid = _stable_id(page_url)
        if "user_id" in metadata:
            pid = _stable_id(f"{metadata['user_id']}:{metadata.get('investigation_id', '')}:{page_url}")
        ts = datetime.now(timezone.utc).isoformat()
        meta = _flatten_metadata(page_url, page_id, ts, metadata)
        col.upsert(
            ids=[pid],
            embeddings=[emb],
            metadatas=[meta],
            documents=[text[: _cache_document_cap()]],
        )
        return True
    except Exception as exc:
        logger.warning("upsert_page failed: %s", exc)
        return False


def search_similar(
    query_text: str,
    n_results: int = 10,
    where: dict | None = None,
    offset: int = 0,
    user_id: int | None = None,
) -> list[dict]:
    """
    Semantic search; results sorted by distance ascending. Never raises.
    Supports offset for pagination.
    """
    col = get_collection()
    if col is None:
        return []
    emb = embedder.embed_text(query_text)
    if emb is None:
        return []
    try:
        n = max(1, int(n_results))
        total_needed = offset + n
        if user_id is not None:
            owner_filter = {"user_id": str(user_id)}
            where = {"$and": [owner_filter, where]} if where else owner_filter
        res = col.query(
            query_embeddings=[emb],
            n_results=total_needed,
            where=where,
            include=["distances", "metadatas"],
        )
        ids = (res.get("ids") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        
        total = len(ids)
        actual_offset = min(offset, total)
        
        out: list[dict] = []
        for i in range(actual_offset, len(ids)):
            if len(out) >= n:
                break
            _pid = ids[i]
            m = metas[i] if i < len(metas) and metas[i] else {}
            md = dict(m) if isinstance(m, dict) else {}
            url = md.get("url", "")
            raw_pid = md.get("page_id")
            page_id_out: int | None = None
            if raw_pid is not None:
                try:
                    page_id_out = int(raw_pid)
                except (TypeError, ValueError):
                    page_id_out = None
            dist_f = float(dists[i]) if i < len(dists) else 0.0
            out.append(
                {
                    "url": url,
                    "page_id": page_id_out,
                    "distance": dist_f,
                    "metadata": md,
                }
            )
        return out
    except Exception as exc:
        logger.warning("search_similar failed: %s", exc)
        return []


def count_pages(user_id: int | None = None) -> int:
    """Return total page count in vector store."""
    col = get_collection()
    if col is None:
        return 0
    try:
        return len(col.get(where={"user_id": str(user_id)}, include=[]) ["ids"]) if user_id is not None else int(col.count())
    except Exception:
        return 0


def is_duplicate(text: str, threshold: float = 0.05) -> bool:
    """True if the nearest neighbour is within *threshold* distance."""
    hits = search_similar(text, n_results=1)
    if not hits:
        return False
    return float(hits[0]["distance"]) < threshold


def get_collection_stats() -> dict:
    col = get_collection()
    total = 0
    if col is not None:
        try:
            total = int(col.count())
        except Exception:
            total = 0
    return {
        "total_documents": total,
        "persist_directory": os.path.abspath(_persist_dir()),
    }


def get_cached_page(url: str, max_age_hours: int = 24) -> dict | None:
    """
    Check if a URL was already scraped within max_age_hours.

    Uses normalized URL for lookup. Returns the cached page dict
    {link, content, status, cached: True} if found and fresh enough, else None.
    """
    col = get_collection()
    if col is None:
        return None
    normalized = _normalize_url(url)
    if not normalized:
        return None
    try:
        results = col.get(
            where={"url": normalized},
            include=["documents", "metadatas"],
        )
        if not results["ids"]:
            return None

        metadata = results["metadatas"][0]
        content = results["documents"][0]

        ts_str = metadata.get("timestamp") or metadata.get("scraped_at") or ""
        if ts_str:
            stored_at = datetime.fromisoformat(ts_str)
            if stored_at.tzinfo is None:
                stored_at = stored_at.replace(tzinfo=timezone.utc)
            age_hours = (
                datetime.now(timezone.utc) - stored_at
            ).total_seconds() / 3600
            if age_hours > max_age_hours:
                return None

        if not content or len(content) < 100:
            return None

        return {
            "link": normalized,
            "content": content,
            "status": 200,
            "cached": True,
            "cached_at": ts_str,
        }

    except Exception as exc:
        logger.debug("Vector cache lookup failed for %s: %s", url, exc)
        return None


def store_page(url: str, content: str, metadata: dict | None = None) -> bool:
    """
    Store a scraped page in ChromaDB for future cache hits.

    Normalizes URL before storing for consistent cache lookups.
    Delegates to upsert_page so the embedding is also stored.
    Returns True if stored successfully, False otherwise.
    """
    if not content or len(content) < 100:
        return False
    normalized = _normalize_url(url)
    if not normalized:
        return False
    return upsert_page(page_url=normalized, text=content, metadata=metadata)


def bulk_check_cache(
    urls: list[str],
    max_age_hours: int = 24,
    user_id: int | None = None,
) -> tuple[list[dict], list[str]]:
    """
    Check multiple URLs against cache in a single ChromaDB batch call.

    Returns:
        cached_pages:   list of page dicts for cache hits
        uncached_urls:  list of URL strings that need to be scraped
    """
    if not urls:
        return [], []
    # API pages cannot reuse global CLI/private caches. Fetch under their own investigation.
    if user_id is not None:
        return [], list(urls)

    collection = get_collection()
    if collection is None:
        return [], list(urls)

    url_to_id = {url: _stable_id(url) for url in urls}
    ids = list(url_to_id.values())

    try:
        results = collection.get(ids=ids, include=["documents", "metadatas"])
    except Exception as exc:
        logger.warning("Bulk cache lookup failed: %s", exc)
        return [], list(urls)

    idx_map = {doc_id: i for i, doc_id in enumerate(results["ids"] or [])}
    cached_pages: list[dict] = []
    uncached_urls: list[str] = []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    for url, doc_id in url_to_id.items():
        if doc_id not in idx_map:
            uncached_urls.append(url)
            continue

        idx = idx_map[doc_id]

        metadata = results["metadatas"][idx]
        content = results["documents"][idx]

        ts_str = metadata.get("timestamp") or metadata.get("scraped_at") or ""
        if ts_str:
            try:
                stored_at = datetime.fromisoformat(ts_str)
                if stored_at.tzinfo is None:
                    stored_at = stored_at.replace(tzinfo=timezone.utc)
                if stored_at < cutoff:
                    uncached_urls.append(url)
                    continue
            except (ValueError, TypeError):
                pass

        if not content or len(content) < 100:
            uncached_urls.append(url)
            continue

        cached_pages.append({
            "link": url,
            "content": content,
            "status": 200,
            "cached": True,
            "cached_at": ts_str,
        })

    return cached_pages, uncached_urls


def _dict_to_flat_vector(vector_dict: dict) -> list[float]:
    """Flatten a style vector dict into a list of floats for ChromaDB."""
    flat: list[float] = []
    for key in sorted(vector_dict.keys()):
        val = vector_dict[key]
        if isinstance(val, dict):
            for subkey in sorted(val.keys()):
                flat.append(float(val.get(subkey, 0.0)))
        else:
            flat.append(float(val) if val is not None else 0.0)
    return flat


def upsert_actor_profile(
    actor_id: int,
    style_vector: dict,
    username: str | None = None,
    platform: str | None = None,
) -> bool:
    """
    Upsert an actor style profile vector into ChromaDB.
    Returns False on failure, True on success.
    """
    col = get_actor_collection()
    if col is None:
        return False
    if not style_vector:
        return False
    try:
        flat_vec = _dict_to_flat_vector(style_vector)
        if not flat_vec:
            return False
        metadata: dict[str, Any] = {"actor_id": str(actor_id)}
        if username is not None:
            metadata["username"] = str(username)
        if platform is not None:
            metadata["platform"] = str(platform)
        col.upsert(
            ids=[str(actor_id)],
            embeddings=[flat_vec],
            metadatas=[metadata],
        )
        return True
    except Exception as exc:
        logger.warning("upsert_actor_profile failed: %s", exc)
        return False


def match_actor_profiles(
    style_vector: dict,
    top_k: int = 10,
    threshold: float = 0.85,
) -> list[dict]:
    """
    Approximate nearest neighbor search against actor style profiles.
    Returns list of {actor_id, similarity} dicts with similarity >= threshold.
    """
    col = get_actor_collection()
    if col is None:
        return []
    if not style_vector:
        return []
    try:
        flat_vec = _dict_to_flat_vector(style_vector)
        if not flat_vec:
            return []
        results = col.query(
            query_embeddings=[flat_vec],
            n_results=top_k,
            include=["distances", "metadatas"],
        )
        ids = (results.get("ids") or [[]])[0]
        dists = (results.get("distances") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]

        matches: list[dict] = []
        for doc_id, dist, meta in zip(ids, dists, metas):
            if doc_id is None:
                continue
            similarity = 1.0 - float(dist)
            if similarity >= threshold:
                match: dict[str, Any] = {
                    "actor_id": int(doc_id),
                    "similarity": similarity,
                }
                if isinstance(meta, dict):
                    if "username" in meta:
                        match["username"] = meta["username"]
                    if "platform" in meta:
                        match["platform"] = meta["platform"]
                matches.append(match)
        return matches
    except Exception as exc:
        logger.warning("match_actor_profiles failed: %s", exc)
        return []


def backfill_owners(first_admin_id: int) -> int:
    """Assign unowned legacy entries only, preserving ids/documents/embeddings."""
    count = 0
    for collection in (get_collection(), get_actor_collection()):
        if collection is None:
            continue
        offset = 0
        while True:
            batch = collection.get(limit=500, offset=offset, include=["metadatas"])
            ids = batch.get("ids") or []
            if not ids:
                break
            for key, meta in zip(ids, batch.get("metadatas") or []):
                meta = dict(meta or {})
                if "user_id" not in meta:
                    meta["user_id"] = str(first_admin_id)
                    meta.setdefault("investigation_id", "legacy")
                    collection.update(ids=[key], metadatas=[meta])
                    count += 1
            offset += len(ids)
    return count
