"""
Higher-level semantic search built on vector/store.py.
"""

from __future__ import annotations

import logging
from typing import Any

from . import store

logger = logging.getLogger(__name__)


def find_related_pages(query: str, n_results: int = 10) -> list[dict]:
    """Semantic search over stored pages (metadata + distance)."""
    return store.search_similar(query, n_results=n_results)


def find_pages_similar_to(reference_url: str, n_results: int = 10, user_id: int | None = None) -> list[dict]:
    """
    Find pages similar to *reference_url* using its stored embedding.
    Returns [] if the URL is not in the collection.
    """
    col = store.get_collection()
    if col is None:
        return []
    try:
        import hashlib

        pid = hashlib.sha256(reference_url.encode("utf-8")).hexdigest()
        got = col.get(where={"$and": [{"url": reference_url}, {"user_id": str(user_id)}]}, include=["embeddings"]) if user_id is not None else col.get(ids=[pid], include=["embeddings"])
        embs = got.get("embeddings")
        if embs is None or len(embs) == 0 or embs[0] is None:
            return []
        emb = list(embs[0])
        n = max(1, int(n_results))
        res = col.query(
            query_embeddings=[emb],
            n_results=n + 1,
            where={"user_id": str(user_id)} if user_id is not None else None,
            include=["distances", "metadatas"],
        )
        ids = (res.get("ids") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        out: list[dict] = []
        for i, _eid in enumerate(ids):
            if _eid in (got.get("ids") or [pid]):
                continue
            m = metas[i] if i < len(metas) and metas[i] else {}
            md = dict(m) if isinstance(m, dict) else {}
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
                    "url": md.get("url", ""),
                    "page_id": page_id_out,
                    "distance": dist_f,
                    "metadata": md,
                }
            )
            if len(out) >= n:
                break
        return out[:n]
    except Exception as exc:
        logger.warning("find_pages_similar_to failed: %s", exc)
        return []


def cross_investigation_recall(
    query: str,
    exclude_investigation_id: int | None = None,
    user_id: int | None = None,
) -> list[dict]:
    """
    Similar pages across investigations; optionally exclude one investigation_id.
    """
    where: dict[str, Any] | None = None
    if exclude_investigation_id is not None:
        ex = str(exclude_investigation_id)
        where = {"investigation_id": {"$ne": ex}}
    return store.search_similar(query, n_results=10, where=where, **({"user_id": user_id} if user_id is not None else {}))
