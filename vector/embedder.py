"""
Local embedding generation via sentence-transformers (all-MiniLM-L6-v2).

Uses the shared model singleton from vector.model_singleton.
"""

from __future__ import annotations

import logging

from vector.model_singleton import get_embedding_model

logger = logging.getLogger(__name__)

_EMBEDDER = None


def get_embedder():
    """Return the shared SentenceTransformer instance, or None if unavailable."""
    global _EMBEDDER
    if _EMBEDDER is None:
        _EMBEDDER = get_embedding_model()
    return _EMBEDDER


def _truncate_to_model_limit(text: str, model) -> str:
    if not text:
        return text
    try:
        tok = getattr(model, "tokenizer", None)
        if tok is None:
            return text[:50000]
        encoded = tok.encode(
            text,
            add_special_tokens=True,
            truncation=True,
            max_length=int(model.max_seq_length),
        )
        return tok.decode(encoded, skip_special_tokens=True)
    except Exception:
        return text[:50000]


def embed_text(text: str) -> list[float] | None:
    """
    Return a 384-dim embedding as a plain Python list, or None if unavailable
    or text is empty.
    """
    if not (text and str(text).strip()):
        return None
    model = get_embedder()
    if model is None:
        return None
    try:
        truncated = _truncate_to_model_limit(str(text), model)
        vec = model.encode(
            truncated,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return [float(x) for x in vec.tolist()]
    except Exception as exc:
        logger.warning("embed_text failed: %s", exc)
        return None


def embed_batch(texts: list[str]) -> list[list[float] | None]:
    """
    Batch embedding. Returns a list parallel to *texts*; any failure becomes None.
    """
    if not texts:
        return []
    model = get_embedder()
    if model is None:
        return [None for _ in texts]
    prepared: list[str] = []
    empty_indices: set[int] = set()
    for i, t in enumerate(texts):
        if not (t and str(t).strip()):
            empty_indices.add(i)
            prepared.append("")
        else:
            prepared.append(_truncate_to_model_limit(str(t), model))
    out: list[list[float] | None] = [None] * len(texts)
    for i in empty_indices:
        out[i] = None
    to_encode_idx = [i for i in range(len(texts)) if i not in empty_indices]
    if not to_encode_idx:
        return out
    try:
        batch_in = [prepared[i] for i in to_encode_idx]
        encoded = model.encode(
            batch_in,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        for j, row_idx in enumerate(to_encode_idx):
            out[row_idx] = [float(x) for x in encoded[j].tolist()]
    except Exception as exc:
        logger.warning("embed_batch failed: %s", exc)
        for i in to_encode_idx:
            out[i] = None
    return out  # type: ignore[return-value]
