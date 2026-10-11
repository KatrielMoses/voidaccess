"""
Thread-safe singleton for the SentenceTransformer embedding model.

Loads all-MiniLM-L6-v2 lazily on first use, then reuses the same instance
across all consumers. This eliminates the ~80 MB duplicate model weight
problem when multiple modules each instantiate their own model at load time.

Import torch and SentenceTransformer INSIDE the getter function to avoid
the 2-5 second startup delay from torch enumerating CUDA devices.
"""

from __future__ import annotations

import logging
import hashlib
import os
import threading

logger = logging.getLogger(__name__)

_model: "SentenceTransformer | None" = None
_lock = threading.Lock()


class EmbeddingBackendError(RuntimeError):
    """Real semantic embeddings are required but only the fallback is available.

    Raised on the central path (owned index configured) so a broken embedder
    fails loud instead of silently serving SHA-256 hash-noise as "semantic"
    vectors — see ``assert_real_embeddings``.
    """


class _FallbackEmbeddingModel:
    """Small deterministic encoder used when sentence-transformers cannot load."""

    @staticmethod
    def _vector(payload: str) -> list[float]:
        digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).digest()
        return [((digest[i % len(digest)] / 255.0) * 2.0) - 1.0 for i in range(384)]

    def encode(self, text, convert_to_numpy: bool = True, **_kwargs):
        import numpy as np

        # Per-text digest: a batch (list) must yield one DISTINCT vector per
        # element, matching the single-text path. The previous implementation
        # hashed the whole joined list once and repeated that vector for every
        # element, collapsing ``embed_batch`` to identical vectors — which
        # silently breaks semantic ranking wherever the fallback is active.
        if isinstance(text, list):
            arr = np.array([self._vector(str(t)) for t in text], dtype=float)
        else:
            arr = np.array(self._vector(text), dtype=float)
        return arr if convert_to_numpy else arr.tolist()


class _EmbeddingModelWrapper:
    def __init__(self, model):
        self._model = model

    def __getattr__(self, name):
        return getattr(self._model, name)

    def encode(self, *args, **kwargs):
        result = self._model.encode(*args, **kwargs)
        try:
            import numpy as np

            if isinstance(result, np.ndarray):
                return result.astype(float)
        except Exception:
            pass
        return result


def get_embedding_model() -> "SentenceTransformer | None":
    """
    Return the shared SentenceTransformer instance.

    Lazy-loads the model on first call, then caches it for all subsequent calls.
    Thread-safe: uses a lock to prevent race conditions during init.
    """
    global _model

    if _model is not None:
        return _model

    with _lock:
        if _model is not None:
            return _model

        os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
        os.environ.setdefault("USE_TF", "0")

        try:
            import torch  # noqa: PLC0415,F401 - imported inside function per M-6
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            _model = _EmbeddingModelWrapper(SentenceTransformer("all-MiniLM-L6-v2"))
            logger.info("Loaded embedding model all-MiniLM-L6-v2 (singleton)")
        except Exception as exc:
            logger.warning("Failed to load embedding model: %s", exc)
            logger.warning(
                "Deterministic embedding fallback is active; install "
                "voidaccess[nlp] (torch + sentence-transformers) for full "
                "vector embeddings."
            )
            _model = _FallbackEmbeddingModel()

    return _model


# ---------------------------------------------------------------------------
# P3-HARDEN / DRIFT-1 — make the silent embedding degradation loud.
#
# numpy 2.x (and other stack breaks) can make real MiniLM fail to load, silently
# activating the deterministic SHA-256 fallback. On the central service that
# quietly kills semantic ranking + owned-index vectors (P3.2's differentiator)
# while every test stays green. The primitives below let the central path assert
# real embeddings at startup and refuse to serve, while the local/$0 path keeps
# the graceful fallback.
# ---------------------------------------------------------------------------


def using_fallback_embeddings() -> bool:
    """True if the ACTIVE embedding model is the deterministic SHA-256 fallback
    (real MiniLM failed to load) or is unavailable — i.e. NOT real embeddings."""
    model = get_embedding_model()
    return model is None or isinstance(model, _FallbackEmbeddingModel)


def semantic_embeddings_required() -> bool:
    """The explicit "semantic required" signal.

    The central service requires real semantic embeddings iff the owned index is
    configured (``MEILI_HOST`` set): semantic ranking + index vectors are the
    differentiator there, so a silent hash-noise fallback is a product failure. A
    local/$0 install (no owned index) has no such requirement and keeps the
    graceful fallback. Read live so tests and a late ``.env`` take effect.
    """
    import config

    return bool((getattr(config, "MEILI_HOST", None) or "").strip())


def assert_real_embeddings(*, context: str = "") -> None:
    """Raise ``EmbeddingBackendError`` if only the fallback embedder is available.

    Called on the central path where semantic embeddings are a hard requirement,
    so a broken embedder fails loud (clear message + refuse) instead of silently
    serving SHA-256 hash noise. A no-op when real MiniLM is loaded.
    """
    if using_fallback_embeddings():
        raise EmbeddingBackendError(
            "Real semantic embeddings (all-MiniLM-L6-v2) failed to load; the "
            "deterministic SHA-256 fallback is active. On the central service the "
            "owned index's vectors and P3.2 semantic ranking would be silently "
            "degraded to hash noise — refusing to serve rather than ship a silent "
            "product failure. Fix the embedding stack (install voidaccess[nlp] "
            "with a compatible numpy<2 + sentence-transformers/torch set) and "
            "restart." + (f" [{context}]" if context else "")
        )
