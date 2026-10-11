"""
tests/test_embedding_backend_health.py — P3-HARDEN / DRIFT-1.

Make the silent embedding degradation loud on the central path while keeping the
local/$0 path graceful. The model backend is forced via the singleton so the test
is deterministic regardless of whether real MiniLM happens to load in this env.
"""

from __future__ import annotations

import pytest

import config
from vector import model_singleton as ms
from vector.model_singleton import (
    EmbeddingBackendError,
    _FallbackEmbeddingModel,
    assert_real_embeddings,
    semantic_embeddings_required,
    using_fallback_embeddings,
)


class _RealishModel:
    """Stand-in for a loaded MiniLM (anything that is NOT the fallback class)."""

    def encode(self, *a, **k):
        import numpy as np

        return np.zeros(384)


@pytest.fixture
def force_model(monkeypatch):
    def _set(model):
        monkeypatch.setattr(ms, "_model", model)

    return _set


# --- the "semantic required" signal ----------------------------------------

def test_semantic_required_true_when_owned_index_configured(monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", "http://meili.test:7700", raising=False)
    assert semantic_embeddings_required() is True


def test_semantic_required_false_without_owned_index(monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    assert semantic_embeddings_required() is False


# --- backend detection ------------------------------------------------------

def test_using_fallback_detects_backend(force_model):
    force_model(_FallbackEmbeddingModel())
    assert using_fallback_embeddings() is True
    force_model(_RealishModel())
    assert using_fallback_embeddings() is False


def test_assert_raises_on_fallback(force_model):
    force_model(_FallbackEmbeddingModel())
    with pytest.raises(EmbeddingBackendError) as exc:
        assert_real_embeddings(context="unit")
    # The message is unambiguous about refusing rather than silently degrading.
    assert "refusing" in str(exc.value).lower()


def test_assert_ok_on_real_model(force_model):
    force_model(_RealishModel())
    assert_real_embeddings(context="unit")  # no raise


# --- the fork: central fails loud, local stays graceful ---------------------

def test_central_path_with_broken_embedder_fails_loud(force_model, monkeypatch):
    """Owned index configured + only the fallback → the startup check refuses."""
    monkeypatch.setattr(config, "MEILI_HOST", "http://meili.test:7700", raising=False)
    force_model(_FallbackEmbeddingModel())
    assert semantic_embeddings_required() is True
    with pytest.raises(EmbeddingBackendError):
        # Mirrors the api/main startup fork.
        if semantic_embeddings_required():
            assert_real_embeddings(context="MEILI_HOST is set")


def test_local_install_stays_graceful(force_model, monkeypatch):
    """No owned index → semantic not required, and the SHA-256 fallback still
    yields a usable 384-dim vector, so a local/$0 user (no torch) still runs."""
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    force_model(_FallbackEmbeddingModel())

    # The startup fork would NOT assert here (nothing to fail loud about).
    assert semantic_embeddings_required() is False

    from vector import embedder

    monkeypatch.setattr(embedder, "_EMBEDDER", None)  # re-fetch through the fallback
    vec = embedder.embed_text("hello world")
    assert vec is not None and len(vec) == 384
