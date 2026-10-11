"""
tests/test_owned_index.py — P3.0 owned persistent index (Meilisearch) suite.

Runs with zero Meilisearch dependency for the unit tests: the transport is
exercised either through a ``FakeMeiliClient`` (an in-memory stand-in keyed by
``content_hash``) injected into ``OwnedIndex``, or through the real
``MeiliClient`` with HTTP mocked by ``aioresponses``. One real-Meilisearch
integration test is gated by the ``MEILI_TEST_URL`` env var and skips when unset.

Coverage maps to the P3.0 acceptance criteria:
* the exact 1.3 schema on every document;
* dedup by ``content_hash`` (re-indexing identical content never duplicates);
* the legal invariant — raw creds/PII can never enter the index (single gate);
* unconfigured → graceful no-op (search falls back to fan-out);
* hybrid keyword+semantic search wired to the existing embedder;
* vectors come from the existing embedder (no new embedding dependency).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from aioresponses import aioresponses

import config
from owned_index import (
    FILTERABLE_ATTRIBUTES,
    PRIMARY_KEY,
    SEARCHABLE_ATTRIBUTES,
    MeiliClient,
    MeiliConfig,
    OwnedIndex,
    SearchHit,
    build_document,
    document_from_snapshot,
)
from owned_index import index as index_module
from owned_index import schema as schema_module
from sanitizer import sanitize_page

# ---------------------------------------------------------------------------
# NER availability: the sanitizer fail-closes to None when spaCy NER is missing,
# which would drop every document. Tests that need a *built* document guard on
# this; the invariant / no-op / config tests do not (they stay green either way).
# ---------------------------------------------------------------------------
_NER_AVAILABLE = sanitize_page("the quick brown fox jumps over the lazy dog") is not None
_needs_ner = pytest.mark.skipif(
    not _NER_AVAILABLE, reason="spaCy NER unavailable; sanitize_page fail-closes to None"
)

_HOST = "http://meili.test:7700"
_UID = "onion_pages"


def _fake_embedder(text):
    """Deterministic 384-dim embedder — same shape as vector.embed_text."""
    if not text:
        return None
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [((digest[i % len(digest)] / 255.0) * 2.0) - 1.0 for i in range(384)]


class FakeMeiliClient:
    """In-memory stand-in for MeiliClient, keyed by content_hash (dedup model)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.last_search_body: dict | None = None
        self.ensured = False
        self.index_uid = _UID

    async def ensure_index(self, *, wait: bool = True):
        self.ensured = True

    async def add_documents(self, docs, *, wait: bool = True):
        for doc in docs:
            # Add-or-replace by primary key — exactly Meili's dedup semantics.
            self.store[doc[PRIMARY_KEY]] = doc
        return {"status": "succeeded"}

    async def get_document(self, doc_id):
        return self.store.get(doc_id)

    async def search(self, body):
        self.last_search_body = body
        q = (body.get("q") or "").lower()
        terms = [t for t in q.split() if t]
        hits = []
        for doc in self.store.values():
            haystack = f"{doc.get('title') or ''} {doc.get('content') or ''}".lower()
            if not terms or any(t in haystack for t in terms):
                hits.append(doc)
        return {"hits": hits[: body.get("limit", 20)]}


@pytest.fixture
def meili_configured(monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", _HOST, raising=False)
    monkeypatch.setattr(config, "MEILI_KEY", "test-key", raising=False)
    monkeypatch.setattr(config, "MEILI_INDEX", _UID, raising=False)


@pytest.fixture
def meili_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    monkeypatch.setattr(config, "MEILI_KEY", "", raising=False)


def _owned(fake=None):
    return OwnedIndex(fake or FakeMeiliClient(), embedder=_fake_embedder)


# ---------------------------------------------------------------------------
# Schema / document builder
# ---------------------------------------------------------------------------

@_needs_ner
def test_document_has_exact_1_3_schema_fields():
    doc = build_document(
        content_hash="a" * 64,
        url="http://abc.onion/page",
        content="darknet market vendor pgp key listing",
        title="Example Market",
        content_snapshot_ref="snapshots/aa/" + "a" * 64,
        first_seen=1_700_000_000,
        last_seen=1_700_000_500,
        liveness="alive",
        language="en",
        category="market",
        embedder=_fake_embedder,
    )
    assert doc is not None
    # Every requirement-1.3 stored field is present.
    for field in (
        "url",
        "title",
        "content_snapshot_ref",
        "content_hash",
        "first_seen",
        "last_seen",
        "liveness",
        "language",
        "category",
    ):
        assert field in doc
    # content_hash is the primary key (dedup key).
    assert PRIMARY_KEY == "content_hash"
    assert doc["content_hash"] == "a" * 64
    # Searchable text field present; user-provided vector attached under the
    # configured embedder name.
    assert doc["content"]
    assert set(SEARCHABLE_ATTRIBUTES) == {"title", "content"}
    assert set(FILTERABLE_ATTRIBUTES) == {
        "liveness",
        "language",
        "category",
        "first_seen",
        "last_seen",
    }
    assert len(doc["_vectors"]["default"]) == 384


@_needs_ner
def test_document_from_snapshot_joins_onion_metadata():
    snapshot = SimpleNamespace(
        content_hash="b" * 64,
        url="http://xyz.onion/",
        storage_ref="snapshots/bb/" + "b" * 64,
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        language="en",
        onion=None,
    )
    onion = SimpleNamespace(
        title="XYZ Forum",
        category="forum",
        status="dead",  # liveness lives on DiscoveredOnion.status
        language="en",
    )
    doc = document_from_snapshot(snapshot, "forum threads and posts", onion=onion)
    assert doc["content_hash"] == "b" * 64
    assert doc["url"] == "http://xyz.onion/"
    assert doc["content_snapshot_ref"] == "snapshots/bb/" + "b" * 64
    assert doc["title"] == "XYZ Forum"
    assert doc["category"] == "forum"
    assert doc["liveness"] == "dead"


def test_epoch_conversion_handles_datetime_and_none():
    from datetime import datetime, timezone

    assert schema_module.to_epoch(None) is None
    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert schema_module.to_epoch(dt) == int(dt.timestamp())
    assert schema_module.to_epoch(1234) == 1234


# ---------------------------------------------------------------------------
# The legal invariant: raw creds/PII can never enter the index
# ---------------------------------------------------------------------------

def test_index_ingests_only_sanitized_content(monkeypatch):
    """A raw credential fed to the builder never reaches the document.

    Robust to NER availability: with NER the credential is redacted (doc built,
    secret absent); without it the fail-closed gate drops the doc entirely. Both
    outcomes keep the raw secret out of the index. A spy proves the single shared
    sanitizer gate is the code path that decides this.
    """
    calls = {"n": 0}
    real = schema_module.sanitize_page

    def spy(text):
        calls["n"] += 1
        return real(text)

    monkeypatch.setattr(schema_module, "sanitize_page", spy)

    secret = "SuperSecretPassw0rd!"
    raw = f"login here\nusername: admin\npassword: {secret}\nemail admin@evil.onion"
    doc = build_document(
        content_hash="c" * 64,
        url="http://leak.onion/",
        content=raw,
        title="creds dump",
        embedder=_fake_embedder,
    )

    assert calls["n"] >= 1  # the single sanitization gate was invoked
    import json

    if doc is not None:
        assert secret not in json.dumps(doc)
    # else: the fail-closed gate dropped the page — the secret is likewise absent.


# ---------------------------------------------------------------------------
# Dedup by content_hash
# ---------------------------------------------------------------------------

@_needs_ner
async def test_reindexing_identical_content_never_duplicates():
    fake = FakeMeiliClient()
    idx = _owned(fake)

    # Identical content → identical content_hash upstream → same Meili primary key.
    digest = hashlib.sha256(b"identical sanitized content").hexdigest()
    for _ in range(3):
        ok = await idx.upsert_document(
            content_hash=digest,
            url="http://a.onion/",
            content="identical sanitized content about markets",
        )
        assert ok
    assert len(fake.store) == 1  # one document, not three

    # Different content hash → a distinct document.
    other = hashlib.sha256(b"different content").hexdigest()
    await idx.upsert_document(
        content_hash=other, url="http://b.onion/", content="different content"
    )
    assert len(fake.store) == 2


# ---------------------------------------------------------------------------
# Search — hybrid assembly + retrieval
# ---------------------------------------------------------------------------

async def test_search_assembles_hybrid_vector_query():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    await idx.search("ransomware leak site", semantic_ratio=0.7)

    body = fake.last_search_body
    assert body["q"] == "ransomware leak site"
    assert len(body["vector"]) == 384  # user-provided query vector
    assert body["hybrid"]["semanticRatio"] == 0.7
    assert body["hybrid"]["embedder"] == "default"


async def test_keyword_only_search_omits_vector():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    await idx.search("markets", keyword_only=True)
    assert "vector" not in fake.last_search_body
    assert "hybrid" not in fake.last_search_body


@_needs_ner
async def test_keyword_and_semantic_retrieval():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    digest = hashlib.sha256(b"vendor listing").hexdigest()
    await idx.upsert_document(
        content_hash=digest,
        url="http://mkt.onion/listing",
        content="market vendor listing with escrow payments and shipping",
        title="Vendor Listing",
        content_snapshot_ref="snapshots/vv/" + digest,
    )

    # Keyword retrieval.
    kw = await idx.search("escrow", keyword_only=True)
    assert [h.content_hash for h in kw] == [digest]
    assert kw[0].content_snapshot_ref == "snapshots/vv/" + digest

    # Hybrid (semantic) retrieval returns the same document and carries a vector.
    hy = await idx.search("vendor escrow")
    assert digest in [h.content_hash for h in hy]
    assert "vector" in fake.last_search_body


async def test_dict_filters_become_meili_filter_string():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    await idx.search(
        "x", filters={"liveness": "alive", "language": "en", "first_seen": 1000}
    )
    filt = fake.last_search_body["filter"]
    assert 'liveness = "alive"' in filt
    assert 'language = "en"' in filt
    assert "first_seen = 1000" in filt  # numbers unquoted for range/numeric filters
    assert " AND " in filt


async def test_string_filter_passes_through():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    await idx.search("x", filters="last_seen > 1700000000")
    assert fake.last_search_body["filter"] == "last_seen > 1700000000"


@_needs_ner
async def test_get_returns_hit_or_none():
    fake = FakeMeiliClient()
    idx = _owned(fake)
    digest = hashlib.sha256(b"one").hexdigest()
    await idx.upsert_document(
        content_hash=digest, url="http://a.onion/", content="alpha bravo charlie"
    )
    hit = await idx.get(digest)
    assert isinstance(hit, SearchHit) and hit.content_hash == digest
    assert await idx.get("f" * 64) is None


# ---------------------------------------------------------------------------
# Unconfigured → graceful no-op (local/$0 path falls back to live fan-out)
# ---------------------------------------------------------------------------

def test_from_config_none_when_unconfigured(meili_unconfigured):
    assert MeiliConfig.from_config() is None
    assert MeiliClient.from_config() is None
    assert OwnedIndex.from_config() is None


async def test_module_helpers_noop_when_unconfigured(meili_unconfigured):
    assert await index_module.ensure_index() is False
    snap = SimpleNamespace(content_hash="a" * 64, url="http://a.onion/", storage_ref=None)
    assert await index_module.index_snapshot(snap, "content") is False
    # Search returns [] so the caller falls back to live fan-out.
    assert await index_module.search_index("anything") == []


def test_from_config_reads_live_values(meili_configured):
    cfg = MeiliConfig.from_config()
    assert cfg is not None
    assert cfg.host == _HOST
    assert cfg.key == "test-key"
    assert cfg.index_uid == _UID


# ---------------------------------------------------------------------------
# Reuse: no new embedding service/dependency; ref→content via snapshot_store
# ---------------------------------------------------------------------------

def test_no_new_embedding_dependency():
    """The embedder is reused from vector/, not re-implemented (acceptance)."""
    pkg_dir = Path(index_module.__file__).parent
    sources = "\n".join(
        p.read_text(encoding="utf-8") for p in pkg_dir.glob("*.py")
    )
    # The one reuse point is an import of the existing embedder.
    assert "from vector import embed_text" in sources
    # No new embedding stack is stood up inside owned_index/.
    assert "sentence_transformers" not in sources
    assert "SentenceTransformer" not in sources
    assert "openai" not in sources.lower()


async def test_read_hit_content_resolves_via_snapshot_store(monkeypatch):
    async def fake_read(ref):
        return b"sanitized-bytes" if ref else None

    import snapshot_store

    monkeypatch.setattr(snapshot_store, "read_snapshot", fake_read)
    hit = SearchHit(content_hash="d" * 64, content_snapshot_ref="snapshots/dd/" + "d" * 64)
    assert await index_module.read_hit_content(hit) == b"sanitized-bytes"
    # A hit with no ref resolves to nothing (no crash).
    assert await index_module.read_hit_content(SearchHit(content_hash="e" * 64)) is None


# ---------------------------------------------------------------------------
# Transport: real MeiliClient with HTTP mocked (aioresponses)
# ---------------------------------------------------------------------------

def test_headers_include_bearer_only_when_key_set():
    with_key = MeiliClient(MeiliConfig(host=_HOST, key="k", index_uid=_UID))
    assert with_key._headers()["Authorization"] == "Bearer k"
    keyless = MeiliClient(MeiliConfig(host=_HOST, key="", index_uid=_UID))
    assert "Authorization" not in keyless._headers()


async def test_client_add_documents_waits_for_task():
    client = MeiliClient(MeiliConfig(host=_HOST, key="k", index_uid=_UID))
    with aioresponses() as m:
        m.post(
            f"{_HOST}/indexes/{_UID}/documents",
            status=202,
            payload={"taskUid": 7, "status": "enqueued"},
        )
        m.get(
            f"{_HOST}/tasks/7",
            status=200,
            payload={"uid": 7, "status": "succeeded"},
        )
        result = await client.add_documents([{"content_hash": "a" * 64}])
    assert result["status"] == "succeeded"


async def test_client_search_returns_hits():
    client = MeiliClient(MeiliConfig(host=_HOST, key="k", index_uid=_UID))
    with aioresponses() as m:
        m.post(
            f"{_HOST}/indexes/{_UID}/search",
            status=200,
            payload={"hits": [{"content_hash": "a" * 64, "url": "http://a.onion/"}]},
        )
        out = await client.search({"q": "x"})
    assert out["hits"][0]["content_hash"] == "a" * 64


async def test_client_get_document_404_is_none():
    client = MeiliClient(MeiliConfig(host=_HOST, key="k", index_uid=_UID))
    with aioresponses() as m:
        m.get(f"{_HOST}/indexes/{_UID}/documents/{'a' * 64}", status=404, payload={})
        assert await client.get_document("a" * 64) is None


async def test_client_ensure_index_creates_and_configures():
    client = MeiliClient(MeiliConfig(host=_HOST, key="k", index_uid=_UID))
    with aioresponses() as m:
        m.post(f"{_HOST}/indexes", status=202, payload={"taskUid": 1})
        m.patch(
            re.compile(rf"{re.escape(_HOST)}/indexes/{_UID}/settings.*"),
            status=202,
            payload={"taskUid": 2},
            repeat=True,
        )
        m.patch(f"{_HOST}/experimental-features", status=200, payload={}, repeat=True)
        m.get(
            re.compile(rf"{re.escape(_HOST)}/tasks/.*"),
            status=200,
            payload={"status": "succeeded"},
            repeat=True,
        )
        # Should complete without raising.
        await client.ensure_index()


# ---------------------------------------------------------------------------
# Real Meilisearch integration — gated; skips without MEILI_TEST_URL.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.getenv("MEILI_TEST_URL"),
    reason="set MEILI_TEST_URL (and optional MEILI_TEST_KEY) to run against real Meilisearch",
)
@_needs_ner
async def test_real_meili_end_to_end(monkeypatch):
    monkeypatch.setattr(config, "MEILI_HOST", os.environ["MEILI_TEST_URL"], raising=False)
    monkeypatch.setattr(config, "MEILI_KEY", os.getenv("MEILI_TEST_KEY", ""), raising=False)
    monkeypatch.setattr(config, "MEILI_INDEX", "onion_pages_test", raising=False)

    idx = OwnedIndex.from_config()  # real embedder (vector.embed_text)
    assert idx is not None
    await idx.client.delete_all_documents()
    await idx.ensure_ready()

    digest = hashlib.sha256(b"real meili integration content").hexdigest()
    content = "acme ransomware group leak site with victim listings and bitcoin address"
    ok = await idx.upsert_document(
        content_hash=digest,
        url="http://acme.onion/leaks",
        content=content,
        title="ACME Leaks",
        content_snapshot_ref="snapshots/" + digest[:2] + "/" + digest,
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        liveness="alive",
        language="en",
        category="ransomware",
    )
    assert ok

    # Read back.
    hit = await idx.get(digest)
    assert hit is not None and hit.url == "http://acme.onion/leaks"

    # Keyword retrieval.
    kw = await idx.search("ransomware", keyword_only=True)
    assert digest in [h.content_hash for h in kw]

    # Hybrid (semantic) retrieval.
    hy = await idx.search("ransomware group leak")
    assert digest in [h.content_hash for h in hy]

    # Dedup: re-index identical content → still one document.
    await idx.upsert_document(content_hash=digest, url="http://acme.onion/leaks", content=content)
    again = await idx.search("ransomware", keyword_only=True)
    assert [h.content_hash for h in again].count(digest) == 1

    await idx.client.delete_all_documents()


@pytest.mark.skipif(
    not os.getenv("MEILI_TEST_URL"),
    reason="set MEILI_TEST_URL (and optional MEILI_TEST_KEY) to run against real Meilisearch",
)
@_needs_ner
async def test_real_meili_g_p3c_no_creds_or_pii_in_index(monkeypatch):
    """G-P3c (legal line) — raw creds/PII never reach the real index.

    Upserts content laced with a credential combo, an AWS secret, and victim PII
    (name/email/phone) through the NORMAL (non-presanitized) path, then reads the
    stored document straight back from Meilisearch and asserts none of the
    secrets/PII survive in the searchable ``content``.
    """
    monkeypatch.setattr(config, "MEILI_HOST", os.environ["MEILI_TEST_URL"], raising=False)
    monkeypatch.setattr(config, "MEILI_KEY", os.getenv("MEILI_TEST_KEY", ""), raising=False)
    monkeypatch.setattr(config, "MEILI_INDEX", "onion_pages_p3c_test", raising=False)

    idx = OwnedIndex.from_config()
    assert idx is not None
    await idx.ensure_ready()
    await idx.client.delete_all_documents()

    PASSWORD = "SuperSecret123!"
    AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    VICTIM_EMAIL = "john.smith@acme-victim.com"
    VICTIM_PHONE = "+1-202-555-0173"
    content = (
        "Leak dump from acme ransomware group. "
        f"Corp login {VICTIM_EMAIL}:{PASSWORD} for the admin panel. "
        f"AWS creds AKIAIOSFODNN7EXAMPLE / {AWS_SECRET}. "
        f"Contact victim John Smith at {VICTIM_PHONE}."
    )
    digest = hashlib.sha256(content.encode()).hexdigest()

    stored = await idx.upsert_document(
        content_hash=digest,
        url="http://acme.onion/leak",
        content=content,           # NOT presanitized — the gate must run
        title="ACME leak",
        liveness="alive",
        language="en",
        category="ransomware",
    )

    forbidden = [PASSWORD, AWS_SECRET, VICTIM_EMAIL, VICTIM_PHONE]
    if not stored:
        # The gate dropped the page entirely — nothing reached the index. Safe.
        assert await idx.get(digest) is None
    else:
        hit = await idx.get(digest)
        assert hit is not None
        blob = (getattr(hit, "content", "") or "") + " " + (getattr(hit, "title", "") or "")
        for secret in forbidden:
            assert secret not in blob, f"leaked into index: {secret!r}"

    await idx.client.delete_all_documents()
