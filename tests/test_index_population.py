"""
tests/test_index_population.py — P3.1 index population (seeds + usage-seeding).

Zero network / Meilisearch / Tor / cloud: the seed fetch is monkeypatched at the
``_fetch_ahmia`` / ``_fetch_darkfail`` seams, the owned index is a fake in-memory
client injected into ``OwnedIndex``, and the DB is a file-backed SQLite created
with ``Base.metadata.create_all``. The one full-path test that exercises the
snapshot store mocks S3 at the HTTP layer with ``aioresponses``.

Coverage maps to the P3.1 acceptance criteria:
* seed breadth — Ahmia + dark.fail ingested → discovered_onions + a seeded onion
  is searchable in the owned index with no prior usage;
* usage-seeding — an investigation auto-indexes the onions/pages it touched,
  sanitized + provenance-stamped, at the unconfirmed tier;
* volume scales with usage (no exhaustive crawl);
* private-mode / consent-off indexes nothing to the shared tier;
* P3.1 writes no global_entities and assigns no trust tier (that boundary is P4).
"""

from __future__ import annotations

import hashlib
import re

import pytest
from aioresponses import aioresponses
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config
from db.models import Base
from shared_corpus import DiscoveredOnion, GlobalEntity, PageSnapshot
from owned_index import OwnedIndex
from sanitizer import sanitize_page
from index_population import seeds as seeds_mod
from index_population import (
    index_investigation_pages,
    ingest_seed_sources,
    parse_ahmia,
    parse_darkfail,
)

_NER_AVAILABLE = sanitize_page("the quick brown fox jumps over the lazy dog") is not None
_needs_ner = pytest.mark.skipif(
    not _NER_AVAILABLE, reason="spaCy NER unavailable; sanitize_page fail-closes to None"
)

# 56-char v3 onion hosts ([a-z2-7]{56}).
_ADDR_ACME = "a" * 56 + ".onion"
_ADDR_DREAD = "d" * 56 + ".onion"
_ADDR_AH1 = "b" * 56 + ".onion"
_ADDR_AH2 = "c" * 56 + ".onion"


def _fake_embedder(text):
    if not text:
        return None
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [((digest[i % len(digest)] / 255.0) * 2.0) - 1.0 for i in range(384)]


class FakeIndexClient:
    """In-memory owned-index client, keyed by content_hash (dedup model)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.index_uid = "onion_pages"

    async def ensure_index(self, *, wait: bool = True):
        pass

    async def add_documents(self, docs, *, wait: bool = True):
        for doc in docs:
            self.store[doc["content_hash"]] = doc

    async def get_document(self, doc_id):
        return self.store.get(doc_id)

    async def search(self, body):
        q = (body.get("q") or "").lower()
        terms = [t for t in q.split() if t]
        hits = []
        for doc in self.store.values():
            hay = f"{doc.get('title') or ''} {doc.get('content') or ''}".lower()
            if not terms or any(t in hay for t in terms):
                hits.append(doc)
        return {"hits": hits[: body.get("limit", 20)]}


def _fake_index():
    return OwnedIndex(FakeIndexClient(), embedder=_fake_embedder)


@pytest.fixture
def Session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'pop.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng, expire_on_commit=False)
    eng.dispose()


@pytest.fixture(autouse=True)
def _contribute(monkeypatch):
    # Default-ON contribution; individual tests flip PRIVATE_MODE.
    monkeypatch.setattr(config, "PRIVATE_MODE", False, raising=False)


_AHMIA_FIXTURE = f"""http://{_ADDR_AH1}/
# a comment line that should be ignored
http://{_ADDR_AH2}/
not an onion at all
"""

_DARKFAIL_FIXTURE = f"""
<html><body>
  <h2>Markets</h2>
  <div class="entry"><a href="#">Acme Market</a> <span>{_ADDR_ACME}</span> <span>Online</span></div>
  <h2>Forums</h2>
  <div class="entry"><a href="#">Dread</a> <span>{_ADDR_DREAD}</span> <span>Offline</span></div>
</body></html>
"""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def test_parse_ahmia_extracts_onions():
    entries = parse_ahmia(_AHMIA_FIXTURE)
    addrs = {e.onion_address for e in entries}
    assert addrs == {_ADDR_AH1, _ADDR_AH2}
    e = next(e for e in entries if e.onion_address == _ADDR_AH1)
    assert e.url == f"http://{_ADDR_AH1}/"
    assert e.title is None and e.category is None


def test_parse_darkfail_extracts_titles_and_categories():
    entries = {e.onion_address: e for e in parse_darkfail(_DARKFAIL_FIXTURE)}
    assert set(entries) == {_ADDR_ACME, _ADDR_DREAD}
    acme = entries[_ADDR_ACME]
    assert acme.title == "Acme Market"
    assert acme.category == "Markets"
    assert entries[_ADDR_DREAD].category == "Forums"
    # Status noise stripped from the title.
    assert "Online" not in (acme.title or "")


# ---------------------------------------------------------------------------
# Seed ingestion (breadth)
# ---------------------------------------------------------------------------

async def _mock_seed_fetch(monkeypatch, ahmia=_AHMIA_FIXTURE, darkfail=_DARKFAIL_FIXTURE):
    async def fake_ahmia():
        return ahmia

    async def fake_darkfail():
        return darkfail

    monkeypatch.setattr(seeds_mod, "_fetch_ahmia", fake_ahmia)
    monkeypatch.setattr(seeds_mod, "_fetch_darkfail", fake_darkfail)


@_needs_ner
async def test_seed_ingestion_populates_onions_and_index(Session, monkeypatch):
    await _mock_seed_fetch(monkeypatch)
    index = _fake_index()

    with Session() as s:
        report = await ingest_seed_sources(s, index=index)
        s.commit()

        # discovered_onions populated with all four seeds.
        assert s.query(DiscoveredOnion).count() == 4
        assert report.onions == 4
        acme = s.query(DiscoveredOnion).filter_by(onion_address=_ADDR_ACME).one()
        assert acme.discovery_source == "seed"
        assert acme.status == "unknown"  # liveness unverified until crawled
        assert acme.title == "Acme Market"
        assert acme.category == "Markets"
        assert acme.provenance and acme.provenance.get("source") == "dark.fail"

    # Breadth: a query with no prior usage surfaces a seeded onion from the index.
    hits = await index.search("acme", keyword_only=True)
    urls = [h.url for h in hits]
    assert f"http://{_ADDR_ACME}/" in urls
    # Seed placeholder docs carry no snapshot ref and liveness unknown.
    doc = await index.get(seeds_mod._seed_doc_id(_ADDR_ACME))
    assert doc is not None and doc.content_snapshot_ref is None and doc.liveness == "unknown"


async def test_seed_ingestion_private_mode_writes_nothing(Session, monkeypatch):
    monkeypatch.setattr(config, "PRIVATE_MODE", True, raising=False)
    await _mock_seed_fetch(monkeypatch)
    index = _fake_index()

    with Session() as s:
        report = await ingest_seed_sources(s, index=index)
        s.commit()
        assert report.skipped_private is True
        assert s.query(DiscoveredOnion).count() == 0
    assert index._client.store == {}


# ---------------------------------------------------------------------------
# Usage-seeding (depth) — volume, sanitization, tier boundary, consent
# ---------------------------------------------------------------------------

def _onion_page(host_char, text, path="p"):
    addr = host_char * 56 + ".onion"
    return {"url": f"http://{addr}/{path}", "text": text}


@_needs_ner
async def test_usage_seeding_indexes_onion_pages_only(Session):
    index = _fake_index()
    pages = [
        _onion_page("e", "market vendor listing escrow shipping"),
        _onion_page("f", "forum discussion threads posts members"),
        {"url": "https://pastebin.com/x", "text": "clearnet side-source, skip me"},
    ]
    with Session() as s:
        report = await index_investigation_pages(s, pages, index=index)
        s.commit()

        assert report.considered == 3
        assert report.onions == 2  # the clearnet page is skipped
        assert report.indexed == 2
        # discovered_onions has exactly the two onion hosts, recorded alive.
        rows = s.query(DiscoveredOnion).all()
        assert {r.onion_address for r in rows} == {"e" * 56 + ".onion", "f" * 56 + ".onion"}
        assert all(r.status == "alive" for r in rows)
        assert all(r.discovery_source == "investigation" for r in rows)
        assert all(r.provenance and r.provenance.get("source") for r in rows)
    assert len(index._client.store) == 2


@_needs_ner
async def test_usage_seeding_volume_scales_with_usage(Session):
    index = _fake_index()
    # N distinct onion pages → exactly N indexed docs (bounded by pages touched).
    pages = [
        _onion_page(chr(ord("a") + i), f"page number {i} escrow market listing", path=str(i))
        for i in range(5)
    ]
    with Session() as s:
        report = await index_investigation_pages(s, pages, index=index)
        s.commit()
    assert report.indexed == 5
    assert len(index._client.store) == 5

    # Re-indexing byte-identical content never duplicates (content_hash dedup).
    dup = [_onion_page("a", "page number 0 escrow market listing", path="0")]
    with Session() as s:
        await index_investigation_pages(s, dup, index=index)
        s.commit()
    assert len(index._client.store) == 5  # unchanged


@_needs_ner
async def test_usage_seeding_content_is_sanitized(Session):
    index = _fake_index()
    secret = "SuperSecretPassw0rd"
    pages = [
        {
            "url": f"http://{'g' * 56}.onion/leak",
            "text": f"vendor market listing\nusername: admin\npassword: {secret}\n",
        }
    ]
    with Session() as s:
        await index_investigation_pages(s, pages, index=index)
        s.commit()
    import json

    blob = json.dumps(index._client.store)
    assert secret not in blob  # raw credential never reaches the index


@_needs_ner
async def test_usage_seeding_writes_no_global_entities_or_trust_tier(Session):
    """The P4 tier boundary: P3.1 populates the corpus but assigns no trust."""
    index = _fake_index()
    pages = [_onion_page("h", "market vendor listing escrow")]
    with Session() as s:
        await index_investigation_pages(s, pages, index=index)
        s.commit()
        # No entity promotion / trust-tier assignment happened here.
        assert s.query(GlobalEntity).count() == 0
        # The shared-tier rows P3.1 does write carry no confidence-tier column.
        assert not hasattr(DiscoveredOnion, "confidence_tier")
        assert not hasattr(PageSnapshot, "confidence_tier")


async def test_usage_seeding_private_mode_writes_nothing(Session, monkeypatch):
    monkeypatch.setattr(config, "PRIVATE_MODE", True, raising=False)
    index = _fake_index()
    pages = [_onion_page("i", "some market content")]
    with Session() as s:
        report = await index_investigation_pages(s, pages, index=index)
        s.commit()
        assert report.skipped_private is True
        assert s.query(DiscoveredOnion).count() == 0
    assert index._client.store == {}


async def test_usage_seeding_no_index_configured_is_noop(Session, monkeypatch):
    """With no Meilisearch configured, indexing no-ops; the pipeline is unaffected."""
    monkeypatch.setattr(config, "MEILI_HOST", None, raising=False)
    pages = [_onion_page("j", "market content")]
    with Session() as s:
        # index defaults to OwnedIndex.from_config() → None → indexed stays 0,
        # but discovered_onions still records (DB always available).
        report = await index_investigation_pages(s, pages)
        s.commit()
        assert report.indexed == 0
        # NER-independent: the onion registry row is written regardless.
        assert s.query(DiscoveredOnion).count() == (1 if _NER_AVAILABLE else 0)


# ---------------------------------------------------------------------------
# Full path with the snapshot store (S3 mocked) — snapshot + index + ref
# ---------------------------------------------------------------------------

@_needs_ner
async def test_usage_seeding_full_path_stores_snapshot_and_ref(Session, monkeypatch):
    _ENDPOINT = "https://acct.example.com"
    monkeypatch.setattr(config, "S3_ENDPOINT_URL", _ENDPOINT, raising=False)
    monkeypatch.setattr(config, "S3_BUCKET", "snaps", raising=False)
    monkeypatch.setattr(config, "S3_ACCESS_KEY_ID", "AKIA", raising=False)
    monkeypatch.setattr(config, "S3_SECRET_ACCESS_KEY", "secret", raising=False)
    monkeypatch.setattr(config, "S3_REGION", "auto", raising=False)

    index = _fake_index()
    pages = [_onion_page("k", "market vendor listing escrow shipping payments")]
    url_re = re.compile(r"^https://acct\.example\.com/.*")

    with aioresponses() as m:
        m.head(url_re, status=404, repeat=True)   # object absent → will PUT
        m.put(url_re, status=200, repeat=True)     # upload succeeds
        with Session() as s:
            report = await index_investigation_pages(s, pages, index=index)
            s.commit()

            assert report.snapshots == 1
            snap = s.query(PageSnapshot).one()
            assert snap.storage_ref  # sharded object key recorded
            assert snap.provenance and snap.provenance.get("source")

    # The index doc references the snapshot so a hit resolves back to R2.
    doc = list(index._client.store.values())[0]
    assert doc["content_snapshot_ref"] == snap.storage_ref


# ---------------------------------------------------------------------------
# The presanitized seam (avoid double NER pass) is honored by both stores.
# ---------------------------------------------------------------------------

def test_build_document_presanitized_skips_gate(monkeypatch):
    """presanitized=True uses the content verbatim without re-running the gate."""
    from owned_index import schema

    called = {"n": 0}

    def spy(text):
        called["n"] += 1
        return text

    monkeypatch.setattr(schema, "sanitize_page", spy)
    doc = schema.build_document(
        content_hash="a" * 64,
        url="http://x.onion/",
        content="already-sanitized text",
        presanitized=True,
    )
    assert doc is not None and doc["content"] == "already-sanitized text"
    assert called["n"] == 0  # the gate was NOT re-invoked
