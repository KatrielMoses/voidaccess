"""Offline tests for the P1.4 blocklist-feed cluster (feeds/).

No network: each feed's ``_fetch_text`` seam is monkeypatched to return canned feed
text; ``_cached_index`` is reset per test.
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock

import pytest

import feeds


_SHA1 = "a" * 40

_SSLBL_CSV = (
    "# abuse.ch SSLBL\n"
    "Firstseen,SHA1,Listingreason\n"
    f"2024-01-01 00:00:00,{_SHA1},MalwareX C2\n"
)
_OPENPHISH_TXT = "http://evil.example.com/login\nhttps://1.2.3.4/verify\n"
_PHISHTANK_CSV = "phish_id,url,target\n1,http://phish.example.net/pay,Bank\n"


def _use_feed(monkeypatch, feed, text):
    monkeypatch.setattr(feed, "_cached_index", None)
    monkeypatch.setattr(feed, "_fetch_text", AsyncMock(return_value=text))


# --------------------------------------------------------------------------- #
# One fetch, zero per-entity network
# --------------------------------------------------------------------------- #
async def test_feed_fetched_once_for_many_entities(monkeypatch):
    fetch = AsyncMock(return_value=_OPENPHISH_TXT)
    monkeypatch.setattr(feeds.OPENPHISH, "_cached_index", None)
    monkeypatch.setattr(feeds.OPENPHISH, "_fetch_text", fetch)

    entities = [{"entity_type": "DOMAIN", "value": f"host{i}.com"} for i in range(50)]
    entities.append({"entity_type": "DOMAIN", "value": "evil.example.com"})
    matches = await feeds.OPENPHISH.match(entities)

    assert [m[0]["value"] for m in matches] == ["evil.example.com"]
    assert fetch.call_count == 1  # one feed fetch served all 51 entities


# --------------------------------------------------------------------------- #
# Flagging: phishing domain + malicious cert fingerprint
# --------------------------------------------------------------------------- #
async def test_openphish_flags_domain_and_ip(monkeypatch):
    _use_feed(monkeypatch, feeds.OPENPHISH, _OPENPHISH_TXT)
    entities = [
        {"entity_type": "DOMAIN", "value": "evil.example.com"},
        {"entity_type": "IP_ADDRESS", "value": "1.2.3.4"},
        {"entity_type": "DOMAIN", "value": "clean.com"},
    ]
    matches = await feeds.OPENPHISH.match(entities)
    hit_values = {m[0]["value"] for m in matches}
    assert hit_values == {"evil.example.com", "1.2.3.4"}
    tags = matches[0][1]
    assert "phishing" in tags and "phishing_openphish" in tags and "feed:openphish" in tags


async def test_sslbl_flags_cert_fingerprint(monkeypatch):
    _use_feed(monkeypatch, feeds.SSLBL, _SSLBL_CSV)
    entities = [
        {"entity_type": "FILE_HASH_SHA1", "value": _SHA1.upper()},  # case-insensitive
        {"entity_type": "FILE_HASH_SHA1", "value": "b" * 40},
    ]
    matches = await feeds.SSLBL.match(entities)
    assert [m[0]["value"] for m in matches] == [_SHA1.upper()]
    assert set(matches[0][1]) == {"malicious_cert", "malicious_cert_sslbl", "feed:sslbl"}


# --------------------------------------------------------------------------- #
# skipped_no_key + feed-down
# --------------------------------------------------------------------------- #
async def test_phishtank_skipped_without_key(monkeypatch):
    monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
    monkeypatch.setattr(feeds.PHISHTANK, "_cached_index", None)
    # If the gate failed it would try to fetch; make that fail loudly.
    monkeypatch.setattr(feeds.PHISHTANK, "_fetch_text",
                        AsyncMock(side_effect=AssertionError("must not fetch without key")))
    matches = await feeds.PHISHTANK.match([{"entity_type": "DOMAIN", "value": "x.com"}])
    assert matches == []
    assert feeds.PHISHTANK.status() == "skipped_no_key"


async def test_feed_down_is_graceful(monkeypatch):
    monkeypatch.setattr(feeds.OPENPHISH, "_cached_index", None)
    monkeypatch.setattr(feeds.OPENPHISH, "_fetch_text", AsyncMock(side_effect=RuntimeError("down")))
    matches = await feeds.OPENPHISH.match([{"entity_type": "DOMAIN", "value": "evil.example.com"}])
    assert matches == []
    assert feeds.OPENPHISH.status() == "unavailable"


# --------------------------------------------------------------------------- #
# Provenance + license on every artifact + hygiene
# --------------------------------------------------------------------------- #
async def test_enrich_blocklists_stamps_provenance_and_defangs(monkeypatch):
    _use_feed(monkeypatch, feeds.OPENPHISH, _OPENPHISH_TXT)
    _use_feed(monkeypatch, feeds.SSLBL, "")            # empty → no matches
    monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)  # skipped_no_key

    entities = [{"entity_type": "IP_ADDRESS", "value": "1.2.3.4"}]
    pages, stats = await feeds.enrich_blocklists(entities)

    assert len(pages) == 1
    page = pages[0]
    # Structured provenance + license stamp at ingest.
    assert page["provenance"]["feed"] == "openphish"
    assert page["provenance"]["license"] == "OpenPhish Community (non-commercial use)"
    assert page["source"] == "openphish"
    # IOC defanged in the page content (hygiene).
    assert "1.2.3[.]4" in page["content"]
    # Stats report status per feed, incl. skipped_no_key (never a silent ok_0).
    assert stats["phishtank"]["status"] == "skipped_no_key"
    assert stats["openphish"]["count"] == 1


_RANSOMWHERE_JSON = (
    '{"result":['
    '{"address":"1MixedCaseWalletAbc123","family":"Conti Ransomware"},'
    '{"address":"bc1qexamplewallet0001","family":"LockBit"}'
    ']}'
)


async def test_ransomwhere_flags_wallet_case_sensitive_with_family_and_provenance(monkeypatch):
    from unittest.mock import AsyncMock as _AM

    fetch = _AM(return_value=_RANSOMWHERE_JSON)
    monkeypatch.setattr(feeds.RANSOMWHERE, "_cached_index", None)
    monkeypatch.setattr(feeds.RANSOMWHERE, "_fetch_text", fetch)

    entities = [
        {"entity_type": "BITCOIN_ADDRESS", "value": "1MixedCaseWalletAbc123"},  # exact case
        {"entity_type": "BITCOIN_ADDRESS", "value": "1mixedcasewalletabc123"},  # lowered — must NOT match
    ] + [{"entity_type": "BITCOIN_ADDRESS", "value": f"1clean{i}"} for i in range(30)]

    matches = await feeds.RANSOMWHERE.match(entities)
    assert [m[0]["value"] for m in matches] == ["1MixedCaseWalletAbc123"]  # case preserved
    tags = matches[0][1]
    assert "ransom_wallet" in tags
    assert "ransom_wallet_conti_ransomware" in tags  # dynamic family tag
    assert "feed:ransomwhere" in tags
    # One feed fetch served all 32 wallets — zero per-entity network.
    assert fetch.call_count == 1

    # Provenance stamp present on the emitted page.
    page = feeds._feed_page(feeds.RANSOMWHERE, matches)
    assert page["provenance"]["feed"] == "ransomwhere"
    assert page["provenance"]["attribution"] == "ransomwhe.re"


def test_license_registry_has_attribution_for_cc_by():
    assert feeds.LICENSES["ransomlook"]["license"] == "CC BY 4.0"
    assert feeds.provenance("ransomlook")["attribution"]


def test_ransomlook_pages_carry_cc_by_attribution():
    from sources.enrichment import ransomlook_to_pages

    pages = ransomlook_to_pages([{"group": "LockBit", "description": "d", "onion_urls": [], "victims": []}])
    summary = pages[0]
    assert "CC BY 4.0" in summary["content"]
    assert "ransomlook.io" in summary["content"]
    assert summary["provenance"]["license"] == "CC BY 4.0"


# --------------------------------------------------------------------------- #
# Entity write-back
# --------------------------------------------------------------------------- #
async def test_write_back_flags_matched_entity(db_engine, monkeypatch):
    from db.models import Entity, Page, Investigation
    from db.session import get_session

    _use_feed(monkeypatch, feeds.OPENPHISH, _OPENPHISH_TXT)
    _use_feed(monkeypatch, feeds.SSLBL, "")
    monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)

    inv_id = uuid.uuid4()
    page_id = uuid.uuid4()
    with get_session() as s:
        s.add(Investigation(id=inv_id, query="q", status="completed"))
        s.add(Page(id=page_id, url="http://x"))
        s.add(Entity(id=uuid.uuid4(), page_id=page_id, investigation_id=inv_id,
                     entity_type="DOMAIN", value="evil.example.com",
                     canonical_value="evil.example.com", confidence=1.0))
        s.commit()

    await feeds.enrich_blocklists([{"entity_type": "DOMAIN", "value": "evil.example.com"}])

    with get_session() as s:
        row = s.query(Entity).filter(Entity.value == "evil.example.com").first()
        tags = json.loads(row.corroborating_sources or "[]")
    assert "phishing" in tags
    assert "feed:openphish" in tags
