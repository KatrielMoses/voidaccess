"""Offline tests for VOIDACCESS_ENRICHMENT_SOURCES (sources/enrichment_allowlist.py).

No real network: fetchers are mocked, or aioresponses asserts zero requests.
"""
from __future__ import annotations

import re
from unittest.mock import AsyncMock, patch

import pytest
from aioresponses import aioresponses

from sources import enrichment as enr
from sources import cve_intel
from sources import enrichment_allowlist as al
from sources.enrichment_allowlist import (
    CLOUD_ENRICHMENT_SOURCES,
    ENRICHMENT_SOURCE_IDS,
    EnrichmentAllowlistError,
    get_enrichment_allowlist,
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from tests.conftest import FakeEntity, make_results

ENV = "VOIDACCESS_ENRICHMENT_SOURCES"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    al.reset_enrichment_allowlist_state()
    yield
    al.reset_enrichment_allowlist_state()


# --------------------------------------------------------------------------- #
# registry / parsing
# --------------------------------------------------------------------------- #
def test_unset_and_blank_mean_no_restriction(monkeypatch):
    assert get_enrichment_allowlist() is None
    for blank in ("", "   ", " , ,"):
        monkeypatch.setenv(ENV, blank)
        assert get_enrichment_allowlist() is None
    assert all(is_enrichment_source_enabled(sid) for sid in ENRICHMENT_SOURCE_IDS)


def test_case_and_whitespace_tolerance(monkeypatch):
    monkeypatch.setenv(ENV, "  NVD , Cisa_KEV,, ")
    assert get_enrichment_allowlist() == frozenset({"nvd", "cisa_kev"})
    assert is_enrichment_source_enabled("nvd")
    assert not is_enrichment_source_enabled("otx")


def test_unknown_id_error_names_bad_and_lists_valid(monkeypatch):
    monkeypatch.setenv(ENV, "nvd,nvdd,otxx")
    with pytest.raises(EnrichmentAllowlistError) as ei:
        get_enrichment_allowlist()
    msg = str(ei.value)
    assert "nvdd" in msg and "otxx" in msg
    for sid in ("nvd", "cisa_kev", "rdap"):
        assert sid in msg
    assert isinstance(ei.value, ValueError)
    with pytest.raises(EnrichmentAllowlistError):
        validate_enrichment_allowlist()


def test_unregistered_call_site_id_is_rejected():
    with pytest.raises(EnrichmentAllowlistError):
        is_enrichment_source_enabled("not_a_source")


def test_cloud_value_ids_all_registered():
    ids = CLOUD_ENRICHMENT_SOURCES.split(",")
    assert set(ids) == {"rdap", "crtsh", "wayback", "cisa_kev", "nvd", "mitre_attack", "ransomlook"}
    assert "ransomware_live" not in ids  # T&C: no commercial use without approval
    assert all(i in ENRICHMENT_SOURCE_IDS for i in ids)


def test_required_ids_registered():
    required = (
        "otx malwarebazaar threatfox urlhaus ransomware_live ransomlook cisa_kev nvd epss "
        "exploitdb shodan_internetdb virustotal mitre_attack blocklists feodo_tracker "
        "c2_tracker abuseipdb greynoise crtsh wayback urlscan hybrid_analysis hibp emailrep "
        "disposable_email xposedornot leakcheck hudsonrock rdap circl securitytrails "
        "blockcypher etherscan hibp_pwned_passwords"
    ).split()
    assert not [r for r in required if r not in ENRICHMENT_SOURCE_IDS]


# --------------------------------------------------------------------------- #
# enrich_investigation fan-out
# --------------------------------------------------------------------------- #
def _patch_all():
    """Patch every fan-out fetcher; returns (stack-of-patches, mocks by name)."""
    mocks = {
        "otx": AsyncMock(return_value=[]),
        "malwarebazaar": AsyncMock(return_value=[]),
        "threatfox": AsyncMock(return_value=[]),
        "urlhaus": AsyncMock(return_value=[]),
        "ransomware_live": AsyncMock(return_value=[]),
        "ransomlook": AsyncMock(return_value=[]),
        "cisa_kev": AsyncMock(return_value=[]),
        "nvd": AsyncMock(return_value=[]),
        "shodan_internetdb": AsyncMock(return_value=[]),
        "virustotal": AsyncMock(return_value=[]),
        "fusion": AsyncMock(return_value=[]),
        "blocklists": AsyncMock(return_value=([], {})),
    }
    patches = [
        patch.object(enr, "fetch_otx_pulses", mocks["otx"]),
        patch.object(enr, "fetch_malwarebazaar", mocks["malwarebazaar"]),
        patch.object(enr, "fetch_threatfox", mocks["threatfox"]),
        patch.object(enr, "fetch_urlhaus", mocks["urlhaus"]),
        patch.object(enr, "fetch_ransomware_live", mocks["ransomware_live"]),
        patch.object(enr, "fetch_ransomlook", mocks["ransomlook"]),
        patch("sources.cisa.enrich_cisa", mocks["cisa_kev"]),
        patch("sources.nvd.enrich_nvd", mocks["nvd"]),
        patch("sources.shodan.enrich_shodan", mocks["shodan_internetdb"]),
        patch("sources.virustotal.enrich_virustotal", mocks["virustotal"]),
        patch("sources.cve_intel.fuse_cve_intelligence", mocks["fusion"]),
        patch("feeds.enrich_blocklists", mocks["blocklists"]),
    ]
    return patches, mocks


async def _run(env: str | None, monkeypatch):
    if env is not None:
        monkeypatch.setenv(ENV, env)
    patches, mocks = _patch_all()
    for p in patches:
        p.start()
    try:
        pages = await enr.enrich_investigation("lockbit", otx_api_key="k", entities=[])
    finally:
        for p in patches:
            p.stop()
    return pages, mocks


async def test_unset_invokes_every_fetcher(monkeypatch):
    _, mocks = await _run(None, monkeypatch)
    for name, m in mocks.items():
        assert m.await_count == 1, name


async def test_allowlist_restricts_fetchers(monkeypatch):
    _, mocks = await _run("nvd,cisa_kev", monkeypatch)
    called = {n for n, m in mocks.items() if m.await_count}
    assert {"nvd", "cisa_kev", "fusion"} <= called
    for name in ("otx", "malwarebazaar", "threatfox", "urlhaus", "ransomware_live",
                 "ransomlook", "shodan_internetdb", "virustotal"):
        assert mocks[name].await_count == 0, name
        assert mocks[name].call_count == 0, name  # no coroutine even created
    assert mocks["blocklists"].await_count == 1  # reached, but each feed gates itself


async def test_all_fan_out_sources_disabled_does_not_crash(monkeypatch):
    pages, mocks = await _run("rdap", monkeypatch)
    assert pages == []
    for name in ("otx", "malwarebazaar", "ransomlook", "nvd", "cisa_kev", "shodan_internetdb"):
        assert mocks[name].call_count == 0


async def test_unknown_id_not_swallowed_by_enrich_investigation(monkeypatch):
    monkeypatch.setenv(ENV, "nvd,bogus_src")
    with pytest.raises(EnrichmentAllowlistError, match="bogus_src"):
        await enr.enrich_investigation("x", entities=[])
    with pytest.raises(EnrichmentAllowlistError):
        await enr.run_dns_enrichment([])  # wraps a broad try/except internally


async def test_case_whitespace_in_enrich_investigation(monkeypatch):
    _, mocks = await _run(" NVD ", monkeypatch)
    assert mocks["nvd"].await_count == 1
    assert mocks["otx"].call_count == 0


async def test_fetchers_gate_themselves(monkeypatch):
    """Direct callers (e.g. monitor seed refresh) are gated too: no HTTP at all."""
    monkeypatch.setenv(ENV, "nvd")
    monkeypatch.setenv("ABUSECH_API_KEY", "x")
    with aioresponses() as m:
        assert await enr.fetch_threatfox("") == []
        assert await enr.fetch_malwarebazaar("") == []
        assert await enr.fetch_urlhaus("emotet") == []
        assert await enr.fetch_ransomware_live("lockbit") == []
        assert await enr.fetch_ransomlook("lockbit") == []
        assert await enr.fetch_otx_pulses("x", "key") == []
        assert not m.requests


# --------------------------------------------------------------------------- #
# entity-level sources: no HTTP when excluded
# --------------------------------------------------------------------------- #
async def test_hudsonrock_excluded_makes_no_http_call(monkeypatch):
    from sources import infostealer as ist

    monkeypatch.setenv(ENV, "nvd")
    results = make_results(FakeEntity("EMAIL_ADDRESS", "v@corp.example"),
                           FakeEntity("DOMAIN", "corp.example"))
    with aioresponses() as m:
        _, stats = await ist.enrich_infostealer_entities(results, "inv-1")
        assert not m.requests
    assert stats["hudsonrock"] == "disabled"


async def test_hudsonrock_included_makes_call(monkeypatch):
    from sources import infostealer as ist

    monkeypatch.setenv(ENV, "hudsonrock")
    pat = re.compile(r"https://cavalier\.hudsonrock\.com/api/json/v2/osint-tools/search-by-email.*")
    results = make_results(FakeEntity("EMAIL_ADDRESS", "v@corp.example"))
    with aioresponses() as m:
        m.get(pat, status=200, payload={"message": "x", "stealers": []})
        await ist.enrich_infostealer_entities(results, "inv-1")
        assert len(m.requests) == 1


async def test_ip_reputation_gates_each_source(monkeypatch):
    from sources import ip_reputation as ipr

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "a")
    monkeypatch.setenv("GREYNOISE_API_KEY", "g")
    abuse = AsyncMock(return_value={"data": {"abuseConfidenceScore": 90}})
    grey = AsyncMock(return_value={"classification": "malicious"})
    feodo = AsyncMock(return_value={"8.8.4.4": "x"})
    c2 = AsyncMock(return_value={})
    with patch.object(ipr, "_cached_check_abuseipdb", abuse), \
         patch.object(ipr, "_cached_check_greynoise", grey), \
         patch.object(ipr, "load_feodo_feed", feodo), \
         patch.object(ipr, "load_c2_feeds", c2):
        # unset: everything runs
        res = await ipr.check_ip_reputation("8.8.4.4")
        assert abuse.await_count == grey.await_count == feodo.await_count == c2.await_count == 1
        assert res["feodo_hit"] and res["abuseipdb_score"] == 90

        for m_ in (abuse, grey, feodo, c2):
            m_.reset_mock()
        monkeypatch.setenv(ENV, "greynoise")
        res = await ipr.check_ip_reputation("8.8.4.4")
        assert abuse.call_count == feodo.call_count == c2.call_count == 0
        assert grey.await_count == 1
        assert res["abuseipdb_score"] is None and res["feodo_hit"] is False


async def test_domain_reputation_gates_each_source(monkeypatch):
    from sources import domain_reputation as dr

    crt = AsyncMock(return_value=[])
    us = AsyncMock(return_value={"malicious": False})
    wb = AsyncMock(return_value={"exists": True, "first_seen": None})
    with patch.object(dr, "_cached_query_crt_sh", crt), \
         patch.object(dr, "_cached_query_urlscan", us), \
         patch.object(dr, "_cached_query_wayback", wb):
        monkeypatch.setenv(ENV, "crtsh")
        res = await dr.check_domain_reputation("example.com")
        assert crt.await_count == 1
        assert us.call_count == 0 and wb.call_count == 0
        assert res["wayback_exists"] is False


async def test_hash_reputation_cache_not_shared_across_allowlists(monkeypatch):
    from sources import hash_reputation as hr

    sha = "a" * 64
    hr._hash_cache.clear()
    ha = AsyncMock(return_value={"found": False})
    mb = AsyncMock(return_value={"found": False})
    tf = AsyncMock(return_value={"found": False})
    vt = AsyncMock(return_value={"found": False})
    with patch.object(hr, "_cached_query_hybrid_analysis", ha), \
         patch.object(hr, "_cached_query_malwarebazaar", mb), \
         patch.object(hr, "_cached_query_threatfox", tf), \
         patch.object(hr, "_cached_query_virustotal", vt):
        monkeypatch.setenv(ENV, "virustotal")
        await hr.check_hash_reputation(sha)
        assert vt.await_count == 1 and mb.call_count == tf.call_count == ha.call_count == 0
        assert sha not in hr._hash_cache  # restricted result never cached
        monkeypatch.delenv(ENV)
        await hr.check_hash_reputation(sha)
        assert mb.await_count == tf.await_count == ha.await_count == 1


async def test_dns_enrichment_circl_rdap_gating(monkeypatch):
    from sources.dns_enrichment import enrich_with_dns

    ents = [{"entity_type": "DOMAIN", "value": "example.com"}]
    monkeypatch.setenv(ENV, "nvd")
    with aioresponses() as m:
        out = await enrich_with_dns(ents)
        assert not m.requests
    assert out["domain_enrichments"] == {} and out["new_entities"] == []


async def test_blocklist_feed_gating_and_umbrella(monkeypatch):
    import feeds

    seen = []

    async def fake_fetch(self):
        seen.append(self.name)
        return "1.2.3.4\n"

    entities = [{"entity_type": "IP_ADDRESS", "value": "1.2.3.4"}]
    with patch.object(feeds.BlocklistFeed, "_fetch_text", fake_fetch):
        monkeypatch.setenv(ENV, "nvd")
        pages, stats = await feeds.enrich_blocklists(entities)
        assert pages == [] and not seen
        assert all(v["status"] == "disabled" for v in stats.values())

        monkeypatch.setenv(ENV, "blocklists")
        await feeds.enrich_blocklists(entities)
        assert set(seen) == {"sslbl", "openphish", "phishtank", "ransomwhere"} - {"phishtank"} | (
            {"phishtank"} if feeds.PHISHTANK._has_key() else set())

        seen.clear()
        monkeypatch.setenv(ENV, "sslbl")
        await feeds.enrich_blocklists(entities)
        assert seen == ["sslbl"]


async def test_pwned_passwords_gated(monkeypatch):
    import credential_presence as cp

    monkeypatch.setenv(ENV, "nvd")
    with aioresponses() as m:
        res = await cp.check_password_presence("hunter2")
        page, stats = await cp.scan_pages_for_pwned_credentials(
            [{"text": "a@b.co:pw1\nc@d.co:pw2\ne@f.co:pw3\n"}])
        assert not m.requests
    assert res["status"] == "disabled"
    assert page is None and stats["status"] == "disabled"


async def test_mitre_gate_covers_both_entry_points(monkeypatch):
    from sources import historical_intel as hi

    fetch = AsyncMock(return_value={"objects": []})
    monkeypatch.setenv(ENV, "nvd")
    with patch.object(hi._mitre_feed, "fetch", fetch), \
         patch.object(hi._fbi_feed, "fetch", fetch):
        assert await hi.get_techniques_for_actor("apt28") == []
        out = await hi.enrich_historical({"THREAT_ACTOR": [{"value": "apt28"}]})
        assert out == []
    assert fetch.call_count == 0

    monkeypatch.setenv(ENV, "mitre_attack")
    with patch.object(hi._mitre_feed, "fetch", fetch):
        await hi.get_techniques_for_actor("apt28")
    assert fetch.call_count == 1


# --------------------------------------------------------------------------- #
# cve_intel degradation with the cloud value (epss/exploitdb off)
# --------------------------------------------------------------------------- #
async def test_cve_fusion_degrades_cleanly_with_cloud_value(monkeypatch):
    monkeypatch.setenv(ENV, CLOUD_ENRICHMENT_SOURCES)
    nvd = [{"cve_id": "CVE-2021-44228", "base_score": 10.0, "base_severity": "CRITICAL",
            "description": "log4j", "cwes": []}]
    kev = [{"source": "cisa_kev", "entity_value": "CVE-2021-44228",
            "is_actively_exploited": True, "ransomware_use": False, "date_added": "2021-12-10"}]
    with aioresponses() as m:
        pages = await cve_intel.fuse_cve_intelligence("log4j", [], nvd, kev)
        assert not m.requests  # EPSS / Exploit-DB never contacted
    assert len(pages) == 1
    text = pages[0]["text"]
    assert "CVE-2021-44228" in text and "CISA KEV" in text
    assert "not queried" in text and "epss" in text and "exploitdb" in text
    assert "EPSS:" not in text and "Exploit-DB: public" not in text


def test_cve_fusion_partial_tag_only_when_restricted(monkeypatch):
    rec = cve_intel._fuse_one("CVE-1-1", None, None, None, None)
    assert "cve_priority_partial" not in rec["priority_tags"]
    rec = cve_intel._fuse_one("CVE-1-1", None, None, None, None, ["epss"])
    assert "cve_priority_partial" in rec["priority_tags"]


async def test_cve_fusion_all_feeds_off_emits_nothing(monkeypatch):
    monkeypatch.setenv(ENV, "rdap")
    ents = [{"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228"}]
    assert await cve_intel.fuse_cve_intelligence("q", ents, [], []) == []
