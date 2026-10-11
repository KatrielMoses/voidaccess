"""Offline tests for the P1.3 CVE-intelligence cluster: EPSS, Exploit-DB, fusion.

No network: netpool's session is mocked (Pattern A) for EPSS; Exploit-DB's cached
feed is mocked; the fusion sub-fetchers are patched.
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sources import cve_intel


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _mock_session(json_payload, status=200):
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_payload)
    resp.text = AsyncMock(return_value="")
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=resp)
    ctx.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()
    session.get = MagicMock(return_value=ctx)
    return session


_EXPLOITDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,aliases,screenshot_url,application_url,source_url\n"
    "50592,exploits/x.py,Log4j RCE,2021-12-10,a,remote,java,0,,,1,CVE-2021-44228;OSVDB-1,,,,\n"
    "12345,exploits/y.py,Other,2020-01-01,b,local,linux,0,,,0,CVE-2020-0001,,,,\n"
)


# --------------------------------------------------------------------------- #
# EPSS
# --------------------------------------------------------------------------- #
async def test_epss_parses_score_and_percentile():
    from sources.epss import enrich_epss

    payload = {"data": [
        {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"},
    ]}
    with patch("aiohttp.ClientSession", return_value=_mock_session(payload)):
        out = await enrich_epss(["CVE-2021-44228", "not-a-cve", "CVE-2021-44228"])
    assert out == {"CVE-2021-44228": {"epss_score": 0.97, "epss_percentile": 0.99}}


async def test_epss_caps_and_dedups():
    from sources.epss import enrich_epss, MAX_EPSS_PER_INVESTIGATION, _normalize_cves

    many = [f"CVE-2021-{1000+i}" for i in range(MAX_EPSS_PER_INVESTIGATION + 10)]
    assert len(_normalize_cves(many)) == MAX_EPSS_PER_INVESTIGATION


async def test_epss_graceful_on_http_error():
    from sources.epss import enrich_epss

    with patch("aiohttp.ClientSession", return_value=_mock_session({}, status=503)):
        out = await enrich_epss(["CVE-2021-44228"])
    assert out == {}


# --------------------------------------------------------------------------- #
# Exploit-DB — one cached fetch, zero per-CVE network
# --------------------------------------------------------------------------- #
async def test_exploitdb_maps_cve_to_edb_and_makes_no_per_cve_call(monkeypatch):
    import sources.exploitdb as edb

    monkeypatch.setattr(edb, "_cached_index", None)
    fetch = AsyncMock(return_value=_EXPLOITDB_CSV)
    monkeypatch.setattr(edb._feed, "fetch", fetch)

    # Look up MANY CVEs in a single call; the feed must be fetched exactly once
    # (the derived index is built once and every lookup is in-memory) — proving no
    # per-CVE network call.
    lookups = ["CVE-2021-44228", "CVE-2020-0001", "CVE-9999-9999", "junk"]
    lookups += [f"CVE-2019-{1000+i}" for i in range(50)]
    out = await edb.enrich_exploitdb(lookups)
    assert out["CVE-2021-44228"] == {"exploit_public": True, "edb_ids": ["50592"]}
    assert out["CVE-2020-0001"] == {"exploit_public": True, "edb_ids": ["12345"]}
    assert out["CVE-9999-9999"] == {"exploit_public": False, "edb_ids": []}
    assert "junk" not in out
    assert fetch.call_count == 1


# --------------------------------------------------------------------------- #
# Fusion + derived signal
# --------------------------------------------------------------------------- #
def _nvd(cve, score, sev, desc=""):
    return {"source": "nvd", "entity_type": "CVE_NUMBER", "entity_value": cve,
            "base_score": score, "base_severity": sev, "vector": "AV:N",
            "cwes": ["CWE-502"], "description": desc}


def _kev(cve, ransomware=False):
    return {"source": "cisa_kev", "entity_type": "CVE_NUMBER", "entity_value": cve,
            "is_actively_exploited": True, "date_added": "2021-12-10",
            "ransomware_use": ransomware}


async def test_fusion_builds_unified_view_and_strips_pii(monkeypatch):
    monkeypatch.setattr(cve_intel, "enrich_epss", AsyncMock(
        return_value={"CVE-2021-44228": {"epss_score": 0.97, "epss_percentile": 0.99}}))
    monkeypatch.setattr(cve_intel, "enrich_exploitdb", AsyncMock(
        return_value={"CVE-2021-44228": {"exploit_public": True, "edb_ids": ["50592"]}}))

    entities = [{"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228"}]
    nvd_results = [_nvd("CVE-2021-44228", 10.0, "CRITICAL", desc="report to admin@corp.com now")]
    kev_results = [_kev("CVE-2021-44228", ransomware=True)]

    pages = await cve_intel.fuse_cve_intelligence("log4j", entities, nvd_results, kev_results)
    assert len(pages) == 1
    page = pages[0]
    assert page["source"] == "cve_intel"
    body = page["content"]
    assert "CVE-2021-44228" in body
    assert "CVSS Base Score: 10.0 CRITICAL" in body
    assert "CISA KEV: actively exploited" in body and "ransomware campaign use" in body
    assert "EPSS: 0.97" in body
    assert "Exploit-DB: public exploit exists (EDB-ID 50592)" in body
    assert "priority: critical" in body
    # PII stripped from the description.
    assert "admin@corp.com" not in body
    assert "adm***@corp.com" in body


async def test_fusion_graceful_when_epss_and_exploitdb_fail(monkeypatch):
    monkeypatch.setattr(cve_intel, "enrich_epss", AsyncMock(side_effect=RuntimeError("down")))
    monkeypatch.setattr(cve_intel, "enrich_exploitdb", AsyncMock(side_effect=RuntimeError("down")))

    entities = [{"entity_type": "CVE_NUMBER", "value": "CVE-2020-1234"}]
    pages = await cve_intel.fuse_cve_intelligence(
        "q", entities, [_nvd("CVE-2020-1234", 8.0, "HIGH")], [])
    assert len(pages) == 1
    body = pages[0]["content"]
    assert "CVE-2020-1234" in body
    assert "CVSS Base Score: 8.0 HIGH" in body
    # No KEV/EPSS/ExploitDB lines, but a priority is still derived (CVSS high).
    assert "priority: medium" in body


def test_priority_band_rule():
    band = cve_intel._priority_band
    assert band(kev=True, ransomware=True, exploit_public=False, cvss=None, epss=None) == "critical"
    assert band(kev=True, ransomware=False, exploit_public=False, cvss=5.0, epss=0.0) == "high"
    assert band(kev=False, ransomware=False, exploit_public=True, cvss=5.0, epss=0.0) == "medium"
    assert band(kev=False, ransomware=False, exploit_public=False, cvss=7.5, epss=None) == "medium"
    assert band(kev=False, ransomware=False, exploit_public=False, cvss=2.0, epss=0.01) == "low"


# --------------------------------------------------------------------------- #
# Entity write-back (against the shared in-memory SQLite fixture)
# --------------------------------------------------------------------------- #
async def test_write_back_persists_derived_tags(db_engine, monkeypatch):
    from db.models import Entity, Page, Investigation
    from db.session import get_session

    monkeypatch.setattr(cve_intel, "enrich_epss", AsyncMock(return_value={}))
    monkeypatch.setattr(cve_intel, "enrich_exploitdb", AsyncMock(return_value={}))

    inv_id = uuid.uuid4()
    page_id = uuid.uuid4()
    with get_session() as s:
        s.add(Investigation(id=inv_id, query="q", status="completed"))
        s.add(Page(id=page_id, url="http://x"))
        s.add(Entity(id=uuid.uuid4(), page_id=page_id, investigation_id=inv_id,
                     entity_type="CVE_NUMBER", value="CVE-2021-44228",
                     canonical_value="cve-2021-44228", confidence=1.0))
        s.commit()

    entities = [{"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228"}]
    await cve_intel.fuse_cve_intelligence(
        "q", entities, [_nvd("CVE-2021-44228", 10.0, "CRITICAL")], [_kev("CVE-2021-44228")])

    with get_session() as s:
        row = s.query(Entity).filter(Entity.value == "CVE-2021-44228").first()
        tags = json.loads(row.corroborating_sources or "[]")
    assert "cve_priority:high" in tags or "cve_priority:critical" in tags
    assert "kev" in tags
    assert "cvss:critical" in tags
