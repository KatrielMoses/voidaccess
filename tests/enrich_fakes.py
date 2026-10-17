"""Deterministic stand-ins for the enrichment sources (no network).

Shared by tests/test_enrich_deadline.py and the golden fixture it compares
against. Every value is synthetic (reserved CVE year 2099, RFC 5737 IPs,
example.invalid hosts). ``delays`` maps a source name to seconds of sleep.
"""

from __future__ import annotations

import asyncio

ENTITIES_WITH_CVES = [
    {"entity_type": "CVE_NUMBER", "value": "CVE-2099-0001"},
    {"entity_type": "CVE_NUMBER", "value": "CVE-2099-0002"},
    {"entity_type": "RANSOMWARE_GROUP", "value": "ExampleGroup"},
    {"entity_type": "MALWARE_FAMILY", "value": "SampleLoader"},
    {"entity_type": "IP_ADDRESS", "value": "192.0.2.10"},
]
# Actors and no CVE/MITRE entity: the entity-based MITRE overlay fires.
ENTITIES_ACTORS_ONLY = [
    {"entity_type": "RANSOMWARE_GROUP", "value": "ExampleGroup"},
    {"entity_type": "THREAT_ACTOR", "value": "SampleActor"},
    {"entity_type": "IP_ADDRESS", "value": "192.0.2.10"},
]


def install(monkeypatch, delays: dict[str, float] | None = None, calls: list | None = None):
    delays = dict(delays or {})
    calls = calls if calls is not None else []

    async def _pause(name: str) -> None:
        calls.append(name)
        if delays.get(name):
            await asyncio.sleep(delays[name])

    async def cisa(query, entities):
        await _pause("cisa")
        cves = [e["value"] for e in entities if e["entity_type"] == "CVE_NUMBER"]
        out = [{"source": "cisa_kev", "entity_value": c, "vendor_project": "ExampleVendor",
                "product": "ExampleProduct", "date_added": "2099-01-01"} for c in cves[:1]]
        out.append({"source": "cisa_advisory", "entity_value": "SampleLoader",
                    "advisory_title": "Example advisory", "advisory_url": "https://example.invalid/adv"})
        return out

    async def nvd(entities, **kwargs):
        collected = kwargs.get("collected")
        out = collected if collected is not None else []
        for e in entities:
            if e["entity_type"] != "CVE_NUMBER":
                continue
            await _pause("nvd")
            out.append({"source": "nvd", "entity_value": e["value"], "base_score": 9.8,
                        "base_severity": "CRITICAL", "description": "Example flaw"})
        return out

    async def shodan(entities):
        await _pause("shodan")
        return [{"source": "shodan_internetdb", "entity_value": e["value"], "open_ports": [443]}
                for e in entities if e["entity_type"] == "IP_ADDRESS"]

    async def virustotal(entities):
        await _pause("virustotal")
        return []

    async def historical(unenriched):
        await _pause("historical")
        out = []
        for et in sorted(unenriched):
            for ent in unenriched[et]:
                out.append({"source": "mitre_attack", "entity_value": ent["value"],
                            "mitre_id": "G9999", "mitre_name": ent["value"],
                            "techniques": ["T1486", "T1059"]})
        return out

    async def fuse(query, entities, nvd_results, kev_results):
        await _pause("fusion")
        cves = sorted({r["entity_value"] for r in list(nvd_results) + list(kev_results)}
                      | {e["value"] for e in entities if e["entity_type"] == "CVE_NUMBER"})
        nvd_set = {r["entity_value"] for r in nvd_results}
        kev_set = {r["entity_value"] for r in kev_results}
        return [{"source": "cve_intel", "url": f"https://example.invalid/cve/{c}",
                 "content": f"{c} nvd={c in nvd_set} kev={c in kev_set}"} for c in cves]

    async def techniques(actor):
        await _pause("overlay")
        return ["T1566 - Phishing"]

    async def blocklists(entities):
        await _pause("blocklists")
        return [{"source": "sslbl", "url": "https://example.invalid/bl", "content": "match"}], {}

    async def empty(*_a, **_k):
        return []

    async def rl(query):
        await _pause("ransomware_live")
        return [{"group": "ExampleGroup", "description": "Example group"}]

    monkeypatch.setattr("sources.cisa.enrich_cisa", cisa)
    monkeypatch.setattr("sources.nvd.enrich_nvd", nvd)
    monkeypatch.setattr("sources.shodan.enrich_shodan", shodan)
    monkeypatch.setattr("sources.virustotal.enrich_virustotal", virustotal)
    monkeypatch.setattr("sources.historical_intel.enrich_historical", historical)
    monkeypatch.setattr("sources.historical_intel.get_techniques_for_actor", techniques)
    monkeypatch.setattr("sources.cve_intel.fuse_cve_intelligence", fuse)
    monkeypatch.setattr("feeds.enrich_blocklists", blocklists)
    import sources.enrichment as en

    for name in ("fetch_otx_pulses", "fetch_malwarebazaar", "fetch_threatfox", "fetch_urlhaus",
                 "fetch_ransomlook"):
        monkeypatch.setattr(en, name, empty)
    monkeypatch.setattr(en, "fetch_ransomware_live", rl)
    return calls
