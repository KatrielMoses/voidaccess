"""Enrichment deadline (E4): finished work survives, the phase ends on time,
and a source a deadline cut off is reported ``timed_out``, never ``ok``.

Sources are the fakes in ``tests/enrich_fakes.py`` (no network). Deadlines are
scaled down so a test that exercises them takes about a second.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from tests import enrich_fakes as fakes
import sources.enrichment as en
from sources import source_control

GOLDEN = Path(__file__).parent / "fixtures" / "enrich_deadline_golden.json"
DEADLINE = 1.2
SLOW = 5.0  # far past any scaled deadline


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("VOIDACCESS_ENRICHMENT_SOURCES", "VOIDACCESS_DISABLED_SOURCES"):
        monkeypatch.delenv(var, raising=False)
    source_control.reset_tracker()
    yield
    source_control.reset_tracker()


@pytest.fixture
def scaled(monkeypatch):
    """The real deadline arithmetic, at 1/50 scale."""
    monkeypatch.setattr(en, "ENRICHMENT_DEADLINE_S", DEADLINE)
    monkeypatch.setattr(en, "NEW_SOURCES_MARGIN_S", 0.1)
    monkeypatch.setattr(en, "NVD_BUDGET_S", 0.5)
    monkeypatch.setattr(en, "CVE_FUSION_TIMEOUT_S", 0.25)
    monkeypatch.setattr(en, "HISTORICAL_RESERVE_S", 0.3)


def _run(entities=fakes.ENTITIES_WITH_CVES):
    started = time.monotonic()
    pages = asyncio.run(en.enrich_investigation("example query", entities=list(entities)))
    return pages, time.monotonic() - started


def _sources(pages):
    return [p.get("source") for p in pages]


def _status(source_id):
    return source_control.source_entry(source_id)["status"]


# (4) Fast run: byte-for-byte what the pre-E4 code produced -------------------

@pytest.mark.parametrize("case, entities", [
    ("with_cves", fakes.ENTITIES_WITH_CVES),
    ("actors_only", fakes.ENTITIES_ACTORS_ONLY),
])
def test_fast_run_output_equals_the_pre_fix_golden(monkeypatch, case, entities):
    fakes.install(monkeypatch)
    pages, _ = _run(entities)
    assert json.loads(json.dumps(pages)) == json.loads(GOLDEN.read_text())[case]
    for sid in ("cisa_kev", "nvd", "cve_intel", "shodan_internetdb", "mitre_attack"):
        assert _status(sid) == "ok", sid


# (1) A slow NVD loses only its own results -----------------------------------

def test_slow_nvd_keeps_kev_fusion_and_mitre(monkeypatch, scaled):
    fakes.install(monkeypatch, delays={"nvd": SLOW})
    pages, elapsed = _run()
    got = _sources(pages)
    assert "cisa_advisory" in got
    assert "shodan_internetdb" in got
    assert "mitre_attack" in got          # historical intel
    assert "sslbl" in got                 # blocklists
    fused = [p for p in pages if p.get("source") == "cve_intel"]
    assert fused, "the CVE fusion ran on KEV even though NVD was cut"
    assert all("nvd=False" in p["content"] for p in fused)
    assert any("kev=True" in p["content"] for p in fused)
    assert elapsed < DEADLINE + 0.3
    assert _status("nvd") == "timed_out"
    assert _status("cve_intel") == "ok" and _status("cisa_kev") == "ok"


def test_nvd_cut_keeps_the_cves_it_already_enriched(monkeypatch, scaled):
    # First CVE fast, the second never returns in time.
    calls: list = []
    fakes.install(monkeypatch, calls=calls)
    first = {"done": False}
    original = __import__("sources.nvd", fromlist=["enrich_nvd"]).enrich_nvd

    async def nvd(entities, **kwargs):
        out = kwargs["collected"]
        out.append({"source": "nvd", "entity_value": "CVE-2099-0001", "base_score": 9.8})
        first["done"] = True
        await asyncio.sleep(SLOW)
        return out

    monkeypatch.setattr("sources.nvd.enrich_nvd", nvd)
    pages, _ = _run()
    assert first["done"] and original is not nvd
    fused = {p["content"].split()[0]: p["content"] for p in pages if p.get("source") == "cve_intel"}
    assert "nvd=True" in fused["CVE-2099-0001"]
    assert "nvd=False" in fused["CVE-2099-0002"]
    assert _status("nvd") == "timed_out"


def test_real_nvd_stops_issuing_requests_at_its_budget(monkeypatch):
    import sources.nvd as nvd

    issued: list[str] = []

    async def fetch(cve_id, session=None):
        issued.append(cve_id)
        await asyncio.sleep(0.05)
        return {"entity_value": cve_id}

    monkeypatch.setattr(nvd, "fetch_nvd_cve", fetch)
    entities = [{"entity_type": "CVE_NUMBER", "value": f"CVE-2099-{i:04d}"} for i in range(1, 11)]
    collected: list = []
    out = asyncio.run(nvd.enrich_nvd(entities, budget_s=0.12, collected=collected))
    assert out is collected
    assert 2 <= len(issued) < 10
    assert len(collected) == len(issued)


# (2) The phase ends by its deadline, whatever is slow -------------------------

@pytest.mark.parametrize("slow", [
    ("nvd",),
    ("cisa", "shodan", "virustotal"),
    ("historical",),
    ("fusion",),
    ("blocklists", "overlay"),
    ("ransomware_live",),
    ("cisa", "nvd", "shodan", "virustotal", "historical", "fusion", "overlay", "blocklists",
     "ransomware_live"),
])
def test_phase_ends_by_its_deadline(monkeypatch, scaled, slow):
    fakes.install(monkeypatch, delays={name: SLOW for name in slow})
    _, elapsed = _run()
    assert elapsed < DEADLINE + 0.3, elapsed


# (3) Cut off -> timed_out, failed -> error, never ok ---------------------------

def test_everything_slow_reports_timed_out_not_ok(monkeypatch, scaled):
    fakes.install(monkeypatch, delays={name: SLOW for name in (
        "cisa", "nvd", "shodan", "virustotal", "historical", "fusion", "blocklists",
        "overlay", "ransomware_live")})
    pages, _ = _run()
    for sid in ("cisa_kev", "nvd", "shodan_internetdb", "virustotal", "mitre_attack",
                "cve_intel", "epss", "exploitdb", "sslbl", "ransomware_live"):
        assert _status(sid) == "timed_out", sid
    assert "ransomware_live" not in _sources(pages)


def test_slow_fusion_falls_back_to_legacy_cve_pages(monkeypatch, scaled):
    fakes.install(monkeypatch, delays={"fusion": SLOW})
    pages, _ = _run()
    got = _sources(pages)
    assert "cve_intel" not in got
    assert "nvd" in got or any("CVSS" in (p.get("content") or "") or "CVE:" in (p.get("content") or "")
                               for p in pages)
    assert "mitre_attack" in got and "shodan_internetdb" in got
    for sid in ("cve_intel", "epss", "exploitdb"):
        assert _status(sid) == "timed_out", sid
    assert _status("nvd") == "ok" and _status("cisa_kev") == "ok"


def test_slow_virustotal_does_not_block_historical_intel(monkeypatch, scaled):
    fakes.install(monkeypatch, delays={"virustotal": SLOW})
    pages, _ = _run()
    assert "mitre_attack" in _sources(pages)
    assert _status("virustotal") == "timed_out"
    assert _status("mitre_attack") == "ok"


def test_a_failing_source_reports_error(monkeypatch, scaled):
    fakes.install(monkeypatch)

    async def boom(*_a, **_k):
        raise RuntimeError("upstream down")

    monkeypatch.setattr("sources.shodan.enrich_shodan", boom)
    monkeypatch.setattr(en, "fetch_ransomlook", boom)
    pages, _ = _run()
    assert _status("shodan_internetdb") == "error"
    assert _status("ransomlook") == "error"
    assert "mitre_attack" in _sources(pages) and "cve_intel" in _sources(pages)


def test_the_group_keeps_finished_parts_if_cancelled_from_outside(monkeypatch, scaled):
    """Backstop: even if the outer gather cancels the group, its parts survive."""
    fakes.install(monkeypatch, delays={"nvd": SLOW, "fusion": SLOW})
    # Give the group more time than the phase, so the outer gather cuts it.
    monkeypatch.setattr(en, "NEW_SOURCES_MARGIN_S", -1.0)
    pages, elapsed = _run()
    got = _sources(pages)
    assert "cisa_advisory" in got and "mitre_attack" in got and "shodan_internetdb" in got
    assert elapsed < DEADLINE + 0.3
    assert _status("nvd") == "timed_out" and _status("cve_intel") == "timed_out"


# (5) The cloud profile runs exactly the sources it ran before ----------------

def test_cloud_profile_enabled_set_is_unchanged(monkeypatch):
    # Recorded from the pre-E4 code (1fe80fb) with the same fakes.
    monkeypatch.setenv("VOIDACCESS_DISABLED_SOURCES", source_control.CLOUD_DISABLED_SOURCES)
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "rdap,crtsh,wayback,cisa_kev,nvd,mitre_attack")
    calls = fakes.install(monkeypatch)
    pages, _ = _run(fakes.ENTITIES_WITH_CVES)
    assert sorted(set(calls)) == ["blocklists", "cisa", "fusion", "historical", "nvd", "overlay"]
    # E5: one overlay page per ATT&CK group the run's actors resolve to
    # exactly (SampleLoader is a malware family, not a group).
    assert _sources(pages) == [
        "cisa_advisory", "cve_intel", "cve_intel", "mitre_attack",
        "mitre_attack_overlay", "sslbl",
    ]


def test_allowlisted_off_sources_keep_their_gate_status(monkeypatch, scaled):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "cisa_kev,mitre_attack")
    fakes.install(monkeypatch, delays={"cisa": SLOW})
    _run()
    assert _status("cisa_kev") == "timed_out"
    assert _status("shodan_internetdb") == "skipped_by_allowlist"
    assert _status("nvd") == "skipped_by_allowlist"


# Pipeline: sources_used and the enrich.source trace agree ---------------------

def test_cli_reports_a_cut_source_as_timed_out_in_sources_used_and_trace(tmp_path, monkeypatch, scaled):
    from tests import test_trace_events as t3

    import voidaccess_cli.commands.investigate as inv
    from progress import CallbackSink

    session_module = t3._isolate_db(tmp_path, monkeypatch)
    fakes.install(monkeypatch, delays={"nvd": SLOW})
    for target in (
        "sources.domain_reputation.enrich_domain_entities",
        "sources.hash_reputation.enrich_hash_entities",
        "sources.email_reputation.enrich_email_entities",
        "sources.breach_lookup.enrich_breach_entities",
        "sources.infostealer.enrich_infostealer_entities",
    ):
        async def passthrough(results, *_a, **_k):
            return results, {}
        monkeypatch.setattr(target, passthrough)

    async def no_hibp(_pages):
        return None, {"status": "ok", "pwned": 0}

    async def no_ip(*_a, **_k):
        return None

    monkeypatch.setattr("credential_presence.scan_pages_for_pwned_credentials", no_hibp)
    monkeypatch.setattr("sources.ip_reputation.enrich_ip_entities", no_ip)

    async def paste(_q):
        return [{"url": "https://paste.example.invalid/raw/1", "text": t3.PAGE_TEXT * 3,
                 "title": "lockbit ransomware notes", "source": "paste_sites"}]

    async def none(_q):
        return []

    monkeypatch.setattr(inv, "_scrape_pastes", paste)
    for name in ("_scrape_github", "_scrape_gitlab", "_scrape_rss"):
        monkeypatch.setattr(inv, name, none)

    out = tmp_path / "out"
    out.mkdir()
    events = []
    asyncio.run(inv._run_investigation(
        query="lockbit ransomware", out_dir=out, model=None, no_tor=True, no_llm=True,
        depth="shallow", fmt="json", quiet=True, sinks=[CallbackSink(events.append)], trace=True,
    ))
    session_module._get_engine_cached.cache_clear()
    report = json.loads(next(out.glob("*.json")).read_text())
    assert report["sources_used"]["nvd"]["status"] == "timed_out"
    # Fakes make no HTTP calls, so finished sources are only listed if cut.
    assert report["sources_used"].get("cisa_kev", {}).get("status") != "timed_out"
    traced = {e.data["source"]: e.data["status"] for e in events if e.kind == "enrich.source"}
    assert traced["nvd"] == "timeout"
    assert all(status != "ok" for source, status in traced.items() if source == "nvd")
