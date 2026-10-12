"""Honest per-source status and request counts in ``sources_used`` (E1C / C3)."""

from __future__ import annotations

import asyncio

import pytest

from sources import source_control as sc
from tests import e1c_harness as h


# --------------------------------------------------------------------------- #
# URL -> source attribution
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1", "nvd"),
        ("https://api.pwnedpasswords.com/range/ABCDE", "hibp_pwned_passwords"),
        ("https://haveibeenpwned.com/api/v3/breachedaccount/x", "hibp"),
        ("https://openphish.com/feed.txt", "openphish"),
        ("https://sslbl.abuse.ch/blacklist/sslblacklist.csv", "sslbl"),
        ("http://data.phishtank.com/data/k/online-valid.csv", "phishtank"),
        ("https://api.ransomwhe.re/export", "ransomwhere"),
        ("https://www.justice.gov/news/press-releases/rss", "fbi_doj_press"),
        ("https://raw.githubusercontent.com/mitre/cti/master/x.json", "mitre_attack"),
        ("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/x", "c2_tracker"),
        ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/f.csv", "exploitdb"),
        ("https://gitlab.com/api/v4/search", "gitlab"),
        ("https://pastebin.com/raw/abcd1234", "pastebin"),
        ("https://paste.ee/r/x", "paste_ee"),
        ("https://example.com/", None),
    ],
)
def test_source_for_url(url, expected):
    assert sc.source_for_url(url) == expected


def test_the_real_feed_urls_map_to_their_own_ids(monkeypatch):
    """Guards the attribution table against drifting from the code's real URLs."""
    import feeds

    monkeypatch.setenv("PHISHTANK_API_KEY", "k")
    for feed in feeds._FEEDS:
        url = feed._url_factory() if feed._url_factory else feed._url
        assert sc.source_for_url(url) == feed.name, (feed.name, url)


def test_every_url_rule_targets_a_registered_source_id():
    known = sc.all_source_ids()
    assert {sid for _h, _p, sid in sc.SOURCE_URL_RULES} <= set(known)


# --------------------------------------------------------------------------- #
# Request counting at the shared HTTP chokepoint
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, status):
        self.status = status


class _CM:
    def __init__(self, status=200, boom=False):
        self.status, self.boom = status, boom

    async def __aenter__(self):
        if self.boom:
            raise OSError("connection reset")
        return _Resp(self.status)

    async def __aexit__(self, *exc):
        return False


def _guarded(monkeypatch, make):
    import netpool
    from sources import http_pool

    class Fake:
        def get(self, url, **kw):
            return make(url)

    monkeypatch.setattr(netpool, "get_clearnet_session", lambda: Fake())
    return http_pool.get_clearnet_session()


def test_pooled_session_counts_requests_per_source(monkeypatch):
    session = _guarded(monkeypatch, lambda url: _CM(200))

    async def go():
        for url in (
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://openphish.com/feed.txt",
            "https://example.com/untracked",
        ):
            async with session.get(url) as resp:
                assert resp.status == 200

    asyncio.run(go())
    assert sc.get_tracker().snapshot_requests() == {"nvd": 2, "openphish": 1}
    assert sc.resolve_status("nvd") == "ok"


def test_source_whose_every_call_failed_is_error_not_ok(monkeypatch):
    session = _guarded(monkeypatch, lambda url: _CM(boom="nvd" in url or "nist" in url))

    async def go():
        for _ in range(2):
            with pytest.raises(OSError):
                async with session.get("https://services.nvd.nist.gov/rest/json/cves/2.0"):
                    pass

    asyncio.run(go())
    assert sc.get_tracker().request_count("nvd") == 2
    assert sc.resolve_status("nvd") == "error"


def test_rate_limited_answers_count_as_failures(monkeypatch):
    session = _guarded(monkeypatch, lambda url: _CM(429))

    async def go():
        async with session.get("https://api.greynoise.io/v3/community/1.1.1.1"):
            pass

    asyncio.run(go())
    assert sc.resolve_status("greynoise") == "error"


def test_a_404_is_a_normal_answer_not_a_failure(monkeypatch):
    session = _guarded(monkeypatch, lambda url: _CM(404))

    async def go():
        async with session.get("https://api.greynoise.io/v3/community/1.1.1.1"):
            pass

    asyncio.run(go())
    assert sc.resolve_status("greynoise") != "error"


def test_attribute_requests_to_overrides_url_mapping(monkeypatch):
    session = _guarded(monkeypatch, lambda url: _CM(200))

    async def go():
        with sc.attribute_requests_to("rss"):
            async with session.get("https://www.cisa.gov/news.xml"):
                pass
        async with session.get("https://www.cisa.gov/known_exploited.json"):
            pass

    asyncio.run(go())
    assert sc.get_tracker().snapshot_requests() == {"rss": 1, "cisa_kev": 1}


# --------------------------------------------------------------------------- #
# Status resolution
# --------------------------------------------------------------------------- #
def test_missing_key_with_no_requests_is_no_key(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    assert sc.resolve_status("otx") == "no_key"
    sc.get_tracker().record_request("otx")
    assert sc.resolve_status("otx") == "ok"


def test_denied_beats_everything(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "openphish")
    sc.get_tracker().record_request("openphish")
    assert sc.resolve_status("openphish") == "disabled"


def test_timeout_and_error_flags():
    assert sc.resolve_status("nvd", timed_out=True) == "timed_out"
    assert sc.resolve_status("nvd", error=True) == "error"
    assert sc.resolve_status("nvd", ok=False) == "error"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ok_3_results", "ok"),
        ("ok_0_results", "ok"),
        ("error_timeout", "timed_out"),
        ("error", "error"),
        ("unavailable", "error"),
        ("skipped_no_key", "no_key"),
        ("disabled", "skipped_by_allowlist"),  # no deny-list entry => the allowlist did it
    ],
)
def test_normalize_module_status(raw, expected, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    assert sc.normalize_module_status("hibp", raw) == expected


def test_normalize_module_status_disabled_by_deny_list(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "hibp")
    assert sc.normalize_module_status("hibp", "disabled") == "disabled"


def test_every_reported_status_is_in_the_vocabulary():
    for status in (
        "ok", "error", "timed_out", "skipped_by_allowlist", "disabled", "no_key", "skipped",
    ):
        assert status in sc.SOURCE_STATUSES


# --------------------------------------------------------------------------- #
# finalize_sources_used
# --------------------------------------------------------------------------- #
def test_finalize_lists_denied_children_of_umbrellas(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "paste_sites,blocklists")
    used = {"paste_sites": {"status": "ok", "count": 3}, "sslbl": {"status": "ok", "count": 0}}
    sc.finalize_sources_used(used)
    for sid in ("paste_sites", "pastebin", "paste_ee", "dpaste", "rentry",
                "sslbl", "openphish", "phishtank", "ransomwhere"):
        assert used[sid]["status"] == "disabled", sid
        assert used[sid]["requests"] == 0


def test_finalize_never_leaves_an_allowlisted_off_source_ok(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "rdap,nvd")
    used = {
        "nvd": {"status": "ok", "count": 1},
        "ransomlook": {"status": "ok", "count": 0},
        "sslbl": {"status": "ok", "count": 0},
    }
    sc.finalize_sources_used(used)
    assert used["nvd"]["status"] == "ok"
    assert used["ransomlook"]["status"] == "skipped_by_allowlist"
    assert used["sslbl"]["status"] == "skipped_by_allowlist"
    assert used["otx"]["status"] == "skipped_by_allowlist"


def test_finalize_blocklists_umbrella_in_allowlist_keeps_feeds(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "blocklists")
    used = {}
    sc.finalize_sources_used(used)
    assert "sslbl" not in used or used["sslbl"]["status"] != "skipped_by_allowlist"
    assert used["nvd"]["status"] == "skipped_by_allowlist"


def test_finalize_adds_sources_that_made_calls_but_were_not_reported():
    sc.get_tracker().record_request("epss", 3)
    used = {}
    sc.finalize_sources_used(used)
    assert used["epss"]["requests"] == 3 and used["epss"]["status"] in sc.SOURCE_STATUSES


def test_overlay_status_strings_for_the_api_shape(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "cisa_kev,pastebin")
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "nvd")
    used = {"cisa": "ok_2_results", "nvd": "ok_1_results", "otx": "skipped_no_key"}
    sc.overlay_status_strings(used, {"cisa_kev": "cisa"})
    assert used["cisa"] == "disabled" and used["cisa_kev"] == "disabled"
    assert used["pastebin"] == "disabled"
    assert used["nvd"] == "ok_1_results"
    assert used["otx"] == "skipped_no_key"  # a missing key is not rewritten
    assert used["ransomlook"] == "skipped_by_allowlist"


# --------------------------------------------------------------------------- #
# End to end through the CLI pipeline
# --------------------------------------------------------------------------- #
def _enrich_stub(calls_by_source):
    async def stub(*_a, **_k):
        for sid, n in calls_by_source.items():
            sc.record_request(sid, n)
        return [{
            "url": "https://nvd.nist.gov/vuln",
            "link": "https://nvd.nist.gov/vuln",
            "text": "CVE-2023-4966 is exploited by LockBit.",
            "content": "CVE-2023-4966 is exploited by LockBit.",
            "source": "nvd",
        }]

    return stub


def _prepare(tmp_path, monkeypatch, enrich=None):
    for var in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "OTX_API_KEY", "HIBP_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    inv = h.prepare(tmp_path, monkeypatch, generate_summary=lambda *a, **k: "A summary.")
    if enrich is not None:
        monkeypatch.setattr("sources.enrichment.enrich_investigation", enrich)
    return inv


def test_pipeline_reports_status_count_and_requests_per_source(tmp_path, monkeypatch):
    inv = _prepare(tmp_path, monkeypatch, _enrich_stub({"nvd": 2, "epss": 1}))
    events = tmp_path / "events.jsonl"
    h.run(inv, tmp_path, events_jsonl=events)
    used = h.read_payload(tmp_path)["sources_used"]

    assert used["nvd"] == {"status": "ok", "count": 1, "requests": 2}
    assert used["epss"]["requests"] == 1  # a source nobody reported by name still appears
    assert used["rss"]["status"] == "ok" and used["rss"]["count"] == 1
    assert used["telegram"]["status"] == "no_key"
    assert used["tor_search"]["status"] == "skipped"  # --no-tor
    assert used["torch"]["status"] == "skipped" and used["haystack"]["status"] == "skipped"
    for sid, entry in used.items():
        assert entry["status"] in sc.SOURCE_STATUSES, (sid, entry)
        assert isinstance(entry["requests"], int), (sid, entry)

    completed = h.read_events(events)[-1]
    assert completed["type"] == "completed"
    metrics = completed["metrics"]
    assert metrics["source_requests"] == {"nvd": 2, "epss": 1}
    assert metrics["source_requests_by_step"]["enrichment"] == {"nvd": 2, "epss": 1}
    assert metrics["sources_status"]["nvd"] == "ok"
    assert metrics["summary_kind"] == "llm"


def test_pipeline_allowlisted_off_source_never_shows_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "rdap")
    inv = _prepare(tmp_path, monkeypatch)
    h.run(inv, tmp_path)
    used = h.read_payload(tmp_path)["sources_used"]
    for sid in ("nvd", "ransomlook", "sslbl", "openphish", "phishtank", "ransomwhere",
                "otx", "virustotal", "cisa_kev"):
        assert used[sid]["status"] == "skipped_by_allowlist", (sid, used[sid])


def test_pipeline_default_run_has_no_allowlist_or_disabled_entries(tmp_path, monkeypatch):
    """Self-hosters: with no env vars set nothing is reported skipped or disabled."""
    inv = _prepare(tmp_path, monkeypatch)
    h.run(inv, tmp_path)
    used = h.read_payload(tmp_path)["sources_used"]
    assert not [s for s, e in used.items() if e["status"] in ("disabled", "skipped_by_allowlist")]


def test_side_source_failure_is_error_by_class_name(tmp_path, monkeypatch):
    async def boom(_q):
        raise RuntimeError("secret detail")

    inv = h.prepare(
        tmp_path, monkeypatch,
        generate_summary=lambda *a, **k: "A summary.",
        side_sources={"_scrape_github": boom},
    )
    h.run(inv, tmp_path)
    entry = h.read_payload(tmp_path)["sources_used"]["github"]
    assert entry["status"] == "error" and entry["error"] == "RuntimeError"
    assert "secret detail" not in str(entry)


def test_side_source_own_off_switch_is_disabled_not_ok(monkeypatch):
    """PASTE_SCRAPING_ENABLED=false used to read as ok with zero results."""
    from voidaccess_cli.commands import investigate as module

    monkeypatch.setenv("PASTE_SCRAPING_ENABLED", "false")

    async def go():
        return await module._run_side_source(
            "paste_sites", "PASTE_SCRAPING_ENABLED", "sources.paste_scraper",
            "scrape_paste_sites", "q",
        )

    assert asyncio.run(go()) == []
    assert sc.get_tracker().states["paste_sites"] == "disabled"
    assert sc.resolve_status("paste_sites") == "disabled"
