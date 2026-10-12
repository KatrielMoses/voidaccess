"""VOIDACCESS_DISABLED_SOURCES: the opt-in cloud deny-list (E1C / C5)."""

from __future__ import annotations

import asyncio

import pytest

from sources import source_control as sc
from tests import e1c_harness as h

CLOUD = sc.CLOUD_DISABLED_SOURCES
CLOUD_IDS = [s for s in CLOUD.split(",") if s]


# --------------------------------------------------------------------------- #
# Parsing and validation
# --------------------------------------------------------------------------- #
def test_unset_or_blank_means_nothing_is_disabled(monkeypatch):
    assert sc.get_disabled_sources() == frozenset()
    for blank in ("", "   ", " , ,"):
        monkeypatch.setenv(sc.DISABLED_ENV, blank)
        assert sc.get_disabled_sources() == frozenset()
        assert sc.is_source_disabled("openphish") is False


def test_ids_are_trimmed_and_case_insensitive(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, " OpenPhish , SSLBL ")
    assert sc.get_disabled_sources() == frozenset({"openphish", "sslbl"})


def test_unknown_id_is_an_error_not_a_silent_no_op(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "openphish,not_a_source")
    with pytest.raises(sc.SourceControlError, match="not_a_source"):
        sc.get_disabled_sources()


def test_cli_rejects_an_unknown_id_before_any_work(monkeypatch):
    from typer.testing import CliRunner

    from voidaccess_cli.main import app

    monkeypatch.setenv(sc.DISABLED_ENV, "opnphish")  # typo
    result = CliRunner().invoke(app, ["investigate", "lockbit ransomware", "--no-llm", "--no-tor"])
    assert result.exit_code == 2
    assert "VOIDACCESS_DISABLED_SOURCES" in result.output and "opnphish" in result.output


def test_the_recommended_cloud_value_is_valid_and_covers_the_licence_gap(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, CLOUD)
    denied = sc.get_disabled_sources()
    assert {
        "openphish", "sslbl", "phishtank", "ransomwhere", "hibp_pwned_passwords",
        "fbi_doj_press", "pastebin", "paste_ee", "dpaste", "rentry",
    } <= denied


def test_umbrella_ids_deny_their_children(monkeypatch):
    monkeypatch.setenv(sc.DISABLED_ENV, "paste_sites,blocklists")
    for child in ("pastebin", "paste_ee", "dpaste", "rentry", "sslbl", "openphish",
                  "phishtank", "ransomwhere"):
        assert sc.is_source_disabled(child), child
    assert not sc.is_source_disabled("nvd")


def test_every_search_stage_id_is_documented_in_architecture_md():
    from pathlib import Path

    doc = (Path(__file__).resolve().parent.parent / "docs" / "architecture.md").read_text()
    missing = [sid for sid in sc.all_source_ids() if f"`{sid}`" not in doc]
    assert not missing, f"undocumented source ids: {missing}"
    assert "VOIDACCESS_DISABLED_SOURCES" in doc


# --------------------------------------------------------------------------- #
# Enrichment gate composes with the allowlist
# --------------------------------------------------------------------------- #
def test_enrichment_gate_honours_the_deny_list(monkeypatch):
    from sources.enrichment_allowlist import is_enrichment_source_enabled

    assert is_enrichment_source_enabled("hibp_pwned_passwords") is True
    monkeypatch.setenv(sc.DISABLED_ENV, "hibp_pwned_passwords")
    assert is_enrichment_source_enabled("hibp_pwned_passwords") is False
    assert is_enrichment_source_enabled("nvd") is True


def test_deny_list_wins_over_the_allowlist(monkeypatch):
    from sources.enrichment_allowlist import is_enrichment_source_enabled

    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "nvd,openphish")
    monkeypatch.setenv(sc.DISABLED_ENV, "openphish")
    assert is_enrichment_source_enabled("openphish") is False
    assert is_enrichment_source_enabled("nvd") is True
    assert sc.resolve_status("openphish") == "disabled"  # not skipped_by_allowlist


# --------------------------------------------------------------------------- #
# Each stage makes no call to a denied source
# --------------------------------------------------------------------------- #
def _spy_on_feed_fetches(monkeypatch):
    """Record which feeds fetch. Patches the class, never an instance: an instance
    setattr would leave a stale attribute behind and shadow later class patches."""
    import feeds

    fetched = []

    async def spy(self):
        fetched.append(self.name)
        return None

    monkeypatch.setattr(feeds.BlocklistFeed, "_fetch_text", spy)
    return fetched


def test_blocklist_feed_matcher_does_not_fetch_a_denied_feed(monkeypatch):
    import feeds

    monkeypatch.setenv("PHISHTANK_API_KEY", "k")
    fetched = _spy_on_feed_fetches(monkeypatch)
    monkeypatch.setenv(sc.DISABLED_ENV, "sslbl,openphish")
    asyncio.run(feeds.enrich_blocklists([{"entity_type": "DOMAIN", "value": "x.com"}]))
    # Denied feeds are never fetched. The umbrella id in the *allowlist* sense
    # must not re-enable a feed the deny-list named.
    assert "sslbl" not in fetched and "openphish" not in fetched
    assert "phishtank" in fetched and "ransomwhere" in fetched
    assert feeds.SSLBL.status() == "disabled" and feeds.OPENPHISH.status() == "disabled"


def test_blocklists_umbrella_in_the_deny_list_stops_all_four(monkeypatch):
    import feeds

    monkeypatch.setenv("PHISHTANK_API_KEY", "k")
    fetched = _spy_on_feed_fetches(monkeypatch)
    monkeypatch.setenv(sc.DISABLED_ENV, "blocklists")
    asyncio.run(feeds.enrich_blocklists([{"entity_type": "DOMAIN", "value": "x.com"}]))
    assert fetched == []


def test_historical_intel_skips_a_denied_fbi_feed_but_not_mitre(monkeypatch):
    from sources import historical_intel as hi

    calls = []

    async def fbi_fetch():
        calls.append("fbi")
        return []

    async def mitre_fetch():
        calls.append("mitre")
        return []

    monkeypatch.setattr(hi._fbi_feed, "fetch", fbi_fetch)
    monkeypatch.setattr(hi._mitre_feed, "fetch", mitre_fetch)
    monkeypatch.setenv(sc.DISABLED_ENV, "fbi_doj_press")
    assert asyncio.run(hi._fetch_fbi_results("lockbit")) == []
    asyncio.run(hi._fetch_mitre_index())
    assert calls == ["mitre"]


def test_credential_presence_makes_no_call_when_denied(monkeypatch):
    import credential_presence as cp

    def boom(*_a, **_k):
        raise AssertionError("no HTTP to Pwned Passwords when denied")

    monkeypatch.setattr(cp.http_pool, "clearnet_session", boom)
    monkeypatch.setenv(sc.DISABLED_ENV, "hibp_pwned_passwords")

    result = asyncio.run(cp.check_password_presence("hunter2"))
    assert result["status"] == "disabled" and result["present"] is False

    page, stats = asyncio.run(
        cp.scan_pages_for_pwned_credentials([{"text": "a@b.com:hunter2\nc@d.com:pass\ne@f.com:x"}])
    )
    assert page is None and stats["status"] == "disabled" and stats["observed"] == 0


def test_paste_scraper_skips_denied_sites_individually(monkeypatch):
    from sources import paste_scraper

    scraped = []

    async def fake_scrape_source(self, source, term):
        scraped.append(source["name"])
        return []

    monkeypatch.setattr(paste_scraper.PasteScraper, "_scrape_source", fake_scrape_source)

    async def run():
        async with paste_scraper.PasteScraper() as scraper:
            await scraper.search_and_fetch("lockbit ransomware")

    asyncio.run(run())
    assert set(scraped) == {"Pastebin", "dpaste", "paste.ee"}  # Rentry has no search URL

    scraped.clear()
    monkeypatch.setenv(sc.DISABLED_ENV, "pastebin,paste_ee")
    asyncio.run(run())
    assert set(scraped) == {"dpaste"}

    scraped.clear()
    monkeypatch.setenv(sc.DISABLED_ENV, "paste_sites")
    asyncio.run(run())
    assert scraped == []


def test_rss_scraper_skips_denied_feeds(monkeypatch):
    from sources import rss_scraper

    fetched = []

    async def fake_fetch_feed(self, feed, terms):
        fetched.append(feed["name"])
        return []

    monkeypatch.setattr(rss_scraper.RSSFeedScraper, "_fetch_feed", fake_fetch_feed)

    async def run():
        async with rss_scraper.RSSFeedScraper() as scraper:
            await scraper.fetch_relevant_articles("lockbit ransomware")

    asyncio.run(run())
    total = len(fetched)
    assert total == len(rss_scraper.RSS_FEEDS)

    fetched.clear()
    monkeypatch.setenv(sc.DISABLED_ENV, "fbi_doj_press")
    asyncio.run(run())
    assert total - len(fetched) == 2  # the FBI and DOJ feeds only
    assert not [n for n in fetched if "FBI" in n or "Department of Justice" in n]

    fetched.clear()
    monkeypatch.setenv(sc.DISABLED_ENV, "rss")
    asyncio.run(run())
    assert fetched == []


@pytest.mark.parametrize(
    "source_id,module,func",
    [
        ("github", "sources.github_scraper", "scrape_github"),
        ("gitlab", "sources.gitlab_scraper", "scrape_gitlab"),
    ],
)
def test_git_scrapers_never_open_a_session_when_denied(monkeypatch, source_id, module, func):
    import importlib

    mod = importlib.import_module(module)

    class Boom:
        def __init__(self, *a, **k):
            raise AssertionError(f"{source_id} scraper constructed while denied")

    monkeypatch.setattr(mod, "GitHubScraper" if source_id == "github" else "GitLabScraper", Boom)
    monkeypatch.setenv(sc.DISABLED_ENV, source_id)
    assert asyncio.run(getattr(mod, func)("lockbit")) == []


def test_telegram_is_not_touched_when_denied(monkeypatch):
    from sources import telegram

    monkeypatch.setenv(sc.DISABLED_ENV, "telegram")
    monkeypatch.setattr(
        telegram, "_import_telethon",
        lambda: (_ for _ in ()).throw(AssertionError("telethon imported while denied")),
    )
    assert asyncio.run(telegram.fetch_telegram_messages(["@chan"], "lockbit")) == []


def test_tor_search_fan_out_is_skipped_when_denied(monkeypatch):
    import search.search as search_mod

    async def boom():
        raise AssertionError("engine stats touched while tor_search is denied")

    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", boom)
    monkeypatch.setenv(sc.DISABLED_ENV, "tor_search")
    assert asyncio.run(search_mod._search_async("lockbit")) == []


def test_onion_engines_torch_and_haystack_are_denied_individually(monkeypatch):
    from sources import engines

    touched = []

    class _NoNetwork:
        def get(self, url, **kw):
            raise OSError("no network in tests")

    def acquire(url):
        touched.append(url)
        return _NoNetwork(), "k"

    monkeypatch.setattr(engines.tor_pool, "acquire_tor_session", acquire)
    monkeypatch.setattr(engines.tor_pool, "release_tor_session", lambda k: None)
    monkeypatch.setenv(sc.DISABLED_ENV, "torch")
    asyncio.run(engines.search_onionsearch("lockbit"))
    status = engines.get_last_onionsearch_status()
    assert status["Torch"] == "disabled"
    assert len(touched) == 1 and "torch" not in touched[0].lower()  # only Haystack was tried
    assert sc.get_tracker().request_count("torch") == 0
    assert sc.get_tracker().request_count("haystack") == 1


# --------------------------------------------------------------------------- #
# The whole pipeline with the cloud value: every listed source is `disabled`
# and makes zero requests (HTTP faked, so nothing leaves the machine).
# --------------------------------------------------------------------------- #
class _Resp:
    status = 200
    headers: dict = {}
    charset = "utf-8"

    async def text(self, *a, **k):
        return ""

    async def json(self, *a, **k):
        return {}

    async def read(self):
        return b""


class _CM:
    async def __aenter__(self):
        return _Resp()

    async def __aexit__(self, *exc):
        return False


class _FakeHttp:
    """Stands in for the shared clearnet session; records every URL asked for."""

    def __init__(self):
        self.urls: list[str] = []

    def _req(self, url, **kw):
        self.urls.append(url)
        return _CM()

    get = post = head = _req

    def request(self, method, url, **kw):
        return self._req(url, **kw)


def _run_pipeline_with_fake_http(tmp_path, monkeypatch):
    import netpool
    from voidaccess_cli.commands import investigate as module

    real = {
        name: getattr(module, name)
        for name in ("_scrape_pastes", "_scrape_rss")
    }
    fake = _FakeHttp()
    monkeypatch.setattr(netpool, "get_clearnet_session", lambda: fake)
    # Bulk feeds are cached on disk for hours; a warm /tmp cache would hide the
    # request a run is supposed to make. Start every run cold and write nothing.
    import sources.cache as cache_mod

    monkeypatch.setattr(cache_mod, "_memory_cache", {})
    monkeypatch.setattr(cache_mod.CachedFeed, "_is_fresh", lambda self: False)
    monkeypatch.setattr(cache_mod.CachedFeed, "_write_file", lambda self, data: None)
    for var in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "PHISHTANK_API_KEY", "HIBP_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GITHUB_SCRAPING_ENABLED", "false")  # owns its own aiohttp session
    inv = h.prepare(
        tmp_path, monkeypatch,
        generate_summary=lambda *a, **k: "A summary.",
        side_sources={"_scrape_pastes": real["_scrape_pastes"], "_scrape_rss": real["_scrape_rss"]},
    )
    return inv, fake


def test_cloud_value_run_disables_each_listed_source_with_zero_requests(tmp_path, monkeypatch):
    import sources.enrichment as enrichment

    real_enrich = enrichment.enrich_investigation
    inv, fake = _run_pipeline_with_fake_http(tmp_path, monkeypatch)
    # h.prepare stubbed enrichment; put the real one back.
    monkeypatch.setattr(enrichment, "enrich_investigation", real_enrich)
    monkeypatch.setenv(sc.DISABLED_ENV, CLOUD)

    h.run(inv, tmp_path, no_tor=True, quiet=True)
    used = h.read_payload(tmp_path)["sources_used"]

    for sid in CLOUD_IDS:
        assert used[sid]["status"] == "disabled", (sid, used.get(sid))
        assert used[sid]["requests"] == 0, (sid, used[sid])

    # And not a single URL belonging to a denied source was ever requested.
    contacted = {sc.source_for_url(u) for u in fake.urls}
    assert not (contacted & set(CLOUD_IDS)), contacted & set(CLOUD_IDS)

    # The counting is live: sources that were allowed to run did make calls.
    assert fake.urls, "the fake HTTP layer saw no traffic at all"
    assert any(entry["requests"] > 0 for sid, entry in used.items() if sid not in CLOUD_IDS)


def test_same_run_without_the_deny_list_does_contact_those_sources(tmp_path, monkeypatch):
    """The control: the zero above is the deny-list's doing, not an inert harness."""
    import sources.enrichment as enrichment

    real_enrich = enrichment.enrich_investigation
    inv, fake = _run_pipeline_with_fake_http(tmp_path, monkeypatch)
    monkeypatch.setattr(enrichment, "enrich_investigation", real_enrich)

    h.run(inv, tmp_path, no_tor=True, quiet=True)
    contacted = {sc.source_for_url(u) for u in fake.urls}
    assert {"ransomwhere", "sslbl", "openphish"} & contacted
    assert "pastebin" in contacted or "dpaste" in contacted or "paste_ee" in contacted
    used = h.read_payload(tmp_path)["sources_used"]
    assert not [s for s, e in used.items() if e["status"] == "disabled"]
