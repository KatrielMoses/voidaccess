"""E5: honest source status, the replaced feed endpoints, exact MITRE attribution.

Every value is synthetic (example.invalid hosts, made-up onion labels,
reserved CVE year 2099); nothing touches the network.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest

from sources import source_control

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _onion(tag: str) -> str:
    label = (tag + "abcdefghijklmnopqrstuvwxyz234567" * 3)[:56]
    return f"http://{label}.onion"


@pytest.fixture(autouse=True)
def _fresh_tracker(monkeypatch):
    for var in ("VOIDACCESS_ENRICHMENT_SOURCES", "VOIDACCESS_DISABLED_SOURCES"):
        monkeypatch.delenv(var, raising=False)
    source_control.reset_tracker()
    yield
    source_control.reset_tracker()


class _Resp:
    def __init__(self, status: int, body: str = "", content_type: str = "application/json"):
        self.status = status
        self._body = body
        self.headers = {"Content-Type": content_type}
        self.charset = "utf-8"

    async def text(self):
        return self._body

    async def json(self, content_type=None):
        return json.loads(self._body)


class _Ctx:
    def __init__(self, resp: _Resp):
        self.resp = resp

    async def __aenter__(self):
        return self.resp

    async def __aexit__(self, *exc):
        return False

    def __await__(self):
        async def _value():
            return self.resp
        return _value().__await__()


class FakeClearnet:
    """Stands in for http_pool's guarded session, with the real accounting:
    every call is counted for its source and wrapped in http_pool._track."""

    def __init__(self, routes: dict[str, tuple[int, str]]):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url, **_kw):
        from sources import http_pool

        self.calls.append(url)
        source_control.record_request_for_url(url)
        status, body = self.routes.get(url, (404, ""))
        return http_pool._track(_Ctx(_Resp(status, body)), url)

    post = get


@pytest.fixture
def clearnet(monkeypatch):
    holder: dict = {}

    def install(routes):
        fake = FakeClearnet(routes)

        @contextlib.asynccontextmanager
        async def session():
            yield fake

        monkeypatch.setattr("sources.http_pool.clearnet_session", session)
        holder["fake"] = fake
        return fake

    return install


def _status(source_id: str) -> str:
    return source_control.source_entry(source_id)["status"]


# --------------------------------------------------------------------------- #
# E5-6: honest status
# --------------------------------------------------------------------------- #

FIXED_ENDPOINTS = {
    "ransomware_live": "https://data.ransomware.live/groups.json",
    "cisa_kev": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "fbi_doj_press": "https://www.justice.gov/news/rss",
    "mitre_attack": "https://raw.githubusercontent.com/mitre/cti/master/x.json",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "ransomwhere": "https://api.ransomwhe.re/export",
}
PER_ITEM = {
    "shodan_internetdb": "https://internetdb.shodan.io/192.0.2.1",
    "hibp": "https://haveibeenpwned.com/api/v3/breachedaccount/x",
    "virustotal": "https://www.virustotal.com/api/v3/files/abc",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-0001",
}


async def _call(fake, url, awaited=False):
    if awaited:
        return await fake.get(url)
    async with fake.get(url) as resp:
        return resp


@pytest.mark.parametrize("source_id, url", sorted(FIXED_ENDPOINTS.items()))
@pytest.mark.parametrize("status", [404, 400, 410])
def test_fixed_endpoint_non_2xx_is_an_error(source_id, url, status):
    fake = FakeClearnet({url: (status, "")})
    asyncio.run(_call(fake, url))
    assert _status(source_id) == "error"


@pytest.mark.parametrize("source_id, url", sorted(PER_ITEM.items()))
def test_per_item_404_means_no_record_and_stays_ok(source_id, url):
    fake = FakeClearnet({url: (404, "")})
    asyncio.run(_call(fake, url))
    assert _status(source_id) == "ok"


def test_per_item_rate_limit_or_5xx_is_still_a_failure():
    url = PER_ITEM["shodan_internetdb"]
    asyncio.run(_call(FakeClearnet({url: (429, "")}), url))
    assert _status("shodan_internetdb") == "error"


def test_mixed_results_read_partial():
    good = "https://api.ransomwhe.re/export"
    bad = "https://api.ransomwhe.re/missing"
    fake = FakeClearnet({good: (200, "[]"), bad: (404, "")})
    asyncio.run(_call(fake, good))
    asyncio.run(_call(fake, bad))
    assert _status("ransomwhere") == "partial"
    assert "partial" in source_control.SOURCE_STATUSES


def test_awaited_get_is_counted_like_async_with():
    url = FIXED_ENDPOINTS["sslbl"]
    asyncio.run(_call(FakeClearnet({url: (404, "")}), url, awaited=True))
    assert _status("sslbl") == "error"


def test_cached_feed_failure_is_fetched_once_per_run(clearnet, tmp_path):
    from sources.cache import CachedFeed

    url = FIXED_ENDPOINTS["ransomwhere"]
    fake = clearnet({url: (404, "")})
    feed = CachedFeed(url, str(tmp_path / "feed.json"), ttl_seconds=60)
    assert asyncio.run(feed.fetch()) is None
    assert asyncio.run(feed.fetch()) is None
    assert fake.calls == [url]
    assert _status("ransomwhere") == "error"
    source_control.reset_tracker()  # next run
    asyncio.run(feed.fetch())
    assert fake.calls == [url, url]


# --------------------------------------------------------------------------- #
# E5-7: the three endpoints, with synthetic fixtures; the R1 cases
# --------------------------------------------------------------------------- #

GROUPS_JSON = json.dumps([
    {"name": "examplelock", "altname": "", "description": "Example group",
     "locations": [{"fqdn": "examplelockaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
                    "available": True, "title": "Example"}],
     "_victim_count": 3},
    {"name": "othergroup", "description": "", "locations": []},
])
RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Feed</title>
<item><title>ExampleLock affiliates charged</title><link>https://example.invalid/press/1</link>
<pubDate>Fri, 01 Jan 2099 00:00:00 +0000</pubDate><category>Ransomware</category></item>
<item><title>Unrelated notice</title><link>https://example.invalid/press/2</link></item>
</channel></rss>"""


def test_parse_rss_reads_items_and_refuses_entities():
    from sources.cache import parse_rss

    items = parse_rss(RSS)
    assert items[0] == {"title": "ExampleLock affiliates charged",
                        "link": "https://example.invalid/press/1",
                        "published": "Fri, 01 Jan 2099 00:00:00 +0000", "tags": ["Ransomware"]}
    with pytest.raises(ValueError):
        parse_rss('<!DOCTYPE x [<!ENTITY a "b">]><rss/>')


def _isolated_feed(monkeypatch, feed, tmp_path, name):
    from sources import cache

    monkeypatch.setattr(feed, "cache_path", tmp_path / name)
    cache._memory_cache.pop(feed.url, None)


def test_ransomware_live_reads_the_data_feed(clearnet, monkeypatch, tmp_path):
    import sources.enrichment as en

    _isolated_feed(monkeypatch, en._rl_groups_feed, tmp_path, "rl.json")
    _isolated_feed(monkeypatch, en._rl_victims_feed, tmp_path, "victims.json")
    victims = json.dumps([
        {"group_name": "examplelock", "post_title": "Example Victim Co", "website": "example.invalid",
         "published": "2099-01-02", "discovered": "2099-01-02",
         "post_url": "http://examplelockaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/post/1"},
        {"group_name": "othergroup", "post_title": "Other", "post_url": ""},
    ])
    fake = clearnet({
        en.RANSOMWARE_LIVE_GROUPS_URL: (200, GROUPS_JSON),
        en.RANSOMWARE_LIVE_VICTIMS_URL: (200, victims),
    })
    groups = asyncio.run(en.fetch_ransomware_live("examplelock ransomware"))
    assert [g["group"] for g in groups] == ["examplelock"]
    assert groups[0]["onion_urls"][0].endswith(".onion")
    assert groups[0]["claim_urls"] == [json.loads(victims)[0]["post_url"]]
    assert all("api.ransomware.live" not in u for u in fake.calls)
    assert _status("ransomware_live") == "ok"


def test_ransomware_live_dead_endpoint_reports_error(clearnet, monkeypatch, tmp_path):
    import sources.enrichment as en

    _isolated_feed(monkeypatch, en._rl_groups_feed, tmp_path, "rl.json")
    clearnet({en.RANSOMWARE_LIVE_GROUPS_URL: (404, "")})
    assert asyncio.run(en.fetch_ransomware_live("examplelock")) == []
    assert _status("ransomware_live") == "error"


def test_cisa_advisories_from_rss(clearnet, monkeypatch, tmp_path):
    from sources import cisa

    _isolated_feed(monkeypatch, cisa._adv_feed, tmp_path, "adv.xml")
    clearnet({cisa.CISA_ADVISORIES_URL: (200, RSS)})
    found = asyncio.run(cisa.enrich_cisa_advisories("ExampleLock", "RANSOMWARE_GROUP"))
    assert found and found[0]["advisory_url"] == "https://example.invalid/press/1"
    assert found[0]["advisory_date"].startswith("Fri, 01 Jan 2099")
    assert _status("cisa_kev") == "ok"


def test_cisa_advisories_dead_endpoint_reports_error(clearnet, monkeypatch, tmp_path):
    from sources import cisa

    _isolated_feed(monkeypatch, cisa._adv_feed, tmp_path, "adv.xml")
    clearnet({cisa.CISA_ADVISORIES_URL: (404, "")})
    assert asyncio.run(cisa.enrich_cisa_advisories("ExampleLock", "RANSOMWARE_GROUP")) == []
    assert _status("cisa_kev") == "error"


def test_fbi_doj_press_from_news_rss(clearnet, monkeypatch, tmp_path):
    from sources import historical_intel as hi

    assert hi._fbi_feed.url == "https://www.justice.gov/news/rss"
    _isolated_feed(monkeypatch, hi._fbi_feed, tmp_path, "fbi.xml")
    clearnet({hi._fbi_feed.url: (200, RSS)})
    found = asyncio.run(hi._fetch_fbi_results("ExampleLock"))
    assert [f["press_url"] for f in found] == ["https://example.invalid/press/1"]
    assert _status("fbi_doj_press") == "ok"


def test_fbi_doj_press_dead_endpoint_reports_error(clearnet, monkeypatch, tmp_path):
    from sources import historical_intel as hi

    _isolated_feed(monkeypatch, hi._fbi_feed, tmp_path, "fbi.xml")
    clearnet({hi._fbi_feed.url: (404, "")})
    assert asyncio.run(hi._fetch_fbi_results("ExampleLock")) == []
    assert _status("fbi_doj_press") == "error"


# --------------------------------------------------------------------------- #
# E5-8: exact MITRE attribution
# --------------------------------------------------------------------------- #

def _ref(ext_id):
    return [{"source_name": "mitre-attack", "external_id": ext_id}]


STIX = {"objects": [
    {"type": "intrusion-set", "id": "is-play", "name": "Play", "aliases": ["Play"], "external_references": _ref("G1040")},
    {"type": "intrusion-set", "id": "is-turla", "name": "Turla", "aliases": ["Turla", "Snake"], "external_references": _ref("G0010")},
    {"type": "intrusion-set", "id": "is-muddy", "name": "MuddyWater", "aliases": ["MuddyWater", "Earth Vetala"], "external_references": _ref("G0069")},
    {"type": "intrusion-set", "id": "is-dragon", "name": "Dragonfly", "aliases": ["Dragonfly", "TG-4192"], "external_references": _ref("G0035")},
    {"type": "intrusion-set", "id": "is-side", "name": "Sidewinder", "aliases": ["Sidewinder"], "external_references": _ref("G0121")},
    {"type": "intrusion-set", "id": "is-old", "name": "Bert Collective", "aliases": ["bert"], "revoked": True, "external_references": _ref("G0999")},
    {"type": "intrusion-set", "id": "is-wiz", "name": "Wizard Spider", "aliases": ["Wizard Spider"], "external_references": _ref("G0102")},
    {"type": "malware", "id": "sw-uro", "name": "Uroburos", "x_mitre_aliases": ["Uroburos", "Snake"]},
    {"type": "tool", "id": "sw-tor", "name": "Tor", "x_mitre_aliases": ["Tor"]},
    {"type": "malware", "id": "sw-royal", "name": "Royal", "x_mitre_aliases": ["Royal"]},
    {"type": "malware", "id": "sw-play", "name": "Playcrypt", "x_mitre_aliases": ["Playcrypt", "Play"]},
    {"type": "attack-pattern", "id": "ap-1", "external_references": _ref("T1486")},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "is-play", "target_ref": "ap-1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "is-muddy", "target_ref": "ap-1"},
]}


@pytest.mark.parametrize("name, want", [
    ("Tor", None), ("tor", None), ("Play", "G1040"), ("PLAY", "G1040"), ("royal", None),
    ("snake", None), ("bert", None), ("muddy", None), ("Dragon", None), ("side", None),
    ("conti", "G0102"), ("lockbit", None), ("cobalt strike", None),
])
def test_attack_names_resolve_exactly(name, want):
    from sources import historical_intel as hi

    group = hi._AttackIndex(STIX["objects"]).resolve(name)
    assert (hi.group_id(group) if group else None) == want


def test_overlay_skips_runs_that_already_have_techniques_and_counts_handles(monkeypatch):
    import sources.enrichment as en
    from tests import enrich_fakes as fakes

    fakes.install(monkeypatch)
    with_t = [{"entity_type": "THREAT_ACTOR_HANDLE", "value": "ExampleGroup"},
              {"entity_type": "MITRE_TECHNIQUE", "value": "T1059"}]
    pages = asyncio.run(en._enrich_new_sources("q", with_t))
    assert "mitre_attack_overlay" not in [p.get("source") for p in pages]

    handle_only = [{"entity_type": "THREAT_ACTOR_HANDLE", "value": "ExampleGroup"}]
    pages = asyncio.run(en._enrich_new_sources("q", handle_only))
    overlay = [p for p in pages if p.get("source") == "mitre_attack_overlay"]
    assert len(overlay) == 1
    lines = overlay[0]["content"].splitlines()[1:]
    assert lines and all(line.endswith("[group: ExampleGroup G9001]") for line in lines)
    assert overlay[0]["mitre_group"] == "G9001"


