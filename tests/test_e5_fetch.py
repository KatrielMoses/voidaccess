"""E5: onion selection (diversity, depth-aware top-N), backfill, depth-1 links,
and counting only real pages.

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
# E5-1 / E5-2 / E5-3: selection, depth-aware top-N, backfill
# --------------------------------------------------------------------------- #


def test_select_diverse_one_per_host_two_per_family_result_links_first():
    from search.selection import select_diverse

    ranked = [
        {"link": _onion("aaaaaaa1") + "/a", "title": "t"},
        {"link": _onion("aaaaaaa1") + "/b", "title": "t"},      # same host
        {"link": _onion("aaaaaaa2") + "/", "title": "t"},       # same family (2nd ok)
        {"link": _onion("aaaaaaa3") + "/", "title": "t"},       # same family (3rd: no)
        {"link": _onion("textonly") + "/", "title": "x", "from_text": True},
        {"link": _onion("bbbbbbb1") + "/", "title": "t"},
    ]
    picked, rest = select_diverse(ranked, 10)
    links = [p["link"] for p in picked]
    assert links == [ranked[0]["link"], ranked[2]["link"], ranked[5]["link"], ranked[4]["link"]]
    assert ranked[1] in rest and ranked[3] in rest


def test_onion_top_n_follows_depth_and_env(monkeypatch):
    from search.selection import onion_top_n
    from voidaccess_cli.commands.investigate import DEPTH_PRESETS

    assert [DEPTH_PRESETS[d]["top_n"] for d in ("shallow", "normal", "deep")] == [15, 25, 40]
    monkeypatch.delenv("VOIDACCESS_ONION_TOP_N", raising=False)
    assert onion_top_n(25) == 25
    for raw, want in (("8", 8), ("2", 5), ("500", 60), ("junk", 25)):
        monkeypatch.setenv("VOIDACCESS_ONION_TOP_N", raw)
        assert onion_top_n(25) == want


class _Content:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _n):
        yield self.body


class _PageResp:
    def __init__(self, status, body: bytes):
        self.status = status
        self.headers = {"Content-Type": "text/html"}
        self.charset = "utf-8"
        self.content = _Content(body)


class _OnionSession:
    def __init__(self, bodies: dict[str, object]):
        self.bodies = bodies
        self.fetched: list[str] = []

    def get(self, url, headers=None, **_kw):
        self.fetched.append(url)
        body = self.bodies.get(url, 404)
        session = self

        class _CM:
            async def __aenter__(self_inner):
                if isinstance(body, int):
                    return _PageResp(body, b"")
                return _PageResp(200, body)

            async def __aexit__(self_inner, *exc):
                return False

        return _CM()


def _page(words: str) -> bytes:
    return f"<html><body><article><p>{(words + ' ') * 40}</p></article></body></html>".encode()


@pytest.fixture
def onion_scraper(monkeypatch):
    import scraper.scrape as scrape

    def install(bodies):
        session = _OnionSession(bodies)
        monkeypatch.setattr(scrape, "_acquire_tor_session", lambda url: (session, None))
        monkeypatch.setattr(scrape, "_persist_pages", lambda items: None)
        monkeypatch.setattr(scrape.pacing, "retry_plan", lambda n, d: (0, ()))

        async def no_seeds(**_kw):
            return 0

        monkeypatch.setattr(scrape, "_discover_seeds_from_one_page", no_seeds)
        return scrape, session

    return install


def test_mirror_crowding_backfills_to_fifteen_unique_pages_in_one_extra_batch(onion_scraper):
    """A1: 13 mirror hosts serve identical bytes among 30 candidates."""
    from search.selection import select_diverse
    from utils.content_dedup import deduplicate_page_records
    from voidaccess_cli.commands import investigate as inv

    mirrors = [_onion(f"m{i:02d}mirror") + "/" for i in range(13)]
    uniques = [_onion(f"u{i:02d}unique") + "/" for i in range(17)]
    ranked = [{"link": u, "title": "lockbit"} for u in mirrors + uniques]  # mirrors rank first
    bodies = {u: _page("identical mirrored leak site listing") for u in mirrors}
    bodies.update({u: _page(f"distinct page number {i} about lockbit") for i, u in enumerate(uniques)})
    scrape, session = onion_scraper(bodies)

    picked, pool = select_diverse(ranked, 15)
    batches = 0

    async def fetch(links):
        nonlocal batches
        batches += 1
        return await scrape.scrape_multiple(links, max_workers=8, collect_outlinks=True)

    pages: list[dict] = []
    first = asyncio.run(fetch(picked))
    pages += [{"url": u, "text": t, "source": "tor_search"} for u, t in first.items()]

    class _NoTrace:
        def __getattr__(self, _name):
            return lambda *a, **k: None

    extra = inv._extra_fetch_links(_NoTrace(), picked, pool, pages, {}, 15, "shallow")
    assert extra, "dedup emptied slots, so a backfill batch is due"
    more = asyncio.run(fetch(extra))
    pages += [{"url": u, "text": t, "source": "tor_search"} for u, t in more.items()]

    unique = deduplicate_page_records([dict(p) for p in pages])
    assert len(unique) == 15
    assert batches == 2  # the first batch plus at most one extra


def test_depth1_takes_same_host_links_first_and_is_off_for_shallow(onion_scraper):
    from search.selection import DEPTH1_LINKS, DiversityState, depth1_candidates

    a, b = _onion("aaaasite"), _onion("bbbbsite")
    outlinks = [(a + "/", [a + "/post/1", b + "/x", a + "/post/2"])]
    state = DiversityState([a + "/"])
    picked = depth1_candidates(outlinks, 10, state)
    assert picked[0] == a + "/post/1"   # same site first
    assert b + "/x" in picked
    assert DEPTH1_LINKS == {"shallow": 0, "normal": 10, "deep": 20}


def test_outlinks_come_from_fetched_bytes_without_assets_or_self():
    from scraper.scrape import extract_onion_outlinks

    page = _onion("pagehost") + "/index"
    other = _onion("otherhst")
    html = (
        f'<a href="/post/1">p</a><a href="{other}/x#frag">x</a>'
        f'<link href="/style.css"><a href="{page}">self</a><a href="https://example.invalid/">c</a>'
    ).encode()
    assert extract_onion_outlinks(page, html) == [_onion("pagehost") + "/post/1", other + "/x"]


# --------------------------------------------------------------------------- #
# E5-5: only real pages are pages
# --------------------------------------------------------------------------- #


def test_failed_and_empty_fetches_are_not_pages(onion_scraper, monkeypatch):
    """A6: no stored page carries only a search title."""
    ok, gone, empty = _onion("okokokok") + "/", _onion("gonegone") + "/", _onion("emptyemp") + "/"
    scrape, _ = onion_scraper({ok: _page("real content"), gone: 404,
                               empty: b"<html><body></body></html>"})
    stored: list = []
    monkeypatch.setattr(scrape, "_persist_pages", lambda items: stored.extend(items))
    links = [{"link": u, "title": "Search result title"} for u in (ok, gone, empty)]
    results = asyncio.run(scrape.scrape_multiple(links, max_workers=3))
    assert list(results) == [ok]
    assert "Search result title" not in results[ok] or "real content" in results[ok]
    assert [item[0] for item in stored] == [ok]
    assert all(item[3] for item in stored)  # db text present


def test_scrape_single_returns_no_text_for_a_failed_fetch(onion_scraper):
    gone = _onion("gonegone") + "/"
    scrape, _ = onion_scraper({gone: 503})
    url, text = asyncio.run(scrape.scrape_single({"link": gone, "title": "Title"}))
    assert (url, text) == (gone, "")


