"""23B: engine cull, per-engine status, cleaner results, more pages per engine.

All fixtures are synthetic (made-up 56-character onion hosts, made-up titles).
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import quote

import pytest

import search.search as search_mod
from search import engine_status as es
from search import result_clean as rc
from search.engine_catalog import SEARCH_ENGINES, active_engines


def _onion(ch: str) -> str:
    return f"http://{ch * 56}.onion"


A, B, C, D = _onion("a"), _onion("b"), _onion("c"), _onion("d")
CATALOG = {e["name"]: e for e in SEARCH_ENGINES}


def _host(url: str) -> str:
    return rc.host_of(url)


# --------------------------------------------------------------------------- #
# B1 engine cull
# --------------------------------------------------------------------------- #

def test_dead_and_chrome_only_engines_are_quarantined():
    for name in ("Torgle", "Torgol", "Amnesia", "Torland", "TorNet"):
        assert CATALOG[name]["status"] == "quarantined", name
    assert [e["name"] for e in active_engines()] == [
        "Ahmia (Clearnet Proxy)", "Ahmia", "OnionLand", "Excavator", "Onionway", "Tor66",
        "The Deep Searches",
    ]


def test_ahmia_entries_are_unchanged():
    assert CATALOG["Ahmia (Clearnet Proxy)"] == {
        "name": "Ahmia (Clearnet Proxy)", "url": "https://ahmia.fi/search/?q={query}", "status": "active",
    }
    assert CATALOG["Ahmia"] == {
        "name": "Ahmia",
        "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
        "status": "active",
    }


def test_torch_and_haystack_are_quarantined_and_never_contacted(monkeypatch):
    import sources.engines as engines

    assert not engines.onionsearch_enabled()
    touched: list[str] = []

    def acquire(url):
        touched.append(url)
        raise AssertionError("a quarantined engine was contacted")

    monkeypatch.setattr(engines.tor_pool, "acquire_tor_session", acquire)
    assert asyncio.run(engines.search_onionsearch("lockbit")) == []
    assert touched == []
    status = engines.get_last_onionsearch_status()
    assert status == {"Torch": "skipped_quarantined", "Haystack": "skipped_quarantined"}

    from sources import source_control as sc

    assert sc.normalize_module_status("torch", status["Torch"]) == sc.STATUS_SKIPPED


def test_quarantine_is_reversible(monkeypatch):
    import sources.engines as engines

    monkeypatch.setattr(
        engines, "_ONIONSEARCH_ENGINES",
        [dict(e, status="active") for e in engines._ONIONSEARCH_ENGINES],
    )
    assert engines.onionsearch_enabled()


def test_paging_templates_are_well_formed():
    paging = {e["name"]: e["pages"] for e in SEARCH_ENGINES if e.get("pages")}
    assert set(paging) == {"Excavator", "Onionway", "The Deep Searches"}
    for name, cfg in paging.items():
        engine = CATALOG[name]
        assert engine["status"] == "active"
        page2 = cfg["url"].format(query="x y", page=2)
        assert page2.startswith(engine["url"].format(query="x y"))
        assert page2.endswith("page=2")
        assert 2 <= cfg["max"] <= 3 and cfg["full"] >= 1


# --------------------------------------------------------------------------- #
# B3 result clean-up
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("href,target", [
    (f"/l?l={quote(quote(A + '/forum/1', safe=''), safe='')}", A + "/forum/1"),
    (f"/out?u={quote(B + '/x', safe='')}", B + "/x"),
    (f"http://engine.onion/r?url={quote(C + '/p?id=4', safe='')}&from=s", C + "/p?id=4"),
    (f"/click?redirect_url={quote(D, safe='')}", D),
    (f"/redirect?q={quote(A + '/q', safe='')}", A + "/q"),
    (f"/go?site={'a' * 56}.onion/page", A + "/page"),
])
def test_unwrap_redirect(href, target):
    assert rc.unwrap_redirect(href) == target


@pytest.mark.parametrize("href", [
    f"/search?q={quote(A, safe='')}",  # q on a search path is the search text
    "/search?q=lockbit&page=2",
    A + "/plain/path",
    "/l?l=not-a-url",
])
def test_unwrap_redirect_leaves_other_links(href):
    assert rc.unwrap_redirect(href) is None


@pytest.mark.parametrize("url,clean", [
    (A + "/t?id=7&utm_source=x&utm_medium=y", A + "/t?id=7"),
    (A + "/t?ref=engine&fbclid=abc&page=2#top", A + "/t?page=2"),
    (A + "/viewtopic.php?t=9&sid=0123456789abcdef0123456789abcdef", A + "/viewtopic.php?t=9"),
    (A + "/viewtopic.php?t=9&sid=forums", A + "/viewtopic.php?t=9&sid=forums"),
    (A + "/a;jsessionid=XYZ123/b?PHPSESSID=1&k=v", A + "/a/b?k=v"),
    ("HTTP://" + "A" * 56 + ".ONION/CasePath", "http://" + "a" * 56 + ".onion/CasePath"),
    (A + "/keep?b=2&a=1&c=%20x", A + "/keep?b=2&a=1&c=%20x"),
])
def test_normalize_result_url(url, clean):
    assert rc.normalize_result_url(url) == clean


def test_search_engine_hosts_cover_catalog_side_sources_and_known_engines():
    assert rc.is_search_engine_host(CATALOG["Tor66"]["url"].format(query="x"))
    assert rc.is_search_engine_host(CATALOG["Torland"]["url"].format(query="x"))  # quarantined too
    assert rc.is_search_engine_host("http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/")
    assert rc.is_search_engine_host("https://www.ahmia.fi/search/?q=x")
    assert rc.is_search_engine_host(next(iter(rc.KNOWN_SEARCH_HOSTS)))
    assert not rc.is_search_engine_host(A + "/forum")


def test_parser_drops_engine_hosts_unwraps_and_normalises():
    base = "http://" + "e" * 56 + ".onion/search?q=lockbit"
    other_engine = CATALOG["Excavator"]["url"].format(query="lockbit")
    html = f"""<html><body>
      <a href="/l?l={quote(quote(A + '/leak?utm_source=e', safe=''), safe='')}">Synthetic result one</a>
      <a href="{B}/thread?id=3#reply">Synthetic result two</a>
      <a href="{other_engine}">Another search engine</a>
      <a href="{base}&page=2">Next page</a>
      <p>see also {C}/mention and {CATALOG['Tor66']['url'].format(query='q')}</p>
    </body></html>"""
    links = search_mod._parse_html_links(html, base)
    assert [(l["link"], bool(l.get("from_text"))) for l in links] == [
        (A + "/leak", False),
        (B + "/thread?id=3", False),
        (C + "/mention", True),
    ]
    assert links[0]["title"] == "Synthetic result one"


def test_merge_duplicates_records_engines_and_keeps_best():
    links = [
        {"link": A + "/x", "title": A[7:], "from_text": True, "source_engine": "E1", "source_weight": 0.5},
        {"link": B + "/y", "title": "other", "source_engine": "E1", "source_weight": 0.5},
        {"link": A + "/x/?utm_campaign=z#f", "title": "Real title", "source_engine": "E2", "source_weight": 0.5},
        {"link": "HTTPS://" + "a" * 56 + ".onion/x", "title": "Third", "source_engine": "E3", "source_weight": 0.9},
        {"link": A + "/x", "title": "again", "source_engine": "E2", "source_weight": 0.5},
        {"link": "", "title": "no url"},
    ]
    out = search_mod._dedupe_links(links)
    assert [l["title"] for l in out] == ["Third", "other"]  # A keeps position 0
    assert out[0]["found_by"] == ["E1", "E2", "E3"] and out[0]["engine_count"] == 3
    assert out[1]["found_by"] == ["E1"] and out[1]["engine_count"] == 1


def test_merge_prefers_a_result_link_over_a_text_mention():
    out = rc.merge_duplicates([
        {"link": A, "title": "t1", "from_text": True, "source_engine": "E1", "source_weight": 0.9},
        {"link": A + "/", "title": "Result", "source_engine": "E2", "source_weight": 0.5},
    ])
    assert len(out) == 1 and out[0]["title"] == "Result" and out[0]["found_by"] == ["E1", "E2"]


def test_agreement_breaks_near_ties_but_not_relevance():
    from search.ranking import semantic_rank

    vectors = {"q": [1.0, 0.0], "near1": [0.99, 0.141], "near2": [0.99, 0.141], "far": [0.5, 0.866]}
    one = {"title": "near1", "engine_count": 1}
    three = {"title": "near2", "engine_count": 3}
    off_topic = {"title": "far", "engine_count": 6}
    ranked = semantic_rank("q", [one, off_topic, three], embedder=lambda t: vectors[t])
    assert [c["title"] for c in ranked] == ["near2", "near1", "far"]


# --------------------------------------------------------------------------- #
# B2 per-engine status
# --------------------------------------------------------------------------- #

def _r(name, links=0, error=None, failure=None, ms=10):
    return search_mod.EngineResult(
        name=name, links=[{"link": f"{A}/{i}"} for i in range(links)], error=error,
        failure=failure, took_ms=ms,
    )


@pytest.mark.parametrize("result,outcome", [
    (_r("e", 3), "ok"),
    (_r("e", 0), "empty"),
    (_r("e", error="timeout"), "unreachable"),
    (_r("e", error="deadline"), "unreachable"),
    (_r("e", error="HTTP 429"), "rate_limited"),
    (_r("e", error="HTTP 503"), "error"),
    (_r("e", error="boom"), "error"),
    (_r("e", error="Cannot connect", failure="unreachable"), "unreachable"),
    (_r("e", error="circuit_open"), None),
    (_r("e", error="cancelled"), None),
])
def test_outcome_of(result, outcome):
    assert es.outcome_of(result) == outcome


def test_failure_for_exception():
    from python_socks import ProxyConnectionError, ProxyError

    assert es.failure_for_exception(asyncio.TimeoutError()) == "unreachable"
    assert es.failure_for_exception(ConnectionRefusedError()) == "unreachable"
    assert es.failure_for_exception(ProxyConnectionError("x")) == "unreachable"
    assert es.failure_for_exception(ProxyError("host unreachable")) == "unreachable"
    assert es.failure_for_exception(ValueError("parse")) == "error"
    assert es.failure_for_http(429) == "rate_limited"
    assert es.failure_for_http(500) == "error"


def test_summarize_takes_the_best_outcome_per_engine():
    summary = es.summarize([
        _r("E1", 0), _r("E1", 2),  # refined empty, exact ok
        _r("E2", error="timeout"), _r("E2", 0),
        _r("E3", error="HTTP 429"),
        _r("E4", error="timeout"),
        _r("E5", error="circuit_open"),
        ValueError("task failed"),
    ])
    assert {k: v["status"] for k, v in summary["engines"].items()} == {
        "E1": "ok", "E2": "empty", "E3": "rate_limited", "E4": "unreachable",
    }
    assert summary["engines"]["E1"]["results"] == 2 and summary["engines"]["E1"]["attempts"] == 2
    assert summary["engine_status_counts"] == {
        "ok": 1, "empty": 1, "unreachable": 1, "rate_limited": 1, "error": 0,
    }
    assert summary["engines_attempted"] == 4


@pytest.mark.parametrize("results,found,text,reason", [
    ([_r("E1", error="timeout"), _r("E2", error="timeout"), _r("E3", error="deadline")], 0,
     "3 of 3 engines unreachable", "engines_unreachable"),
    ([_r("E1", 0), _r("E2", 0)], 0, "engines answered but found nothing", "no_results"),
    ([_r("E1", 0), _r("E2", error="timeout"), _r("E3", error="HTTP 429")], 0,
     "engines answered but found nothing (1 of 3 engines unreachable, 1 rate-limited)", "no_results"),
    ([_r("E1", error="HTTP 500")], 0, "no engine answered with results (1 failed)", "engines_failed"),
    ([_r("E1", 4), _r("E2", error="timeout")], 4, "1 of 2 engines returned results (1 unreachable)", None),
    ([], 0, "no search engine was queried", None),
])
def test_describe_says_which_case(results, found, text, reason):
    summary = es.summarize(results)
    assert es.describe(summary, found) == text
    assert es.nothing_found_reason(summary, found) == reason


class _Resp:
    def __init__(self, status, body=""):
        self.status = status
        self._body = body

    async def text(self, *a, **k):
        return self._body


class _Session:
    """Fake aiohttp session: url -> status/body, an exception, or (delay, body)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url, **_kw):
        self.calls.append(url)
        action = self.routes.get(url, (404, ""))

        class _CM:
            async def __aenter__(self_inner):
                if isinstance(action, BaseException):
                    raise action
                status, body = action[:2]
                if len(action) == 3:
                    await asyncio.sleep(action[2])
                return _Resp(status, body)

            async def __aexit__(self_inner, *exc):
                return False

        return _CM()


@pytest.fixture
def no_retry(monkeypatch):
    monkeypatch.setattr(search_mod.search_config, "engine_retry_count", lambda: 0)
    monkeypatch.setattr(search_mod, "record_request", lambda *_a: None)


def _fetch(engine, session, stop_at=None):
    async def go():
        return await search_mod._fetch_engine(
            engine, "q", session, asyncio.Semaphore(5), stop_at=stop_at
        )
    return asyncio.run(go())


ENGINE = {"name": "E", "url": "http://" + "e" * 56 + ".onion/s?q={query}", "status": "active"}


def test_fetch_engine_classifies_failures(no_retry):
    from python_socks import ProxyConnectionError

    url = ENGINE["url"].format(query="q")
    assert _fetch(ENGINE, _Session({url: (429, "")})).failure == "rate_limited"
    assert _fetch(ENGINE, _Session({url: (500, "")})).failure == "error"
    assert _fetch(ENGINE, _Session({url: ProxyConnectionError("x")})).failure == "unreachable"
    assert _fetch(ENGINE, _Session({url: asyncio.TimeoutError()})).failure == "unreachable"
    ok = _fetch(ENGINE, _Session({url: (200, f'<a href="{A}/r">Synthetic</a>')}))
    assert es.outcome_of(ok) == "ok" and ok.first_page_ms is not None and ok.pages == 1


def _patch_fanout(monkeypatch, fake_fetch):
    async def no_stats():
        return []

    async def never_skip(_n):
        return False

    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", no_stats)
    monkeypatch.setattr(search_mod, "should_skip_engine_async", never_skip)
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", lambda *a, **k: None)
    monkeypatch.setattr(search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda k: None)


FANOUT = [
    {"name": n, "url": f"http://{n.lower()}.onion/?q={{query}}", "status": "active"}
    for n in ("Good", "Quiet", "Dead", "Busy", "Slow")
]


def test_fanout_summary_reports_each_engine(monkeypatch):
    async def fake_fetch(engine, query, session, semaphore):
        name = engine["name"]
        if name == "Good":
            return search_mod.EngineResult(name=name, links=[{"link": f"{A}/{query}", "title": "Synthetic"}])
        if name == "Quiet":
            return search_mod.EngineResult(name=name, links=[])
        if name == "Dead":
            return search_mod.EngineResult(name=name, links=[], error="Cannot connect", failure="unreachable")
        if name == "Busy":
            return search_mod.EngineResult(name=name, links=[], error="HTTP 429", failure="rate_limited")
        await asyncio.sleep(5)
        return search_mod.EngineResult(name=name, links=[])

    _patch_fanout(monkeypatch, fake_fetch)
    monkeypatch.setenv("VOIDACCESS_SEARCH_DEADLINE", "0.5")
    monkeypatch.setattr(search_mod, "SEARCH_ENGINES", FANOUT)
    links = search_mod.get_search_results_async("q", 5, None, "exact q", None)
    summary = search_mod.get_last_search_summary()
    assert {k: v["status"] for k, v in summary["engines"].items()} == {
        "Good": "ok", "Quiet": "empty", "Dead": "unreachable", "Busy": "rate_limited", "Slow": "unreachable",
    }
    assert summary["engines"]["Good"]["attempts"] == 2  # refined + exact query
    assert summary["engines_attempted"] == 5
    # Pre-23B keys are still there.
    assert {"success", "total", "active", "circuits_open", "results"} <= set(summary)
    assert es.describe(summary, len(links)) == "1 of 5 engines returned results (2 unreachable, 1 rate-limited)"


def test_trace_keeps_status_and_adds_outcome(monkeypatch):
    calls = []
    monkeypatch.setattr(
        search_mod._trace, "search_result", lambda *a, **k: calls.append((a, k))
    )
    monkeypatch.setattr(search_mod._trace, "url_found", lambda *a, **k: None)
    search_mod._trace_engine_result(_r("E", 0), 0)
    search_mod._trace_engine_result(_r("E", error="deadline"), 0)
    assert [(a[1], k["outcome"]) for a, k in calls] == [("ok", "empty"), ("timeout", "unreachable")]


def test_trace_search_result_emits_outcome_field():
    from progress import trace as tr

    events = []

    class _T:
        def trace(self, stage, kind, data):
            events.append(data)

    token = tr._ctx_tracer.set(_T())
    try:
        tr.search_result("E", "ok", 0, 5, outcome="empty")
        tr.search_result("E", "ok", 0, 5, outcome="bogus")
    finally:
        tr._ctx_tracer.reset(token)
    assert events[0]["outcome"] == "empty" and "outcome" not in events[1]


# --------------------------------------------------------------------------- #
# B4 more results per engine
# --------------------------------------------------------------------------- #

PAGED = {
    "name": "P", "url": "http://" + "p" * 56 + ".onion/s?q={query}", "status": "active",
    "pages": {"url": "http://" + "p" * 56 + ".onion/s?q={query}&page={page}", "max": 3, "full": 3},
}


def _page(hosts, start):
    return "".join(f'<a href="{_onion(h)}/item{start + i}">Synthetic item {i}</a>' for i, h in enumerate(hosts))


def _paged_routes(page2=None, page3=None, page1_hosts="abc"):
    p1 = PAGED["url"].format(query="q")
    p2 = PAGED["pages"]["url"].format(query="q", page=2)
    p3 = PAGED["pages"]["url"].format(query="q", page=3)
    routes = {p1: (200, _page(page1_hosts, 0))}
    if page2 is not None:
        routes[p2] = page2
    if page3 is not None:
        routes[p3] = page3
    return routes


def test_full_first_page_fetches_further_pages_and_dedupes(no_retry):
    # page 2 repeats one page-1 link; page 3 is new.
    page2 = (200, _page("a", 0) + _page("de", 10))
    page3 = (200, _page("fg", 20))
    session = _Session(_paged_routes(page2, page3))
    result = _fetch(PAGED, session, stop_at=time.monotonic() + 30)
    assert result.pages == 3
    assert len(result.links) == 3 + 2 + 2
    assert len({rc.dedup_key(l["link"]) for l in result.links}) == len(result.links)
    assert len(session.calls) == 3


def test_partial_first_page_reads_no_more(no_retry):
    session = _Session(_paged_routes((200, _page("de", 10)), page1_hosts="ab"))
    result = _fetch(PAGED, session, stop_at=time.monotonic() + 30)
    assert result.pages == 1 and len(session.calls) == 1


def test_no_budget_or_switch_off_reads_no_more(no_retry, monkeypatch):
    routes = _paged_routes((200, _page("de", 10)), (200, _page("fg", 20)))
    session = _Session(routes)
    assert _fetch(PAGED, session, stop_at=None).pages == 1
    session = _Session(routes)
    assert _fetch(PAGED, session, stop_at=time.monotonic() + 2).pages == 1
    monkeypatch.setenv("VOIDACCESS_SEARCH_PAGES", "0")
    session = _Session(routes)
    assert _fetch(PAGED, session, stop_at=time.monotonic() + 30).pages == 1
    assert len(session.calls) == 1


def test_slow_page_is_cut_and_page_one_kept(no_retry, monkeypatch):
    monkeypatch.setattr(search_mod, "PAGE_MIN_BUDGET_S", 0.3)
    monkeypatch.setattr(search_mod, "PAGE_MARGIN_S", 0.0)
    routes = _paged_routes((200, _page("de", 10)), (200, _page("fg", 20), 5.0))
    session = _Session(routes)
    t0 = time.monotonic()
    result = _fetch(PAGED, session, stop_at=time.monotonic() + 0.6)
    assert time.monotonic() - t0 < 2.0
    assert result.error is None and result.pages == 2 and len(result.links) == 5


def test_page_errors_never_cost_page_one(no_retry):
    from python_socks import ProxyConnectionError

    routes = _paged_routes((500, ""), ProxyConnectionError("x"))
    result = _fetch(PAGED, _Session(routes), stop_at=time.monotonic() + 30)
    assert result.error is None and result.pages == 1 and len(result.links) == 3


def test_fanout_passes_the_engine_deadline_to_paging(monkeypatch):
    seen = {}

    async def fake_fetch(engine, query, session, semaphore):
        seen[engine["name"]] = search_mod._PAGE_STOP_AT.get() - time.monotonic()
        return search_mod.EngineResult(name=engine["name"], links=[])

    _patch_fanout(monkeypatch, fake_fetch)
    monkeypatch.setattr(search_mod, "get_engine_timeout", lambda stats: 20)
    monkeypatch.setenv("VOIDACCESS_SEARCH_DEADLINE", "7")
    asyncio.run(search_mod._search_async("q", engines=FANOUT[:2], allow_diversify=False))
    assert all(5.0 < left <= 7.0 for left in seen.values()), seen
    monkeypatch.delenv("VOIDACCESS_SEARCH_DEADLINE")
    asyncio.run(search_mod._search_async("q", engines=FANOUT[:2], allow_diversify=False))
    assert all(18.0 < left <= 20.0 for left in seen.values()), seen


# --------------------------------------------------------------------------- #
# B5 alternatives only on engines that answered
# --------------------------------------------------------------------------- #

def test_alternative_engines_prefer_answering_engines():
    engines = [{"name": n} for n in ("Dead", "Quiet", "Big", "Small")]
    processed = [
        _r("Dead", error="timeout"), _r("Quiet", 0), _r("Big", 4), _r("Small", 1),
        _r("Big", 0),
    ]
    assert [e["name"] for e in search_mod._alternative_engines(engines, processed)] == ["Big", "Small", "Quiet"]
    assert search_mod._alternative_engines(engines, [_r("Dead", error="timeout")]) == []


def test_diversify_skips_an_engine_unreachable_in_this_run(monkeypatch):
    queried: list[tuple[str, str]] = []

    async def fake_fetch(engine, query, session, semaphore):
        queried.append((engine["name"], query))
        if engine["name"] == "Dead":
            await asyncio.sleep(0.3)
            return search_mod.EngineResult(name="Dead", links=[], error="timeout", failure="unreachable")
        return search_mod.EngineResult(name=engine["name"], links=[])

    async def alternatives(query, count, llm):
        return ["alt one", "alt two"]

    _patch_fanout(monkeypatch, fake_fetch)
    monkeypatch.delenv("VOIDACCESS_SEARCH_DEADLINE", raising=False)
    monkeypatch.setattr(search_mod, "diversify_query", alternatives)
    engines = [
        {"name": n, "url": f"http://{n.lower()}.onion/?q={{query}}", "status": "active"}
        for n in ("Dead", "Quiet")
    ]
    t0 = time.monotonic()
    asyncio.run(search_mod._search_async("q", engines=engines, llm_client=object()))
    elapsed = time.monotonic() - t0
    assert ("Dead", "alt one") not in queried and ("Quiet", "alt one") in queried
    assert elapsed < 0.55  # one dead-engine wait, not three


# --------------------------------------------------------------------------- #
# JSON report block
# --------------------------------------------------------------------------- #

def test_search_engines_report_block():
    from voidaccess_cli.commands.investigate import _search_engines_report

    summary = es.summarize([_r("E1", 0), _r("E2", error="timeout")])
    block = _search_engines_report(summary, 0, no_tor=False)
    assert block["engines"]["E1"]["status"] == "empty"
    assert block["engines"]["E2"]["status"] == "unreachable"
    assert block["nothing_found"] == "no_results"
    assert block["message"] == "engines answered but found nothing (1 of 2 engines unreachable)"
    off = _search_engines_report({}, 0, no_tor=True)
    assert off["engines_attempted"] == 0 and off["message"] == "not run (--no-tor)"
