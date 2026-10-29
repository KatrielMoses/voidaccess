import asyncio
import contextvars
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
import requests
from bs4 import BeautifulSoup

from config import TOR_PROXY_HOST, TOR_PROXY_PORT
from scraper import tor_pool
from search import tor_isolation
from db.search_engine_stats import (
    engine_priority_score,
    get_all_engine_stats_async,
    get_engine_timeout,
    record_engine_attempt_async,
    should_skip_engine_async,
)
from search.query_builder import diversify_query
from search.engine_catalog import SEARCH_ENGINES
from sources.source_control import record_request, source_gate
from progress import trace as _trace
from utils import cancel
from utils.content_safety import gate_search_results
from search.result_clean import (
    dedup_key,
    is_search_engine_host,
    merge_duplicates,
    normalize_result_url,
    unwrap_redirect,
)
from utils.async_utils import run_async
from search import config as search_config
from search import engine_status as _engine_status

logger = logging.getLogger(__name__)

ENGINE_WEIGHTS = {
    "ahmia": 0.9,
    "torch": 0.7,
}


def _normalize_for_dedup(url: str) -> str:
    # Lower-cased, no trailing slash, http/https folded, and (23B-B3) without
    # tracking/session parameters or fragment.
    return dedup_key(url)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54"
]


_ONION_URL_RE = re.compile(r'https?://[a-z0-9._-]+\.onion(?:/[^\s"\'<>]*)?', re.IGNORECASE)

MAX_CONCURRENT = 10
# Compatibility exports of the `normal` baseline; every runtime read goes
# through search_config's pacing-aware accessors instead.
SEARCH_TIMEOUT = search_config.SEARCH_TIMEOUT
ENGINE_RETRY_COUNT = search_config.ENGINE_RETRY_COUNT

_ENGINE_STATUS: dict[str, dict] = {}
_LAST_SEARCH_SUMMARY: dict[str, int] = {}


@dataclass
class EngineResult:
    name: str
    links: list[dict]
    error: Optional[str] = None
    took_ms: int = 0
    # Results the content-safety gate removed from ``links`` (traced, never used).
    safety_dropped: list[dict] = field(default_factory=list)
    # 23B-B2: "unreachable" / "rate_limited" / "error" when the attempt failed
    # (search/engine_status.py); None lets the error text decide.
    failure: Optional[str] = None
    # 23B-B4: result pages read (1 unless the engine paginates), and how long
    # page 1 took (what the adaptive per-engine timeout learns from).
    pages: int = 1
    first_page_ms: Optional[int] = None


def _get_tor_session():
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        "https": f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
    }
    return session


# Public alias used by scripts/health_check.py.  Kept here (the canonical module)
# so `from search.search import get_tor_session` resolves — before P1.1
# consolidation this alias existed only in search/__init__.py, so that submodule
# import was silently broken.
get_tor_session = _get_tor_session


def get_search_session() -> aiohttp.ClientSession:
    """Return a Tor-proxied session for search use.

    Kept for backward compatibility.  This is the pool's *shared un-isolated*
    bucket, because it names no target and so has no isolation key to derive
    one from.  Per-engine isolation happens in `_search_async`, which acquires a
    session keyed on each engine's hostname — prefer
    `search.tor_isolation.acquire_engine_session` in new code.
    """
    return tor_pool.get_tor_session_cached()


async def close_search_session() -> None:
    """Close search's Tor sessions — call on shutdown.

    Search no longer owns a session of its own; it borrows from the shared pool,
    so this drains that pool.  Safe to call alongside
    `scraper.scrape.close_cached_sessions()` (which drains the same pool) — the
    second call simply finds it empty.
    """
    await tor_pool.close_pool()


def _is_onion_url(url: str) -> bool:
    return bool(_ONION_URL_RE.search(url))


async def fetch_with_timeout(
    url: str,
    session: aiohttp.ClientSession,
) -> aiohttp.ClientResponse:
    """Fetch a URL with timeout using the provided session."""
    return await session.get(url, timeout=aiohttp.ClientTimeout(total=search_config.search_timeout()))


# 23B-B4 paging: stop this long before the engine's own budget ends, and do not
# start a page fetch with less than this left.
PAGE_MARGIN_S = 1.0
PAGE_MIN_BUDGET_S = 3.0
# A further page gets at most this many times page 1's own time (a page takes
# about as long as page 1 on the same circuit), so paging a fast engine never
# holds the fan-out up to the engine's full timeout.
PAGE_TIME_FACTOR = 1.5
# The fan-out sets this per engine task (a contextvar, so _fetch_engine keeps
# its four-argument call shape).
_PAGE_STOP_AT: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "search_page_stop_at", default=None
)


async def _fetch_engine(
    engine: dict,
    query: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    stop_at: Optional[float] = None,
) -> EngineResult:
    """Page 1 of *engine* for *query* (with retries), then, for an engine with
    a ``pages`` entry whose page 1 was full, its further pages concurrently,
    only within the time left before *stop_at* (a ``time.monotonic()``
    instant: the engine's own timeout or the search deadline, whichever is
    first). Without *stop_at* only page 1 is read."""
    url = engine["url"].format(query=query)
    name = engine["name"]
    if stop_at is None:
        stop_at = _PAGE_STOP_AT.get()

    headers = {"User-Agent": random.choice(USER_AGENTS)}

    async with semaphore:
        started = time.monotonic()
        for attempt in range(search_config.engine_retry_count() + 1):
            if cancel.is_cancelled():
                return EngineResult(name=name, links=[], error="cancelled")
            try:
                record_request("tor_search")
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=search_config.search_timeout())) as resp:
                    if resp.status != 200:
                        if attempt < search_config.engine_retry_count():
                            await asyncio.sleep(search_config.retry_backoff(attempt))
                            continue
                        return EngineResult(
                            name=name,
                            links=[],
                            error=f"HTTP {resp.status}",
                            failure=_engine_status.failure_for_http(resp.status),
                        )

                    text = await resp.text()

                links = _parse_html_links(text, url)
                result = EngineResult(
                    name=name, links=links,
                    first_page_ms=int((time.monotonic() - started) * 1000),
                )
                try:
                    await _fetch_more_pages(engine, query, session, headers, result, stop_at)
                except Exception as exc:  # paging never costs page 1
                    logger.debug("Engine %s paging failed (ignored): %s", name, type(exc).__name__)
                return result

            except asyncio.TimeoutError:
                if attempt < search_config.engine_retry_count():
                    await asyncio.sleep(search_config.retry_backoff(attempt))
                    continue
                return EngineResult(name=name, links=[], error="timeout", failure=_engine_status.UNREACHABLE)
            except Exception as e:
                if attempt < search_config.engine_retry_count():
                    await asyncio.sleep(search_config.retry_backoff(attempt))
                    continue
                return EngineResult(
                    name=name, links=[], error=str(e),
                    failure=_engine_status.failure_for_exception(e),
                )

        return EngineResult(name=name, links=[], error="max retries")


async def _fetch_more_pages(
    engine: dict,
    query: str,
    session: aiohttp.ClientSession,
    headers: dict,
    result: EngineResult,
    stop_at: Optional[float],
) -> None:
    """23B-B4: add pages 2..max of a paginating engine to *result* in place.

    Runs only when the engine declares ``pages`` in the catalog, paging is on
    (``VOIDACCESS_SEARCH_PAGES``), page 1 had at least ``full`` links and at
    least PAGE_MIN_BUDGET_S remain before *stop_at*. The pages are fetched
    concurrently, once each (no retries), within PAGE_TIME_FACTOR x page 1's
    time and never past *stop_at*; whatever has not arrived by then is
    cancelled and page 1 is kept.
    Links already on an earlier page are skipped."""
    cfg = engine.get("pages")
    if not cfg or stop_at is None or not search_config.engine_pages_enabled():
        return
    if len(result.links) < int(cfg.get("full", 1)) or cancel.is_cancelled():
        return
    budget = stop_at - time.monotonic() - PAGE_MARGIN_S
    if budget < PAGE_MIN_BUDGET_S:
        return
    if result.first_page_ms is not None:
        budget = min(budget, max(PAGE_MIN_BUDGET_S, PAGE_TIME_FACTOR * result.first_page_ms / 1000.0))
    page_urls = [
        cfg["url"].format(query=query, page=page)
        for page in range(2, int(cfg.get("max", 2)) + 1)
    ]
    if not page_urls:
        return
    timeout = aiohttp.ClientTimeout(total=min(budget, search_config.search_timeout()))

    async def one_page(page_url: str) -> Optional[list[dict]]:
        record_request("tor_search")
        async with session.get(page_url, headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return _parse_html_links(await resp.text(), page_url)

    tasks = [asyncio.ensure_future(one_page(u)) for u in page_urls]
    done, pending = await asyncio.wait(tasks, timeout=budget)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    seen = {dedup_key(link.get("link", "")) for link in result.links}
    for task in tasks:  # page order
        if task not in done or task.cancelled() or task.exception() is not None:
            continue
        page_links = task.result()
        if page_links is None:
            continue
        result.pages += 1
        for link in page_links:
            key = dedup_key(link.get("link", ""))
            if key and key not in seen:
                seen.add(key)
                result.links.append(link)


def _parse_html_links(html: str, base_url: str) -> list[dict]:
    """Extract .onion result links from a search engine result page.

    Handles three common formats:
    - Direct href:    <a href="http://x.onion/path">
    - Redirect param: <a href="/results?url=http://x.onion/path"> (also l=, u=,
      redirect_url=, q= on a redirect path; see search/result_clean.py)
    - Plain text:     URLs mentioned in body text but not hyperlinked

    Links are normalised (tracking/session parameters and fragment removed),
    and links on the engine's own host or on any other search engine's host
    are dropped (23B-B3).
    """
    from urllib.parse import urlparse  # noqa: PLC0415

    links: list[dict] = []
    seen: set[str] = set()
    base_host = (urlparse(base_url).hostname or "").lower()

    def _host(url: str) -> str:
        try:
            return (urlparse(url).hostname or "").lower()
        except ValueError:
            return ""

    def _add(url: str, title: str) -> None:
        url = normalize_result_url(url)
        host = _host(url)
        if host == base_host or is_search_engine_host(host):
            return
        norm = url.lower().rstrip("/")
        if norm not in seen:
            seen.add(norm)
            links.append({"title": title[:200], "link": url})

    try:
        soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            title = a.get_text(strip=True)
            if not href or len(title) < 3:
                continue

            # 1. A target wrapped in a redirect parameter (on the engine's own
            #    host, relative, or absolute): the decoded target only.
            target = unwrap_redirect(href) if ".onion" in href.lower() or "%2e" in href.lower() else None
            if target:
                for match in _ONION_URL_RE.findall(target):
                    _add(match, title)
                continue

            # 2. Direct absolute .onion URL in href
            for match in _ONION_URL_RE.findall(href):
                _add(match, title)

        # 3. Any .onion URLs in the raw HTML text not captured via <a> tags
        for match in _ONION_URL_RE.findall(html):
            match = normalize_result_url(match)
            host = _host(match)
            if host != base_host and not is_search_engine_host(host):
                norm = match.lower().rstrip("/")
                if norm not in seen:
                    seen.add(norm)
                    # Not a result link: an address mentioned in the page text.
                    links.append({"title": host, "link": match, "from_text": True})

    except Exception:
        pass

    return links


def _default_stats(name: str) -> dict:
    return {
        "engine_name": name,
        "total_attempts": 0,
        "total_successes": 0,
        "total_results": 0,
        "consecutive_failures": 0,
        "avg_response_time_ms": 0,
        "is_circuit_open": False,
        "score": 0.5,
    }


async def _search_async(
    query: str,
    max_workers: int = MAX_CONCURRENT,
    llm_client=None,
    engines: Optional[list[dict]] = None,
    allow_diversify: bool = True,
    query_index: int = 0,
    record_summary: bool = True,
) -> list[EngineResult]:
    """One fan-out of *query* over the active engines.

    *record_summary* False leaves ``get_last_search_summary()`` alone (the
    exact-query fan-out runs next to the refined one and must not overwrite
    its summary)."""
    global _LAST_SEARCH_SUMMARY
    if not source_gate("tor_search"):
        # VOIDACCESS_DISABLED_SOURCES: the whole onion-engine fan-out is off.
        if record_summary:
            _LAST_SEARCH_SUMMARY = {
                "success": 0, "total": 0, "active": 0, "circuits_open": 0, "results": 0,
            }
        _trace.search_result("tor_search", "disabled", 0, query_index=query_index)
        return []
    semaphore = asyncio.Semaphore(max_workers)
    # Static catalog lifecycle (P1.1): only `active` engines enter the fan-out.
    # This is distinct from — and runs before — the dynamic circuit-breaker skip
    # below: a `quarantined`/`removed` engine is never dispatched at all, so a
    # permanently-dead engine stops burning a Tor circuit every breaker cycle.
    engine_list = [
        e for e in (engines or SEARCH_ENGINES)
        if e.get("status", "active") == "active"
    ]
    try:
        stats_rows = await get_all_engine_stats_async()
    except Exception:
        stats_rows = []
    stats_by_name = {row["engine_name"]: row for row in stats_rows}
    sorted_engines = sorted(
        engine_list,
        key=lambda e: engine_priority_score(stats_by_name.get(e["name"], _default_stats(e["name"]))),
        reverse=True,
    )
    stage_start = time.monotonic()
    deadline = search_config.search_deadline()
    active_engines: list[dict] = []
    skipped_results: list[EngineResult] = []
    record_tasks: list[asyncio.Task] = []
    for engine in sorted_engines:
        name = engine["name"]
        if await should_skip_engine_async(name):
            skipped_results.append(EngineResult(name=name, links=[], error="circuit_open"))
            _trace.search_result(name, "disabled", 0, query_index=query_index)
            continue
        active_engines.append(engine)

    # No batch-wide session.  Each engine borrows its own from the shared Tor
    # pool, keyed on its hostname, so the 16 onion engines land on 16 circuits
    # instead of all sharing one — see search/tor_isolation.py for the policy.
    async def run_engine(engine: dict) -> EngineResult:
        name = engine["name"]
        if cancel.is_cancelled():
            # Cancel checkpoint between engines: do not start another one.
            return EngineResult(name=name, links=[], error="cancelled")
        timeout = get_engine_timeout(stats_by_name.get(name, _default_stats(name)))
        engine_url = engine["url"].format(query=query)
        _trace.search_request(name, query_index)

        async def fetch_with_engine_session():
            # Acquired inside the task, released however the fetch ends —
            # including the wait_for timeout below, which cancels this
            # coroutine and so runs the finally.
            session, iso_key = tor_isolation.acquire_engine_session(engine_url)
            # 23B-B4: extra result pages must finish before this engine's own
            # timeout and before the search deadline.
            stop_at = start + timeout
            if deadline is not None:
                stop_at = min(stop_at, stage_start + deadline)
            _PAGE_STOP_AT.set(stop_at)
            try:
                return await _fetch_engine(engine, query, session, semaphore)
            finally:
                tor_isolation.release_engine_session(iso_key)

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(fetch_with_engine_session(), timeout=timeout)
            result.took_ms = int((time.monotonic() - start) * 1000)
            result.links, result.safety_dropped = gate_search_results(result.links)
            if result.error == "cancelled":
                # A cancel is not an engine failure: leave the breaker alone.
                return result
            success = result.error is None
            # The breaker's adaptive timeout learns page-1 time, not paging.
            stat_ms = result.first_page_ms if result.first_page_ms is not None else result.took_ms
            task = record_engine_attempt_async(name, success, len(result.links), stat_ms)
            if task is not None:
                record_tasks.append(task)
            if result.error:
                logger.warning(f"Engine {name} failed: {result.error}")
            elif not result.links:
                logger.warning(f"Engine {name} returned 0 results")
            return result
        except asyncio.TimeoutError:
            took_ms = int((time.monotonic() - start) * 1000)
            task = record_engine_attempt_async(name, False, 0, took_ms)
            if task is not None:
                record_tasks.append(task)
            logger.warning(f"Engine {name} timed out")
            return EngineResult(
                name=name, links=[], error="timeout", took_ms=took_ms,
                failure=_engine_status.UNREACHABLE,
            )
        except Exception as e:
            took_ms = int((time.monotonic() - start) * 1000)
            task = record_engine_attempt_async(name, False, 0, took_ms)
            if task is not None:
                record_tasks.append(task)
            logger.warning(f"Engine {name} exception: {e}")
            return EngineResult(
                name=name, links=[], error=str(e), took_ms=took_ms,
                failure=_engine_status.failure_for_exception(e),
            )

    async def run_engine_traced(engine: dict) -> EngineResult:
        result = await run_engine(engine)
        if _trace.active():
            _trace_engine_result(result, query_index)
        return result

    run_one = run_engine_traced if _trace.active() else run_engine

    if deadline is None and cancel.current() is None:
        tasks = [run_one(e) for e in active_engines]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        deadline_results: list[EngineResult] = []
    else:
        # Opt-in deadline: keep what arrived, cancel the stragglers.  Cancelled
        # engines are not recorded against the circuit breaker (a deadline cut
        # is not an engine failure).
        engine_tasks = {
            asyncio.ensure_future(run_one(e)): e["name"] for e in active_engines
        }
        done, pending = await cancel.wait_cancellable(
            set(engine_tasks), timeout=deadline
        )
        cancelled_run = cancel.is_cancelled()
        if cancelled_run and pending:
            # Cancel arrived: in-flight engines get the grace period (finish the
            # current item), then are stopped. Cancelled engines are never
            # recorded against the circuit breaker.
            more_done, pending = await asyncio.wait(
                pending, timeout=cancel.grace_period()
            )
            done = set(done) | set(more_done)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        results = []
        for task in done:
            try:
                results.append(task.result())
            except BaseException as exc:  # noqa: BLE001 - mirror gather(return_exceptions=True)
                results.append(exc)
        deadline_results = [
            EngineResult(
                name=engine_tasks[t],
                links=[],
                error="cancelled" if cancelled_run else "deadline",
                failure=None if cancelled_run else _engine_status.UNREACHABLE,
            )
            for t in pending
        ]
        if pending and not cancelled_run:
            logger.warning(
                "Search deadline %.0fs reached: %d/%d engines still running, returning partial results",
                deadline, len(pending), len(engine_tasks),
            )

    processed: list[EngineResult] = list(skipped_results) + deadline_results
    for r in results:
        if isinstance(r, Exception):
            logger.warning(f"Engine task exception: {r}")
            continue
        processed.append(r)

    if record_tasks:
        await asyncio.gather(*record_tasks, return_exceptions=True)

    result_count = sum(len(r.links) for r in processed)
    if (
        allow_diversify
        and result_count < 5
        and llm_client is not None
        and active_engines
        and not cancel.is_cancelled()
    ):
        top_engines = _alternative_engines(active_engines, processed)
        alternatives = await diversify_query(query, result_count, llm_client) if top_engines else []
        for alt_index, alternative in enumerate(alternatives[:2], start=query_index + 1):
            _trace.query_refined("collect", alt_index, alternative)
            processed.extend(
                await _search_async(
                    alternative,
                    max_workers=min(max_workers, 3),
                    llm_client=None,
                    engines=top_engines,
                    allow_diversify=False,
                    query_index=alt_index,
                )
            )

    success_count = sum(1 for r in processed if r.error is None)
    circuit_open_count = sum(1 for r in processed if r.error == "circuit_open")
    total = len(engine_list)
    final_count = sum(len(r.links) for r in processed)
    if record_summary:
        _LAST_SEARCH_SUMMARY = {
            "success": success_count,
            "total": total,
            "active": len(active_engines),
            "circuits_open": circuit_open_count,
            "results": final_count,
            # 23B-B2: engines / engine_status_counts / engines_attempted
            **_engine_status.summarize(processed),
        }
    logger.info(
        "Search complete: %d/%d engines, %d results, %d circuits open",
        success_count,
        total,
        final_count,
        circuit_open_count,
    )
    return processed


def _alternative_engines(
    active_engines: list[dict], processed: list[EngineResult], n: int = 3
) -> list[dict]:
    """Engines for the diversified alternative queries (23B-B5).

    Only engines that answered in this run (``ok`` first, by result count,
    then ``empty``), at most *n*. An engine that was unreachable a moment ago
    would only hold each alternative fan-out until its timeout again, and in
    the cloud runner (a fresh database per run) the circuit breaker has no
    memory to skip it. None answered: no alternatives at all."""
    best: dict[str, tuple[int, int]] = {}
    for result in processed:
        outcome = _engine_status.outcome_of(result)
        if outcome not in (_engine_status.OK, _engine_status.EMPTY):
            continue
        rank = (1 if outcome == _engine_status.OK else 0, len(result.links))
        if rank > best.get(result.name, (-1, -1)):
            best[result.name] = rank
    healthy = [e for e in active_engines if e["name"] in best]
    healthy.sort(key=lambda e: best[e["name"]], reverse=True)
    return healthy[:n]


def _trace_engine_result(result: EngineResult, query_index: int) -> None:
    """``search.result`` for one engine, then ``url.found`` for its links.

    ``status`` keeps its pre-23B values (``ok`` also for 0 links: the cloud
    runner reads it as "answered"); ``outcome`` is the 23B-B2 engine outcome."""
    error = result.error
    if error is None:
        status = "ok"
    elif error in ("timeout", "deadline"):
        status = "timeout"
    else:
        status = "error"
    _trace.search_result(
        result.name, status, len(result.links), result.took_ms, query_index=query_index,
        outcome=_engine_status.outcome_of(result),
    )
    for link in result.links:
        _trace.url_found("collect", link.get("link", ""), engine=result.name, title=link.get("title"))
    for link in result.safety_dropped:
        _trace.url_dropped("collect", link.get("link", ""), "safety")


def _trace_merged_links(all_links: list[dict], deduped: list[dict], ranked: list[dict]) -> None:
    """Duplicates collapsed by the dedup, and owned-index hits the merge added."""
    state = _trace.current().trace_state
    kept_ids = {state.known_url_id(link.get("link", "")) for link in deduped}
    for link in all_links:
        uid = state.known_url_id(link.get("link", ""))
        if uid is not None and uid not in kept_ids:
            kept_ids.add(uid)
            _trace.url_dropped("collect", link.get("link", ""), "duplicate")
    for link in ranked:
        _trace.url_found(
            "collect", link.get("link", ""),
            engine=link.get("source_engine") or "owned_index", title=link.get("title"),
        )


# query_index of the exact-query fan-out in trace events (0 is the refined
# query, 1 and 2 the diversified alternatives).
EXACT_QUERY_INDEX = 3


async def _search_with_exact(
    query: str,
    max_workers: int,
    llm_client,
    exact_query: Optional[str],
) -> tuple[list[EngineResult], list[EngineResult]]:
    """The refined-query fan-out and, at the same time, the exact-query one.

    Both run under the same search deadline concurrently, so the search stage
    takes no longer. A failing exact fan-out never fails the search."""
    if not exact_query:
        return await _search_async(query, max_workers, llm_client=llm_client), []
    _trace.query_refined("collect", EXACT_QUERY_INDEX, exact_query)
    primary, exact = await asyncio.gather(
        _search_async(query, max_workers, llm_client=llm_client),
        _search_async(
            exact_query, max_workers, llm_client=None, allow_diversify=False,
            query_index=EXACT_QUERY_INDEX, record_summary=False,
        ),
        return_exceptions=True,
    )
    if isinstance(primary, BaseException):
        raise primary
    if isinstance(exact, BaseException):
        logger.warning("Exact-query search failed: %s", type(exact).__name__)
        exact = []
    return primary, exact


def _weighted_links(results: list[EngineResult]) -> list[dict]:
    links: list[dict] = []
    for result in results:
        engine_name = result.name.lower()
        weight = 0.5
        for known in ENGINE_WEIGHTS:
            if known in engine_name:
                weight = ENGINE_WEIGHTS[known]
                break
        for link in result.links:
            link["source_engine"] = result.name
            link["source_weight"] = weight
            links.append(link)
        status = "ok" if not result.error else result.error
        logger.debug(f"Engine {result.name}: {len(result.links)} links ({status})")
    return links


def get_search_results_async(
    query: str,
    max_workers: int = MAX_CONCURRENT,
    llm_client=None,
    exact_query: Optional[str] = None,
    keep_exact=None,
) -> list[dict]:
    """Async search - call from async context.

    *exact_query* (22S): also send this query (the user's own words, or the
    selector) to every engine, concurrently with *query*. Of its results only
    those *keep_exact* accepts are added (all when it is None), after the
    refined query's own, so the candidate list grows only by results that
    match what the user searched for."""
    import time
    start = time.monotonic()

    results, exact_results = run_async(
        _search_with_exact(query, max_workers, llm_client, exact_query)
    )

    if exact_results and _LAST_SEARCH_SUMMARY:
        # The per-engine outcome covers both fan-outs (an engine that found
        # nothing for the refined query may have answered the exact one).
        _LAST_SEARCH_SUMMARY.update(_engine_status.summarize([*results, *exact_results]))

    all_links = _weighted_links(results)
    if exact_results:
        extra = _weighted_links(exact_results)
        if keep_exact is not None:
            kept_extra = [link for link in extra if keep_exact(link)]
            if _trace.active():
                kept_ids = {id(link) for link in kept_extra}
                primary_urls = {_normalize_for_dedup(link.get("link", "")) for link in all_links}
                for link in extra:
                    if id(link) not in kept_ids and (
                        _normalize_for_dedup(link.get("link", "")) not in primary_urls
                    ):
                        _trace.url_dropped("collect", link.get("link", ""), "irrelevant")
            extra = kept_extra
        logger.info("Exact-query search: %d matching results added", len(extra))
        all_links.extend(extra)

    deduped = unique = _dedupe_links(all_links)

    # P3.2 — merge the owned index into the fan-out and rank the union by semantic
    # relevance (replaces the static source_weight ordering, which is now only a
    # tiebreak). No-ops to external-only when Meilisearch is unconfigured. Shared
    # with the API path via search.ranking.merge_and_rank for API↔CLI parity.
    from search.ranking import merge_and_rank

    unique = run_async(merge_and_rank(query, unique))
    unique, unsafe = gate_search_results(unique)
    for link in unsafe:
        _trace.url_dropped("collect", link.get("link", ""), "safety")
    if _trace.active():
        try:
            _trace_merged_links(all_links, deduped, unique)
        except Exception as exc:  # tracing never breaks a search
            logger.debug("search trace failed (ignored): %s", exc)

    elapsed = (time.monotonic() - start) * 1000
    logger.info(f"Search completed: {len(unique)} unique links in {elapsed:.0f}ms")

    return unique


def _dedupe_links(links: list[dict]) -> list[dict]:
    """Exact-duplicate URLs (after 23B-B3 normalisation) merged into one, at
    the first one's position, recording every engine that found it
    (``found_by`` / ``engine_count``); see search.result_clean.merge_duplicates."""
    return merge_duplicates(links)


def get_search_results(query: str, max_workers: int = MAX_CONCURRENT) -> list[dict]:
    """Sync wrapper for backward compatibility."""
    return get_search_results_async(query, max_workers)


def get_last_search_summary() -> dict[str, int]:
    return dict(_LAST_SEARCH_SUMMARY)
