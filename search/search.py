import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass
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
from utils.async_utils import run_async
from search import config as search_config

logger = logging.getLogger(__name__)

ENGINE_WEIGHTS = {
    "ahmia": 0.9,
    "torch": 0.7,
}


def _normalize_for_dedup(url: str) -> str:
    url = url.lower().rstrip("/")
    url = url.replace("https://", "http://")
    return url


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


async def _fetch_engine(
    engine: dict,
    query: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
) -> EngineResult:
    url = engine["url"].format(query=query)
    name = engine["name"]
    is_onion = _is_onion_url(url)
    
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    
    async with semaphore:
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
                        )
                    
                    text = await resp.text()

                    links = _parse_html_links(text, url)
                    return EngineResult(name=name, links=links)

            except asyncio.TimeoutError:
                if attempt < search_config.engine_retry_count():
                    await asyncio.sleep(search_config.retry_backoff(attempt))
                    continue
                return EngineResult(name=name, links=[], error="timeout")
            except Exception as e:
                if attempt < search_config.engine_retry_count():
                    await asyncio.sleep(search_config.retry_backoff(attempt))
                    continue
                return EngineResult(name=name, links=[], error=str(e))
        
        return EngineResult(name=name, links=[], error="max retries")


def _parse_html_links(html: str, base_url: str) -> list[dict]:
    """Extract .onion result links from a search engine result page.

    Handles three common formats:
    - Direct href:    <a href="http://x.onion/path">
    - Redirect param: <a href="/results?url=http://x.onion/path">
    - Plain text:     URLs mentioned in body text but not hyperlinked
    """
    from urllib.parse import urlparse, parse_qs, unquote  # noqa: PLC0415

    links: list[dict] = []
    seen: set[str] = set()
    base_host = (urlparse(base_url).hostname or "").lower()

    def _add(url: str, title: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if host == base_host:
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

            # 1. Direct absolute .onion URL in href
            for match in _ONION_URL_RE.findall(href):
                _add(match, title)

            # 2. .onion URL hidden in a query parameter (redirect, url, link, site)
            if ".onion" in href and not _ONION_URL_RE.search(href):
                try:
                    qs = parse_qs(urlparse(href).query)
                    for param in ("url", "redirect", "link", "site", "address", "q"):
                        for val in qs.get(param, []):
                            decoded = unquote(val)
                            for match in _ONION_URL_RE.findall(decoded):
                                _add(match, title)
                except Exception:
                    pass

        # 3. Any .onion URLs in the raw HTML text not captured via <a> tags
        for match in _ONION_URL_RE.findall(html):
            host = (urlparse(match).hostname or "").lower()
            if host != base_host:
                norm = match.lower().rstrip("/")
                if norm not in seen:
                    seen.add(norm)
                    links.append({"title": host, "link": match})

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
) -> list[EngineResult]:
    global _LAST_SEARCH_SUMMARY
    if not source_gate("tor_search"):
        # VOIDACCESS_DISABLED_SOURCES: the whole onion-engine fan-out is off.
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
            try:
                return await _fetch_engine(engine, query, session, semaphore)
            finally:
                tor_isolation.release_engine_session(iso_key)

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(fetch_with_engine_session(), timeout=timeout)
            result.took_ms = int((time.monotonic() - start) * 1000)
            if result.error == "cancelled":
                # A cancel is not an engine failure: leave the breaker alone.
                return result
            success = result.error is None
            task = record_engine_attempt_async(name, success, len(result.links), result.took_ms)
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
            return EngineResult(name=name, links=[], error="timeout", took_ms=took_ms)
        except Exception as e:
            took_ms = int((time.monotonic() - start) * 1000)
            task = record_engine_attempt_async(name, False, 0, took_ms)
            if task is not None:
                record_tasks.append(task)
            logger.warning(f"Engine {name} exception: {e}")
            return EngineResult(name=name, links=[], error=str(e), took_ms=took_ms)

    async def run_engine_traced(engine: dict) -> EngineResult:
        result = await run_engine(engine)
        if _trace.active():
            _trace_engine_result(result, query_index)
        return result

    run_one = run_engine_traced if _trace.active() else run_engine

    deadline = search_config.search_deadline()
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
        alternatives = await diversify_query(query, result_count, llm_client)
        top_engines = active_engines[:3]
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
    _LAST_SEARCH_SUMMARY = {
        "success": success_count,
        "total": total,
        "active": len(active_engines),
        "circuits_open": circuit_open_count,
        "results": final_count,
    }
    logger.info(
        "Search complete: %d/%d engines, %d results, %d circuits open",
        success_count,
        total,
        final_count,
        circuit_open_count,
    )
    return processed


def _trace_engine_result(result: EngineResult, query_index: int) -> None:
    """``search.result`` for one engine, then ``url.found`` for its links."""
    error = result.error
    if error is None:
        status = "ok"
    elif error in ("timeout", "deadline"):
        status = "timeout"
    else:
        status = "error"
    _trace.search_result(
        result.name, status, len(result.links), result.took_ms, query_index=query_index
    )
    for link in result.links:
        _trace.url_found("collect", link.get("link", ""), engine=result.name, title=link.get("title"))


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


def get_search_results_async(query: str, max_workers: int = MAX_CONCURRENT, llm_client=None) -> list[dict]:
    """Async search - call from async context."""
    import time
    start = time.monotonic()

    results = run_async(_search_async(query, max_workers, llm_client=llm_client))

    all_links = []
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
            all_links.append(link)
        status = "ok" if not result.error else result.error
        logger.debug(f"Engine {result.name}: {len(result.links)} links ({status})")

    deduped = unique = _dedupe_links(all_links)

    # P3.2 — merge the owned index into the fan-out and rank the union by semantic
    # relevance (replaces the static source_weight ordering, which is now only a
    # tiebreak). No-ops to external-only when Meilisearch is unconfigured. Shared
    # with the API path via search.ranking.merge_and_rank for API↔CLI parity.
    from search.ranking import merge_and_rank

    unique = run_async(merge_and_rank(query, unique))
    if _trace.active():
        try:
            _trace_merged_links(all_links, deduped, unique)
        except Exception as exc:  # tracing never breaks a search
            logger.debug("search trace failed (ignored): %s", exc)

    elapsed = (time.monotonic() - start) * 1000
    logger.info(f"Search completed: {len(unique)} unique links in {elapsed:.0f}ms")

    return unique


def _dedupe_links(links: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique = []
    for link_dict in links:
        link = link_dict.get("link", "")
        normalized = _normalize_for_dedup(link)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(link_dict)
    return unique


def get_search_results(query: str, max_workers: int = MAX_CONCURRENT) -> list[dict]:
    """Sync wrapper for backward compatibility."""
    return get_search_results_async(query, max_workers)


def get_last_search_summary() -> dict[str, int]:
    return dict(_LAST_SEARCH_SUMMARY)
