"""
crawler/spider.py — Async recursive .onion spider (Phase 1C).

Public API:
    CrawlResult   dataclass — returned by crawl()
    crawl()       async function — main entry point

All HTTP requests go through the Tor SOCKS5 proxy, via the shared stream-
isolation pool in `scraper/tor_pool.py` — one circuit per target hostname,
shared with every other Tor fetcher in the process.  No clearnet requests to
dark web targets.

Politeness rules (non-negotiable for Tor stability):
  - Same domain  → random 2–8 s delay between consecutive requests
  - New domain   → random 0.5–2 s delay on first access
  - Per-domain concurrency cap: 3 simultaneous requests (asyncio.Semaphore)
  - 1 MB download cap per page (identical to scrape.py)

Error handling:
  - A failed page is logged, its source marked 'failed' in the DB, and the
    crawl continues — a single bad page never terminates the run.
  - Retry/backoff mirrors scrape.py: up to 3 retries (2 s / 4 s / 8 s),
    no retry on 4xx responses.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

import pacing
from crawler.dedup import ContentDedup, UrlDedup
from crawler.frontier import Frontier
from crawler.utils import extract_onion_links, is_valid_onion, normalize_url
from utils.onion_sweep import gated_text_onion_urls
from scraper import tor_pool
from scraper.scrape import _extract_text, sniffs_as_text
from vector import bulk_check_cache, upsert_page

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (mirror scrape.py where applicable)
# ---------------------------------------------------------------------------

# Timing constants below are the `normal` pacing baseline; the active profile
# scales them at call time via the `pacing` module (see pacing/README.md).

MAX_DOWNLOAD_BYTES = 1_000_000          # 1 MB hard cap
MAX_RETURN_CHARS = 2_000                # truncation in results list
MAX_RETRIES = 3
RETRY_DELAYS = (2.0, 4.0, 8.0)         # seconds before retry 1, 2, 3
RETRYABLE_STATUS = {500, 502, 503, 504}
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

_SAME_DOMAIN_DELAY = (2.0, 8.0)        # seconds, random within range
_NEW_DOMAIN_DELAY = (0.5, 2.0)         # seconds, random within range
_CONNECT_TIMEOUT = 10                  # seconds
_READ_TIMEOUT = 45                     # seconds
_DOMAIN_MAX_CONCURRENT = 3             # asyncio.Semaphore value per domain
_GLOBAL_CONCURRENCY = 10               # max simultaneous page fetches overall
# Onion addresses found in page text, not in an <a href>: at most this many per
# page, queued this far below any real link (scores are 0..1, so a penalty of
# 1.0 puts every text-found address behind every real link).
TEXT_ONIONS_PER_PAGE = 10
TEXT_ONION_PRIORITY_PENALTY = 1.0

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) "
    "Gecko/20100101 Firefox/137.0"
)


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

@dataclass
class CrawlResult:
    """
    Summary of a completed crawl run.

    *results* is a list of dicts, each with keys "url" and "content",
    shaped the same as individual entries from scrape_multiple() so both
    are interchangeable in the intelligence pipeline.
    """
    pages_crawled: int = 0
    pages_failed: int = 0
    new_urls_discovered: int = 0
    results: List[Dict] = field(default_factory=list)
    # Of new_urls_discovered: addresses found in page text, not in a link.
    text_urls_discovered: int = 0


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

class Spider:
    """
    Recursive async .onion crawler.

    Instantiate once per crawl run; do not reuse across runs.
    """

    def __init__(
        self,
        seed_urls: List[str],
        query: str,
        max_depth: int = 2,
        max_pages: int = 200,
        min_relevance: float = 0.3,
    ) -> None:
        self.seed_urls = seed_urls
        self.query = query
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.min_relevance = min_relevance

        self._frontier = Frontier(query)
        self._url_dedup = UrlDedup()
        self._content_dedup = ContentDedup()

        # Per-domain politeness state
        self._domain_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(_DOMAIN_MAX_CONCURRENT)
        )
        self._domain_last_access: Dict[str, float] = {}
        self._timing_lock = asyncio.Lock()

        # Counters
        self._pages_crawled = 0
        self._pages_failed = 0
        self._new_urls_discovered = 0
        self._text_urls_discovered = 0
        self._results: List[Dict] = []

    # ------------------------------------------------------------------
    # Politeness
    # ------------------------------------------------------------------

    async def _polite_delay(self, domain: str) -> None:
        """
        Compute and sleep the required inter-request delay for *domain*.

        Uses _timing_lock to read/update last-access atomically in the
        event loop; the actual sleep happens outside the lock so other
        coroutines are not blocked.
        """
        # The pacing profile scales both politeness windows.  This is the
        # natural home for `quiet` to extend further: the crawler already has
        # a concept of per-domain politeness, so the profile widens the
        # existing window rather than bolting on a separate delay.  Both ends
        # are scaled so the jitter the randomisation exists to provide is
        # preserved instead of collapsing to a point.
        new_domain_delay = pacing.scale_delay_range(*_NEW_DOMAIN_DELAY)
        same_domain_delay = pacing.scale_delay_range(*_SAME_DOMAIN_DELAY)

        async with self._timing_lock:
            last = self._domain_last_access.get(domain)
            now = time.monotonic()
            if last is None:
                delay = random.uniform(*new_domain_delay)
            else:
                elapsed = now - last
                needed = random.uniform(*same_domain_delay)
                delay = max(0.0, needed - elapsed)
            # Reserve the slot so concurrent coroutines don't both sleep 0
            self._domain_last_access[domain] = now + delay

        if delay > 0:
            await asyncio.sleep(delay)

    # ------------------------------------------------------------------
    # Fetch with retry (mirrors scrape.py's _fetch_one)
    # ------------------------------------------------------------------

    async def _fetch(
        self,
        url: str,
        session: aiohttp.ClientSession,
    ) -> Optional[Tuple[bytes, str, str]]:
        """
        Fetch *url* with exponential-backoff retry.

        Returns (raw_bytes, html, extracted_text) on success, or None on
        any unrecoverable failure.  Never raises.

        *session* comes from the shared Tor pool, whose session-level timeout is
        tuned for the scraper (a 5 s read).  Crawling needs far more patience
        than that, so the crawler's own window is applied as a **per-request**
        override: aiohttp lets a `timeout=` on the call beat the session
        default, which keeps one shared circuit per host while letting the two
        callers disagree about how long to wait.  Baking these into the pooled
        session instead would silently impose 45 s reads on every scrape too.
        """
        headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        }
        last_exc: object = None

        # Resolved per call, not per import, so a profile selected after this
        # module was imported still applies.  Reading the module constants here
        # also keeps existing tests that monkeypatch RETRY_DELAYS working.
        max_retries, retry_delays = pacing.retry_plan(MAX_RETRIES, RETRY_DELAYS)
        request_timeout = aiohttp.ClientTimeout(
            connect=pacing.scale_timeout(_CONNECT_TIMEOUT),
            sock_read=pacing.scale_timeout(_READ_TIMEOUT),
        )

        for attempt in range(max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(retry_delays[attempt - 1])

            try:
                async with session.get(
                    url, headers=headers, timeout=request_timeout
                ) as resp:
                    if resp.status in RETRYABLE_STATUS:
                        last_exc = f"HTTP {resp.status}"
                        continue

                    if resp.status != 200:
                        return None  # 4xx — not retried

                    ct = (resp.headers.get("Content-Type") or "").lower()
                    if ct and not any(t in ct for t in ALLOWED_CONTENT_TYPES):
                        return None

                    # Stream with 1 MB hard cap
                    chunks: List[bytes] = []
                    total = 0
                    async for chunk in resp.content.iter_chunked(8192):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_DOWNLOAD_BYTES:
                            break
                        chunks.append(chunk)

                    raw_bytes = b"".join(chunks)
                    if not ct and not sniffs_as_text(raw_bytes):
                        return None
                    html = raw_bytes.decode(resp.charset or "utf-8", errors="replace")
                    text = _extract_text(html)
                    return raw_bytes, html, text

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc

        _logger.debug("All retries exhausted for %s: %s", url, last_exc)
        return None

    # ------------------------------------------------------------------
    # DB helpers (pattern from scrape.py _persist_pages)
    # ------------------------------------------------------------------

    def _db_upsert_source(self, url: str, status: str) -> None:
        """
        Upsert the .onion domain for *url* into the sources table.

        Only sets *status* when the row is newly created; existing rows are
        left at their current status so we never downgrade 'active' → 'discovered'.
        If *status* is 'failed' or 'active' it is always applied (overwrite).
        """
        try:
            from config import DATABASE_URL as _db_url
            if not _db_url:
                return
            from db.queries import get_or_create_source, update_source_status
            from db.session import get_session
        except ImportError:
            return

        try:
            hostname = (urlparse(url).hostname or "").lower()
            if not hostname.endswith(".onion"):
                return
            with get_session() as session:
                src, created = get_or_create_source(
                    session, hostname, source_type="crawled"
                )
                # Always apply terminal statuses; only apply 'discovered' to new rows
                if status in ("active", "failed") or created:
                    update_source_status(session, src.id, status)
        except Exception as exc:
            _logger.debug("DB source upsert failed url=%s status=%s: %s", url, status, exc)

    def _db_persist_page(
        self,
        url: str,
        raw_bytes: bytes,
        text: str,
        content_hash: str,
    ) -> None:
        """Write a successfully scraped page to the database."""
        try:
            from config import DATABASE_URL as _db_url
            if not _db_url:
                return
            from db.queries import create_page, get_or_create_source, update_source_status
            from db.session import get_session
        except ImportError:
            return

        try:
            with get_session() as session:
                hostname = (urlparse(url).hostname or "").lower()
                source_id = None
                if hostname.endswith(".onion"):
                    src, _ = get_or_create_source(
                        session, hostname, source_type="crawled"
                    )
                    update_source_status(session, src.id, "active")
                    source_id = src.id

                create_page(
                    session,
                    url=url,
                    source_id=source_id,
                    cleaned_text=text,
                    raw_content_hash=content_hash,
                    byte_size=len(raw_bytes),
                )
        except Exception as exc:
            _logger.debug("DB page persist failed url=%s: %s", url, exc)

    # ------------------------------------------------------------------
    # Core page processing
    # ------------------------------------------------------------------

    async def _process_url(
        self,
        url: str,
        depth: int,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> None:
        """
        Fetch *url*, extract links, and update all state.

        Acquires the per-domain semaphore after the politeness delay so at
        most _DOMAIN_MAX_CONCURRENT fetches to the same domain run in
        parallel at any time.

        When *session* is None — the production path — the session is taken from
        the shared Tor isolation pool, keyed on this URL's hostname, and the
        in-flight hold is released in the `finally`.  Acquisition happens
        *inside* the semaphore so that hold lasts only as long as the fetch, not
        through the politeness delay, which under a `quiet` profile can be tens
        of seconds.

        An explicitly supplied *session* is used as-is and never released here,
        because the caller owns it.  This is the same "pass None for sessions
        that were not acquired from the pool" seam that
        `scraper.scrape._fetch_one` uses, and it is what lets unit tests drive
        this method with a mock session instead of a live circuit.
        """
        from utils.content_safety import scan_page_text, url_is_blocked

        if url_is_blocked(url):
            self._pages_failed += 1
            return

        domain = (urlparse(url).hostname or url).lower()
        await self._polite_delay(domain)

        async with self._domain_semaphores[domain]:
            iso_key: Optional[str] = None
            if session is None:
                session, iso_key = tor_pool.acquire_tor_session(url)
            try:
                result = await self._fetch(url, session)

                if result is None:
                    self._pages_failed += 1
                    _logger.debug("Fetch returned None for %s", url)
                    self._db_upsert_source(url, "failed")
                    return

                raw_bytes, html, text = result
                # A page the content-safety gate drops is not stored, returned
                # or followed.
                text, dropped = scan_page_text(url, text or "")
                if dropped:
                    self._pages_failed += 1
                    return
                content_hash = hashlib.sha256(raw_bytes).hexdigest()

                # Content dedup: skip DB write if hash already stored
                if not self._content_dedup.is_duplicate(content_hash):
                    self._db_persist_page(url, raw_bytes, text, content_hash)
                else:
                    # Source still reached successfully — keep status accurate
                    self._db_upsert_source(url, "active")

                self._pages_crawled += 1

                # Truncate content for the results list
                snippet = (text or "")[:MAX_RETURN_CHARS]
                suffix = "...(truncated)"
                if len(text or "") > MAX_RETURN_CHARS:
                    available = MAX_RETURN_CHARS - len(suffix)
                    snippet = (text[:available] + suffix) if available > 0 else suffix

                self._results.append({"url": url, "content": snippet})

                # Extract and enqueue child links
                if depth < self.max_depth:
                    links = extract_onion_links(html, base_url=url)
                    for link in links:
                        normed = normalize_url(link)
                        if not normed:
                            continue
                        if self._url_dedup.is_new(normed):
                            self._new_urls_discovered += 1
                            self._url_dedup.mark_seen(normed)
                            self._db_upsert_source(normed, "discovered")

                            link_score = self._frontier.score(normed, (text or "")[:500])
                            if link_score >= self.min_relevance:
                                self._frontier.push(normed, depth + 1, link_score)

                    # Onion addresses printed in the page text (mirrors, file
                    # servers, defanged links) that no <a href> carried. Each is
                    # safety-gated inside gated_text_onion_urls, must clear the
                    # same min_relevance as a real link, and is pushed one full
                    # point lower so every real link is popped first. They come
                    # out of the same max_pages budget as everything else.
                    self._push_text_onions(html, links, text, depth)

            except Exception as exc:
                self._pages_failed += 1
                _logger.warning("Unexpected error processing %s: %s", url, exc, exc_info=True)
                self._db_upsert_source(url, "failed")

            finally:
                if iso_key is not None:
                    tor_pool.release_tor_session(iso_key)

    def _push_text_onions(
        self, html: str, href_links: List[str], text: str, depth: int
    ) -> None:
        """Queue text-found onion addresses behind the page's real links."""
        href_hosts = {(urlparse(u).hostname or "").lower() for u in href_links}
        try:
            found = gated_text_onion_urls(
                html or "",
                exclude_hosts=href_hosts,
                max_results=TEXT_ONIONS_PER_PAGE,
            )
        except Exception as exc:
            _logger.debug("Text onion sweep failed: %s", exc)
            return
        for link in found:
            normed = normalize_url(link)
            if not normed or not is_valid_onion(normed):
                continue
            if not self._url_dedup.is_new(normed):
                continue
            self._new_urls_discovered += 1
            self._text_urls_discovered += 1
            self._url_dedup.mark_seen(normed)
            self._db_upsert_source(normed, "discovered")
            link_score = self._frontier.score(normed, (text or "")[:500])
            if link_score >= self.min_relevance:
                self._frontier.push(normed, depth + 1, link_score - TEXT_ONION_PRIORITY_PENALTY)

    # ------------------------------------------------------------------
    # Main crawl loop
    # ------------------------------------------------------------------

    async def run(self) -> CrawlResult:
        """
        Execute the full crawl and return a CrawlResult.

        Flow:
          1. Normalize and validate seed URLs → push to frontier (score=1.0)
          2. Open one Tor-proxied aiohttp session for the entire run
          3. Dispatch up to _GLOBAL_CONCURRENCY concurrent _process_url tasks
          4. Replenish tasks as each completes; stop when frontier is empty
             or max_pages total have been processed
        """
        for url in self.seed_urls:
            normed = normalize_url(url)
            if not normed or not is_valid_onion(normed):
                _logger.warning("Skipping invalid seed URL: %s", url)
                continue
            if self._url_dedup.is_new(normed):
                self._url_dedup.mark_seen(normed)
                self._db_upsert_source(normed, "discovered")
                self._frontier.push(normed, depth=0, score=1.0)

        if self._frontier.empty():
            _logger.warning("No valid seed URLs; returning empty CrawlResult.")
            return CrawlResult()

        # No session is created here any more.  A crawl run used to open one
        # credential-less Tor session for every page it would ever fetch, which
        # put the whole run on a single circuit.  Sessions now come from the
        # shared pool, per target hostname, acquired inside _process_url — so a
        # crawl that walks three onion services uses three circuits, and the
        # scraper fetching one of those same hosts reuses the crawler's circuit
        # instead of building a second one.
        active: set[asyncio.Task] = set()
        total_processed = 0

        while True:
            # Fill task pool up to concurrency cap while pages remain
            batch: list[tuple[str, int]] = []
            while (
                not self._frontier.empty()
                and len(active) < _GLOBAL_CONCURRENCY
                and total_processed + len(active) < self.max_pages
            ):
                url, depth = self._frontier.pop()
                batch.append((url, depth))

            if batch:
                cached_pages, uncached_urls = bulk_check_cache(
                    [url for url, _depth in batch]
                )
                cached_map = {page.get("link"): page for page in cached_pages}
                for url, depth in batch:
                    cached_page = cached_map.get(url)
                    if cached_page is not None:
                        content = str(cached_page.get("content", ""))
                        self._pages_crawled += 1
                        self._results.append({"url": url, "content": content[:MAX_RETURN_CHARS]})
                        try:
                            upsert_page(
                                url,
                                content,
                                metadata={"crawler": "spider", "cached": True},
                            )
                        except Exception as exc:
                            _logger.debug("cache refresh upsert failed for %s: %s", url, exc)
                        continue
                    if url not in uncached_urls:
                        continue
                    task = asyncio.create_task(
                        self._process_url(url, depth),
                        name=f"crawl:{url}",
                    )
                    active.add(task)

            if not active:
                break  # frontier empty, nothing in flight

            done, active = await asyncio.wait(
                active, return_when=asyncio.FIRST_COMPLETED
            )
            total_processed += len(done)

            # Propagate any unexpected task exceptions to the log
            for t in done:
                exc = t.exception()
                if exc:
                    _logger.error("Task %s raised: %s", t.get_name(), exc)

        return CrawlResult(
            pages_crawled=self._pages_crawled,
            pages_failed=self._pages_failed,
            new_urls_discovered=self._new_urls_discovered,
            results=self._results,
            text_urls_discovered=self._text_urls_discovered,
        )


# ---------------------------------------------------------------------------
# Public module-level function
# ---------------------------------------------------------------------------

async def crawl(
    seed_urls: List[str],
    query: str,
    max_depth: int = 2,
    max_pages: int = 200,
    min_relevance: float = 0.3,
) -> CrawlResult:
    """
    Recursively crawl from *seed_urls*, prioritising links relevant to *query*.

    All requests are routed through the Tor SOCKS5 proxy configured in
    TOR_PROXY_HOST / TOR_PROXY_PORT.  Returns a CrawlResult dataclass.
    """
    spider = Spider(
        seed_urls=seed_urls,
        query=query,
        max_depth=max_depth,
        max_pages=max_pages,
        min_relevance=min_relevance,
    )
    return await spider.run()
