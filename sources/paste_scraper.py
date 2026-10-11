"""
sources/paste_scraper.py — Clearnet paste site scraper for VoidAccess.

Searches public paste sites (Pastebin, dpaste, paste.ee, Rentry) for
intelligence relevant to an investigation query.  Runs over CLEARNET — these
sites are public and do not require Tor.

Typical high-signal content found on paste sites:
    - Stolen credentials & breach dumps
    - Malware configs / C2 infrastructure
    - IOC lists (hashes, IPs, domains)
    - Ransomware negotiation logs
    - Leaked private keys

Public API:
    async def scrape_paste_sites(
        query: str,
        refined_query: str = "",
        max_results: int = 15,
    ) -> list[dict]

Returns page dicts compatible with the existing scrape pipeline format:
    {
        "url": str,
        "text_content": str,
        "title": str,
        "source_type": "paste_site",
        "source_name": str,
        "scraped_at": str,
        "word_count": int,
        "relevance": int,
    }
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote_plus

import aiohttp

import pacing
from sources import http_pool
from sources.proxy_client import clearnet_fetch
from utils.content_safety import is_blocked_query, sanitize_content

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Paste site configuration
# ---------------------------------------------------------------------------

PASTE_SOURCES = [
    {
        "name": "Pastebin",
        "search_url": "https://pastebin.com/search?q={query}",
        "paste_url": "https://pastebin.com/raw/{id}",
        "result_pattern": r'href="/([a-zA-Z0-9]{8})"',
        "requires_key": False,
        "rate_limit": 1.5,
    },
    {
        "name": "Rentry",
        # Rentry has no public search endpoint — pastes are fetched via
        # direct URL when discovered through Tor results / enrichment.
        "search_url": None,
        "direct_urls": [],
        "paste_url": "https://rentry.co/{id}/raw",
        "requires_key": False,
        "rate_limit": 1.0,
    },
    {
        "name": "dpaste",
        "search_url": "https://dpaste.org/search/?q={query}",
        "paste_url": "https://dpaste.org/{id}/raw/",
        "result_pattern": r'href="/([A-Z0-9]{5,8})/"',
        "requires_key": False,
        "rate_limit": 1.0,
    },
    {
        "name": "paste.ee",
        "search_url": "https://paste.ee/search?q={query}",
        "paste_url": "https://paste.ee/r/{id}",
        "result_pattern": r'href="/p/([a-zA-Z0-9]+)"',
        "requires_key": False,
        "rate_limit": 1.0,
    },
]

# Timing baselines (`normal` pacing profile); scaled at call time.
REQUEST_TIMEOUT = 30       # seconds, main paste-site session
ROBOTS_TIMEOUT = 5         # seconds, robots.txt probe
# Per-source `rate_limit` above is a provider-dictated FLOOR, routed through
# pacing.scale_delay_floor() — not scale_delay(), which would let `aggressive`
# shorten it.  Pastebin documents "not more than 1 request per second" on its
# scraping API and blocks clients that exceed it, so 1.5 s is the documented
# 1.0 s plus margin.  dpaste / paste.ee / Rentry publish no limit; their 1.0 s
# is VoidAccess's own courtesy pacing (see docs/BACKLOG.md classification).
DEFAULT_RATE_LIMIT = 1.0   # seconds between requests to one paste source

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

MAX_PASTE_SIZE = 512 * 1024
MAX_PASTES_PER_SOURCE = 5
MAX_TOTAL_PASTES = 15

# Bitcoin / IP / hash / email / onion / leak-keyword patterns. Pre-compiled
# once so the relevance scorer does not recompile on every paste.
_HIGH_VALUE_PATTERNS = [
    re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),     # Bitcoin address
    re.compile(r'\b[A-Fa-f0-9]{32}\b'),                     # MD5
    re.compile(r'\b[A-Fa-f0-9]{64}\b'),                     # SHA256
    re.compile(r'\bCVE-\d{4}-\d+\b', re.IGNORECASE),
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # IPv4
    re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.'),      # Email
    re.compile(r'[a-zA-Z2-7]{16,56}\.onion', re.IGNORECASE),
    re.compile(r'-----BEGIN PGP'),
    re.compile(
        r'password|passwd|credentials|leaked|dump|breach|config|c2|'
        r'command.control',
        re.IGNORECASE,
    ),
]

_TECH_PATTERNS = [
    re.compile(r'\b(CVE-\d{4}-\d+)\b', re.IGNORECASE),
    re.compile(r'\b([A-Z][a-z]+[A-Z][a-z]+)\b'),  # CamelCase tool names
    re.compile(
        r'\b(cobalt strike|metasploit|mimikatz|lockbit|blackcat|alphv|'
        r'revil|conti|ryuk|maze|darkside)\b',
        re.IGNORECASE,
    ),
]


def _is_paste_scraping_enabled() -> bool:
    """Return True if PASTE_SCRAPING_ENABLED env var is unset or truthy."""
    return os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() == "true"


# ---------------------------------------------------------------------------
# PasteScraper
# ---------------------------------------------------------------------------


class PasteScraper:
    """
    Scrapes paste sites for intelligence relevant to an investigation query.
    Use as an async context manager so the underlying aiohttp session is
    properly closed.
    """

    def __init__(self) -> None:
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "PasteScraper":
        # Shared clearnet pool (P1.2): borrow the pooled session (the direct
        # transport for clearnet_fetch), never close it. HEADERS move onto each
        # clearnet_fetch call; clearnet_fetch already supplies its own per-request
        # timeout, so the old session-level timeout was already overridden.
        self._session = http_pool.get_clearnet_session()
        return self

    async def __aexit__(self, *args) -> None:
        # The shared session is owned by the pool; nothing to close here.
        self._session = None

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    async def search_and_fetch(
        self,
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_PASTES,
    ) -> list[dict]:
        """
        Search all configured paste sources and fetch relevant content.
        Returns a list of page dicts (see module docstring for shape).
        """
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning(
                "Paste scraping blocked — prohibited query"
            )
            return []

        search_terms = self._build_search_terms(query, refined_query)

        logger.info(
            "Paste scraping: '%s' across %d sources",
            query[:50],
            len(PASTE_SOURCES),
        )

        # Run every (source, term) pair concurrently.
        tasks: list = []
        for source in PASTE_SOURCES:
            if not source.get("search_url"):
                continue
            for term in search_terms[:2]:
                tasks.append(self._scrape_source(source, term))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_results: list[dict] = []
        seen_urls: set[str] = set()
        for result in results:
            if isinstance(result, Exception):
                continue
            if not isinstance(result, list):
                continue
            for page in result:
                url = page.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(page)

        all_results.sort(
            key=lambda x: x.get("relevance", 0),
            reverse=True,
        )

        final = all_results[:max_results]
        logger.info("Paste scraping: found %d pastes", len(final))
        return final

    # -----------------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------------

    def _build_search_terms(
        self,
        query: str,
        refined_query: str,
    ) -> list[str]:
        """Build 1-3 search terms; prefers specific technical terms."""
        terms: list[str] = []

        if refined_query and refined_query != query:
            terms.append(refined_query[:100])

        terms.append(query[:100])

        for pattern in _TECH_PATTERNS:
            for m in pattern.findall(query)[:1]:
                term = m if isinstance(m, str) else m[0]
                if term and term not in terms:
                    terms.append(term)

        return terms[:3]

    async def _scrape_source(
        self,
        source: dict,
        search_term: str,
    ) -> list[dict]:
        """Search one paste source and fetch matching paste contents."""
        results: list[dict] = []

        try:
            paste_ids = await self._search_source(source, search_term)
            if not paste_ids:
                return []

            fetch_tasks = [
                self._fetch_paste(source, paste_id)
                for paste_id in paste_ids[:MAX_PASTES_PER_SOURCE]
            ]
            pages = await asyncio.gather(
                *fetch_tasks,
                return_exceptions=True,
            )

            for page in pages:
                if isinstance(page, dict) and page.get("text_content"):
                    page["relevance"] = self._score_relevance(
                        page["text_content"],
                        search_term,
                    )
                    if page["relevance"] > 0:
                        results.append(page)
        except Exception as exc:
            logger.debug(
                "Paste source %s error: %s",
                source.get("name", "?"),
                exc,
            )

        return results

    async def _search_source(
        self,
        source: dict,
        search_term: str,
    ) -> list[str]:
        """Issue a search request and extract paste IDs from the result HTML."""
        if self._session is None:
            return []

        search_url_template = source.get("search_url")
        if not search_url_template:
            return []

        encoded_term = quote_plus(search_term)
        search_url = search_url_template.format(query=encoded_term)

        try:
            status, _content_type, body = await clearnet_fetch(
                search_url,
                expect="html",
                headers=HEADERS,
                fallback_session=self._session,
            )
            if status != 200:
                return []
            html = body.decode("utf-8", errors="ignore")

            pattern = source.get("result_pattern") or ""
            if not pattern:
                return []

            ids = re.findall(pattern, html)

            seen: set[str] = set()
            unique_ids: list[str] = []
            for i in ids:
                if i not in seen:
                    seen.add(i)
                    unique_ids.append(i)

            await asyncio.sleep(
                pacing.scale_delay_floor(
                    source.get("rate_limit", DEFAULT_RATE_LIMIT)
                )
            )
            return unique_ids[:10]
        except Exception as exc:
            logger.debug(
                "Search failed for %s: %s",
                source.get("name", "?"),
                exc,
            )
            return []

    async def _fetch_paste(
        self,
        source: dict,
        paste_id: str,
    ) -> dict:
        """Fetch the raw content of a single paste."""
        if self._session is None:
            return {}

        paste_url = source["paste_url"].format(id=paste_id)

        try:
            status, _content_type, body = await clearnet_fetch(
                paste_url,
                expect="text",
                headers=HEADERS,
                fallback_session=self._session,
            )
            if status != 200:
                return {}

            # Size gate now uses the real bytes received, not the
            # content-length header (which can be missing or wrong).
            # Truncate to MAX_PASTE_SIZE if needed; the threshold value
            # is preserved exactly from the pre-v1.6 implementation.
            if len(body) > MAX_PASTE_SIZE:
                body = body[:MAX_PASTE_SIZE]

            content = body.decode("utf-8", errors="ignore")

            clean_content, was_flagged = sanitize_content(content)
            if was_flagged:
                logger.info("Paste content blocked: %s", paste_url)
                return {}

            if not clean_content or len(clean_content.strip()) < 50:
                return {}

            return {
                "url": paste_url,
                "text_content": clean_content,
                "title": f"{source['name']} — {paste_id}",
                "source_type": "paste_site",
                "source_name": source["name"],
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean_content.split()),
            }
        except Exception as exc:
            logger.debug("Fetch failed %s: %s", paste_url, exc)
            return {}

    def _score_relevance(self, content: str, search_term: str) -> int:
        """Score how relevant a paste is. Higher = more relevant."""
        if not content or not search_term:
            return 0

        content_lower = content.lower()
        term_lower = search_term.lower()
        score = 0

        if term_lower in content_lower:
            score += 10

        for word in term_lower.split():
            if len(word) > 3 and word in content_lower:
                score += 2

        for pattern in _HIGH_VALUE_PATTERNS:
            if pattern.search(content):
                score += 3

        return score


# ---------------------------------------------------------------------------
# Module-level robots.txt check (safety helper)
# ---------------------------------------------------------------------------


async def check_robots_txt(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
) -> bool:
    """
    Best-effort robots.txt check. Returns True when crawling is allowed (or
    when the check itself fails — we err on the side of allowing).
    """
    try:
        from urllib.robotparser import RobotFileParser

        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        async with session.get(
            robots_url,
            timeout=aiohttp.ClientTimeout(total=pacing.scale_timeout(ROBOTS_TIMEOUT)),
        ) as resp:
            if resp.status != 200:
                return True
            content = await resp.text(encoding="utf-8", errors="ignore")

        rp = RobotFileParser()
        rp.parse(content.splitlines())
        return rp.can_fetch("*", path)
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def scrape_paste_sites(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_TOTAL_PASTES,
) -> list[dict]:
    """
    Public entry point — fetch paste site results for *query*.
    Returns [] when paste scraping is disabled via env var.
    """
    if not _is_paste_scraping_enabled():
        logger.info("Paste scraping disabled via PASTE_SCRAPING_ENABLED=false")
        return []

    async with PasteScraper() as scraper:
        return await scraper.search_and_fetch(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
