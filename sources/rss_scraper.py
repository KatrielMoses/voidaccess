"""
sources/rss_scraper.py — RSS/Atom feed scraper for VoidAccess.

Fetches recent articles from curated threat intelligence blogs and feeds
relevant to the investigation query.  Runs over CLEARNET — these are public
security blogs that do not require Tor.

Feed results are cached per-URL for 1 hour (feeds update infrequently).
Articles are scored by relevance to the query and filtered by age (max 90 days).

Public API:
    async def scrape_rss_feeds(
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_ARTICLES,
    ) -> list[dict]

Returns page dicts compatible with the extraction pipeline:
    {
        "url": str,
        "text_content": str,
        "title": str,
        "source_type": "rss_feed",
        "source_name": str,
        "feed_category": str,
        "published_at": str,
        "relevance": int,
        "feed_weight": int,
        "scraped_at": str,
        "word_count": int,
    }
"""

from __future__ import annotations

import asyncio
import aiohttp
import trafilatura
import hashlib
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pacing
from sources import http_pool
from sources.enrichment import is_onion_url
from sources.proxy_client import clearnet_fetch
from sources.source_control import (
    STATUS_DISABLED,
    attribute_requests_to,
    is_rss_feed_disabled,
    note_gate_refusal,
)
from utils.content_safety import is_blocked_query, sanitize_content

# Timing baselines (`normal` pacing profile); scaled at call time.
FEED_TIMEOUT = 15    # seconds, feed fetch
ENTRY_TIMEOUT = 10   # seconds, per-entry fetch

# Request headers, passed per-request through clearnet_fetch now that the session
# is the shared, header-less clearnet pool (P1.2). Module-level so they apply
# even when a scraper instance is used without its `async with` context.
_RSS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; RSS-Reader/1.0; +https://github.com/voidaccess/voidaccess)",
    "Accept": (
        "application/rss+xml, application/atom+xml, "
        "application/xml, text/xml"
    ),
}

logger = logging.getLogger(__name__)

CACHE_DIR = Path("/tmp/voidaccess_rss_cache")
CACHE_TTL_SECONDS = 3600  # 1 hour

MAX_ARTICLE_AGE_DAYS = 90
MAX_ARTICLES_PER_FEED = 3
MAX_TOTAL_ARTICLES = 20
MAX_ARTICLE_SIZE = 100 * 1024  # 100 KB
MIN_MEANINGFUL_ARTICLE_TEXT = 100
# 22R-3: articles that match no query term are relevant to nothing; recency
# alone only orders results. At most this many recent, unmatched articles are
# still kept per run, labelled background feed items.
RSS_RECENCY_ONLY_CAP = 5

# Per-run counts for the relevance block (the CLI runs one query per process).
_last_run_stats: dict[str, int] = {"recency_only_kept": 0, "feed_items_capped": 0}


def last_run_stats() -> dict[str, int]:
    """Counts from the most recent ``fetch_relevant_articles`` call."""
    return dict(_last_run_stats)


def reset_run_stats() -> None:
    _last_run_stats.update(recency_only_kept=0, feed_items_capped=0)

RSS_FEEDS = [
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "journalism",
        "tags": ["breach", "fraud", "cybercrime", "ransomware", "dark web", "banking"],
        "weight": 10,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "journalism",
        "tags": ["ransomware", "malware", "breach", "vulnerability", "darkweb", "leak"],
        "weight": 10,
    },
    {
        "name": "The Record by Recorded Future",
        "url": "https://therecord.media/feed",
        "category": "journalism",
        "tags": ["cybercrime", "espionage", "ransomware", "government", "critical infrastructure"],
        "weight": 9,
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "journalism",
        "tags": ["vulnerability", "threat", "attack", "malware", "breach", "security"],
        "weight": 8,
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/Securityweek",
        "category": "journalism",
        "tags": ["vulnerability", "ransomware", "breach", "malware", "exploit"],
        "weight": 8,
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "category": "journalism",
        "tags": ["vulnerability", "ransomware", "malware", "breach", "APT"],
        "weight": 7,
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "technical",
        "tags": ["IOC", "malware", "exploit", "vulnerability", "incident"],
        "weight": 9,
    },
    {
        "name": "Malwarebytes Labs",
        "url": "https://www.malwarebytes.com/blog/feed/",
        "category": "technical",
        "tags": ["malware", "ransomware", "threat", "stealer", "trojan", "adware"],
        "weight": 8,
    },
    {
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "technical",
        "tags": ["malware", "IOC", "APT", "exploit", "vulnerability", "threat actor"],
        "weight": 10,
    },
    {
        "name": "Sophos News",
        "url": "https://news.sophos.com/en-us/feed/",
        "category": "technical",
        "tags": ["ransomware", "malware", "threat", "exploit", "attack"],
        "weight": 8,
    },
    {
        "name": "Mandiant Blog",
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
        "category": "threat_intel",
        "tags": ["APT", "threat actor", "espionage", "malware", "incident response", "zero day"],
        "weight": 10,
    },
    {
        "name": "CrowdStrike Blog",
        "url": "https://www.crowdstrike.com/blog/feed/",
        "category": "threat_intel",
        "tags": ["APT", "threat actor", "ransomware", "malware", "eCrime", "adversary"],
        "weight": 10,
    },
    {
        "name": "Secureworks CTU",
        "url": "https://www.secureworks.com/rss?feed=blog",
        "category": "threat_intel",
        "tags": ["threat actor", "malware", "APT", "ransomware", "darkweb", "TTPs"],
        "weight": 9,
    },
    {
        "name": "US-CERT Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "government",
        "tags": ["vulnerability", "alert", "advisory", "critical infrastructure", "KEV"],
        "weight": 10,
    },
    {
        "name": "CISA News",
        "url": "https://www.cisa.gov/news.xml",
        "category": "government",
        "tags": ["vulnerability", "advisory", "ransomware", "critical infrastructure"],
        "weight": 9,
    },
    {
        "name": "FBI Cyber Division News",
        "url": "https://www.fbi.gov/feeds/fbi-in-the-news/rss.xml",
        "category": "government",
        "tags": ["cybercrime", "ransomware", "darkweb", "arrest", "seizure", "takedown"],
        "weight": 9,
    },
    # v1.6.2 — DOJ News (replacement for the permanently-404
    # /news/press-releases/rss endpoint).  The DOJ restructured their
    # Drupal site and the old press-releases-only RSS path now returns
    # 404; the all-news feed at /news/rss is the working replacement and
    # contains every DOJ press release (plus speeches, videos, etc.,
    # filtered by relevance downstream).  Verified live 2026-07.
    {
        "name": "US Department of Justice News",
        "url": "https://www.justice.gov/news/rss",
        "category": "government",
        "tags": [
            "cybercrime", "ransomware", "fraud", "indictment", "takedown",
            "seizure", "sanctions", "enforcement", "DOJ",
        ],
        "weight": 9,
    },
    {
        "name": "Recorded Future Intelligence",
        "url": "https://www.recordedfuture.com/feed",
        "category": "threat_intel",
        "tags": ["threat actor", "dark web", "IOC", "malware", "vulnerability", "APT"],
        "weight": 9,
    },
    {
        "name": "Palo Alto Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "category": "threat_intel",
        "tags": ["malware", "APT", "threat actor", "ransomware", "phishing", "exploit"],
        "weight": 10,
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "category": "threat_intel",
        "tags": ["APT", "ransomware", "vulnerability", "threat actor", "malware", "nation state"],
        "weight": 9,
    },
    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "technical",
        "tags": ["zero day", "exploit", "vulnerability", "CVE", "browser", "kernel"],
        "weight": 9,
    },
]

_KNOWN_ACTORS = [
    "lockbit", "blackcat", "alphv", "cl0p", "clop", "play", "akira",
    "blackbasta", "black basta", "revil", "conti", "ryuk", "maze",
    "darkside", "hive", "ragnarlocker", "cobalt strike", "metasploit",
    "mimikatz", "beacon", "sliver", "havoc", "brute ratel", "covenant",
    "lazarus", "apt28", "apt29", "cozy bear", "fancy bear",
    "sandworm", "volt typhoon", "scattered spider", "lapsus",
]


class RSSCache:
    """Simple file-based cache for RSS feed article lists.

    v1.6.2 — also caches feed-FETCH failures (empty / 404 results) for
    the cache TTL window, so a temporarily-broken feed URL is not
    re-attempted on every investigation within the TTL.  Without this,
    a dead feed URL in RSS_FEEDS would log the same failure on every
    run until ops manually removed it.  Now: the FIRST run sees the
    failure, every subsequent run within CACHE_TTL_SECONDS silently
    skips the feed (no fetch, no log noise).
    """

    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, url: str) -> Path:
        key = hashlib.md5(url.encode()).hexdigest()
        return CACHE_DIR / f"{key}.json"

    def get(self, url: str) -> Optional[list]:
        """Return cached article list for *url*, or None on miss/expiry.

        A return value of ``[]`` is the cache hit for a failed fetch —
        callers should treat ``[]`` the same as a fresh empty result
        (no fetch attempt, no log noise).  Returns None only when
        there is no cache entry or the entry has expired.
        """
        path = self._cache_path(url)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            age = time.time() - data.get("cached_at", 0)
            if age > CACHE_TTL_SECONDS:
                path.unlink(missing_ok=True)
                return None
            return data.get("articles", [])
        except Exception:
            return None

    def set(self, url: str, articles: list) -> None:
        """Persist the feed's article list (or empty list for failures)
        for CACHE_TTL_SECONDS.  An empty list is the canonical
        representation of a failed/empty feed fetch so subsequent
        runs within the TTL window don't retry it.
        """
        path = self._cache_path(url)
        try:
            path.write_text(json.dumps({
                "cached_at": time.time(),
                "articles": articles,
            }))
        except Exception as e:
            logger.debug("RSS cache write failed: %s", e)


class RSSFeedScraper:
    """Fetches and parses RSS/Atom feeds from curated threat intelligence sources."""

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache = RSSCache()
        # v1.6.2 — per-investigation article-fetch cache.  Same article
        # URL appears in many feeds (CISA, FBI, etc. all link to the
        # same parent landing pages) so without this the same URL was
        # being re-fetched 15-17+ times per run, generating a 404 storm
        # when the URL was dead (e.g. the old
        # ``/cybersecurity-advisories/all.json`` and
        # ``/news/press-releases/rss`` paths).  We cache BOTH successes
        # (full text) AND failures (sentinel) so a broken URL is attempted
        # exactly once per investigation, not once per article.  Lives
        # only for the lifetime of this scraper instance (one per
        # ``scrape_rss_feeds()`` call) — so it's per-investigation, not
        # persistent across runs.  The sentinel value marks "we already
        # tried this URL this run and it failed; don't try again".
        self._article_fetch_cache: dict[str, object] = {}
        # 22R-3: query matcher (set per fetch) and recent articles that
        # matched no query term, kept aside for the capped background slot.
        self._matcher = None
        self._recency_candidates: list[tuple[int, int, dict, dict]] = []

    async def __aenter__(self):
        # Shared clearnet pool (P1.2): borrow the pooled session (the direct
        # transport for clearnet_fetch), never close it. Headers (_RSS_HEADERS)
        # move onto each clearnet_fetch call; those calls already pass their own
        # per-request timeout, so the old session-level timeout was already
        # overridden.
        self._session = http_pool.get_clearnet_session()
        return self

    async def __aexit__(self, *args):
        # The shared session is owned by the pool; nothing to close here.
        self._session = None

    async def fetch_relevant_articles(
        self,
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_ARTICLES,
    ) -> list[dict]:
        """
        Fetch articles from all feeds relevant to the query.
        Returns page dicts compatible with the extraction pipeline.
        """
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning("RSS scraping blocked — prohibited query")
            return []

        search_terms = self._extract_search_terms(query, refined_query)
        try:
            from voidaccess.relevance import QueryMatcher, intent_for

            self._matcher = QueryMatcher(intent_for(query), refined_query or query)
        except Exception as exc:  # pragma: no cover - relevance never breaks RSS
            logger.debug("RSS relevance matcher unavailable: %s", exc)
            self._matcher = None
        self._recency_candidates = []

        logger.info(
            "RSS feeds: fetching for '%s' (%d feeds)",
            query[:50],
            len(RSS_FEEDS),
        )

        active_feeds = [f for f in RSS_FEEDS if not _rss_feed_disabled(f)]
        tasks = [self._fetch_feed(feed, search_terms) for feed in active_feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_articles: list[dict] = []
        seen_urls: set[str] = set()

        for result in results:
            if isinstance(result, list):
                for article in result:
                    url = article.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_articles.append(article)

        all_articles.sort(
            key=lambda x: x.get("relevance", 0) * x.get("feed_weight", 1),
            reverse=True,
        )

        final = all_articles[:max_results]
        recency = await self._recency_only_articles(
            min(RSS_RECENCY_ONLY_CAP, max(0, max_results - len(final))),
            {a.get("url", "") for a in final},
        )
        final.extend(recency)
        logger.info(
            "RSS feeds: %d relevant articles found, %d recent background items",
            len(final) - len(recency), len(recency),
        )
        return final

    async def _recency_only_articles(self, cap: int, taken: set[str]) -> list[dict]:
        """The capped background slot: recent articles that matched no query term."""
        seen: set[str] = set()
        ranked: list[tuple[int, int, dict, dict]] = []
        for item in sorted(
            getattr(self, "_recency_candidates", []),
            key=lambda c: (-(c[0] * c[1]), str(c[2].get("url", ""))),
        ):
            url = item[2].get("url", "")
            if url and url not in taken and url not in seen:
                seen.add(url)
                ranked.append(item)
        kept: list[dict] = []
        for recency, _weight, article, feed in ranked:
            if len(kept) >= cap:
                break
            page = await self._article_page(article, feed, recency)
            if page is not None:
                page["recency_only"] = True
                kept.append(page)
        _last_run_stats["recency_only_kept"] = len(kept)
        _last_run_stats["feed_items_capped"] = max(0, len(ranked) - len(kept))
        return kept

    def _extract_search_terms(self, query: str, refined_query: str) -> list[str]:
        """Extract key terms for relevance matching."""
        text = f"{query} {refined_query}".lower()
        words = [w for w in re.split(r"\W+", text) if len(w) > 3]
        terms = list(set(words))

        terms.append(query.lower())
        if refined_query:
            terms.append(refined_query.lower())

        cves = re.findall(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
        terms.extend(c.lower() for c in cves)

        for actor in _KNOWN_ACTORS:
            if actor in text:
                terms.append(actor)

        return list(set(terms))

    async def _fetch_feed(self, feed: dict, search_terms: list[str]) -> list[dict]:
        """Fetch one RSS feed and return relevant articles."""
        # Request counts: every RSS fetch is the ``rss`` source, except the
        # FBI/DOJ feeds, which are the ``fbi_doj_press`` source.
        name = feed.get("name", "").lower()
        owner = (
            "fbi_doj_press"
            if "fbi" in name or "department of justice" in name
            else "rss"
        )
        with attribute_requests_to(owner):
            return await self._fetch_feed_inner(feed, search_terms)

    async def _fetch_feed_inner(self, feed: dict, search_terms: list[str]) -> list[dict]:
        feed_url = feed["url"]
        feed_name = feed["name"]

        cached = self._cache.get(feed_url)
        if cached is not None:
            # v1.6.2 — cache covers both successes AND failures (cached
            # as empty list).  A None-miss means the entry has expired
            # or was never written; a non-None return is a cache hit
            # (including the empty-list "this feed failed recently"
            # sentinel).  Either way, do not re-fetch — that's the
            # whole point of the negative-result cache.
            logger.debug("RSS cache hit: %s", feed_name)
            raw_articles = cached
        else:
            raw_articles = await self._fetch_and_parse(feed_url, feed_name)
            # v1.6.2 — cache the result either way: successes as the
            # article list, failures as [] so the next run within the
            # TTL window skips the fetch entirely (no log spam).
            self._cache.set(feed_url, raw_articles or [])

        if not raw_articles:
            return []

        relevant: list[dict] = []
        for article in raw_articles:
            relevance = self._score_article(article, search_terms, feed)
            if relevance <= 0:
                recency = self._recency_score(article)
                if recency:
                    if not hasattr(self, "_recency_candidates"):
                        self._recency_candidates = []
                    self._recency_candidates.append(
                        (recency, int(feed.get("weight", 5) or 5), article, feed)
                    )
                continue

            page = await self._article_page(article, feed, relevance)
            if page is None:
                continue
            relevant.append(page)

            if len(relevant) >= MAX_ARTICLES_PER_FEED:
                break

        return relevant

    async def _article_page(self, article: dict, feed: dict, relevance: int) -> Optional[dict]:
        """The page dict for one article (full text when reachable), or None."""
        feed_name = feed.get("name", "")
        snippet_only = os.getenv("VOIDACCESS_RSS_SNIPPET_ONLY") == "1"
        full_content = "" if snippet_only else await self._fetch_article_content(article.get("url", ""))
        content = full_content or article.get("summary", "")

        if not snippet_only and (not content or len(content.strip()) < 100):
            return None

        clean, flagged = sanitize_content(content or article.get("title", ""))
        if flagged or not clean:
            return None

        return {
            "url": article.get("url", ""),
            "text_content": clean,
            "title": article.get("title", feed_name),
            "source_type": "rss_feed",
            "source_name": feed_name,
            "feed_category": feed.get("category", "unknown"),
            "published_at": article.get("published", ""),
            "relevance": relevance,
            "feed_weight": feed.get("weight", 5),
            "scraped_at": datetime.now(timezone.utc).isoformat(),
            "word_count": len(clean.split()),
        }

    async def _fetch_and_parse(self, feed_url: str, feed_name: str) -> list[dict]:
        """Fetch and parse an RSS/Atom feed XML.

        Phase 1.6 wiring: feeds are fetched through the
        ``clearnet_fetch`` chokepoint from ``sources.proxy_client``.
        The chokepoint forces ``browser=false`` on any proxy path,
        which is what preserves the raw XML bytes — a headless-browser
        rendering would mangle them.  On any non-200 the empty-list
        contract is preserved exactly.
        """
        if not self._session:
            return []
        try:
            status, _content_type, body = await clearnet_fetch(
                feed_url,
                expect="xml",
                headers=_RSS_HEADERS,
                timeout=pacing.scale_timeout(FEED_TIMEOUT),
                fallback_session=self._session,
            )
            if status != 200:
                return []
            content = body.decode("utf-8", errors="ignore")
            return self._parse_feed(content, feed_url)
        except asyncio.TimeoutError:
            logger.debug("RSS timeout: %s", feed_name)
            return []
        except Exception as e:
            logger.debug("RSS fetch error %s: %s", feed_name, e)
            return []

    def _parse_feed(self, content: str, feed_url: str) -> list[dict]:
        """
        Parse RSS 2.0 or Atom feed XML.
        Returns list of article dicts: title, url, summary, published.
        """
        articles: list[dict] = []
        try:
            # Strip namespace declarations and prefixes so ET can parse any RSS/Atom
            content = re.sub(r'\s+xmlns(?::[a-zA-Z0-9_]+)?="[^"]*"', "", content)
            def _strip_ns(m: re.Match) -> str:
                slash, ns, tag = m.group(1), m.group(2), m.group(3)
                if ns.lower() == "http":
                    return m.group(0)
                return f"<{slash}{ns}_{tag}"
            content = re.sub(r"<(/?)([a-zA-Z][a-zA-Z0-9_]*):([a-zA-Z][a-zA-Z0-9_]*)", _strip_ns, content)

            root = ET.fromstring(content)
            is_atom = "feed" in root.tag.lower()

            if is_atom:
                for entry in root.findall("entry")[:20]:
                    url = ""
                    for link in entry.findall("link"):
                        if link.get("rel") in ("alternate", None):
                            url = link.get("href", "")
                            break
                    title_el = entry.find("title")
                    summary_el = entry.find("summary") or entry.find("content")
                    pub_el = entry.find("published") or entry.find("updated")
                    if url:
                        articles.append({
                            "url": url,
                            "title": (title_el.text or "") if title_el is not None else "",
                            "summary": (summary_el.text or "") if summary_el is not None else "",
                            "published": (pub_el.text or "") if pub_el is not None else "",
                        })
            else:
                channel = root.find("channel") or root
                for item in channel.findall("item")[:20]:
                    link_el = item.find("link")
                    title_el = item.find("title")
                    desc_el = item.find("description")
                    pub_el = item.find("pubDate")
                    url = (link_el.text or "").strip() if link_el is not None else ""
                    if url:
                        articles.append({
                            "url": url,
                            "title": (title_el.text or "") if title_el is not None else "",
                            "summary": self._strip_html(
                                (desc_el.text or "") if desc_el is not None else ""
                            ),
                            "published": (pub_el.text or "") if pub_el is not None else "",
                        })

        except ET.ParseError as e:
            logger.debug("RSS parse error %s: %s", feed_url, e)
        except Exception as e:
            logger.debug("RSS parse unexpected error: %s", e)

        return articles

    async def _fetch_article_content(self, url: str) -> Optional[str]:
        """Fetch and extract plain text from an article URL.

        Two layers of defense against a .onion URL being fetched over clearnet:

        1. The ``is_onion_url`` guard here (BELT) — fires before any network
           call, returns None, logs at debug, and triggers the existing
           summary-fallback in ``_fetch_feed`` exactly like any other failure.
        2. The chokepoint's own guard inside ``clearnet_fetch`` (SUSPENDERS)
           — raises ValueError unconditionally on .onion URLs.

        Both are intentional redundancy.  A routing bug that bypassed the
        chokepoint would still be caught here.  The curated RSS_FEEDS list
        is entirely clearnet security blogs, so this guard is purely
        structural protection, not something that fires in normal operation.

        Phase 1.6 wiring: the fetch itself goes through ``clearnet_fetch``,
        with the per-call timeout preserved at 10 s and the size-truncation
        threshold preserved at ``MAX_ARTICLE_SIZE`` (now measured against
        the raw bytes returned by the chokepoint rather than the decoded
        text — the numeric threshold is unchanged).

        v1.6.2 — per-investigation cache:
        Consults ``self._article_fetch_cache`` first.  A cached entry (success
        or ``None`` for failure) is returned immediately without a network
        call, so the same article URL is fetched at most once per run.  The
        same article appears in many feeds (CISA + FBI + government blogs
        all link to the same landing pages) and a single dead URL (e.g. the
        legacy ``/cybersecurity-advisories/all.json`` or
        ``/news/press-releases/rss`` paths) used to trigger 15-17+ identical
        fetches per run — now exactly one, with the rest served from cache.
        """
        if not url or not self._session:
            return None

        # --- v1.6.2: per-run article cache check -------------------------
        article_cache = getattr(self, "_article_fetch_cache", None)
        if article_cache is None:
            article_cache = self._article_fetch_cache = {}
        cached = article_cache.get(url)
        if cached is not None:
            # Either a real string (success — return text directly) or
            # the sentinel "we already tried this URL and it returned
            # None" entry.  We can't store a plain None because
            # ``dict.get(url)`` would return None for both "not cached"
            # and "cached as failure" — use a sentinel.
            if cached is _ARTICLE_FETCH_SENTINEL:
                return None
            return cached

        # --- Belt-and-suspenders .onion guard -----------------------------
        if is_onion_url(url):
            logger.debug(
                "RSS article URL is .onion — refusing clearnet fetch: %s",
                url[:60],
            )
            self._article_fetch_cache[url] = _ARTICLE_FETCH_SENTINEL
            return None

        try:
            status, _content_type, body = await clearnet_fetch(
                url,
                expect="html",
                headers=_RSS_HEADERS,
                timeout=pacing.scale_timeout(ENTRY_TIMEOUT),
                fallback_session=self._session,
            )
            if status != 200:
                self._article_fetch_cache[url] = _ARTICLE_FETCH_SENTINEL
                return None
            # Size gate now uses the real bytes received, not the decoded
            # text.  The threshold value (MAX_ARTICLE_SIZE) is unchanged;
            # only the unit (chars → bytes) shifts for the truncation
            # slice — for ASCII content the behavior is identical.
            if len(body) > MAX_ARTICLE_SIZE:
                body = body[:MAX_ARTICLE_SIZE]
            html = body.decode("utf-8", errors="ignore")
            text = self._extract_article_text(html)
            if text and len(text) > 100:
                self._article_fetch_cache[url] = text
                return text
            self._article_fetch_cache[url] = _ARTICLE_FETCH_SENTINEL
            return None
        except Exception:
            self._article_fetch_cache[url] = _ARTICLE_FETCH_SENTINEL
            return None

    def _extract_article_text(self, html: str) -> str:
        """Extract the article body, with a conservative raw-text fallback.

        Keep this call aligned with ``scraper.scrape._extract_text`` so RSS
        article pages receive the same main-content extraction as regular
        scraped pages.  A short/empty Trafilatura result is not treated as a
        successful extraction: some pages are difficult to parse, and their
        raw visible text is still more useful than silently returning nothing.
        """
        try:
            text = trafilatura.extract(
                html,
                include_comments=False,
                include_tables=True,
            )
            if text and len(text.strip()) >= MIN_MEANINGFUL_ARTICLE_TEXT:
                return text.strip()
        except Exception:
            pass  # Trafilatura/lxml failure -> use the raw-strip fallback

        return self._raw_strip_article_text(html)

    @staticmethod
    def _raw_strip_article_text(html: str) -> str:
        """Strip scripts, styles, and tags; collapse whitespace."""
        html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL)
        html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", html)
        for entity, char in {
            "&amp;": "&", "&lt;": "<", "&gt;": ">",
            "&quot;": '"', "&#39;": "'", "&nbsp;": " ", "&apos;": "'",
        }.items():
            text = text.replace(entity, char)
        return re.sub(r"\s+", " ", text).strip()

    def _strip_html(self, html: str) -> str:
        """Strip HTML tags from a string."""
        text = re.sub(r"<[^>]+>", " ", html)
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _recency_score(article: dict) -> int:
        """Ordering score from the publication date; 0 when too old or undated."""
        pub_str = article.get("published", "")
        if not pub_str:
            return 0
        try:
            from email.utils import parsedate_to_datetime
            try:
                pub_dt = parsedate_to_datetime(pub_str)
            except Exception:
                import dateutil.parser
                pub_dt = dateutil.parser.parse(pub_str)

            now = datetime.now(timezone.utc)
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)

            age_days = (now - pub_dt).days
            if age_days > MAX_ARTICLE_AGE_DAYS:
                return 0
            if age_days <= 7:
                return 5
            if age_days <= 30:
                return 3
            return 1
        except Exception:
            return 1

    def _matches_query(self, article: dict, search_terms: list[str]) -> bool:
        """22R-3: does a query term or alias appear in the title or summary?

        With a query matcher (the normal path) this is the relevance-tier
        match: the selector, threat name or alias, topic phrase, or a
        non-generic term. Without one, any non-generic search term counts.
        """
        title = article.get("title", "") or ""
        summary = article.get("summary", "") or ""
        hay = f"{title}\n{summary}"
        matcher = getattr(self, "_matcher", None)
        if matcher is not None:
            try:
                return bool(matcher.direct_matches(hay) or matcher.related_match(hay))
            except Exception:
                pass
        from voidaccess.query_intent import GENERIC_TERMS

        low = hay.lower()
        return any(
            len(term) > 3 and term not in GENERIC_TERMS and term in low
            for term in search_terms
        )

    def _score_article(
        self,
        article: dict,
        search_terms: list[str],
        feed: dict,
    ) -> int:
        """Score article relevance to search terms (0 = exclude).

        Relevance needs a query-term match in the title or summary; recency
        and feed tags only order the matching articles.
        """
        pub_str = article.get("published", "")
        recency = self._recency_score(article)
        if pub_str and recency == 0:
            return 0  # older than MAX_ARTICLE_AGE_DAYS
        if not self._matches_query(article, search_terms):
            return 0

        score = recency
        title = article.get("title", "").lower()
        summary = article.get("summary", "").lower()
        for term in search_terms:
            if len(term) > 3:
                if term in title:
                    score += 5
                elif term in summary:
                    score += 2

        feed_tags = [t.lower() for t in feed.get("tags", [])]
        for term in search_terms:
            if term in feed_tags:
                score += 1

        return max(score, 1)


# Module-level sentinel used in RSSFeedScraper._article_fetch_cache to
# mark "we already tried this URL this run and it failed".  Real results
# are stored as strings, so this unique object cleanly distinguishes
# "not cached" from "cached as a failure" without a separate
# sentinel-key namespace.
_ARTICLE_FETCH_SENTINEL = object()


def _rss_feed_disabled(feed: dict) -> bool:
    """Deny-list gate (VOIDACCESS_DISABLED_SOURCES): ``rss`` or ``fbi_doj_press``."""
    if is_rss_feed_disabled(feed.get("name", "")):
        name = feed.get("name", "").lower()
        note_gate_refusal(
            "fbi_doj_press" if ("fbi" in name or "department of justice" in name) else "rss",
            STATUS_DISABLED,
        )
        return True
    return False


async def scrape_rss_feeds(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_TOTAL_ARTICLES,
) -> list[dict]:
    """
    Main entry point.  Returns page dicts compatible with the extraction pipeline.
    Opt-out via RSS_FEEDS_ENABLED=false.
    """
    if os.getenv("RSS_FEEDS_ENABLED", "true").lower() != "true":
        logger.info("RSS feeds disabled")
        return []

    async with RSSFeedScraper() as scraper:
        return await scraper.fetch_relevant_articles(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
