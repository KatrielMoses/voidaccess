"""
sources/cache.py — Simple file-based TTL cache for external feeds.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_memory_cache: dict[str, tuple[Any, float]] = {}


def _rss_to_entries(text: str) -> list[dict]:
    """
    Flatten an RSS/Atom document into JSON-serializable entry dicts.

    Keys mirror what consumers expect from the former JSON feeds, so a feed
    that moved from JSON to RSS upstream (CISA advisories, DOJ press releases)
    keeps working: ``title`` / ``link`` / ``published`` and the CISA-style
    aliases ``url`` / ``datePublished`` / ``tags``. Entry bodies are not kept:
    no consumer reads them and the CISA feed ships ~1 MB of HTML per fetch.
    """
    import feedparser  # type: ignore[import-untyped]

    parsed = feedparser.parse(text)
    # feedparser never raises: an HTML error/challenge page comes back with an
    # empty ``version`` (no recognized RSS/Atom dialect) and a truncated body
    # with the bozo flag and no entries. Raise in both cases so fetch() falls
    # back to the stale cache instead of caching an empty list for the whole TTL.
    if not parsed.version or (not parsed.entries and parsed.bozo):
        raise ValueError(
            f"not an RSS/Atom feed: {parsed.get('bozo_exception') or 'unrecognized format'}"
        )
    entries: list[dict] = []
    for e in parsed.entries:
        link = e.get("link", "")
        # Atom entries commonly carry only <updated>; feedparser does not alias it.
        published = (
            _iso_date(e.get("published_parsed") or e.get("updated_parsed"))
            or e.get("published")
            or e.get("updated", "")
        )
        entries.append({
            "title": e.get("title", ""),
            "link": link,
            "url": link,
            "published": published,
            "datePublished": published,
            "tags": [t.get("term", "") for t in e.get("tags", []) if t.get("term")],
        })
    return entries


def _iso_date(parsed_time: time.struct_time | None) -> str:
    """Render feedparser's UTC ``*_parsed`` struct as ISO-8601, or "" if absent."""
    if parsed_time is None:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", parsed_time)


def _parse_feed_body(text: str, content_type: str) -> Any:
    """
    Decode a feed body as JSON, or as RSS/Atom when the server sends a feed.

    Anything else (an HTML error page served with HTTP 200, for example)
    raises ``ValueError`` so the caller can fall back to its stale cache.
    """
    ct = content_type.lower()
    head = text.lstrip()[:512].lower()
    if any(t in ct for t in ("xml", "rss", "atom")) or "<rss" in head or "<feed" in head:
        return _rss_to_entries(text)
    return json.loads(text)


class CachedFeed:
    """
    Fetch a remote JSON or RSS feed and cache it to *cache_path* for *ttl_seconds*.

    RSS/Atom responses are normalized to a list of entry dicts (see
    :func:`_rss_to_entries`) so the on-disk cache is always JSON.

    On every call to :meth:`fetch`:
      - If a fresh cache file exists (mtime < ttl_seconds), return cached data.
      - If stale or missing: fetch from *url*, save, and return.
      - If fetch fails but stale cache exists: return stale cache with a warning.
      - If fetch fails and no cache exists: log error and return None.
    """

    def __init__(self, url: str, cache_path: str, ttl_seconds: int):
        self.url = url
        self.cache_path = Path(cache_path)
        self.ttl_seconds = ttl_seconds

    def _is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        mtime = self.cache_path.stat().st_mtime
        return (time.time() - mtime) < self.ttl_seconds

    async def fetch(self) -> Optional[dict | list]:
        import aiohttp

        now = time.time()
        cache_key = self.url

        if cache_key in _memory_cache:
            cached_data, timestamp = _memory_cache[cache_key]
            if (now - timestamp) < self.ttl_seconds:
                return cached_data

        if self._is_fresh():
            try:
                with self.cache_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    _memory_cache[cache_key] = (data, now)
                    return data
            except Exception:
                pass

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.url) as resp:
                    if resp.status != 200:
                        logger.warning("CachedFeed: HTTP %s for %s", resp.status, self.url)
                        stale = self._stale_cache()
                        if stale is not None and cache_key in _memory_cache:
                            return stale
                        return stale
                    data = _parse_feed_body(
                        await resp.text(),
                        resp.headers.get("Content-Type", ""),
                    )
                    self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                    with self.cache_path.open("w", encoding="utf-8") as f:
                        json.dump(data, f)
                    _memory_cache[cache_key] = (data, now)
                    return data
        except Exception as e:
            logger.warning("CachedFeed: fetch failed for %s: %s", self.url, e)
            if cache_key in _memory_cache:
                cached_data, timestamp = _memory_cache[cache_key]
                logger.warning("CachedFeed: returning stale memory cache for %s", self.url)
                return cached_data
            return self._stale_cache()

    def _stale_cache(self) -> Optional[dict | list]:
        if self.cache_path.exists():
            try:
                with self.cache_path.open("r", encoding="utf-8") as f:
                    logger.warning("CachedFeed: falling back to stale cache %s", self.cache_path)
                    return json.load(f)
            except Exception:
                pass
        return None
