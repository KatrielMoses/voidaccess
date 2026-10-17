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


def parse_rss(text: str) -> list[dict]:
    """RSS 2.0 items as ``{"title", "link", "published", "tags"}`` dicts.

    Stdlib only. The XML comes from a fixed government feed; DTDs and entity
    declarations are refused outright so no expansion can happen."""
    import xml.etree.ElementTree as ET

    if "<!DOCTYPE" in text[:2048] or "<!ENTITY" in text:
        raise ValueError("RSS with a DTD or entity declarations refused")
    root = ET.fromstring(text)
    items: list[dict] = []
    for item in root.iter("item"):
        def _text(tag: str) -> str:
            node = item.find(tag)
            return (node.text or "").strip() if node is not None else ""
        items.append({
            "title": _text("title"),
            "link": _text("link"),
            "published": _text("pubDate"),
            "tags": [(c.text or "").strip() for c in item.findall("category") if c.text],
        })
    return items


class CachedFeed:
    """
    Fetch a remote JSON feed and cache it to *cache_path* for *ttl_seconds*.

    On every call to :meth:`fetch`:
      - If a fresh cache file exists (mtime < ttl_seconds), return cached data.
      - If stale or missing: fetch from *url*, save, and return.
      - If fetch fails but stale cache exists: return stale cache with a warning.
      - If fetch fails and no cache exists: log error and return None.
    """

    def __init__(self, url: str, cache_path: str, ttl_seconds: int, parse: str = "json",
                 headers: Optional[dict] = None):
        self.url = url
        self.cache_path = Path(cache_path)
        self.ttl_seconds = ttl_seconds
        # "json" (default, unchanged behavior) parses the body as JSON; "text"
        # caches and returns the raw body as a str — used for bulk CSV feeds
        # (e.g. ExploitDB's files_exploits.csv) that are not JSON.
        # "rss" caches the raw XML and returns parse_rss() items.
        if parse not in ("json", "text", "rss"):
            raise ValueError(f"CachedFeed parse must be 'json', 'text' or 'rss', got {parse!r}")
        self.parse = parse
        # Optional request headers, e.g. abuse.ch's Auth-Key. Resolved per-fetch by
        # a callable so a key that appears in the env after construction is picked
        # up; a plain dict is also accepted.
        self._headers = headers

    def _load_file(self):
        with self.cache_path.open("r", encoding="utf-8") as f:
            if self.parse == "text":
                return f.read()
            if self.parse == "rss":
                return parse_rss(f.read())
            return json.load(f)

    def _write_file(self, data) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("w", encoding="utf-8") as f:
            if self.parse in ("text", "rss"):
                f.write(data)
            else:
                json.dump(data, f)

    def _failed(self):
        """Remember for the rest of the run that this feed failed, and fall
        back to whatever stale copy there is."""
        from sources import source_control

        source_control.get_tracker().mark_feed_failed(self.url)
        if self.url in _memory_cache:
            return _memory_cache[self.url][0]
        return self._stale_cache()

    def _is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        mtime = self.cache_path.stat().st_mtime
        return (time.time() - mtime) < self.ttl_seconds

    async def fetch(self) -> Optional[dict | list | str]:
        import aiohttp
        from sources import http_pool

        now = time.time()
        cache_key = self.url

        if cache_key in _memory_cache:
            cached_data, timestamp = _memory_cache[cache_key]
            if (now - timestamp) < self.ttl_seconds:
                return cached_data

        if self._is_fresh():
            try:
                data = self._load_file()
                _memory_cache[cache_key] = (data, now)
                return data
            except Exception:
                pass

        from sources import source_control

        if source_control.get_tracker().feed_failed(self.url):
            # Failed earlier in this run: do not hammer a dead endpoint.
            if cache_key in _memory_cache:
                return _memory_cache[cache_key][0]
            return self._stale_cache()

        headers = self._headers() if callable(self._headers) else self._headers

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with http_pool.clearnet_session() as session:
                async with session.get(self.url, timeout=timeout, headers=headers) as resp:
                    if resp.status != 200:
                        logger.warning("CachedFeed: HTTP %s for %s", resp.status, self.url)
                        return self._failed()
                    if self.parse == "json":
                        data = await resp.json(content_type=None)
                        raw = data
                    else:
                        raw = await resp.text()
                        data = parse_rss(raw) if self.parse == "rss" else raw
                    self._write_file(raw)
                    _memory_cache[cache_key] = (data, now)
                    return data
        except Exception as e:
            logger.warning("CachedFeed: fetch failed for %s: %s", self.url, e)
            # Transport errors were already counted by http_pool; a 200 whose
            # body would not parse is a failed call too.
            if not isinstance(e, (aiohttp.ClientError, TimeoutError)):
                source_control.record_source_failure(source_control.source_for_url(self.url))
            if cache_key in _memory_cache:
                logger.warning("CachedFeed: returning stale memory cache for %s", self.url)
            return self._failed()

    def _stale_cache(self) -> Optional[dict | list | str]:
        if self.cache_path.exists():
            try:
                logger.warning("CachedFeed: falling back to stale cache %s", self.cache_path)
                return self._load_file()
            except Exception:
                pass
        return None
