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
        if parse not in ("json", "text"):
            raise ValueError(f"CachedFeed parse must be 'json' or 'text', got {parse!r}")
        self.parse = parse
        # Optional request headers, e.g. abuse.ch's Auth-Key. Resolved per-fetch by
        # a callable so a key that appears in the env after construction is picked
        # up; a plain dict is also accepted.
        self._headers = headers

    def _load_file(self):
        with self.cache_path.open("r", encoding="utf-8") as f:
            return f.read() if self.parse == "text" else json.load(f)

    def _write_file(self, data) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("w", encoding="utf-8") as f:
            if self.parse == "text":
                f.write(data)
            else:
                json.dump(data, f)

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

        headers = self._headers() if callable(self._headers) else self._headers

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with http_pool.clearnet_session() as session:
                async with session.get(self.url, timeout=timeout, headers=headers) as resp:
                    if resp.status != 200:
                        logger.warning("CachedFeed: HTTP %s for %s", resp.status, self.url)
                        stale = self._stale_cache()
                        if stale is not None and cache_key in _memory_cache:
                            return stale
                        return stale
                    data = await resp.text() if self.parse == "text" else await resp.json(content_type=None)
                    self._write_file(data)
                    _memory_cache[cache_key] = (data, now)
                    return data
        except Exception as e:
            logger.warning("CachedFeed: fetch failed for %s: %s", self.url, e)
            if cache_key in _memory_cache:
                cached_data, timestamp = _memory_cache[cache_key]
                logger.warning("CachedFeed: returning stale memory cache for %s", self.url)
                return cached_data
            return self._stale_cache()

    def _stale_cache(self) -> Optional[dict | list | str]:
        if self.cache_path.exists():
            try:
                logger.warning("CachedFeed: falling back to stale cache %s", self.cache_path)
                return self._load_file()
            except Exception:
                pass
        return None
