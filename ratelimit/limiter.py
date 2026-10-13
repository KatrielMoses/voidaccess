"""
ratelimit/limiter.py — fixed-window in-process rate limiter.

``RateLimiter.allow(key, limit, window)`` returns False once *limit* calls have
been made for *key* within the current *window* seconds; the window then resets.
Thread-safe via a single lock (contention is trivial for an API front door).
Bucket entries are pruned when stale, and a hard cap bounds the dict so a flood
of distinct keys cannot exhaust memory.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

# Above this many live buckets, drop expired ones (and, if still over, the
# oldest) so a spray of unique keys can't grow the map without bound.
_MAX_BUCKETS = 50_000


class RateLimiter:
    def __init__(self) -> None:
        # key -> (window_start_epoch, count)
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(
        self, key: str, limit: int, window: float, *, now: Optional[float] = None
    ) -> bool:
        """Return True if a call for *key* is within *limit* per *window* seconds."""
        if limit <= 0:
            return False
        ts = time.monotonic() if now is None else now
        with self._lock:
            start, count = self._buckets.get(key, (ts, 0))
            if ts - start >= window:
                # New window.
                self._buckets[key] = (ts, 1)
                if len(self._buckets) > _MAX_BUCKETS:
                    self._prune(ts, window)
                return True
            if count >= limit:
                self._buckets[key] = (start, count)
                return False
            self._buckets[key] = (start, count + 1)
            return True

    def _prune(self, now: float, window: float) -> None:
        # Called under lock. Drop windows that have fully elapsed.
        stale = [k for k, (start, _) in self._buckets.items() if now - start >= window]
        for k in stale:
            self._buckets.pop(k, None)
        if len(self._buckets) > _MAX_BUCKETS:
            # Still over: drop the oldest windows.
            for k, _ in sorted(self._buckets.items(), key=lambda kv: kv[1][0])[
                : len(self._buckets) - _MAX_BUCKETS
            ]:
                self._buckets.pop(k, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# Process-wide default limiter — the single substrate all limits share.
_DEFAULT = RateLimiter()


def default_limiter() -> RateLimiter:
    return _DEFAULT


def is_rate_limiting_disabled() -> bool:
    """Honor the existing ``DISABLE_RATE_LIMIT`` env switch (read live)."""
    return (os.getenv("DISABLE_RATE_LIMIT", "false") or "false").strip().lower() == "true"


def allow(key: str, limit: int, window: float) -> bool:
    """Convenience: check the process-default limiter (bypassed when disabled)."""
    if is_rate_limiting_disabled():
        return True
    return _DEFAULT.allow(key, limit, window)


def client_key(request) -> str:
    """Select the right-most untrusted hop; forwarding is opt-in.

    A numeric setting trusts that many proxy hops including the socket peer.
    CIDRs trust only matching addresses, walking the chain from the peer.
    Invalid configuration or malformed headers falls back to the direct peer.
    """
    import ipaddress

    peer = getattr(getattr(request, "client", None), "host", None) or "unknown"
    trusted = (os.getenv("VOIDACCESS_TRUSTED_PROXIES", "0") or "0").strip()
    xff = request.headers.get("x-forwarded-for", "")
    if not xff or trusted == "0":
        return peer
    try:
        chain = [str(ipaddress.ip_address(h.strip())) for h in xff.split(",")]
        chain.append(str(ipaddress.ip_address(peer)))
        if trusted.isdecimal():
            count = int(trusted)
            # An incomplete chain cannot establish a client identity.
            return chain[-count - 1] if 0 < count < len(chain) else peer
        networks = [ipaddress.ip_network(c.strip()) for c in trusted.split(",")]
        while len(chain) > 1 and any(ipaddress.ip_address(chain[-1]) in n for n in networks):
            chain.pop()
        return chain[-1]
    except ValueError:
        return peer


def reset() -> None:
    """Clear the process-default limiter (test isolation)."""
    _DEFAULT.reset()
