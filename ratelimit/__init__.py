"""
ratelimit — a real, in-process rate limiter (P2.3).

Replaces the no-op global middleware and the fragile triple-``slowapi``-instance
wiring with one small, dependency-free limiter that:

* actually enforces — a burst past the limit is rejected (HTTP 429);
* works **per-process without Redis** (a single $0 box, no broker);
* is the single substrate every limit uses — the global per-IP cap, the
  per-route login/create limits now, and P4's per-API-key ingest limits (CC-1)
  later, all via one ``allow(key, limit, window)`` call.

Algorithm: fixed-window counters keyed by an arbitrary string. Simple, O(1),
and "burst → 429" is exact at the window boundary. Thread-safe. Buckets are
pruned opportunistically so memory stays bounded on a long-lived process.

Rate-limit *windows* are server-side policy quotas (e.g. 5 logins/min), not
politeness toward an external target, so they are fixed config values and
deliberately not scaled through ``pacing`` (which governs outbound patience).
"""

from ratelimit.limiter import (
    RateLimiter,
    allow,
    client_key,
    default_limiter,
    is_rate_limiting_disabled,
    reset,
)

__all__ = [
    "RateLimiter",
    "allow",
    "client_key",
    "default_limiter",
    "is_rate_limiting_disabled",
    "reset",
]
