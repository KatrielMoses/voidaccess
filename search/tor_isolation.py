"""
search/tor_isolation.py — the search fan-out's Tor stream-isolation policy.

Exists so search's isolation decision has one named, documented home instead of
being implied by whichever key function a call site happened to reach for.  The
mechanism (the pooled sessions, the cap, the in-flight-safe eviction) lives in
`scraper/tor_pool.py`; only the *policy* is here.

THE ISOLATION UNIT IS THE ENGINE'S HOSTNAME
-------------------------------------------
The fan-out queries N engines once each, concurrently.  Per-engine-hostname is
the right granularity because a single engine sees, and can trivially correlate,
everything we send it anyway:

  * the retries inside `_fetch_engine` are the same query to the same engine;
  * the diversified re-queries (`_search_async` recursing over alternative
    phrasings against the top 3 engines) are additional queries to an engine
    that already saw the first one.

So all of an engine's traffic within one investigation belongs on one circuit —
building a fresh circuit per attempt would buy nothing and cost a circuit
build.  Different engines, though, must not share: before this module existed
the whole fan-out ran on one credential-less session, which put every engine
on a single circuit and let any one engine operator observe the timing pattern
of our queries to all the others.

CLEARNET ENGINES GET NO CREDENTIAL — AND STAY ON TOR
----------------------------------------------------
One catalog engine is clearnet (`ahmia.fi`).  It is deliberately **still routed
through Tor** — that is what hides the investigator's IP from the service, and it
is what CLAUDE.md's Tor-safety rule requires.  Sending it direct would leak the
operator's real address to a service that currently only ever sees a Tor exit,
so that is not done.

What they do *not* get is an isolation credential: they fall into the pool's
shared un-isolated bucket, byte-for-byte the SOCKS5 no-auth behaviour they have
today.  Isolation is an anonymity property of the .onion path; a clearnet
service is identified by its own DNS name regardless of which circuit carries
it, so a per-host credential would churn circuits for no gain.

WHY THIS DELEGATES RATHER THAN REIMPLEMENTS
-------------------------------------------
Given the two rules above, this key is currently *the same* mapping as
`tor_pool.tor_isolation_key` — onion hostname, or the shared bucket.  It is a
separate named function anyway because:

  * `tor_isolation_key`'s onion-only behaviour is pinned by
    tests/test_scrape_isolation.py::test_clearnet_is_not_isolated and must not
    be edited to serve search;
  * if the clearnet decision is ever revisited (isolating clearnet engines from
    each other would be a one-line change *here*), this is the single place that
    changes, and the pinned scraper contract is untouched.

It delegates instead of copying the parsing so the two can never disagree about
what counts as an onion hostname.
"""

from __future__ import annotations

from typing import Optional, Tuple

import aiohttp

from scraper import tor_pool


def search_engine_isolation_key(url: str) -> str:
    """
    Return the circuit-isolation unit for a search engine URL.

    `.onion` engines isolate on their hostname; clearnet engines return the
    shared un-isolated bucket.  See this module's docstring for why.
    """
    return tor_pool.tor_isolation_key(url)


def acquire_engine_session(url: str) -> Tuple[aiohttp.ClientSession, str]:
    """
    Get the pooled session for a search engine URL and mark it in flight.

    Must be paired with `release_engine_session` in a `finally`, or the entry is
    pinned against eviction for the life of the process.
    """
    return tor_pool.acquire_tor_session(
        url, key=search_engine_isolation_key(url)
    )


def release_engine_session(key: Optional[str]) -> None:
    """Release an in-flight hold taken by `acquire_engine_session`."""
    if key is not None:
        tor_pool.release_tor_session(key)
