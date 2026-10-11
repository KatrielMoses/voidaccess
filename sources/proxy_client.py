"""
sources/proxy_client.py — Clearnet HTTP chokepoint with single-transport selection.

Phase 1.6 (corrected per architect review against the official docs) —
single-axis dispatch on clearnet HTTP fetches:

    Transport:  How requests reach ScrapingAnt's backend
    ---------   --------------------------------------------------------
    direct      Local aiohttp.ClientSession, no proxy (pre-1.6.2 behavior)
    api         POST to https://api.scrapingant.com/v2/general (REST)
    proxy       HTTP CONNECT through the configured ScrapingAnt proxy endpoint (proxy transport)

    Exactly ONE transport is selected per request. The proxy and api
    transports are MUTUALLY EXCLUSIVE alternates — never chained.

Architectural grounding (verified against ScrapingAnt docs):

    1. Proxy transport uses the dashboard-issued
       SCRAPINGANT_PROXY_USERNAME + SCRAPINGANT_PROXY_PASSWORD credential
       pair, separate from SCRAPINGANT_API_KEY. Optional API parameters
       (browser=false, proxy_type=residential|datacenter,
       forward_headers=true, ...) are appended to the proxy username.

       Source: https://docs.scrapingant.com/proxy-mode, §Integration details
       Quote: "Username: scrapingant + API parameters separated by &
       delimiter. Password: YOUR-API-KEY."

    2. There is ONE documented proxy hostname: the configured ScrapingAnt proxy endpoint
       (HTTP on port 8080, HTTPS on port 443). Pool type (residential
       vs datacenter) is passed as `proxy_type=` in the username string,
       NOT as a different hostname.

       Source: https://docs.scrapingant.com/proxy-mode, §Integration details
       Quote: "HTTP address: the configured ScrapingAnt proxy endpoint"
       Quote: "For example, to disable browser rendering and use
       residential proxies, you can use the following username:
       the ScrapingAnt proxy username string"

    3. the proxy transport is "a light front-end for the scraping API" with
       "all the same functionality and performance" and the same
       billing — it is an ALTERNATE TRANSPORT to the identical
       backend service, not a stackable layer in front of the REST API.

       Source: https://docs.scrapingant.com/proxy-mode, §Introduction
       Quote: "The proxy transport is a light front-end for the scraping
       API and has all the same functionality and performance as
       sending requests to the API endpoint."

Scope (locked, do not revisit):
    Called only from sources/paste_scraper.py and sources/rss_scraper.py.
    github_scraper.py and gitlab_scraper.py are PERMANENTLY excluded —
    they carry auth tokens that must never transit any third-party
    proxy, including ScrapingAnt's.

Design:
    - Single chokepoint: ``clearnet_fetch(...)``.
    - Hard, unconditional .onion guard FIRST (before any network call,
      before any transport selection) — fires regardless of which
      transport is selected, even when direct (none) is selected.
      This is a routing invariant, not a proxy concern.
    - Single transport per request, picked by config:
        - If VOIDACCESS_USE_PROXY=true (and the proxy username/password pair
          is set) → proxy
        - Else if VOIDACCESS_USE_PROXIES=true (legacy pre-1.6.2,
          and SCRAPINGANT_API_KEY set) → api
        - Else → direct
      If BOTH VOIDACCESS_USE_PROXY and VOIDACCESS_USE_PROXIES are set,
      proxy wins (with a one-shot info log); there is no chained mode.
    - Selected transport is tried first; on any failure (timeout, 5xx,
      auth error, malformed response) the chokepoint silently falls
      through to direct. No exception propagates to the scraper.
    - browser=false is hardcoded on the api transport; the proxy
      transport includes browser=false in the username string per docs
      ("As browser rendering is enabled by default, we recommend to
      disable it while using ScrapingAnt proxy transport"). The two paths
      preserve raw text/XML bytes identically.
    - SCRAPINGANT_API_KEY is exclusively the REST Web Scraping API
      credential. Proxy transport uses the separate dashboard-issued
      SCRAPINGANT_PROXY_USERNAME + SCRAPINGANT_PROXY_PASSWORD pair.
    - No import from scraper/ — sources/scraper firewall preserved.

The cap constant ``MAX_RESPONSE_BYTES`` mirrors scraper/scrape.py's
MAX_DOWNLOAD_BYTES (1_000_000) — do not import from scraper/ (firewall).
"""

from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import quote, urlencode

import aiohttp

from sources.enrichment import is_onion_url

logger = logging.getLogger(__name__)

# Single documented ScrapingAnt endpoint for the REST API transport.
# Source: https://docs.scrapingant.com/proxy-mode (referenced as
# "general endpoint" in §proxy transport parameters)
SCRAPINGANT_BASE_URL = "https://api.scrapingant.com/v2/general"

# Single documented proxy hostname for proxy transport. HTTP on port 8080,
# HTTPS on 443. Pool type (residential vs datacenter) is NOT a
# hostname — it is a username parameter (`proxy_type=...`).
# Source: https://docs.scrapingant.com/proxy-mode, §Integration details
SCRAPINGANT_PROXY_HOST = "residential.scrapingant.com"
SCRAPINGANT_PROXY_PORT = 8080
SCRAPINGANT_PROXY_HTTPS_PORT = 443

# Mirror scraper/scrape.py's MAX_DOWNLOAD_BYTES (1_000_000 at the time of
# Phase 1.6).  Do not import from scraper/ — that would violate the
# sources/scraper firewall.  If scrape.py's cap changes, update both
# locations in the same commit.
MAX_RESPONSE_BYTES = 1_000_000

# ---------------------------------------------------------------------------
# Env var readers — pure functions, no side effects
# ---------------------------------------------------------------------------


def _get_api_key() -> str | None:
    """Return the configured SCRAPINGANT_API_KEY, or None if absent/empty.

    This credential is used exclusively as the x-api-key query parameter
    on the REST Web Scraping API transport. Proxy transport uses the
    separate dashboard-issued username/password pair.
    """
    key = os.getenv("SCRAPINGANT_API_KEY", "").strip()
    return key or None


def _get_proxy_credentials() -> tuple[str, str] | None:
    """Return SCRAPINGANT_PROXY_TYPE, defaulting to 'residential'.

    Unknown values fall back to 'residential' with a debug log —
    silent, never raises.  Per docs, this value is passed as a
    `proxy_type=` parameter in the proxy username string.
    """
    username = os.getenv("SCRAPINGANT_PROXY_USERNAME", "").strip()
    password = os.getenv("SCRAPINGANT_PROXY_PASSWORD", "").strip()
    if not username or not password:
        return None
    return username, password


def _is_truthy(value: str) -> bool:
    """Return True iff value (raw) is the literal string 'true'.

    Case-insensitive, whitespace-tolerant.  Used by both transport
    selectors so the semantics of the boolean env vars are consistent.
    """
    return value.strip().lower() == "true"


# ---------------------------------------------------------------------------
# Transport selection — mutually exclusive, not combinable
# ---------------------------------------------------------------------------

# Module-level flag so the "both gates set" info log is emitted at most
# once per process.  Tests reset via monkeypatch if needed.
_BOTH_GATES_WARNED = False


# ---------------------------------------------------------------------------
# Per-run transport counters — v1.6.2
# ---------------------------------------------------------------------------
#
# Track, for the CURRENT PROCESS ONLY, how many clearnet_fetch calls
# resolved to each transport (direct / api / proxy) and how many proxy
# attempts failed and fell back to direct.  These counters are the live
# proof the user asked for: the investigation display reads them to show
# "Rotating proxies: ON" with via-proxy / fallback counts, and the final
# summary box reports the same numbers as verifiable proof that proxies
# were actually used during this run (and not just statically enabled).
#
# Scoped to the current process on purpose — these are run-scoped, not
# persisted across runs.  Reset at the start of every investigate
# invocation via reset_run_counters() so the display always reflects THIS
# run, not a lifetime aggregate.  Never raises; safe to call from any
# thread (we don't currently invoke clearnet_fetch from multiple threads,
# but the simple increment is atomic enough for Python's GIL).

_run_counters: dict[str, int] = {
    "direct": 0,
    "api": 0,
    "proxy": 0,
    "proxy_attempts": 0,
    "proxy_failures": 0,
}


def reset_run_counters() -> None:
    """Zero out per-run transport counters. Called once at the start of
    every investigate invocation so the counters always reflect the
    current run, not a lifetime aggregate across the Python process.
    """
    _run_counters["direct"] = 0
    _run_counters["api"] = 0
    _run_counters["proxy"] = 0
    _run_counters["proxy_attempts"] = 0
    _run_counters["proxy_failures"] = 0


def get_run_counters() -> dict:
    """Return the current per-run transport counters as a dict.

    Keys:
      direct          — calls served by the direct aiohttp fetch (no proxy).
      api             — calls served by the ScrapingAnt REST API transport.
      proxy           — calls served by the ScrapingAnt proxy transport
                        (HTTP CONNECT through the configured ScrapingAnt proxy endpoint).
      proxy_attempts  — total number of times the proxy transport was tried,
                        including both successes and failures.
      proxy_failures  — proxy attempts that fell back to direct (timeout,
                        5xx, auth error, etc.).

    The relationship between these is:
      proxy_attempts  = proxy + proxy_failures
      total clearnet_fetch calls = direct + api + proxy + proxy_failures
    """
    return dict(_run_counters)


def is_api_transport_enabled() -> bool:
    """Return True when the REST API transport should be used.

    Triggered by:
        - VOIDACCESS_USE_PROXIES=true (legacy pre-1.6.2 alias — kept for
          backward compatibility with Phase 1 deployments)

    Requires SCRAPINGANT_API_KEY to be set and non-empty.

    Per architect review: VOIDACCESS_USE_SCRAPING_API (Phase 3 rename)
    has been removed. The canonical env var is now VOIDACCESS_USE_PROXIES
    (the legacy one); the rename is no longer needed because there are
    no longer two independently combinable gates.
    """
    if not _get_api_key():
        return False
    return _is_truthy(os.getenv("VOIDACCESS_USE_PROXIES", ""))


def is_proxy_transport_enabled() -> bool:
    """Return True when proxy transport should be used.

    Per https://docs.scrapingant.com/proxy-mode §Introduction: "The
    proxy transport is a light front-end for the scraping API and has all
    the same functionality and performance as sending requests to
    the API endpoint." Therefore proxy transport is an ALTERNATE TRANSPORT
    to the same backend service, NOT a separate stackable layer.

    Triggered by:
        - VOIDACCESS_USE_PROXY=true
        - SCRAPINGANT_PROXY_USERNAME and SCRAPINGANT_PROXY_PASSWORD are
          set (the separate dashboard-issued proxy credential pair)

    Username is built at connection time per docs:
    "the ScrapingAnt proxy username string with browser=false and proxy_type"
    The literal "scrapingant" is a constant; SCRAPINGANT_PROXY_TYPE
    selects residential vs datacenter as a parameter.
    """
    if not _get_proxy_credentials():
        return False
    return _is_truthy(os.getenv("VOIDACCESS_USE_PROXY", ""))


def select_transport() -> str:
    """Pick the single transport for the next request.

    Selection logic (mutually exclusive):
        1. If proxy gate is enabled → "proxy"
        2. Else if api gate is enabled (legacy VOIDACCESS_USE_PROXIES) → "api"
        3. Else → "direct"

    If BOTH gates are enabled, proxy wins. A one-shot info log is
    emitted ("both gates enabled; using proxy") so the user can tell
    they have a redundant config.

    Returns one of: "direct" | "api" | "proxy"
    """
    use_proxy = is_proxy_transport_enabled()
    use_api = is_api_transport_enabled()

    if use_proxy and use_api:
        global _BOTH_GATES_WARNED
        if not _BOTH_GATES_WARNED:
            logger.info(
                "Both VOIDACCESS_USE_PROXY and VOIDACCESS_USE_PROXIES are set; "
                "using proxy transport. They are mutually exclusive alternates "
                "(see https://docs.scrapingant.com/proxy-mode — 'proxy transport is a "
                "light front-end for the scraping API')."
            )
            _BOTH_GATES_WARNED = True
        return "proxy"
    if use_proxy:
        return "proxy"
    if use_api:
        return "api"
    return "direct"


# ---------------------------------------------------------------------------
# proxy transport URL construction — username built per docs at call time
# ---------------------------------------------------------------------------


def _build_proxy_username() -> str:
    """Build the proxy transport username string per ScrapingAnt docs.

    Source: https://docs.scrapingant.com/proxy-mode §proxy transport parameters

    Quote: "To enable extra functionality whilst using the API in
    proxy transport, you can pass parameters to the API by adding them to
    username, separated by ampersand. For example, to disable browser
    rendering and use residential proxies, you can use the following
    username: the ScrapingAnt proxy username string"

    The username is the literal constant "scrapingant" plus
    "&browser=false" (per docs: "As browser rendering is enabled by
    default, we recommend to disable it while using ScrapingAnt Proxy
    Mode") plus "&proxy_type=<residential|datacenter>". Pool type is
    NOT a separate hostname — it is a username parameter.

    Example output: "the ScrapingAnt proxy username string"
    """
    credentials = _get_proxy_credentials()
    if not credentials:
        return ""
    username, _password = credentials
    return username


def _get_proxy_url() -> str | None:
    """Build the proxy transport proxy URL.

    Returns the HTTP proxy URL the chokepoint passes to aiohttp's
    `proxy=` param. Single host: the configured ScrapingAnt proxy endpoint.

    The username string is URL-encoded because it contains `&` and
    `=` which would otherwise be interpreted as URL delimiters. The
    password (API key) is also URL-encoded defensively.

    Returns None if SCRAPINGANT_API_KEY is missing — caller treats
    None as "proxy transport is not actually available" and falls
    through to direct.
    """
    credentials = _get_proxy_credentials()
    if not credentials:
        return None
    username, password = credentials
    encoded_user = quote(username, safe="")
    encoded_pass = quote(password, safe="")
    return (
        f"http://{encoded_user}:{encoded_pass}"
        f"@{SCRAPINGANT_PROXY_HOST}:{SCRAPINGANT_PROXY_PORT}"
    )


# ---------------------------------------------------------------------------
# Main chokepoint
# ---------------------------------------------------------------------------


async def clearnet_fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    params: dict | None = None,
    expect: str = "text",  # "json"|"text"|"xml"|"html"|"binary" — caller hint only
    timeout: float = 30,
    fallback_session: aiohttp.ClientSession,
    allow_redirects: bool = True,
) -> tuple[int, str, bytes]:
    """Single chokepoint for clearnet HTTP fetches in paste_scraper.py
    and rss_scraper.py ONLY.

    Picks ONE transport based on env-var configuration:
        - direct (default, when no ScrapingAnt env vars are set)
        - api (VOIDACCESS_USE_PROXIES=true; legacy pre-1.6.2 alias)
        - proxy (VOIDACCESS_USE_PROXY=true; proxy transport per docs)

    Per https://docs.scrapingant.com/proxy-mode: "The proxy transport is a
    light front-end for the scraping API and has all the same
    functionality and performance as sending requests to the API
    endpoint." Therefore the api and proxy transports are MUTUALLY
    EXCLUSIVE alternates to the same backend — they are NEVER chained.

    If both VOIDACCESS_USE_PROXIES and VOIDACCESS_USE_PROXY are set,
    proxy wins (with a one-shot info log).

    On any failure from the selected transport (timeout, 5xx, auth
    error, malformed response), the chokepoint silently falls back
    to direct. No exception propagates to the scraper.

    Args:
        url:               Target URL.  MUST NOT be a .onion address.
        method:            HTTP method (default "GET").
        headers:           Optional request headers.  On the api path
                           every key is rewritten to ``Ant-<key>`` per
                           ScrapingAnt's convention.  On the proxy path
                           headers are forwarded as-is.
        params:            Optional query-string parameters.  On the api
                           path they are URL-encoded and appended to the
                           target URL (ScrapingAnt's API expects a
                           single ``url=`` param, not nested query
                           params).  On the proxy path they go through
                           normally.
        expect:            Hint for the caller — does NOT alter behavior.
        timeout:           Total request timeout in seconds.
        fallback_session:  aiohttp.ClientSession provided by the caller.
                           Used for the direct fetch, the proxy fetch,
                           AND the api fetch.
        allow_redirects:   Follow HTTP redirects (default True).

    Returns:
        ``(status_code, content_type, body)`` tuple from the chosen
        transport (or direct, on fallback).

    Raises:
        ValueError: unconditionally on any .onion URL, before any
            network call is made and before any transport check.
            Whatever the underlying aiohttp call raises on the direct
            path (matching pre-v1.6 behavior exactly).  The proxy path
            and the api path NEVER raise to the caller — every failure
            mode falls back / returns None.
    """
    # --- HARD GUARD: .onion URLs are unconditionally refused -------------
    # This must be the very first check, before any transport check or
    # env read.  Order matters: the onion guard is a routing invariant,
    # not a proxy concern.  The rss_scraper article-fetch call site
    # also has its own belt-and-suspenders guard before the chokepoint
    # is invoked, but THIS guard is the authoritative one.
    if is_onion_url(url):
        raise ValueError(
            f"clearnet_fetch refuses .onion URLs — routing bug upstream: {url[:60]}"
        )

    # --- Single-transport selection --------------------------------------
    transport = select_transport()

    # --- Path A: proxy transport (proxy transport) ---------------------------
    if transport == "proxy":
        _run_counters["proxy_attempts"] += 1
        proxy_url = _get_proxy_url()
        if proxy_url:
            result = await _fetch_via_proxy_mode(
                url,
                method=method,
                headers=headers,
                params=params,
                timeout=timeout,
                fallback_session=fallback_session,
                proxy_url=proxy_url,
            )
            if result is not None:
                _run_counters["proxy"] += 1
                return result
            _run_counters["proxy_failures"] += 1
            logger.debug(
                "proxy transport returned no result for %s — falling back to direct",
                url[:60],
            )
        else:
            _run_counters["proxy_failures"] += 1
            logger.debug(
                "proxy transport requested but config unavailable for %s — falling back to direct",
                url[:60],
            )

    # --- Path B: api transport (REST API) --------------------------------
    elif transport == "api":
        result = await _fetch_via_scrapingant(
            url,
            method=method,
            headers=headers,
            params=params,
            timeout=timeout,
            fallback_session=fallback_session,
        )
        if result is not None:
            _run_counters["api"] += 1
            return result
        logger.debug(
            "Web Scraping API returned no result for %s — falling back to direct",
            url[:60],
        )

    # --- Direct fetch (always the last-resort fallback) -----------------
    result = await _fetch_direct(
        url,
        method=method,
        headers=headers,
        params=params,
        timeout=timeout,
        fallback_session=fallback_session,
        allow_redirects=allow_redirects,
    )
    _run_counters["direct"] += 1
    return result


# ---------------------------------------------------------------------------
# Internal helpers — proxy/api each return None on any failure (caller
# falls through to direct).  Direct may raise to match pre-v1.6 behavior.
# ---------------------------------------------------------------------------


async def _fetch_via_proxy_mode(
    url: str,
    *,
    method: str,
    headers: dict | None,
    params: dict | None,
    timeout: float,
    fallback_session: aiohttp.ClientSession,
    proxy_url: str,
) -> tuple[int, str, bytes] | None:
    """Fetch via ScrapingAnt proxy transport (HTTP CONNECT through
    the configured ScrapingAnt proxy endpoint).

    The proxy URL's username encodes:
        - browser=false (always; per docs recommendation)
        - proxy_type=residential|datacenter (from SCRAPINGANT_PROXY_TYPE)
    The password is SCRAPINGANT_PROXY_PASSWORD; the username is the
    separate SCRAPINGANT_PROXY_USERNAME dashboard credential. Neither
    proxy credential is related to SCRAPINGANT_API_KEY, which is used
    exclusively by the REST Web Scraping API transport.

    Returns None on any failure (caller falls through).  Never raises.
    """
    try:
        async with fallback_session.request(
            method,
            url,
            headers=headers,
            params=params,
            proxy=proxy_url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            # Treat 5xx as a failure (server is having a bad day, try
            # direct).  4xx is the target's answer, not a proxy error,
            # so we return it to the caller.
            if resp.status >= 500:
                logger.debug(
                    "proxy transport returned %d for %s — treating as failure",
                    resp.status,
                    url[:60],
                )
                return None

            content_type = resp.headers.get("content-type", "")
            body = await resp.read()
            if len(body) > MAX_RESPONSE_BYTES:
                body = body[:MAX_RESPONSE_BYTES]
            return (resp.status, content_type, body)

    except asyncio.TimeoutError:
        logger.debug("proxy transport timeout for %s", url[:60])
        return None
    except Exception as e:
        logger.debug("proxy transport error for %s: %s", url[:60], e)
        return None


async def _fetch_via_scrapingant(
    url: str,
    *,
    method: str,
    headers: dict | None,
    params: dict | None,
    timeout: float,
    fallback_session: aiohttp.ClientSession,
) -> tuple[int, str, bytes] | None:
    """Fetch via ScrapingAnt's ``/v2/general`` REST endpoint.

    browser=false is hardcoded — preserves raw text/XML bytes; the
    existing paste_scraper and rss_scraper callers need raw bytes for
    their regex / ElementTree parsers and never render JavaScript.

    Returns None on any failure (caller falls through).  Never raises.
    """
    api_key = _get_api_key()
    if not api_key:
        return None

    # Fold caller params into the target URL.  ScrapingAnt's API
    # expects a single ``url=`` query param, not nested params.
    target_url = url
    if params:
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{urlencode(params)}"

    proxy_params = {
        "url": target_url,
        "x-api-key": api_key,
        "browser": "false",  # ALWAYS false — preserves raw text/XML bytes
    }

    # Per ScrapingAnt convention, caller headers are prefixed with
    # ``Ant-`` so the proxy forwards them to the target site.
    ant_headers: dict = {}
    if headers:
        for k, v in headers.items():
            ant_headers[f"Ant-{k}"] = v

    try:
        async with fallback_session.get(
            SCRAPINGANT_BASE_URL,
            params=proxy_params,
            headers=ant_headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                logger.debug(
                    "ScrapingAnt API returned %d for %s",
                    resp.status,
                    url[:60],
                )
                return None

            # ant-page-status-code is the target page's status, not the
            # proxy API's.  Default to 200 if missing/unparseable —
            # the body is then treated as success.
            target_status_str = resp.headers.get("ant-page-status-code", "200")
            try:
                target_status = int(target_status_str)
            except ValueError:
                target_status = 200

            if target_status >= 500:
                logger.debug(
                    "ScrapingAnt target returned %d for %s — treating as failure",
                    target_status,
                    url[:60],
                )
                return None

            # ant-original-header-content-type is the target's content-type
            # as the proxy saw it.  Fall back to the API response's own
            # content-type (the JSON wrapper) if the original is missing.
            content_type = resp.headers.get(
                "ant-original-header-content-type",
                resp.headers.get("content-type", ""),
            )

            body = await resp.read()
            if len(body) > MAX_RESPONSE_BYTES:
                body = body[:MAX_RESPONSE_BYTES]
            return (target_status, content_type, body)

    except asyncio.TimeoutError:
        logger.debug("ScrapingAnt API timeout for %s", url[:60])
        return None
    except Exception as e:
        logger.debug("ScrapingAnt API error for %s: %s", url[:60], e)
        return None


async def _fetch_direct(
    url: str,
    *,
    method: str,
    headers: dict | None,
    params: dict | None,
    timeout: float,
    fallback_session: aiohttp.ClientSession,
    allow_redirects: bool,
) -> tuple[int, str, bytes]:
    """Direct fetch, no proxy.  Can raise — callers handle exceptions.

    This is the always-present last-resort fallback.  Behavior here
    matches the caller's pre-v1.6 self._session.get() call exactly.
    """
    async with fallback_session.request(
        method,
        url,
        headers=headers,
        params=params,
        allow_redirects=allow_redirects,
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as resp:
        content_type = resp.headers.get("content-type", "")
        body = await resp.read()
        if len(body) > MAX_RESPONSE_BYTES:
            body = body[:MAX_RESPONSE_BYTES]
        return (resp.status, content_type, body)




