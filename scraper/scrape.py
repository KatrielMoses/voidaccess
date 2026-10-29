"""
scrape.py — async .onion / clearnet page fetcher for VoidAccess.

Public API (unchanged from Phase 0 — ui.py compatibility guaranteed):
    scrape_multiple(urls_data, max_workers=5)  -> Dict[str, str]
    scrape_single(url_data, ...)               -> Tuple[str, str]
    get_tor_session()                          -> requests.Session

Internals rewritten in Phase 1B:
    ThreadPoolExecutor + requests  →  asyncio + aiohttp-socks
    BeautifulSoup-only extraction  →  trafilatura first, BeautifulSoup fallback
    hardcoded 127.0.0.1:9050      →  TOR_PROXY_HOST / TOR_PROXY_PORT from config
    no retry                      →  3-attempt exponential backoff (2 s / 4 s / 8 s)
    no DB persistence             →  pages written to Phase 1A db/ layer when DATABASE_URL is set

Retry/timeout values below are the `normal` pacing baseline.  The active
pacing profile (quiet / normal / aggressive) scales them at call time via the
`pacing` module — see pacing/README.md.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import random
import re
import time
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp
import requests
import trafilatura
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import pacing
import netpool
from progress import trace as _trace
from utils import cancel as _cancel
from config import TOR_PROXY_HOST, TOR_PROXY_PORT, PLAYWRIGHT_ENABLED
from scraper import tor_pool

warnings.filterwarnings("ignore")

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (identical to Phase 0 — ui.py depends on these)
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
]

MAX_DOWNLOAD_BYTES = 1_000_000
MAX_EXTRACTED_TEXT_CHARS = 50_000
MAX_RETURN_CHARS = 15_000
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

# A response without a Content-Type is accepted only when its first bytes
# look like text.
SNIFF_BYTES = 512
_BINARY_MAGIC = (
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"%PDF", b"PK\x03\x04",
    b"ID3", b"OggS", b"\x1aE\xdf\xa3", b"BM", b"II*\x00", b"MM\x00*",
    b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!",
)
_CONTROL_BYTES = bytes(b for b in range(32) if b not in (9, 10, 12, 13, 27)) + b"\x7f"


def sniffs_as_text(head: bytes) -> bool:
    """True when *head* (the first bytes of a body) looks like text: no NUL
    byte, no known binary signature, almost no control characters, and it
    decodes as UTF-8 or Latin-1. An empty body counts as text."""
    head = head[:SNIFF_BYTES]
    if not head:
        return True  # an empty body: nothing is stored either way
    if b"\x00" in head:
        return False
    if head.startswith(_BINARY_MAGIC) or head[4:8] == b"ftyp":
        return False
    # Anything that is not UTF-8 decodes as Latin-1, so the last test is the
    # share of control bytes.
    controls = len(head) - len(head.translate(None, _CONTROL_BYTES))
    return controls * 20 <= len(head)

# Retry configuration — the `normal` pacing baseline.
#
# These were MAX_RETRIES=1 / RETRY_DELAYS=(1.0,) up to v1.9.4, which
# contradicted this module's own docstring ("3-attempt exponential backoff
# (2 s / 4 s / 8 s)").  The backoff described there is what was designed and
# never implemented, so the code is corrected to match the documentation
# rather than the documentation downgraded to match the code.  crawler/
# spider.py — written against the same design — has always used exactly these
# values, which is the corroborating evidence for which side was the bug.
MAX_RETRIES = 3
RETRY_DELAYS = (2.0, 4.0, 8.0)  # seconds before retry 1, 2, 3
RETRYABLE_STATUS = {500, 502, 503, 504}

# Per-attempt outer timeout — `normal` baseline scaled by the active profile at
# call time. The cached direct-session connect/read timeouts now live with the
# shared clearnet pool that owns the session (`netpool`); see below.
PER_ATTEMPT_TIMEOUT = 10.0

# Pooled-Tor-session connect/read defaults now live with the pool that bakes
# them into the session (`scraper/tor_pool.py`); re-exported here because this
# module documented them as part of its surface.  A caller needing different
# patience overrides per request rather than changing these — see the timeout
# section of tor_pool's docstring.
TOR_CONNECT_TIMEOUT = tor_pool.TOR_CONNECT_TIMEOUT
TOR_READ_TIMEOUT = tor_pool.TOR_READ_TIMEOUT

# Tor circuit error patterns - indicates circuit failure, not URL failure
SOCKS_ERRORS = (
    "SOCKS5",
    "socks5",
    "Host unreachable",
    "Connection refused",
    "General SOCKS",
    "circuit",
    "Tor circuit",
)

# Internal / link-local ranges — block clearnet fetches (SSRF prevention)
_BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",
    }
)

# Common HTML timestamp patterns (forums / JSON-LD)
_TIMESTAMP_PATTERNS = [
    (r'<time[^>]+datetime="([^"]+)"', "iso"),
    (r"[Pp]osted[:\s]+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    (r"[Dd]ate[:\s]+(\d{2}/\d{2}/\d{4})", "%d/%m/%Y"),
    (r'data-timestamp="(\d{10})"', "unix10"),
    (
        r'"datePublished":\s*"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"',
        "%Y-%m-%dT%H:%M:%S",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def extract_post_timestamp(html: str) -> Optional[datetime]:
    """
    Attempt to extract the original post timestamp from raw HTML.

    Returns timezone-aware UTC datetime if found, None if not extractable.
    Never raises — all failures return None.
    """
    try:
        if not html:
            return None

        for pattern, fmt in _TIMESTAMP_PATTERNS:
            try:
                match = re.search(pattern, html)
                if not match:
                    continue
                value = match.group(1).strip()

                if fmt == "iso":
                    s = value.replace("Z", "+00:00")
                    if len(s) >= 19 and "T" not in s[:19]:
                        s = value
                    dt = datetime.fromisoformat(s[:32])
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    if datetime(2010, 1, 1, tzinfo=timezone.utc) <= dt <= datetime.now(
                        timezone.utc
                    ):
                        return dt
                    continue

                if fmt == "unix10":
                    ts = int(value)
                    if 1_000_000_000 < ts < 9_999_999_999:
                        return datetime.fromtimestamp(ts, tz=timezone.utc)
                    continue

                sample = value[:19] if len(value) >= 19 else value
                dt = datetime.strptime(sample, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                    if datetime(2010, 1, 1, tzinfo=timezone.utc) <= dt <= datetime.now(
                        timezone.utc
                    ):
                        return dt
            except (ValueError, OverflowError, OSError, TypeError):
                continue

        return None
    except Exception:
        return None


def is_safe_url(url: str) -> bool:
    """
    Return False if URL targets internal/reserved addresses (SSRF prevention).
    .onion hostnames are always allowed (Tor handles routing).
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip()
        if hostname.lower().endswith(".onion"):
            return True
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            _logger.warning("SSRF blocked hostname: %s", hostname)
            return False
        try:
            import socket
            resolved_ip_str = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip_str = None

        ips_to_check = [hostname]
        if resolved_ip_str and resolved_ip_str != hostname:
            ips_to_check.append(resolved_ip_str)

        for ip_str in ips_to_check:
            try:
                ip = ipaddress.ip_address(ip_str)
                for blocked_range in _BLOCKED_IP_RANGES:
                    if ip in blocked_range:
                        _logger.warning("SSRF blocked IP %s (from %s) in %s", ip_str, hostname, blocked_range)
                        return False
            except ValueError:
                pass
        return True
    except Exception:
        return False


def validate_urls_for_scraping(
    url_dicts: List[dict],
) -> Tuple[List[dict], List[str]]:
    """
    Filter URL dicts before scraping. Returns (safe_dicts, blocked_url_strings).
    """
    safe: List[dict] = []
    blocked: List[str] = []
    for url_dict in url_dicts:
        link = url_dict.get("link", url_dict) if isinstance(url_dict, dict) else str(url_dict)
        if is_safe_url(link):
            safe.append(url_dict)
        else:
            blocked.append(link)
    if blocked:
        _logger.warning(
            "SSRF prevention blocked %d URLs: %s",
            len(blocked),
            blocked[:5],
        )
    return safe, blocked

def _normalize_url_data(url_data) -> Tuple[str, str]:
    """Extract (url, title) from a search result dict."""
    if not isinstance(url_data, dict):
        return "", "Untitled"
    url = str(url_data.get("link") or "").strip()
    title = str(url_data.get("title") or "Untitled").strip() or "Untitled"
    return url, title


def is_onion_url(url: str) -> bool:
    """Return True if URL is a .onion address requiring Tor."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname.lower().endswith(".onion")
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent storage/dedup.
    Uses crawler.utils.normalize_url for consistency.
    """
    try:
        from crawler.utils import normalize_url as _norm
        return _norm(url)
    except ImportError:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") if parsed.path else ""
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def classify_urls(urls: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Split URLs into onion (needs Tor) and clearnet (direct fetch).

    Malformed URLs are treated as clearnet.
    """
    onion_urls: List[dict] = []
    clearnet_urls: List[dict] = []
    for url_dict in urls:
        link = url_dict.get("link", "") if isinstance(url_dict, dict) else str(url_dict)
        if is_onion_url(link):
            onion_urls.append(url_dict)
        else:
            clearnet_urls.append(url_dict)
    return onion_urls, clearnet_urls


def _is_onion(url: str) -> bool:
    """Return True if the URL targets a .onion hostname."""
    return is_onion_url(url)


def _build_proxy_url() -> str:
    """
    SOCKS URL for ``requests`` / urllib3 (PySocks understands ``socks5h`` =
    remote DNS at the proxy, required for ``.onion``).

    ``aiohttp_socks`` uses ``python_socks.parse_proxy_url``, which does *not*
    accept the ``socks5h`` scheme — use :func:`_tor_aiohttp_connector` instead.
    """
    return f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}"


# ---------------------------------------------------------------------------
# Tor stream isolation (SOCKS5 authentication)
# ---------------------------------------------------------------------------
#
# The mechanism moved to `scraper/tor_pool.py` so that every Tor-fetching call
# site in the codebase shares one pool and therefore one set of circuits — see
# that module's docstring for the full rationale (why the isolation unit is the
# hostname, how it reconciles with the v1.8.0 session-reuse fix, and why
# timeouts are a session-level default that callers override per request).
#
# What stays here is this module's historical surface.  `_tor_aiohttp_connector`
# and `TOR_ISOLATION_POOL_MAX` are re-exported as module globals *and* passed
# into the pool at call time, so `unittest.mock.patch.object(scrape, ...)` still
# intercepts them — tests/test_scrape_isolation.py patches both, and that file
# is the contract for the pooling logic.

TOR_ISOLATION_POOL_MAX = tor_pool.TOR_ISOLATION_POOL_MAX
_TOR_SHARED_KEY = tor_pool._TOR_SHARED_KEY

tor_isolation_key = tor_pool.tor_isolation_key
tor_socks_credentials = tor_pool.tor_socks_credentials

# The pool state itself is shared by object identity, not copied — mutating
# `scrape._tor_sessions` and `tor_pool._tor_sessions` are the same operation.
_tor_sessions = tor_pool._tor_sessions
_tor_inflight = tor_pool._tor_inflight
_pending_closes = tor_pool._pending_closes


def _tor_aiohttp_connector(
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> ProxyConnector:
    """SOCKS5-with-remote-DNS connector. See `tor_pool.tor_aiohttp_connector`."""
    return tor_pool.tor_aiohttp_connector(username, password)


def _evict_idle_tor_session() -> None:
    """Evict one idle pooled session. See `tor_pool.evict_idle_tor_session`."""
    tor_pool.evict_idle_tor_session(TOR_ISOLATION_POOL_MAX)


_close_session_soon = tor_pool._close_session_soon


def get_tor_session_cached(url: Optional[str] = None) -> aiohttp.ClientSession:
    """
    Return the cached Tor-proxied session for *url*'s isolation unit.

    Thin pass-through to the shared pool.  The connector factory and pool cap
    are resolved from *this* module's globals on every call so the two names
    tests/test_scrape_isolation.py patches remain the effective ones.
    """
    return tor_pool.get_tor_session_cached(
        url,
        connector_factory=_tor_aiohttp_connector,
        pool_max=TOR_ISOLATION_POOL_MAX,
    )


def _acquire_tor_session(url: str) -> Tuple[aiohttp.ClientSession, str]:
    """
    Resolve *url*'s session and mark it in flight.

    Acquisition is synchronous and happens at task-creation time, before the
    first await, so a session handed to a not-yet-started fetch can never be
    chosen as an eviction victim.  Every acquire must be paired with
    `_release_tor_session` in a `finally`.
    """
    return tor_pool.acquire_tor_session(
        url,
        connector_factory=_tor_aiohttp_connector,
        pool_max=TOR_ISOLATION_POOL_MAX,
    )


_release_tor_session = tor_pool.release_tor_session


def get_direct_session_cached() -> aiohttp.ClientSession:
    """Return the shared cached direct (clearnet) session for connection reuse.

    Delegates to the neutral ``netpool`` module, which owns the one clearnet
    session shared with ``sources/`` — see netpool/README.md for why the pool
    lives outside both ``scraper`` and ``sources``.
    """
    return netpool.get_clearnet_session()


async def close_cached_sessions() -> None:
    """Close every cached session (whole isolation pool + shared clearnet) - on shutdown."""
    await tor_pool.close_pool()
    await netpool.close_clearnet_pool()


_reset_tor_session_on_error = tor_pool.reset_tor_session_on_error


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------

def _extract_text(html: str) -> str:
    """
    Extract main textual content from an HTML string.

    trafilatura is tried first — it strips navbars, footers, ads, and scripts,
    leaving the body text.  If trafilatura returns nothing (or crashes), we fall
    back to the BeautifulSoup path used in Phase 0.

    Always truncates to MAX_EXTRACTED_TEXT_CHARS before returning.
    """
    try:
        text = trafilatura.extract(html, include_comments=False, include_tables=True)
        if text and text.strip():
            return text[:MAX_EXTRACTED_TEXT_CHARS]
    except Exception:
        pass  # lxml parse failure or trafilatura bug → fall through

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.extract()
    text = " ".join(soup.get_text(separator=" ").split())
    return text[:MAX_EXTRACTED_TEXT_CHARS]


def _score_content_quality(text: str) -> str:
    """
    Score scraped content quality for prioritization.

    Returns:
        "empty"  - < 100 chars (likely failed fetch)
        "thin"   - 100-500 chars (minimal content)
        "medium" - 500-2000 chars (decent content)
        "rich"   - > 2000 chars (full content)
    """
    length = len(text) if text else 0
    if length < 100:
        return "empty"
    if length < 500:
        return "thin"
    if length < 2000:
        return "medium"
    return "rich"


# ---------------------------------------------------------------------------
# Async core — fetch with retry
# ---------------------------------------------------------------------------

async def _fetch_one(
    session: aiohttp.ClientSession,
    url_data: dict,
    semaphore: asyncio.Semaphore,
    isolation_key: Optional[str] = None,
    extract_typed_relationships: bool = False,
) -> tuple:
    """
    Fetch one URL, releasing its Tor isolation slot however the fetch ends.

    *isolation_key* is the value returned alongside the session by
    `_acquire_tor_session`; pass `None` for sessions that were not acquired
    from the isolation pool (clearnet, and direct unit-test calls).  See
    `_fetch_one_impl` for the fetch semantics themselves.
    """
    try:
        result = await _fetch_one_impl(
            session,
            url_data,
            semaphore,
            extract_typed_relationships=extract_typed_relationships,
        ) if extract_typed_relationships else await _fetch_one_impl(
            session, url_data, semaphore
        )
        if extract_typed_relationships and len(result) == 5:
            return (*result, [])
        return result
    finally:
        if isolation_key is not None:
            _release_tor_session(isolation_key)


def _trace_fetch_failure(url: str, started: float, outcome: object) -> None:
    """``page.fetched`` for a fetch that ended without a page (trace only).

    *outcome* is what the fetch loop knew: an HTTP status code, ``"content_type"``,
    the ``"HTTP 503"`` string a retryable status leaves behind, or an exception.
    """
    if not _trace.active():
        return
    http_status: Optional[int] = None
    if isinstance(outcome, int):
        http_status = outcome
    elif isinstance(outcome, str) and outcome.startswith("HTTP "):
        try:
            http_status = int(outcome[5:])
        except ValueError:
            http_status = None
    if http_status is not None:
        if http_status == 404:
            label = "http_404"
        elif 400 <= http_status < 500:
            label = "http_4xx"
        elif http_status >= 500:
            label = "http_5xx"
        else:
            label = "error"
    elif outcome == "content_type":
        label = "empty"  # not a text page: nothing to extract
    elif outcome == "tor_error":
        label = "tor_error"
    elif isinstance(outcome, asyncio.TimeoutError):
        label = "timeout"
    elif is_onion_url(url):
        label = "tor_error"  # any transport failure over Tor
    else:
        label = "error"
    _trace.page_fetched(
        url, label, http_status=http_status, ms=int((time.monotonic() - started) * 1000)
    )


async def _fetch_one_impl(
    session: aiohttp.ClientSession,
    url_data: dict,
    semaphore: asyncio.Semaphore,
    extract_typed_relationships: bool = False,
) -> tuple:
    """
    Fetch a single URL with exponential-backoff retry.

    Returns:
        (url, display_text, raw_bytes, db_text, posted_at)
        - display_text: "{title} - {extracted_text}" — returned in the public dict
        - raw_bytes:    raw downloaded content (for SHA-256 hash + DB byte_size)
        - db_text:      extracted text only, no title prefix — stored in Page.cleaned_text
        - posted_at:    extracted from HTML when possible, else None

    On any unrecoverable failure returns (url, title, None, None, None).
    Failures never propagate as exceptions — graceful degradation is preserved.
    """
    url, title = _normalize_url_data(url_data)
    if not url:
        return "", title, None, None, None
    started = time.monotonic()

    if not is_safe_url(url):
        _logger.warning("SSRF blocked fetch: %s", url)
        _trace.url_dropped("fetch", url, "ssrf")
        return url, title, None, None, None

    from utils.content_safety import url_is_blocked

    if url_is_blocked(url):
        _trace.url_dropped("fetch", url, "safety")
        return url, title, None, None, None

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        _trace.url_dropped("fetch", url, "invalid")
        return url, title, None, None, None

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    }

    last_exc: object = None

    # Baseline is 3 retries / 2 s / 4 s / 8 s (attempts 0, 1, 2, 3); the active
    # pacing profile adjusts both the count and the backoff at call time.
    # Resolved per call, not per import, so a profile set after this module was
    # imported (the one-shot --pace flag) still takes effect.
    max_retries, retry_delays = pacing.retry_plan(MAX_RETRIES, RETRY_DELAYS)
    per_attempt_timeout = pacing.scale_timeout(PER_ATTEMPT_TIMEOUT)

    async with semaphore:
        for attempt in range(max_retries + 1):
            if _cancel.is_cancelled():
                # Cancel checkpoint between pages: queued fetches never start,
                # and a page that is mid-retry is not retried.
                return url, title, None, None, None
            if attempt > 0:
                await asyncio.sleep(retry_delays[attempt - 1])

            try:
                async def _get_with_timeout():
                    # The orchestrator passes a cached session for this URL's
                    # network (Tor or clearnet).  Reusing it is what preserves
                    # aiohttp's connector pool and, for Tor, the established
                    # SOCKS connection/circuit.  A fresh session is created
                    # only by the cache factory or an explicit error reset.
                    async with session.get(url, headers=headers) as resp:
                        if resp.status in RETRYABLE_STATUS:
                            return "retry", f"HTTP {resp.status}", None, None, None

                        if resp.status != 200:
                            return "fail", resp.status, None, None, None

                        content_type = (resp.headers.get("Content-Type") or "").lower()
                        if content_type and not any(
                            t in content_type for t in ALLOWED_CONTENT_TYPES
                        ):
                            return "fail", "content_type", None, None, None

                        chunks: List[bytes] = []
                        bytes_read = 0
                        async for chunk in resp.content.iter_chunked(8192):
                            if not chunk:
                                continue
                            bytes_read += len(chunk)
                            if bytes_read > MAX_DOWNLOAD_BYTES:
                                break
                            chunks.append(chunk)

                        raw_bytes = b"".join(chunks)
                        if not content_type and not sniffs_as_text(raw_bytes):
                            return "fail", "content_type", None, None, None
                        encoding = resp.charset or "utf-8"
                        return "ok", raw_bytes, encoding, None, None

                status_res, r_bytes, enc, _, _ = await asyncio.wait_for(
                    _get_with_timeout(), timeout=per_attempt_timeout
                )

                if status_res == "retry":
                    last_exc = r_bytes
                    continue
                elif status_res == "fail":
                    _trace_fetch_failure(url, started, r_bytes)
                    return url, title, None, None, None

                raw_bytes = r_bytes
                html = raw_bytes.decode(enc, errors="replace")

                db_text = _extract_text(html)
                posted_at = extract_post_timestamp(html)
                display_text = f"{title} - {db_text}" if db_text else title

                # --- Playwright fallback for JS-rendered pages ---
                # Onion pages are more likely to be JS-rendered (Tor Browser default)
                # and more likely to have slow initial loads, so use a lower threshold.
                _pw_threshold = 500 if is_onion_url(url) else 300
                if PLAYWRIGHT_ENABLED and db_text and len(db_text) < _pw_threshold:
                    # Import lazily to avoid import errors when playwright not installed
                    try:
                        from scraper.scrape_js import fetch_with_playwright, is_js_rendered

                        if is_js_rendered(html, db_text):
                            # This fallback is isolated differently from every
                            # other path here, and it has to be: Playwright's
                            # driver rejects SOCKS5 credentials outright, so
                            # tor_socks_credentials() can never reach Chromium.
                            # scrape_js instead points the browser at a Tor
                            # SocksPort carrying `IsolateDestAddr`, which makes
                            # Tor key circuits on the destination itself. When
                            # that port is absent (system tor, Tor Browser) the
                            # JS path is genuinely un-isolated and says so once
                            # at launch — see scrape_js._resolve_socks_port.
                            _logger.debug(
                                "Playwright fallback triggered for %s...",
                                url[:40] if len(url) > 40 else url,
                            )
                            js_result = await fetch_with_playwright(
                                url=url,
                                tor_proxy_host=TOR_PROXY_HOST,
                                tor_proxy_port=TOR_PROXY_PORT,
                            )
                            # Use JS result if it got more content
                            if js_result.get("content") and len(js_result.get("content", "")) > len(
                                db_text
                            ):
                                html = js_result.get("raw_html", html)
                                db_text = js_result.get("content", "")
                                posted_at = js_result.get("posted_at", posted_at)
                                display_text = f"{title} - {db_text}" if db_text else title
                                _logger.info(
                                    "Playwright improved content: %d chars from %s...",
                                    len(db_text),
                                    url[:40] if len(url) > 40 else url,
                                )
                    except ImportError:
                        # Playwright not installed - skip silently
                        pass
                    except Exception as e:
                        # Keep original aiohttp result if Playwright fails
                        _logger.debug("Playwright fallback failed: %s", e)
                        pass

                # HIGH-3: warn when a page fetched but yielded no extractable text —
                # helps distinguish "fetch failed / timed out" from "genuinely empty".
                # Onion pages are exempt because many Tor sites serve minimal content.
                if not db_text and not is_onion_url(url):
                    _logger.warning(
                        "Page fetched but no text extracted: %s",
                        url[:80] if len(url) > 80 else url,
                    )

                dependency_relationships = []
                if extract_typed_relationships and db_text:
                    try:
                        from extractor.dependency_relationship import (
                            extract_dependency_relationships_from_page,
                        )
                        dependency_relationships = extract_dependency_relationships_from_page(
                            db_text
                        )
                        _logger.info(
                            "Dependency extractor invoked at scrape.py:861 for %s: %d chars, %d claims",
                            url[:80],
                            len(db_text),
                            len(dependency_relationships),
                        )
                    except Exception as exc:
                        # Relationship extraction is additive and optional;
                        # never turn a successful page fetch into a failure.
                        _logger.debug(
                            "No dependency relationships extracted for %s: %s",
                            url[:60],
                            exc,
                        )

                _trace.note_fetch(
                    url,
                    http_status=200,
                    nbytes=len(raw_bytes),
                    ms=int((time.monotonic() - started) * 1000),
                )
                if extract_typed_relationships:
                    return (
                        url,
                        display_text,
                        raw_bytes,
                        db_text,
                        posted_at,
                        dependency_relationships,
                    )
                return url, display_text, raw_bytes, db_text, posted_at

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                error_str = str(exc)
                if any(err.lower() in error_str.lower() for err in SOCKS_ERRORS):
                    _logger.warning(
                        "Tor circuit error for %s: %s",
                        url[:50] if len(url) > 50 else url,
                        error_str[:100],
                    )
                    await _reset_tor_session_on_error(url)
                    _trace_fetch_failure(url, started, "tor_error")
                    return url, title, None, None, None
                last_exc = exc
            except Exception as exc:
                error_str = str(exc)
                if any(err.lower() in error_str.lower() for err in SOCKS_ERRORS):
                    _logger.warning(
                        "Tor circuit error for %s: %s",
                        url[:50] if len(url) > 50 else url,
                        error_str[:100],
                    )
                    await _reset_tor_session_on_error(url)
                    _trace_fetch_failure(url, started, "tor_error")
                    return url, title, None, None, None
                last_exc = exc

        # All retries exhausted
        _logger.debug("All retries exhausted for url=%s: %s", url, last_exc)
        _trace_fetch_failure(url, started, last_exc)
        return url, title, None, None, None


# ---------------------------------------------------------------------------
# Async orchestrator
# ---------------------------------------------------------------------------

async def _gather_all(
    unique_urls_data: List[dict],
    max_workers: int,
    extract_typed_relationships: bool = False,
) -> List[tuple]:
    """
    Fan out fetches: .onion URLs through Tor (separate concurrency limit),
    clearnet URLs directly (higher concurrency). Results preserve input order.
    """
    onion_urls, clearnet_urls = classify_urls(unique_urls_data)
    _logger.warning(
        "Scraping %d onion URLs (via Tor) + %d clearnet URLs (direct)",
        len(onion_urls),
        len(clearnet_urls),
    )

    sem_tor = asyncio.Semaphore(max_workers)
    sem_clearnet = asyncio.Semaphore(15)

    async def run_onion_batch() -> dict[str, tuple]:
        if not onion_urls:
            return {}
        out: dict[str, tuple] = {}
        # One session per distinct .onion hostname, not one per batch and not
        # one per fetch — see the stream-isolation block near the top of this
        # module for why that specific granularity.  Acquisition is synchronous
        # and completes for the whole batch before the first await, so no
        # session handed out here can be evicted while its fetch is pending.
        tasks = []
        for item in onion_urls:
            item_url, _ = _normalize_url_data(item)
            tor_session, iso_key = _acquire_tor_session(item_url)
            tasks.append(
                _fetch_one(
                    tor_session,
                    item,
                    sem_tor,
                    iso_key,
                    extract_typed_relationships,
                )
            )
        _logger.info(
            "Tor stream isolation: %d onion URLs across %d distinct circuits",
            len(onion_urls),
            len({tor_isolation_key(_normalize_url_data(i)[0]) for i in onion_urls}),
        )
        rows = await asyncio.gather(*tasks)
        for row in rows:
            if row[0]:
                out[row[0]] = row
        return out

    async def run_clearnet_batch() -> dict[str, tuple]:
        if not clearnet_urls:
            return {}
        out: dict[str, tuple] = {}
        direct_session = get_direct_session_cached()
        tasks = [
            _fetch_one(
                direct_session,
                item,
                sem_clearnet,
                extract_typed_relationships=extract_typed_relationships,
            )
            for item in clearnet_urls
        ]
        rows = await asyncio.gather(*tasks)
        for row in rows:
            if row[0]:
                out[row[0]] = row
        return out

    tor_map, clearnet_map = await asyncio.gather(
        run_onion_batch(),
        run_clearnet_batch(),
    )

    merged: List[tuple] = []
    for item in unique_urls_data:
        url, _title = _normalize_url_data(item)
        if not url:
            merged.append(
                ("", _title, None, None, None, [])
                if extract_typed_relationships
                else ("", _title, None, None, None)
            )
            continue
        empty_row = (
            (url, _title, None, None, None, [])
            if extract_typed_relationships
            else (url, _title, None, None, None)
        )
        if is_onion_url(url):
            merged.append(tor_map.get(url, empty_row))
        else:
            merged.append(clearnet_map.get(url, empty_row))

    tor_ok = sum(1 for r in merged if r[0] and is_onion_url(r[0]) and r[2])
    clear_ok = sum(
        1 for r in merged if r[0] and not is_onion_url(r[0]) and r[2]
    )
    _logger.warning(
        "Total scraped: %d pages (%d onion, %d clearnet) with stored content",
        tor_ok + clear_ok,
        tor_ok,
        clear_ok,
    )

    return merged


# ---------------------------------------------------------------------------
# Seed discovery (fire-and-forget, runs alongside DB persistence)
# ---------------------------------------------------------------------------

# Cap discovered seeds per investigation so a runaway scrape loop
# can't dump thousands of entries into the seed JSON file.  Per-page
# cap is enforced inside extract_onion_urls_from_content().
SEED_DISCOVERY_MAX_PER_INVESTIGATION = 100


async def _discover_seeds_from_one_page(
    page_url: str,
    content: str,
    investigation_id: Optional[str] = None,
    investigation_counter: Optional[dict] = None,
) -> int:
    """
    Extract .onion hostnames from one scraped page and submit each as a
    discovered seed.  Designed to be awaited concurrently from the
    scraping orchestrator — never raises, never blocks the event loop
    on JSON writes (delegated to asyncio.to_thread inside
    SeedManager.add_discovered_seed_async).

    Args:
        page_url: the page the content was scraped from (used as
            source_url provenance, and also gates the .onion-only check).
        content:  the extracted plain-text content of the page.
        investigation_id: optional — recorded as provenance on each seed.
        investigation_counter: optional mutable dict with key
            ``"count"`` — used to enforce the per-investigation cap.
            When the cap is reached the function returns 0 immediately.

    Returns:
        Number of new seeds successfully submitted.
    """
    if not page_url or not content:
        return 0

    # Only mine .onion pages for .onion references.  We deliberately
    # ignore clearnet pages so the scraper doesn't pick up example
    # addresses from documentation, blog posts, etc.
    if ".onion" not in page_url.lower():
        return 0

    # Enforce per-investigation cap early to skip extraction cost.
    if investigation_counter is not None:
        if investigation_counter.get("count", 0) >= SEED_DISCOVERY_MAX_PER_INVESTIGATION:
            return 0

    try:
        from sources.seed_manager import (
            extract_onion_urls_from_content,
            get_seed_manager,
        )
    except Exception as exc:
        _logger.debug("Seed discovery import failed (non-fatal): %s", exc)
        return 0

    try:
        discovered = extract_onion_urls_from_content(content)
    except Exception as exc:
        _logger.debug("extract_onion_urls_from_content failed: %s", exc)
        return 0

    if not discovered:
        return 0

    seed_manager = get_seed_manager()
    added = 0
    for hostname in discovered:
        if investigation_counter is not None:
            if investigation_counter.get("count", 0) >= SEED_DISCOVERY_MAX_PER_INVESTIGATION:
                break
        target_url = f"http://{hostname}"
        try:
            ok = await seed_manager.add_discovered_seed_async(
                url=target_url,
                source_url=page_url,
                investigation_id=investigation_id,
            )
        except Exception as exc:
            _logger.debug(
                "Seed discovery submit failed for %s (non-fatal): %s",
                hostname, exc,
            )
            continue
        if ok:
            added += 1
            if investigation_counter is not None:
                investigation_counter["count"] = (
                    investigation_counter.get("count", 0) + 1
                )

    if added:
        _logger.info(
            "Seed discovery: +%d new .onion addresses from %s",
            added,
            page_url[:60],
        )

    return added


# ---------------------------------------------------------------------------
# DB persistence (runs synchronously after asyncio.run() returns)
# ---------------------------------------------------------------------------

def _persist_pages(
    items: List[
        Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ],
) -> None:
    """
    Write successfully scraped pages to the database.

    Gracefully skips if:
    - DATABASE_URL is not configured
    - db/ module is not importable (e.g., sqlalchemy not installed)
    - Any per-URL error (IntegrityError on url uniqueness, etc.)

    One session per URL: a failure on one URL cannot roll back others.
    Content-hash deduplication: identical content at a new URL is not re-inserted.
    """
    try:
        from config import DATABASE_URL as _db_url  # re-import for testability
        if not _db_url:
            return
        from db.queries import create_page, get_or_create_source, get_page_by_hash
        from db.session import get_session
    except ImportError:
        return

    for url, _display, raw_bytes, db_text, posted_at in items:
        if not raw_bytes or not url:
            continue

        content_hash = hashlib.sha256(raw_bytes).hexdigest()

        try:
            with get_session() as session:
                # Content-hash dedup: skip if identical content already stored
                if get_page_by_hash(session, content_hash):
                    continue

                hostname = (urlparse(url).hostname or "").lower()
                source_id = None
                if hostname.endswith(".onion"):
                    src, _ = get_or_create_source(session, hostname)
                    source_id = src.id

                create_page(
                    session,
                    url=url,
                    source_id=source_id,
                    cleaned_text=db_text,
                    raw_content_hash=content_hash,
                    byte_size=len(raw_bytes),
                    posted_at=posted_at,
                )
        except Exception as exc:
            # Swallow silently: URL-uniqueness violations, connection errors, etc.
            # DB persistence must never break the scraping pipeline.
            _logger.debug("DB persist failed url=%s: %s", url, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ScrapeBatchResult(dict):
    """Dict-compatible scrape result with optional full-text metadata."""

    def __init__(self, *args, relationship_claims_by_url=None, outlinks_by_url=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.relationship_claims_by_url = relationship_claims_by_url or {}
        # url -> .onion links found in that page's HTML (collect_outlinks=True).
        self.outlinks_by_url = outlinks_by_url or {}


_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#\s]+)""", re.I)
_STATIC_SUFFIXES = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".zip", ".rar", ".7z", ".pdf",
)
MAX_OUTLINKS_PER_PAGE = 50


def extract_onion_outlinks(page_url: str, raw: bytes) -> list[str]:
    """.onion page links in *raw* HTML, resolved against *page_url*, in page
    order, without fragments, static assets or the page itself."""
    from urllib.parse import urljoin, urldefrag

    try:
        html = raw.decode("utf-8", errors="replace")
    except Exception:
        return []
    out: list[str] = []
    seen = {page_url.rstrip("/")}
    for href in _HREF_RE.findall(html):
        link = urldefrag(urljoin(page_url, href.strip()))[0]
        parsed = urlparse(link)
        if parsed.scheme not in ("http", "https"):
            continue
        if not (parsed.hostname or "").lower().endswith(".onion"):
            continue
        if parsed.path.lower().endswith(_STATIC_SUFFIXES):
            continue
        key = link.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
        if len(out) >= MAX_OUTLINKS_PER_PAGE:
            break
    # Addresses printed in the page text (not in any href) go last, so every
    # real link outranks them; the same per-page cap applies. Each one has
    # passed the URL safety gate inside gated_text_onion_urls.
    room = MAX_OUTLINKS_PER_PAGE - len(out)
    if room > 0:
        try:
            from utils.onion_sweep import gated_text_onion_urls

            linked_hosts = {(urlparse(u).hostname or "").lower() for u in out}
            linked_hosts.add((urlparse(page_url).hostname or "").lower())
            for link in gated_text_onion_urls(
                html, exclude_hosts=linked_hosts, max_results=room
            ):
                key = link.rstrip("/")
                if key not in seen:
                    seen.add(key)
                    out.append(link)
        except Exception as exc:
            _logger.debug("Text onion sweep failed: %s", exc)
    return out

async def scrape_multiple(
    urls_data,
    max_workers: int = 5,
    investigation_id: Optional[str] = None,
    extract_typed_relationships: bool = False,
    collect_outlinks: bool = False,
) -> Dict[str, str]:
    """
    Scrape a list of URLs concurrently and return a dict mapping URL → content.

    Arguments and return type are identical to Phase 0 — ui.py is unchanged.

    Pipeline:
        1. Deduplicate input URLs
        2. await _gather_all(...)  — async fetch
        3. Truncate each result to MAX_RETURN_CHARS
        4. Write pages to DB if DATABASE_URL is configured
        5. Fire-and-forget seed discovery for .onion pages (non-blocking,
           bounded per page and per investigation, swallowed on error)
        6. Return {url: content} dict

    Args:
        urls_data:        iterable of URL dicts (Phase 0 contract).
        max_workers:      max concurrency for Tor/.onion fetches.
        investigation_id: optional — recorded as provenance on discovered
                          seeds.  Pass ``None`` to skip provenance tracking.
    """
    if not isinstance(urls_data, (list, tuple)):
        return {}

    max_workers = max(1, min(int(max_workers), 16))

    # Deduplicate by URL (preserve first occurrence)
    unique_urls_data: List[dict] = []
    seen_links: set = set()
    for item in urls_data:
        url, title = _normalize_url_data(item)
        if not url or url in seen_links:
            continue
        seen_links.add(url)
        unique_urls_data.append({"link": url, "title": title})

    safe_urls, blocked = validate_urls_for_scraping(unique_urls_data)
    if blocked:
        _logger.warning("SSRF: blocked %d unsafe URLs from scrape batch", len(blocked))
        for blocked_url in blocked:
            _trace.url_dropped("fetch", blocked_url, "ssrf")
    unique_urls_data = safe_urls

    if not unique_urls_data:
        return {}

    # Async fetch phase
    raw_results = await _gather_all(
        unique_urls_data,
        max_workers,
        extract_typed_relationships=extract_typed_relationships,
    )

    # Assemble public dict with MAX_RETURN_CHARS truncation
    suffix = "...(truncated)"
    results: Dict[str, str] = {}
    relationship_claims_by_url: dict[str, list[dict]] = {}
    db_items: List[
        Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ] = []

    from utils.content_safety import scan_page_text

    outlinks_by_url: dict[str, list[str]] = {}
    for row in raw_results:
        url, display_text, raw_bytes, db_text, posted_at = row[:5]
        if not url:
            continue
        if raw_bytes is None:
            # The fetch failed (its outcome was traced in _fetch_one_impl).
            # A failed fetch is not a page: its search-result title is not
            # page text, so nothing is returned or stored for it.
            continue
        display_text, dropped = scan_page_text(url, display_text or "")
        if dropped:
            _trace.page_fetched(url, "safety_dropped")
            continue
        # display_text is "{title} - {db_text}": when it ends with db_text the
        # scan above already covered it.
        if db_text and not display_text.endswith(db_text):
            db_text, db_dropped = scan_page_text(url, db_text)
            if db_dropped:
                _trace.page_fetched(url, "safety_dropped")
                continue
        # Reported only now, after the safety scan, so a page the filter
        # drops is never first announced as fetched.
        _trace.page_fetched(url, "ok" if db_text else "empty")
        if len(row) > 5 and row[5]:
            relationship_claims_by_url[url] = row[5]
        if not db_text:
            continue  # fetched, but no text: not a page either
        if collect_outlinks and is_onion_url(url):
            outlinks_by_url[url] = extract_onion_outlinks(url, raw_bytes)
        if len(display_text) > MAX_RETURN_CHARS:
            available = MAX_RETURN_CHARS - len(suffix)
            if available > 0:
                display_text = display_text[:available] + suffix
            else:
                display_text = suffix[:MAX_RETURN_CHARS]
        results[url] = display_text
        db_items.append((url, display_text, raw_bytes, db_text, posted_at))

    # DB persistence phase
    await asyncio.to_thread(_persist_pages, db_items)

    # Seed discovery phase — fire-and-forget across all .onion pages,
    # bounded by a per-investigation cap and per-page cap.  Never raises;
    # failures are swallowed inside _discover_seeds_from_one_page.
    discovery_counter: dict = {"count": 0}
    discovery_tasks: List[asyncio.Task] = []
    for url, _display, _raw, db_text, _posted in db_items:
        if not url or not db_text:
            continue
        if ".onion" not in url.lower():
            continue
        discovery_tasks.append(
            asyncio.create_task(
                _discover_seeds_from_one_page(
                    page_url=url,
                    content=db_text,
                    investigation_id=investigation_id,
                    investigation_counter=discovery_counter,
                )
            )
        )
    if discovery_tasks:
        # Bounded concurrency — 4 concurrent discovery coroutines is more
        # than enough since each one delegates the JSON write to a thread.
        sem = asyncio.Semaphore(4)

        async def _run_discovery(t: asyncio.Task) -> None:
            async with sem:
                try:
                    await t
                except Exception as exc:
                    _logger.debug(
                        "Seed discovery task errored (non-fatal): %s", exc
                    )

        await asyncio.gather(*[_run_discovery(t) for t in discovery_tasks])

    if extract_typed_relationships or collect_outlinks:
        return ScrapeBatchResult(
            results,
            relationship_claims_by_url=relationship_claims_by_url,
            outlinks_by_url=outlinks_by_url,
        )
    return results


async def scrape_single(
    url_data,
    rotate: bool = False,
    rotate_interval: int = 5,
    control_port: int = 9051,
    control_password: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Scrape a single URL.  Public signature identical to Phase 0.

    Extra kwargs (rotate, rotate_interval, control_port, control_password) are
    accepted as no-ops.
    # TODO: Tor circuit rotation — Phase 1C
    """
    url, title = _normalize_url_data(url_data)
    if not url:
        return "", title
    results = await scrape_multiple([url_data], max_workers=1)
    # A failed fetch has no page text (the title is not the page).
    return url, results.get(url, "")


def get_tor_session() -> requests.Session:
    """
    Return a requests.Session pre-configured with the Tor SOCKS5 proxy.

    Kept for backward compatibility with health.py and search.py.
    Proxy host/port are now read from config (TOR_PROXY_HOST / TOR_PROXY_PORT).
    """
    session = requests.Session()
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    proxy_url = _build_proxy_url()
    session.proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    return session
