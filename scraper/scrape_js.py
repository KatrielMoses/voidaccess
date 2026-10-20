"""
Playwright-based JavaScript renderer for dark web content.

Used as a fallback when aiohttp returns empty content from JS-heavy sites.
Routes traffic through Tor SOCKS5 proxy same as the main scraper.
"""

import logging

import pacing
from config import TOR_ISOLATION_SOCKS_PORT

logger = logging.getLogger(__name__)

# Playwright browser instance — shared across scrape calls
_BROWSER = None
_BROWSER_LOCK = None
# The `async_playwright()` driver that owns _BROWSER.  Tracked at module scope
# purely so it can be stopped: `.start()` spawns a node driver process, and a
# relaunch that only reassigns _BROWSER leaves the previous driver running with
# nothing referencing it.  In a long-lived API process that is one orphaned
# process per relaunch, forever.
_PLAYWRIGHT = None

# Timing baselines (`normal` pacing profile).  JS rendering is the same
# "how patient are we with a slow target" question as an aiohttp fetch, just
# via a different mechanism, so it scales with the same profile rather than
# being left as separate unscaled fixed behaviour.
PAGE_TIMEOUT_MS = 30_000       # 30 s — navigation
SELECTOR_TIMEOUT_MS = 5_000    # 5 s per content-selector attempt
FALLBACK_RENDER_WAIT_MS = 3_000  # 3 s blind wait when no selector matched

# How long to wait for the isolating SocksPort to accept a TCP connection.  It
# is a local port that either answers at once or refuses at once, so this only
# has to cover the refusal; scaled anyway because it is a timeout and the
# project's rule is that no timeout is hardcoded (see pacing/README.md).
ISOLATION_PROBE_TIMEOUT = 1.0

# Result of the one-time isolating-SocksPort probe: None until probed, then
# (port, is_isolated).  Cached because the browser is a long-lived singleton
# launched against whichever port this resolves to.
_SOCKS_PORT_CHOICE: "tuple[int, bool] | None" = None

# Selectors to wait for — indicates page has rendered
CONTENT_SELECTORS = [
    "article",
    "main",
    ".post",
    ".thread",
    ".message",
    "#content",
    ".content",
    "[role='main']",
]

# JS app markers for detection
JS_APP_MARKERS = [
    'id="app"',
    'id="root"',
    'id="__next"',
    "ng-app",
    "data-reactroot",
    "window.__INITIAL_STATE__",
    "window.__NUXT__",
    "<script>window.location",
    # Dark web forum specific
    "Dread",
    "phpBB",
]


def is_js_rendered(html: str, extracted_text: str) -> bool:
    """
    Returns True if the page appears to be a JS-rendered app
    that requires browser execution to get content.

    Criteria:
    - Extracted text is very short (< 300 chars)
    - Raw HTML contains JS app markers
    - HTML has significant script tags but minimal content tags
    """
    if len(extracted_text) >= 300:
        return False  # Already got content, no need for JS

    if not html:
        return False

    html_lower = html.lower()

    # Check for JS app markers
    has_marker = any(marker.lower() in html_lower for marker in JS_APP_MARKERS)

    # Check script-to-content ratio
    script_count = html_lower.count("<script")
    content_count = html_lower.count("<p") + html_lower.count("<div") + html_lower.count("<article")

    high_script_ratio = script_count > 3 and content_count < script_count

    return has_marker or high_script_ratio


async def _resolve_socks_port(tor_proxy_host: str, tor_proxy_port: int) -> tuple[int, bool]:
    """
    Pick the SOCKS port for the browser: the isolating one if it is really there.

    Returns ``(port, is_isolated)``.  Probed once per process and cached.

    Why this path is different from every other Tor fetcher in the codebase:
    Playwright's driver rejects SOCKS5 credentials for any `socks5://` proxy URL,
    at launch and at context creation alike, so the credential-per-hostname
    mechanism in `scraper/tor_pool.py` is unreachable from Chromium.  Isolation
    has to come from Tor's own `IsolateDestAddr` on a dedicated SocksPort
    instead (docker/Dockerfile.tor opens 9250).

    If that port is not listening we return the ordinary port and log a single
    warning.  Degrading loudly is the point: a silent fallback would leave the
    JS-render path sharing one circuit across every onion host while the rest of
    the system looks isolated.
    """
    global _SOCKS_PORT_CHOICE

    if _SOCKS_PORT_CHOICE is not None:
        return _SOCKS_PORT_CHOICE

    import asyncio

    raw = TOR_ISOLATION_SOCKS_PORT
    if not raw or not str(raw).strip():
        logger.warning(
            "Playwright Tor isolation disabled by configuration "
            "(TOR_ISOLATION_SOCKS_PORT is empty): JS-rendered onion pages will "
            "share one circuit regardless of which host they came from."
        )
        _SOCKS_PORT_CHOICE = (int(tor_proxy_port), False)
        return _SOCKS_PORT_CHOICE

    try:
        iso_port = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning(
            "TOR_ISOLATION_SOCKS_PORT=%r is not a port number — Playwright will "
            "use the ordinary SOCKS port, so JS-rendered onion pages will NOT "
            "be circuit-isolated.",
            raw,
        )
        _SOCKS_PORT_CHOICE = (int(tor_proxy_port), False)
        return _SOCKS_PORT_CHOICE

    if iso_port == int(tor_proxy_port):
        # Same port for both: whatever flags it carries, we cannot tell the two
        # roles apart, so make no isolation claim.
        logger.warning(
            "TOR_ISOLATION_SOCKS_PORT (%d) is the same as TOR_PROXY_PORT — "
            "Playwright cannot be given a separately-isolated circuit path, so "
            "JS-rendered onion pages are NOT isolated by destination.",
            iso_port,
        )
        _SOCKS_PORT_CHOICE = (iso_port, False)
        return _SOCKS_PORT_CHOICE

    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(tor_proxy_host, iso_port),
            timeout=pacing.scale_timeout(ISOLATION_PROBE_TIMEOUT),
        )
        logger.info(
            "Playwright will use the destination-isolated Tor SocksPort %s:%d "
            "(IsolateDestAddr) — JS-rendered onion pages get a circuit per host.",
            tor_proxy_host,
            iso_port,
        )
        _SOCKS_PORT_CHOICE = (iso_port, True)
    except Exception as exc:
        logger.warning(
            "Isolating Tor SocksPort %s:%d is not reachable (%s). Falling back "
            "to %s:%s for the Playwright renderer: JS-rendered onion pages will "
            "SHARE one circuit across different hosts. Every other fetch path is "
            "unaffected. To isolate this path, add "
            "'SocksPort %d IsolateDestAddr IsolateDestPort' to your torrc, or "
            "run the bundled tor container (docker/Dockerfile.tor).",
            tor_proxy_host,
            iso_port,
            type(exc).__name__,
            tor_proxy_host,
            tor_proxy_port,
            iso_port,
        )
        _SOCKS_PORT_CHOICE = (int(tor_proxy_port), False)
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass

    return _SOCKS_PORT_CHOICE


async def _stop_playwright() -> None:
    """
    Stop the tracked Playwright driver, releasing its node process.

    Never raises — a driver that is already gone must not be able to block the
    relaunch that is trying to replace it.
    """
    global _PLAYWRIGHT

    if _PLAYWRIGHT is None:
        return
    try:
        await _PLAYWRIGHT.stop()
    except Exception as exc:
        logger.debug("Playwright driver stop failed (non-fatal): %s", exc)
    finally:
        _PLAYWRIGHT = None


async def get_browser(tor_proxy_host: str = "tor", tor_proxy_port: int = 9050):
    """
    Get or create a shared Playwright browser instance.
    Browser routes all traffic through Tor SOCKS5 proxy.
    Launched once, reused across scrape calls.
    """
    global _BROWSER, _BROWSER_LOCK, _PLAYWRIGHT

    if _BROWSER_LOCK is None:
        import asyncio

        _BROWSER_LOCK = asyncio.Lock()

    async with _BROWSER_LOCK:
        if _BROWSER is not None:
            try:
                if _BROWSER.is_connected():
                    return _BROWSER
            except Exception:
                pass
            # The browser is gone but its driver process is not.  Stop the
            # driver before launching a replacement, otherwise every relaunch
            # orphans one node process for the life of this process.
            _BROWSER = None
            await _stop_playwright()

        socks_port, isolated = await _resolve_socks_port(
            tor_proxy_host, tor_proxy_port
        )

        try:
            from playwright.async_api import async_playwright

            _PLAYWRIGHT = await async_playwright().start()

            _BROWSER = await _PLAYWRIGHT.chromium.launch(
                headless=True,
                chromium_sandbox=True,
                # No `username`/`password` here, ever: Playwright's driver throws
                # "Browser does not support socks5 proxy authentication" for any
                # socks5 URL carrying credentials.  Isolation for this path comes
                # from the port itself — see _resolve_socks_port.
                proxy={
                    "server": f"socks5://{tor_proxy_host}:{socks_port}",
                },
                args=[
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    # Keep the sandbox and zygote enabled for untrusted pages.
                    # Privacy — match Tor Browser fingerprint loosely
                    "--disable-blink-features=AutomationControlled",
                ],
            )
            logger.info(
                "Playwright browser launched (Tor %s:%d, per-host circuit "
                "isolation %s)",
                tor_proxy_host,
                socks_port,
                "ON" if isolated else "OFF",
            )
            return _BROWSER

        except Exception as e:
            logger.error(f"Failed to launch Playwright browser: {e}")
            # A launch that failed halfway still leaves a started driver.
            _BROWSER = None
            await _stop_playwright()
            raise


async def fetch_with_playwright(
    url: str,
    tor_proxy_host: str = "tor",
    tor_proxy_port: int = 9050,
    timeout_ms: int | None = None,
) -> dict:
    """
    Fetch a URL using Playwright (headless Chromium through Tor).

    Waits for JS to execute and content to render before extracting.
    Returns same dict shape as aiohttp scraper for compatibility.

    *timeout_ms* is a `normal`-baseline navigation timeout; it and the two
    render waits below are scaled by the active pacing profile.  Defaulting to
    None rather than PAGE_TIMEOUT_MS keeps the resolution at call time, so a
    profile selected after import still applies.

    Returns:
        {link, content, raw_html, status, posted_at, via}
    """
    nav_timeout_ms = pacing.scale_timeout_ms(
        PAGE_TIMEOUT_MS if timeout_ms is None else timeout_ms
    )
    selector_timeout_ms = pacing.scale_timeout_ms(SELECTOR_TIMEOUT_MS)
    fallback_wait_ms = pacing.scale_timeout_ms(FALLBACK_RENDER_WAIT_MS)
    result = {
        "link": url,
        "content": "",
        "raw_html": "",
        "status": 0,
        "posted_at": None,
        "via": "playwright",
        "error": None,
    }

    page = None
    context = None
    try:
        import trafilatura
        from scraper.scrape import extract_post_timestamp

        browser = await get_browser(tor_proxy_host, tor_proxy_port)

        # Create a new browser context per request (isolation)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; rv:109.0) "
                "Gecko/20100101 Firefox/115.0"
            ),
            # Disable unnecessary resource loading
            java_script_enabled=True,
            bypass_csp=False,
        )

        # Block images, fonts, media — we only need text content
        await context.route(
            "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,mp4,webm}",
            lambda route: route.abort(),
        )

        page = await context.new_page()

        # Navigate to URL
        response = await page.goto(url, timeout=nav_timeout_ms, wait_until="domcontentloaded")

        if response:
            result["status"] = response.status

        # Wait for content to appear (try each selector)
        content_appeared = False
        for selector in CONTENT_SELECTORS:
            try:
                await page.wait_for_selector(
                    selector,
                    timeout=selector_timeout_ms,
                    state="visible",
                )
                content_appeared = True
                break
            except Exception:
                continue

        if not content_appeared:
            # No known content selector found — wait for JS to do whatever it does
            await page.wait_for_timeout(fallback_wait_ms)

        # Extract rendered HTML
        raw_html = await page.content()
        result["raw_html"] = raw_html

        # Extract text with trafilatura (same as aiohttp scraper)
        content = trafilatura.extract(
            raw_html,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
        ) or ""

        # Fallback: get visible text directly if trafilatura returns nothing
        if len(content) < 100:
            content = await page.evaluate(
                """() => {
                    const body = document.body;
                    const scripts = body.querySelectorAll('script, style, nav, header, footer');
                    scripts.forEach(s => s.remove());
                    return body.innerText || body.textContent || '';
                }"""
            )
            content = content.strip() if content else ""

        result["content"] = content[:15000]  # Cap at 15k chars

        # Extract post timestamp from rendered HTML
        result["posted_at"] = extract_post_timestamp(raw_html)

        logger.debug(
            f"Playwright scraped {url[:40] if len(url) > 40 else url}... "
            f"→ {len(result['content'])} chars, status={result['status']}"
        )

    except Exception as e:
        result["error"] = str(e)[:100]
        logger.warning(
            f"Playwright failed for {url[:40] if len(url) > 40 else url}...: {e}"
        )

    finally:
        if page:
            try:
                await page.close()
            except Exception:
                pass
        if context:
            try:
                await context.close()
            except Exception:
                pass

    return result


async def close_browser():
    """Shutdown the shared browser and its driver. Call on app shutdown."""
    global _BROWSER

    if _BROWSER is not None:
        try:
            await _BROWSER.close()
            logger.info("Playwright browser closed")
        except Exception:
            pass
        _BROWSER = None

    # Closing the browser does not stop the driver that launched it; without
    # this, shutdown leaves a node process behind.
    await _stop_playwright()
