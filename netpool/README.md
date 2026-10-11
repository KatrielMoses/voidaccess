# `netpool/` — shared clearnet HTTP connection pool

The clearnet counterpart to `scraper/tor_pool.py`. One cached
`aiohttp.ClientSession` with a keep-alive `TCPConnector`, so every clearnet caller
reuses connections instead of paying a fresh TCP+TLS handshake per request.

## Why a separate top-level module

Both `scraper/` (page scraping) and `sources/` (enrichment) need the same pool,
but `sources/` must not import `scraper/` (the "sources/scraper firewall"
documented in `sources/proxy_client.py`). A neutral module that both import keeps
the pool **DRY** (one session object) *and* the firewall **intact** (nobody imports
across it). `netpool` depends only on `aiohttp`, `pacing`, and `config`.

## API

| Symbol | Role |
|---|---|
| `get_clearnet_session()` | The process-wide cached session. Lazy, self-healing. |
| `clearnet_connector()` | The keep-alive `TCPConnector` (`limit=30`, `limit_per_host=10`). |
| `close_clearnet_pool()` | Close it on shutdown. Idempotent. |

Timeouts are session-level connect/read only (via `pacing.scale_timeout`); callers
supply a per-request `ClientTimeout(total=...)` which overrides — the same model
`proxy_client` uses.

## Layering (who uses this)

```
proxy_client   decides the route (direct / api / proxy)
   │
netpool        IS the direct route's session (this module)
   │
sources/http_pool   guarded, sources-facing handle to it (adds the .onion refusal)
   │
scraper/scrape.py   get_direct_session_cached() delegates here too
```

`netpool` is policy-free (no `.onion` guard) so the scraper can use it unguarded;
the `.onion`-refusal invariant lives in `sources/http_pool.py`.

## Lifecycle

`scraper.scrape.close_cached_sessions()` drains this pool (alongside the Tor pool),
and both the API lifespan (`api/main.py`) and the CLI (`_close_cached_sessions`)
already call that — so there is no separate shutdown wiring. Tests reset the cached
global via `tests/conftest.py`'s `reset_source_state` fixture.
