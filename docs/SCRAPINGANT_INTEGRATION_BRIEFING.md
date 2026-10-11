# VoidAccess × ScrapingAnt Integration Briefing

**Audience:** new engineers and maintainers
**Status:** canonical record of the final corrected ScrapingAnt architecture
**Repository:** `C:\void.access\voidaccess`
**Target release:** v1.6.0
**Date:** 2026-07-03

## Executive Summary

VoidAccess uses ScrapingAnt as an optional clearnet-only integration for paste-site and RSS-feed scraping. The final architecture has three independent products:

1. Web Scraping API
2. Residential Proxy transport
3. Datacenter Proxy transport

The integration is built around a single clearnet chokepoint. Paste scrapers and RSS scrapers call that chokepoint, which selects exactly one transport per request, falls back to direct on failure, and never touches Tor or `.onion` traffic. GitHub and GitLab scrapers are permanently excluded because they carry auth tokens that must not transit a third-party proxy.

## Architecture

All clearnet ScrapingAnt traffic flows through `sources/proxy_client.py::clearnet_fetch()`. The chokepoint checks for `.onion` URLs first and rejects them before any transport logic runs.

```text
paste_scraper.py   rss_scraper.py
        \             /
         \           /
      clearnet_fetch()
            |
   select exactly one transport
            |
   api | residential proxy | datacenter proxy
            |
   fallback to direct on failure
```

The transport decision is per request:

- Web Scraping API if `VOIDACCESS_USE_PROXIES=true`
- Proxy transport if `VOIDACCESS_USE_PROXY=true`
- If both are enabled, the proxy transport wins and the choice is logged once
- There is no chained mode

## Product 1: Web Scraping API

This transport uses `SCRAPINGANT_API_KEY` and posts to `https://api.scrapingant.com/v2/general`.

- Persistent config: `VOIDACCESS_USE_PROXIES=true`
- One-shot CLI flag: `--use-scraping-api`
- Billing: request credits
- Scope: paste sites and RSS feeds only

## Product 2: Residential Proxy transport

This transport uses the ScrapingAnt residential proxy credentials from the dashboard.

- Credentials: `SCRAPINGANT_PROXY_USERNAME` and `SCRAPINGANT_PROXY_PASSWORD`
- Host: `residential.scrapingant.com`
- Ports: `8080` for HTTP proxying, `443` for HTTPS tunneling
- Persistent config: `VOIDACCESS_USE_PROXY=true`
- One-shot CLI flag: `--use-proxies`
- Billing: traffic volume
- Scope: paste sites and RSS feeds only
- Live behavior: sequential unsessioned requests returned different origin IPs, and sticky sessions using a session suffix returned the same IP for repeated calls

## Product 3: Datacenter Proxy transport

This transport uses the same proxy credential pair as the residential transport, but the datacenter pool is selected with `SCRAPINGANT_PROXY_TYPE=datacenter`.

- Credentials: `SCRAPINGANT_PROXY_USERNAME` and `SCRAPINGANT_PROXY_PASSWORD`
- Host: `datacenter.scrapingant.com` is configured in the integration, but live verification is still open
- Persistent config: `VOIDACCESS_USE_PROXY=true` with `SCRAPINGANT_PROXY_TYPE=datacenter`
- One-shot CLI flag: `--use-proxies`
- Status: supported in configuration, not live-verified; document it as unverified rather than proven

## Scope Exclusions

GitHub and GitLab scrapers are permanently excluded from ScrapingAnt routing because their requests carry `GITHUB_TOKEN` and `GITLAB_TOKEN`. Those tokens must never transit a third-party proxy.

Tor and `.onion` traffic are also unaffected in every configuration. The `.onion` guard fires before transport selection, so no ScrapingAnt setting can override it.

## Config Surface

### CLI

- `voidaccess configure proxy` manages the persistent ScrapingAnt settings
- `voidaccess investigate --use-scraping-api` enables the REST transport for one run
- `voidaccess investigate --use-proxies` enables the proxy transport for one run

### Docker / web settings

- ScrapingAnt secrets entered through the web settings path are stored encrypted at rest using the existing `UserApiKey` mechanism
- This applies to `SCRAPINGANT_API_KEY`, `SCRAPINGANT_PROXY_USERNAME`, and `SCRAPINGANT_PROXY_PASSWORD`

### `.env`

- `.env` stores the same values in plaintext, matching every other environment-driven credential in the project
- `SCRAPINGANT_PROXY_TYPE` is a value, not a secret, but follows the same config surface convention

### Mutual Exclusion

The REST API transport and proxy transport are alternates, not a chain. Each request uses one transport at most. If both are enabled, the proxy transport wins for that request.

## Environment Variables

| Variable | Purpose |
|---|---|
| `SCRAPINGANT_API_KEY` | Credential exclusively for the REST Web Scraping API transport |
| `SCRAPINGANT_PROXY_USERNAME` | Residential or datacenter proxy username from the ScrapingAnt dashboard; separate from `SCRAPINGANT_API_KEY` |
| `SCRAPINGANT_PROXY_PASSWORD` | Residential or datacenter proxy password from the ScrapingAnt dashboard; used together with `SCRAPINGANT_PROXY_USERNAME` |
| `SCRAPINGANT_PROXY_TYPE` | Selects `residential` or `datacenter` for proxy transport selection |
| `VOIDACCESS_USE_PROXIES` | Enables the Web Scraping API transport |
| `VOIDACCESS_USE_PROXY` | Enables the proxy transport |

## Correction History

This integration went through multiple corrections while ScrapingAnt's actual product documentation and live behavior were being verified. Earlier drafts conflated the API key with proxy credentials and described the wrong host and transport model. The final architecture above is the corrected version and should be treated as authoritative.
