"""
sources — Phase 1D expanded source coverage + threat intelligence enrichment.

Public API:
    collect_all_sources(query, ...)  async  — unified aggregator
    enrich_investigation(query, otx_api_key)  async  — threat intel enrichment

Sub-modules:
    engines.py     — OnionSearch (Torch/Haystack) HTML scraping
    seeds.py       — curated .onion seed URL list
    pastes.py      — .onion paste site monitor
    telegram.py    — Telegram public channel monitor (clearnet, optional)
    enrichment.py  — AlienVault OTX + Abuse.ch threat intelligence
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from sources.enrichment import enrich_investigation

_logger = logging.getLogger(__name__)

__all__ = ["collect_all_sources", "enrich_investigation"]


async def collect_all_sources(
    query: str,
    include_telegram: bool = False,
    telegram_channels: Optional[List[str]] = None,
    seed_categories: Optional[List[str]] = None,
) -> Dict:
    """
    Aggregate all Phase 1D intelligence sources for *query*.

    The OnionSearch (Torch/Haystack) engine and the paste monitor run
    concurrently via asyncio.gather().  Telegram runs separately, and only
    when *include_telegram=True* and credentials exist.

    Args:
        query:             investigation query string.
        include_telegram:  if True, also fetch matching Telegram messages.
        telegram_channels: list of channel usernames to monitor; ignored when
                           include_telegram=False.
        seed_categories:   list of seed categories to include (e.g. ["forum",
                           "index"]); None returns all categories.

    Returns dict with keys:
        "search_results"   list[dict]  — from OnionSearch (Torch/Haystack)
        "paste_results"    list[dict]  — from paste site monitor
        "telegram_results" list[dict]  — from Telegram (empty if skipped)
        "seed_urls"        list[dict]  — from seeds.py (for crawler to consume)
    """
    from sources.engines import search_onionsearch
    from sources.pastes import fetch_recent_pastes
    from sources.seeds import get_seeds

    # --- All network sources run concurrently -------------------------------
    # DarkSearch was removed in P1.1 (darksearch.io confirmed defunct); the
    # OnionSearch (Torch/Haystack) engine is what remains here.
    onionsearch_results, paste_results, telegram_results = await asyncio.gather(
        search_onionsearch(query),
        fetch_recent_pastes(query),
        _fetch_telegram_if_enabled(
            include_telegram=include_telegram,
            telegram_channels=telegram_channels or [],
            query=query,
        ),
    )
    search_results: List[dict] = list(onionsearch_results)

    # --- Seeds (synchronous) ------------------------------------------------
    if seed_categories:
        seen_urls: set[str] = set()
        seeds: List[dict] = []
        for cat in seed_categories:
            for s in get_seeds(category=cat):
                if s["url"] not in seen_urls:
                    seen_urls.add(s["url"])
                    seeds.append(s)
    else:
        seeds = get_seeds()

    return {
        "search_results": search_results,
        "paste_results": paste_results,
        "telegram_results": telegram_results,
        "seed_urls": seeds,
        "sources_used": {
            "torch": f"ok_{sum(1 for r in onionsearch_results if r.get('source') == 'Torch')}_results",
            "haystack": f"ok_{sum(1 for r in onionsearch_results if r.get('source') == 'Haystack')}_results",
            "telegram": (
                "skipped_no_key" if include_telegram and not telegram_results and _telegram_credentials_missing()
                else f"ok_{len(telegram_results)}_results"
            ),
        },
    }


async def _fetch_telegram_if_enabled(
    include_telegram: bool, telegram_channels: List[str], query: str
) -> List[dict]:
    if not include_telegram:
        return []
    from sources.telegram import fetch_telegram_messages
    return await fetch_telegram_messages(channel_usernames=telegram_channels, query=query)


def _telegram_credentials_missing() -> bool:
    from config import TELEGRAM_API_ID, TELEGRAM_API_HASH
    return not TELEGRAM_API_ID or not TELEGRAM_API_HASH
