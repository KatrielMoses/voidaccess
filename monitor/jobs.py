"""
Scheduled monitor jobs (keyword search pipeline and URL change detection).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

import graph
import scraper.scrape as scrape
import search.search as search
import vector
from db.queries import create_investigation, get_investigation_by_query
from extractor import extract_entities_from_page, extract_entities_from_pages
from monitor import _db
from monitor.diff import compute_diff

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import graph
    import scraper.scrape as scrape
    import search.search as search
    import vector
    from extractor import extract_entities_from_page, extract_entities_from_pages
    from monitor import _db


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def run_keyword_watch(watch: dict, llm=None) -> dict[str, Any]:
    """
    Full pipeline: search → scrape → dedup → extract → graph rebuild.
    """
    name = watch.get("name", "")
    query = watch.get("query", "")
    errors: list[str] = []
    new_pages: list[dict] = []
    duplicate_pages_skipped = 0
    investigation_id = None

    try:
        from db.session import get_session

        with get_session() as session:
            inv = get_investigation_by_query(session, name, user_id=watch.get("user_id"))
            if inv is None:
                inv = create_investigation(session, query=name, user_id=watch.get("user_id"))
            investigation_id = inv.id
    except Exception as exc:
        logger.warning("keyword watch investigation lookup/create failed for %s: %s", name, exc)

    try:
        raw_results = search.get_search_results(query)
    except Exception as exc:
        logger.error("search failed: %s", exc)
        return {
            "name": name,
            "query": query,
            "new_pages": 0,
            "new_entities": 0,
            "duplicate_pages_skipped": 0,
            "errors": [str(exc)],
            "timestamp": _utc_iso(),
        }

    urls_data = [
        {"link": r["link"], "title": r.get("title", "")}
        for r in raw_results
        if r.get("link")
    ]

    try:
        scraped = await scrape.scrape_multiple(urls_data)
    except Exception as exc:
        logger.error("scrape failed: %s", exc)
        return {
            "name": name,
            "query": query,
            "new_pages": 0,
            "new_entities": 0,
            "duplicate_pages_skipped": 0,
            "errors": [str(exc)],
            "timestamp": _utc_iso(),
        }

    pending_urls = list(scraped.keys())
    cached_hits: list[dict] = []
    uncached_urls = pending_urls
    try:
        cached_hits, uncached_urls = vector.bulk_check_cache(pending_urls, **({"user_id": watch["user_id"]} if watch.get("user_id") is not None else {}))
    except Exception as exc:
        logger.warning("bulk_check_cache failed for keyword watch %s: %s", name, exc)
    for cached in cached_hits:
        try:
            vector.upsert_page(
                cached.get("link", ""),
                cached.get("content", ""),
                metadata={"watch_name": name, "watch_type": "keyword", "cached": True},
            )
        except Exception as exc:
            logger.warning("upsert_page failed for cached %s: %s", cached.get("link", ""), exc)
    for url in uncached_urls:
        text = scraped.get(url, "")
        try:
            if watch.get("user_id") is None and vector.is_duplicate(text):
                duplicate_pages_skipped += 1
                continue
        except Exception as exc:
            logger.warning("is_duplicate check failed for %s: %s", url, exc)
        try:
            vector.upsert_page(
                url,
                text,
                metadata={"watch_name": name, "watch_type": "keyword", "investigation_id": str(investigation_id), **({"user_id": str(watch["user_id"])} if watch.get("user_id") is not None else {})},
            )
        except Exception as exc:
            logger.warning("upsert_page failed for %s: %s", url, exc)
        new_pages.append({"url": url, "text": text, "content": text})

    new_entities_total = 0
    if new_pages:
        try:
            results = await extract_entities_from_pages(
                new_pages,
                investigation_id=investigation_id,
                llm=llm,
                run_llm_extraction=llm is not None,
            )
            for er in results:
                new_entities_total += int(er.entity_count)
                errors.extend(er.errors)
        except Exception as exc:
            logger.error("extract_entities_from_pages failed: %s", exc)
            errors.append(str(exc))

    if investigation_id is not None:
        try:
            graph_obj = graph.build_graph_from_db(investigation_id=investigation_id)
            graph_obj = graph.infer_relationships(graph_obj)
            persist = getattr(graph, "persist_graph_edges", None)
            if callable(persist):
                persist(graph_obj, investigation_id)
            try:
                from db.session import get_session
                from db.models import Investigation

                with get_session() as session:
                    inv = session.get(Investigation, investigation_id)
                    if inv is not None:
                        inv.graph_status = "complete"
                        session.commit()
            except Exception as exc:
                logger.warning("failed to mark graph complete for %s: %s", investigation_id, exc)
        except Exception as exc:
            logger.warning("build_graph_from_db: %s", exc)
            errors.append(f"graph: {exc}")

    return {
        "name": name,
        "query": query,
        "new_pages": len(new_pages),
        "new_entities": new_entities_total,
        "duplicate_pages_skipped": duplicate_pages_skipped,
        "errors": errors,
        "timestamp": _utc_iso(),
    }


async def run_url_watch(watch: dict, llm=None) -> dict[str, Any]:
    """Scrape one URL, diff against DB-backed previous content, extract if changed."""
    name = watch.get("name", "")
    url = watch.get("url", "")
    investigation_id = None
    try:
        from db.session import get_session

        with get_session() as session:
            inv = get_investigation_by_query(session, name, user_id=watch.get("user_id"))
            if inv is None:
                inv = create_investigation(session, query=name, user_id=watch.get("user_id"))
            investigation_id = inv.id
    except Exception as exc:
        logger.warning("url watch investigation lookup/create failed for %s: %s", name, exc)
    old_content = _db.get_last_cleaned_text_for_url(url, investigation_id=investigation_id)

    try:
        scraped = await scrape.scrape_multiple([{"link": url, "title": ""}])
    except Exception as exc:
        logger.error("url watch scrape failed: %s", exc)
        return {
            "name": name,
            "url": url,
            "changed": False,
            "diff_summary": "",
            "new_entities": 0,
            "timestamp": _utc_iso(),
        }

    new_content = scraped.get(url, "")
    diff = compute_diff(old_content, new_content)
    changed = bool(diff.get("changed"))
    diff_summary = str(diff.get("diff_summary", ""))
    is_first_scrape = not (old_content or "").strip()

    new_entities = 0
    if changed:
        try:
            vector.upsert_page(
                url,
                new_content,
                metadata={"watch_name": name, "watch_type": "url"},
            )
        except Exception as exc:
            logger.warning("upsert_page failed: %s", exc)
        try:
            er = await extract_entities_from_page(
                new_content,
                url,
                page_id=None,
                investigation_id=investigation_id,
                llm=llm if watch.get("use_llm", False) else None,
                run_llm_extraction=bool(llm) and bool(watch.get("use_llm", False)),
            )
            new_entities = int(er.entity_count)
        except Exception as exc:
            logger.error("extract_entities_from_page failed: %s", exc)

        fp = str(diff.get("content_hash_new", ""))
        _db.update_source_watch_fingerprint(url, fp)

    return {
        "name": name,
        "url": url,
        "changed": changed,
        "diff_summary": diff_summary,
        "new_entities": new_entities,
        "change_ratio": float(diff.get("change_ratio", 0.0)),
        "lines_added": int(diff.get("lines_added", 0)),
        "lines_removed": int(diff.get("lines_removed", 0)),
        "is_first_scrape": is_first_scrape,
        "timestamp": _utc_iso(),
    }


async def refresh_seed_data():
    """
    Weekly job: refresh historical seed data from live APIs.
    Upserts new records, updates existing ones.
    Runs every Sunday at 03:00 UTC.
    """
    logger.warning("Starting weekly seed data refresh...")

    try:
        from sources.enrichment import (
            fetch_threatfox, fetch_malwarebazaar
        )
        from scripts.import_seed import (
            import_threatfox_iocs, import_malwarebazaar
        )
        from db.session import get_session

        tf_results = await fetch_threatfox("", limit=500)
        mb_results = await fetch_malwarebazaar("", limit=500)

        with get_session() as session:
            import_threatfox_iocs(session, tf_results)
            import_malwarebazaar(session, mb_results)

        logger.warning("Weekly seed refresh complete")
    except Exception as e:
        logger.error(f"Weekly seed refresh failed: {e}")


async def validate_seeds_job():
    """
    Weekly job: check which curated .onion seeds are still reachable over Tor.
    Updates status in data/onion_seeds.json. Concurrency is kept low so
    the validation pass doesn't saturate the Tor circuit.
    """
    logger.warning("Starting weekly seed validation...")
    try:
        from sources.seed_manager import get_seed_manager

        seed_manager = get_seed_manager()
        results = await seed_manager.validate_seeds(concurrency=3)
        logger.warning(
            "Seed validation complete: %d/%d active, %d unreachable",
            results.get("active", 0),
            results.get("checked", 0),
            results.get("dead", 0),
        )
    except Exception as e:
        logger.error(f"Seed validation failed: {e}")
