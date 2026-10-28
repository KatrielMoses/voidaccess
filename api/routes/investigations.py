"""
api/routes/investigations.py — Investigation management endpoints.

POST /investigations          — trigger an investigation (background task)
GET  /investigations          — list recent investigations
GET  /investigations/{id}     — get single investigation
GET  /investigations/{id}/entities — list entities for investigation
GET  /investigations/{id}/graph    — graph JSON for investigation
GET  /investigations/{id}/graph/path — shortest path between two entities
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import os
import uuid
from typing import Any, Optional

from api.ownership import require_resource_owner
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy import select as sa_select
from crawler import crawl
from sources.seeds import get_seeds
from sources.seed_manager import get_seed_manager
from sources.paste_scraper import scrape_paste_sites
from sources.github_scraper import scrape_github
from sources.gitlab_scraper import scrape_gitlab
from sources.rss_scraper import scrape_rss_feeds

# Paste-site hostnames used for counting paste-sourced pages in responses.
PASTE_SITE_HOSTNAMES = (
    "pastebin.com",
    "rentry.co",
    "dpaste.org",
    "paste.ee",
)

# Opt-out toggle for the parallel paste site scraper (read at task time so
# tests can monkey-patch the env var without re-importing this module).
def _paste_scraping_enabled() -> bool:
    return os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() == "true"


def _github_scraping_enabled() -> bool:
    return os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() == "true"


def _gitlab_scraping_enabled() -> bool:
    return os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() == "true"


def _rss_scraping_enabled() -> bool:
    return os.getenv("RSS_FEEDS_ENABLED", "true").lower() == "true"


def _telegram_credentials_available() -> bool:
    return bool(os.getenv("TELEGRAM_API_ID", "").strip() and os.getenv("TELEGRAM_API_HASH", "").strip())


def _telegram_channels() -> list[str]:
    return [item.strip() for item in os.getenv("TELEGRAM_CHANNELS", "").split(",") if item.strip()]


async def _gather_with_partial_results(awaitables, timeout: float) -> list:
    """Return completed source results when the phase deadline is reached."""
    tasks = [asyncio.create_task(awaitable) for awaitable in awaitables]
    done, pending = await asyncio.wait(tasks, timeout=timeout)
    results = []
    for task in tasks:
        if task in done:
            try:
                results.append(task.result())
            except Exception as exc:
                results.append(exc)
        else:
            results.append(TimeoutError("parallel source deadline exceeded"))
            task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    return results
from api.auth import CurrentUser, get_current_user, require_password_not_reset_pending
from api.errors import GENERIC_ERROR_MESSAGE, internal_http_exception, log_exception
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
router = APIRouter(dependencies=[Depends(require_resource_owner)])

# In-process cache: investigation_id (str) → infrastructure clusters list.
# Populated during the pipeline run; read by the GET detail endpoint.
_infra_cluster_cache: dict[str, list] = {}

# In-process cache: investigation_id (str) → node-id/community-id map.
# The DB metadata copy is the durable source of truth.
_communities_cache: dict[str, dict[str, int]] = {}

# In-process cache: investigation_id (str) → sources_used status dict.
# Populated during the pipeline run; read by the GET detail endpoint.
# Phase 6.1: this is now a *fast-path* cache — the DB metadata column is
# the source of truth so values survive container restarts.
_sources_used_cache: dict[str, dict] = {}


def _set_sources_used(investigation_id: str, sources_used: dict) -> None:
    """Update in-memory cache AND persist to DB metadata (Phase 6.1).

    Both writes happen on every call so the GET detail endpoint can serve
    fresh values immediately after the pipeline updates them, while still
    surviving a restart that drops the in-memory cache.
    """
    _sources_used_cache[investigation_id] = sources_used
    _update_investigation_metadata(
        investigation_id,
        {"sources_used": sources_used},
    )


def _set_infra_clusters(investigation_id: str, clusters: list) -> None:
    """Update in-memory cache AND persist to DB metadata (Phase 6.1)."""
    _infra_cluster_cache[investigation_id] = clusters
    _update_investigation_metadata(
        investigation_id,
        {"infrastructure_clusters": clusters},
    )


def _set_communities(investigation_id: str, communities: dict[str, int]) -> None:
    """Cache and persist the server-computed community partition."""
    normalized = {
        str(node_id): int(community_id)
        for node_id, community_id in communities.items()
    }
    _communities_cache[investigation_id] = normalized
    _update_investigation_metadata(
        investigation_id,
        {
            "communities": normalized,
            "community_count": len(set(normalized.values())) if normalized else 0,
        },
    )

# ---------------------------------------------------------------------------
# Phase 6.2 — per-phase timeouts (Phase 6.1: caches also persisted to DB)
# ---------------------------------------------------------------------------
# Defaults are conservative ceilings for a healthy investigation; an unhealthy
# network or hung downstream service hits the timeout and we keep moving with
# partial results.  All values are env-var-overridable — see _phase_timeout()
# below — so ops can loosen the cap on a slow host without code changes.
_PHASE_TIMEOUT_DEFAULTS = {
    "parallel_sources": 300,  # already exists upstream; tracked here for symmetry
    "enrichment": 120,
    "graph_build": 60,
    "summary": 90,
    "finalize": 30,
}

_PHASE_TIMEOUT_ENV_VARS = {
    "parallel_sources": "VOIDACCESS_PARALLEL_SOURCES_TIMEOUT",
    "enrichment": "VOIDACCESS_ENRICHMENT_TIMEOUT",
    "graph_build": "VOIDACCESS_GRAPH_TIMEOUT",
    "summary": "VOIDACCESS_SUMMARY_TIMEOUT",
    "finalize": "VOIDACCESS_FINALIZE_TIMEOUT",
}


def _phase_timeout(name: str) -> int:
    """Return the configured timeout for a phase, falling back to the default.

    Read at *call* time so tests / runtime overrides via env var work without
    a module reload.  Invalid values silently fall back to the default so a
    typo (``"120s"`` instead of ``"120"``) never wedges the pipeline.
    """
    default = _PHASE_TIMEOUT_DEFAULTS.get(name, 60)
    env_var = _PHASE_TIMEOUT_ENV_VARS.get(name)
    if env_var:
        raw = os.getenv(env_var)
        if raw:
            try:
                return int(raw)
            except ValueError:
                logger.warning(
                    "[phase-timeout] Invalid %s=%r — using default %ds",
                    env_var, raw, default,
                )
    return default


# Snapshot evaluated at module import.  Modules that need a live value
# (after a runtime env override) should call _phase_timeout() directly.
PHASE_TIMEOUTS: dict[str, int] = {
    name: _phase_timeout(name) for name in _PHASE_TIMEOUT_DEFAULTS
}


async def _run_with_timeout(coro, timeout_seconds: int, phase_name: str, investigation_id: str):
    """Run *coro* with a hard timeout.

    On timeout: logs a warning and returns ``None``.  Never raises
    ``TimeoutError`` to the caller — the pipeline must always be able to
    continue with partial results.  Non-timeout exceptions still propagate
    so genuine bugs surface in normal error handling.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] Phase '%s' timed out after %ds — continuing with partial results",
            investigation_id, phase_name, timeout_seconds,
        )
        return None


async def _run_enrichment_phase(
    extraction_results,
    inv_uuid,
    investigation_id,
    sources_used,
):
    """Post-extraction enrichment cluster (Steps 6.1, 6.2, 6.3, 6.4, 6.8).

    Each sub-step keeps its own per-step ``asyncio.wait_for`` as a
    defence-in-depth cap.  The outer cap (applied by the caller via
    :func:`_run_with_timeout` with ``PHASE_TIMEOUTS["enrichment"]``) is the
    final safety net if all sub-timeouts fire.

    Returns ``(extraction_results, sources_used)`` — both possibly updated.
    """
    # These lookups only read the extracted entities and update separate
    # source-specific DB records.  Run them together and retain each result,
    # using the established partial-results-on-timeout gather pattern.
    from sources.domain_reputation import enrich_domain_entities
    from sources.email_reputation import enrich_email_entities
    from sources.enrichment import run_dns_enrichment
    from sources.hash_reputation import enrich_hash_entities
    from sources.ip_reputation import enrich_ip_entities

    dns_entities = [
        {
            "entity_type": entity.entity_type,
            "canonical_value": entity.value,
            "value": entity.value,
            "confidence": entity.confidence,
        }
        for result in extraction_results
        for entity in getattr(result, "entities", [])
        if hasattr(entity, "entity_type")
    ]

    async def _step(name, awaitable, timeout):
        try:
            return name, await asyncio.wait_for(awaitable, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("[%s] %s enrichment timed out after %ss", inv_uuid, name, timeout)
            return name, TimeoutError("enrichment step timed out")
        except Exception as exc:
            logger.info("[%s] %s enrichment failed (non-fatal): %s", inv_uuid, name, exc)
            return name, exc

    step_results = await _gather_with_partial_results(
        [
            _step("ip_reputation", enrich_ip_entities(extraction_results, inv_uuid), 60),
            _step("circl_pdns", run_dns_enrichment(dns_entities), 120),
            _step("domain_reputation", enrich_domain_entities(extraction_results, inv_uuid), 120),
            _step("hash_reputation", enrich_hash_entities(extraction_results, inv_uuid), 90),
            _step("email_reputation", enrich_email_entities(extraction_results, inv_uuid), 60),
        ],
        timeout=PHASE_TIMEOUTS["enrichment"],
    )

    for name, result in step_results:
        if isinstance(result, Exception):
            sources_used[name] = "error_timeout" if isinstance(result, TimeoutError) else "error"
            continue
        if name == "circl_pdns":
            new_entities = result.get("new_entities", [])
            clusters = result.get("infrastructure_clusters", [])
            if clusters:
                _set_infra_clusters(investigation_id, clusters)
            count = len(new_entities)
            sources_used[name] = f"ok_{count}_enrichments"
        else:
            updated_results, stats = result
            # All current enrichment implementations return the same list;
            # retain the IP step's filtered list if it removed suppressed IPs.
            if name == "ip_reputation":
                extraction_results = updated_results
            status_key = {
                "ip_reputation": "ip_reputation",
                "domain_reputation": "domain_reputation",
                "hash_reputation": "hash_reputation",
                "email_reputation": "email_reputation",
            }[name]
            fallback = {
                "ip_reputation": "ok_0_ips",
                "domain_reputation": "ok_0_domains",
                "hash_reputation": "ok_0_hashes",
                "email_reputation": "ok_0_emails",
            }[name]
            sources_used[name] = stats.get(status_key, fallback)

    _set_sources_used(investigation_id, sources_used)

    # ===== STEP 6.5: Breach-exposure lookup (XposedOrNot + LeakCheck) =====
    try:
        from sources.breach_lookup import enrich_breach_entities as _enrich_breach

        extraction_results, _breach_stats = await asyncio.wait_for(
            _enrich_breach(extraction_results, inv_uuid),
            timeout=90,
        )
        sources_used["xposedornot"] = _breach_stats.get("xposedornot", "ok_0_results")
        sources_used["leakcheck"] = _breach_stats.get("leakcheck", "ok_0_results")
        _set_sources_used(investigation_id, sources_used)
        logger.info(
            "[%s] Breach lookup: %d checked, XposedOrNot %d breached (%d stealer-log), "
            "LeakCheck %d breached, %d corroborated",
            inv_uuid,
            _breach_stats.get("emails_checked", 0),
            _breach_stats.get("xon_breached", 0),
            _breach_stats.get("stealer_log_exposed", 0),
            _breach_stats.get("leakcheck_breached", 0),
            _breach_stats.get("corroborated", 0),
        )
    except asyncio.TimeoutError:
        logger.warning("[%s] Breach-exposure lookup timed out after 90s", inv_uuid)
        sources_used["xposedornot"] = "error_timeout"
        sources_used["leakcheck"] = "error_timeout"
        _set_sources_used(investigation_id, sources_used)
    except Exception as _breach_exc:
        logger.info("[%s] Breach-exposure lookup failed (non-fatal): %s", inv_uuid, _breach_exc)
        sources_used["xposedornot"] = "error"
        sources_used["leakcheck"] = "error"
        _set_sources_used(investigation_id, sources_used)

    # ===== STEP 6.6: Infostealer intelligence (Hudson Rock Cavalier) =====
    try:
        from sources.infostealer import enrich_infostealer_entities as _enrich_infostealer

        extraction_results, _is_stats = await asyncio.wait_for(
            _enrich_infostealer(extraction_results, inv_uuid),
            timeout=90,
        )
        sources_used["hudsonrock"] = _is_stats.get("hudsonrock", "ok_0_results")
        _set_sources_used(investigation_id, sources_used)
        logger.info(
            "[%s] Infostealer (Hudson Rock): %d emails infected, %d domains exposed, "
            "%d machines total",
            inv_uuid,
            _is_stats.get("emails_infected", 0),
            _is_stats.get("domains_exposed", 0),
            _is_stats.get("total_machines", 0),
        )
    except asyncio.TimeoutError:
        logger.warning("[%s] Infostealer enrichment timed out after 90s", inv_uuid)
        sources_used["hudsonrock"] = "error_timeout"
        _set_sources_used(investigation_id, sources_used)
    except Exception as _is_exc:
        logger.info("[%s] Infostealer enrichment failed (non-fatal): %s", inv_uuid, _is_exc)
        sources_used["hudsonrock"] = "error"
        _set_sources_used(investigation_id, sources_used)

    return extraction_results, sources_used


async def _build_graph_phase(
    extraction_results, inv_uuid, investigation_id
):
    """Build the relationship graph for an investigation.

    Flow:
      1. Load entities from DB → build co-occurrence graph (CO_APPEARED_ON edges)
      2. Run inference passes: PGP key reuse + handle similarity across forums
      3. Persist all edges to DB

    Capped by the caller via ``_run_with_timeout`` with
    ``PHASE_TIMEOUTS["graph_build"]``.  Returns ``None`` on internal error
    so the caller can decide to fall back gracefully.
    """
    try:
        from graph.builder import build_graph_from_db, infer_relationships
        from db.session import get_session
        from db.models import Investigation

        # CLI investigations carry IDs as strings, while the ORM UUID columns
        # require uuid.UUID values on SQLite/PostgreSQL alike.
        graph_investigation_id = uuid.UUID(str(inv_uuid))

        graph_obj = await asyncio.to_thread(
            build_graph_from_db, investigation_id=graph_investigation_id
        )
        node_count = len(graph_obj.nodes())
        edge_count = len(graph_obj.edges())
        logger.info(
            "[%s] Graph: %s nodes, %s intra-page edges",
            inv_uuid, node_count, edge_count,
        )

        # Run inference passes before persisting so derived edges are saved.
        # PGP key reuse → CONFIRMED_SAME_ACTOR (0.95).
        # Handle similarity across forums → LIKELY_SAME_ACTOR (0.6).
        graph_obj = infer_relationships(graph_obj)
        inferred_edges = len(graph_obj.edges()) - edge_count
        logger.info(
            "[%s] Graph inference: %s derived edges added (total edges now %s)",
            inv_uuid, inferred_edges, len(graph_obj.edges()),
        )

        try:
            persist_result = await asyncio.to_thread(
                _persist_graph_edges_sync, graph_obj, graph_investigation_id
            )
            graph_status = persist_result.get("status", "written")
            edges_written = persist_result.get("edges_written", 0)
            total_edges = len(graph_obj.edges())
            logger.info(
                "[%s] Graph edges persisted: %s/%s (%s)",
                inv_uuid, edges_written, total_edges, graph_status,
            )
            new_graph_status = (
                "skipped_overflow" if graph_status == "skipped_overflow" else "built"
            )
            with get_session() as session:
                session.query(Investigation).filter_by(id=inv_uuid).update(
                    {"graph_status": new_graph_status}
                )
                session.commit()
        except Exception as e:
            logger.info("[%s] Edge persistence failed (non-fatal): %s", inv_uuid, e)

        # Match the CLI's pre-finalization community step.  Feed the helper
        # the complete graph, before the graph endpoint's display truncation
        # to 20 nodes/50 edges; using that response slice would create an
        # incomplete partition and break CLI/API parity.
        try:
            communities = await asyncio.to_thread(
                _detect_communities_for_graph, graph_obj
            )
            _set_communities(str(inv_uuid), communities)
            logger.info(
                "[%s] Community detection: %s communities (%s nodes)",
                inv_uuid,
                len(set(communities.values())) if communities else 0,
                len(communities),
            )
        except Exception as exc:
            logger.warning(
                "[%s] Community detection failed (non-fatal): %s", inv_uuid, exc
            )
    except Exception as exc:
        logger.exception("[%s] Graph building failed: %s", inv_uuid, str(exc))
        return None
    return True


# Cap on how many (ranked, non-suppressed) entities are handed to the LLM report
# so the summary leads with signal and is not flooded by a long low-value tail.
SUMMARY_ENTITY_LIMIT = 50


# The shared summary helper runs up to two attempts inside one budget; keep it
# under the outer phase cap so the helper, not the cap, ends the phase.
API_SUMMARY_BUDGET_SHARE = 0.9


def _entity_as_dict(entity) -> dict:
    """An entity object or dict as the plain dict the fallback summary reads."""
    if isinstance(entity, dict):
        return entity
    return {
        "entity_type": getattr(entity, "entity_type", None),
        "value": getattr(entity, "value", None),
        "confidence": getattr(entity, "confidence", 0.0),
        "suppressed": getattr(entity, "suppressed", False),
    }


async def _generate_summary_phase(
    extraction_results,
    page_records,
    refined_query,
    llm_client,
    inv_uuid,
    investigation_id,
    scraped_count,
    total_entities,
):
    """Phase 6.2 wrapper around STEP 8 (LLM summary).

    Capped by the caller via ``_run_with_timeout`` with
    ``PHASE_TIMEOUTS["summary"]``.  Falls back to a placeholder string if
    the LLM is unavailable or any error occurs so the pipeline always
    reaches the finalize step with *some* summary.
    """
    if llm_client is None:
        return (
            f"Investigation completed without LLM summary. "
            f"Scraped {scraped_count} pages; extracted {total_entities} entities."
        )
    try:
        from voidaccess.llm import generate_summary
        from voidaccess.summary_fallback import summarize_with_fallback

        summary_entities = []
        if extraction_results:
            for result in extraction_results:
                summary_entities.extend(result.entities)

        # Low-noise report: feed the LLM the high-signal entities first and drop
        # the suppressed long tail (same ranking every other surface uses). This
        # only shapes what the summary sees — nothing is deleted from storage.
        if summary_entities:
            from utils.entity_priority import order_and_filter_for_summary
            summary_entities = order_and_filter_for_summary(
                summary_entities, limit=SUMMARY_ENTITY_LIMIT
            )

        async def _summary_call(pages, **kwargs):
            # generate_summary raises SummaryUnavailable when the LLM fails;
            # summarize_with_fallback retries once with reduced context and then
            # builds the deterministic summary.
            return await _llm_with_backoff(
                generate_summary,
                llm=llm_client,
                query=refined_query,
                content=pages,
                entities=summary_entities if summary_entities else None,
                investigation_id=inv_uuid,
                **kwargs,
            )

        outcome = await summarize_with_fallback(
            _summary_call,
            list(page_records or []),
            query=refined_query,
            budget_s=PHASE_TIMEOUTS["summary"] * API_SUMMARY_BUDGET_SHARE,
            fallback_entities=lambda: [_entity_as_dict(e) for e in summary_entities],
            log_id=str(inv_uuid),
        )
        logger.info(
            "[%s] Summary %s (%d chars, %d attempt(s))",
            inv_uuid, outcome.kind, len(outcome.text or ""), outcome.attempts,
        )
        if outcome.kind == "none":
            return (
                f"Investigation completed without a summary. "
                f"Scraped {scraped_count} pages; extracted {total_entities} entities."
            )
        return outcome.text
    except Exception as exc:
        # Never put the raw exception text in a user-facing summary.
        logger.exception("[%s] Summary generation failed, using fallback summary: %s", inv_uuid, exc)
        return (
            f"Investigation complete for '{refined_query}'. "
            f"Analysis pipeline completed successfully, but summary generation failed."
        )


async def _finalize_phase(inv_uuid, summary):
    """Phase 6.2 wrapper around STEP 9 (DB finalize).

    Capped by the caller via ``_run_with_timeout`` with
    ``PHASE_TIMEOUTS["finalize"]``.  Returns ``True`` on success, ``False``
    if the DB write failed (caller decides whether to log/continue).
    """
    try:
        from db.session import get_session
        from db.queries import update_investigation_summary
        from db.models import Investigation

        with get_session() as session:
            update_investigation_summary(session, inv_uuid, summary)
            session.query(Investigation).filter_by(id=inv_uuid).update(
                {"status": "completed"}
            )
            session.commit()
        return True
    except Exception as exc:
        logger.warning("[%s] Finalize phase failed (non-fatal): %s", inv_uuid, exc)
        return False

# Cooperative cancellation flags: investigation_id (str) → True when cancel requested.
# Checked at pipeline checkpoints; cleared once the pipeline honours the request.
# Falls back cleanly in multi-process deployments (each worker has its own dict;
# cancellation works as long as the pipeline task runs in the same process as the
# cancel HTTP request, which is true for single-worker FastAPI/uvicorn).
_cancel_flags: dict[str, bool] = {}
# The shared cancel token of each running investigation (utils/cancel.py). The
# flag above is what the stage-boundary check reads; the token is what the long
# stages (engine fan-out, page fetch, enrichment) look at between items.
_cancel_tokens: dict[str, "object"] = {}


def _is_cancelled(investigation_id: str) -> bool:
    return _cancel_flags.get(investigation_id, False)


def _set_cancelled(investigation_id: str) -> None:
    _cancel_flags[investigation_id] = True
    token = _cancel_tokens.get(investigation_id)
    if token is not None:
        token.cancel("requested")


def _clear_cancel_flag(investigation_id: str) -> None:
    _cancel_flags.pop(investigation_id, None)


async def _check_cancelled(inv_uuid: uuid.UUID, investigation_id: str) -> bool:
    """Return True and mark investigation cancelled in DB if cancellation was requested."""
    from db.models import Investigation
    from db.session import get_session

    requested = _is_cancelled(investigation_id)
    if not requested:
        try:
            with get_session() as session:
                requested = bool(
                    session.query(Investigation.cancellation_requested)
                    .filter_by(id=inv_uuid)
                    .scalar()
                )
        except Exception:
            requested = False
    if not requested:
        return False
    token = _cancel_tokens.get(investigation_id)
    if token is not None:
        token.cancel("requested")  # a DB-side request also stops in-stage loops
    _clear_cancel_flag(investigation_id)
    logger.info("[%s] Cancellation flag detected — stopping pipeline cleanly", inv_uuid)
    with get_session() as session:
        session.query(Investigation).filter_by(id=inv_uuid).update({"status": "cancelled"})
        session.commit()
    return True

# ---------------------------------------------------------------------------
# Rate limiting (shared key_func with api/main.py; enforcement via app.state.limiter)
# ---------------------------------------------------------------------------

# Per-route rate limit via the in-process ratelimit substrate (no slowapi, no
# Redis). Applied to create_investigation as a FastAPI dependency below.
from api.rate_limit import rate_limit as _rate_limit_dep

_create_investigation_limit = _rate_limit_dep(3, 60, scope="create-investigation")


STEP_LABELS = {
    1: "Refining query",
    2: "Searching dark web",
    3: "Filtering results",
    4: "Scraping pages",
    5: "Extracting entities",
    6: "Enriching intelligence",
    7: "Building graph",
    8: "Generating summary",
    9: "Finalizing results",
}

# Static fallback label for the LLM extraction tier.  The live SSE
# progress event includes a dynamic "page N/M" suffix — see
# `_llm_extraction_progress` in `_run_investigation_task`.
LLM_EXTRACTION_LABEL = "Extracting entities (LLM tier)"


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class InvestigationRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=500, description="Search query (3-500 chars)")
    model: str = Field(default="openrouter/deepseek/deepseek-chat", description="LLM model ID to use")
    run_crawler: bool = False

    @validator("query")
    def query_not_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Query cannot be empty or whitespace")
        if len(v.strip()) < 3:
            raise ValueError("Query must be at least 3 characters")
        return v.strip()


# ---------------------------------------------------------------------------
# Helper: load investigation from DB
# ---------------------------------------------------------------------------


def _count_discovered_seeds_for_investigation(investigation_id_str: str) -> int:
    """
    Count discovered .onion seeds attributed to a given investigation.
    Reads from SeedManager._seeds in memory — same source the admin
    endpoint surfaces, no extra DB query needed.
    """
    try:
        seed_manager = get_seed_manager()
        return sum(
            1
            for s in seed_manager.list_seeds()
            if s.get("category") == "discovered"
            and s.get("investigation_id") == investigation_id_str
        )
    except Exception as exc:
        logger.debug("_count_discovered_seeds_for_investigation failed: %s", exc)
        return 0


def _count_paste_pages_for_investigation(session, internal_id) -> tuple[int, list[str]]:
    """
    Count distinct paste-site pages observed for *internal_id* and return the
    list of paste sources that contributed at least one page.

    Implementation: paste pages are persisted as rows in the `pages` table
    with their paste-site URL, and entities extracted from those pages are
    linked back to the investigation via Entity.investigation_id.  We join
    Entity → Page and filter by hostname instead of adding a DB column.
    """
    try:
        from db.models import Entity, Page

        rows = (
            session.query(Page.url)
            .join(Entity, Entity.page_id == Page.id)
            .filter(Entity.investigation_id == internal_id)
            .distinct()
            .all()
        )
    except Exception as exc:
        logger.debug("paste-page count failed: %s", exc)
        return 0, []

    paste_urls: set[str] = set()
    sources_used: set[str] = set()
    for (url,) in rows:
        if not url:
            continue
        url_lower = url.lower()
        for host in PASTE_SITE_HOSTNAMES:
            if host in url_lower:
                paste_urls.add(url)
                sources_used.add({
                    "pastebin.com": "Pastebin",
                    "rentry.co": "Rentry",
                    "dpaste.org": "dpaste",
                    "paste.ee": "paste.ee",
                }[host])
                break
    return len(paste_urls), sorted(sources_used)


def _get_db_investigation(investigation_id: str) -> Any:
    """Return investigation dict or raise HTTPException 404."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import (  # noqa: PLC0415
            count_distinct_pages_for_investigation,
            get_investigation_by_id_or_run,
        )

        from sqlalchemy import func  # noqa: PLC0415
        from db.models import Entity, EntityRelationship, InvestigationEntityLink  # noqa: PLC0415

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            pages_crawled = count_distinct_pages_for_investigation(session, inv.id)
            paste_pages_found, paste_sources_used = _count_paste_pages_for_investigation(
                session, inv.id
            )

            # Entity IDs for this investigation = own entities + junction-table links
            linked_ids_select = (
                sa_select(InvestigationEntityLink.entity_id)
                .where(InvestigationEntityLink.investigation_id == inv.id)
            )
            entity_subq = (
                session.query(Entity.id)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_select)
                )
                .subquery()
            )
            entity_ids_select = sa_select(entity_subq.c.id)
            entity_count = int(
                session.query(func.count()).select_from(entity_subq).scalar() or 0
            )
            relationship_count = int(
                session.query(func.count(EntityRelationship.id))
                .filter(
                    (EntityRelationship.entity_a_id.in_(entity_ids_select))
                    | (EntityRelationship.entity_b_id.in_(entity_ids_select))
                )
                .scalar()
                or 0
            )

            # Phase 6.1 — sources_used / infrastructure_clusters from DB metadata.
            # The in-memory cache is the fast path; the DB column is the source
            # of truth so values survive a container restart.
            db_metadata = getattr(inv, "metadata_json", None) or {}
            if not isinstance(db_metadata, dict):
                # SQLite legacy may return a JSON string; normalize.
                try:
                    db_metadata = json.loads(db_metadata) if db_metadata else {}
                except (ValueError, TypeError):
                    db_metadata = {}

            db_sources_used = db_metadata.get("sources_used") or {}
            db_infra_clusters = db_metadata.get("infrastructure_clusters") or []
            db_communities = db_metadata.get("communities") or {}

            sources_used = (
                _sources_used_cache.get(str(inv.id))
                or _sources_used_cache.get(investigation_id)
                or db_sources_used
            )
            infrastructure_clusters = (
                _infra_cluster_cache.get(str(inv.id))
                or _infra_cluster_cache.get(investigation_id)
                or db_infra_clusters
            )
            communities = (
                _communities_cache.get(str(inv.id))
                or _communities_cache.get(investigation_id)
                or db_communities
            )
            communities = {
                str(node_id): int(community_id)
                for node_id, community_id in communities.items()
            }

            return {
                "id": str(inv.id),
                "run_id": str(inv.run_id),
                "query": inv.query,
                "refined_query": inv.refined_query,
                "model_used": inv.model_used,
                "preset": inv.preset,
                "summary": inv.summary,
                "status": inv.status,
                "graph_status": getattr(inv, "graph_status", "pending"),
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "current_step": inv.current_step or 0,
                "total_steps": 13,
                "current_step_label": inv.current_step_label or "",
                "entity_count": entity_count,
                "relationship_count": relationship_count,
                "page_count": pages_crawled,
                "pages_crawled": pages_crawled,  # keep for compat
                "paste_pages_found": paste_pages_found,
                "paste_sources_used": paste_sources_used,
                "infrastructure_clusters": infrastructure_clusters,
                "sources_used": sources_used,
                "communities": communities,
                "community_count": len(set(communities.values())) if communities else 0,
                "seeds_discovered": _count_discovered_seeds_for_investigation(str(inv.id)),
            }
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        raise internal_http_exception(exc, context="_get_db_investigation")


async def _update_investigation_status(
    investigation_id: uuid.UUID,
    status: str,
    model_used: Optional[str] = None,
    summary: Optional[str] = None,
) -> None:
    """Update investigation status in a short-lived session."""
    from db.session import get_session
    from db.models import Investigation

    with get_session() as session:
        updates: dict[str, Any] = {"status": status}
        if model_used is not None:
            updates["model_used"] = model_used
        if summary is not None:
            updates["summary"] = summary
        session.query(Investigation).filter_by(id=investigation_id).update(updates)
        session.commit()


def _update_investigation_metadata(
    investigation_id: "uuid.UUID | str",
    patch: dict[str, Any],
    session=None,
) -> bool:
    """Shallow-merge *patch* into ``investigations.metadata`` (JSON column).

    Used by Phase 6.1 to persist in-process pipeline caches (sources_used,
    infrastructure_clusters) so the GET detail endpoint can serve them after
    a container restart.  Accepts an optional *session* for batch callers
    that already hold one open; opens its own short-lived session otherwise.

    Returns ``True`` if the row was updated, ``False`` otherwise (no DB
    configured, row missing, or DB error).  Never raises — failures are
    logged at warning so a transient DB hiccup never kills the pipeline.
    """
    if not os.getenv("DATABASE_URL"):
        return False
    try:
        from db.session import get_session
        from db.models import Investigation
        import json as _json

        inv_uuid = (
            investigation_id
            if isinstance(investigation_id, uuid.UUID)
            else uuid.UUID(str(investigation_id))
        )

        def _merge(_session) -> bool:
            inv = _session.query(Investigation).filter_by(id=inv_uuid).first()
            if inv is None:
                return False
            current = inv.metadata_json
            # SQLite + JSON column round-trip may return a JSON string; always
            # normalize to a dict so the merge below is uniform.
            if current is None:
                merged: dict[str, Any] = {}
            elif isinstance(current, dict):
                merged = dict(current)
            elif isinstance(current, str):
                try:
                    merged = _json.loads(current) if current.strip() else {}
                except (ValueError, TypeError):
                    merged = {}
            else:
                merged = {}
            merged.update(patch)
            # SQLAlchemy's JSON column detects mutations on dict instances
            # via the ORM change-tracking events; explicit assignment keeps
            # the change visible to the session even if the type was loaded
            # as a string (SQLite legacy).
            inv.metadata_json = merged
            return True

        if session is not None:
            return _merge(session)
        with get_session() as s:
            ok = _merge(s)
            if ok:
                s.commit()
            return ok
    except Exception as exc:
        logger.warning(
            "[%s] _update_investigation_metadata failed (non-fatal): %s",
            investigation_id, exc,
        )
        return False


async def _update_progress(
    investigation_id: uuid.UUID,
    step: Optional[int] = None,
    entity_count: Optional[int] = None,
    scraped_pages: Optional[dict] = None,
    label: Optional[str] = None,
) -> None:
    """Fire-and-forget progress field update. Failures are non-critical."""
    try:
        from db.session import get_session
        from db.models import Investigation

        with get_session() as session:
            inv = session.query(Investigation).filter_by(id=investigation_id).first()
            if inv is None:
                return
            if step is not None:
                inv.current_step = step
                inv.current_step_label = label if label is not None else STEP_LABELS.get(step, "Processing")
            elif label is not None:
                inv.current_step_label = label
            if entity_count is not None:
                inv.entity_count = entity_count
            if scraped_pages is not None:
                inv.page_count = len(scraped_pages)
            session.commit()
    except Exception as e:
        logger.warning("[%s] _update_progress failed (non-critical): %s", investigation_id, e)


async def _get_investigation_model_choice(model: Optional[str]) -> tuple[str, Any]:
    """Get model choices and selected model in a short-lived session."""
    from db.session import get_session
    from voidaccess.llm_utils import get_model_choices
    import config as config_module

    with get_session() as session:
        model_choices = get_model_choices()
        if not model_choices:
            raise RuntimeError("No LLM models available")
        selected_model = (
            model
            or config_module.DEFAULT_MODEL
            or "openrouter/deepseek/deepseek-chat"
        )
        return selected_model, model_choices


# ---------------------------------------------------------------------------
# Background task: run investigation pipeline
# ---------------------------------------------------------------------------


# LLM retry bounds.  Unlike an enrichment client's documented interval, 65 s here
# is a guess ("outlast a 1-minute window"), so it is a fallback rather than a
# floor — a provider naming a shorter wait is honoured down to the minimum.
_LLM_RATE_LIMIT_FALLBACK = 65.0
_LLM_RATE_LIMIT_MIN_WAIT = 5.0
_LLM_RATE_LIMIT_MAX_WAIT = 300.0


def _parse_rate_limit_reset(exc: Exception) -> float:
    """
    Seconds to wait after an LLM 429, from the provider's own headers.

    Delegates to ``pacing.retry_after_seconds`` so there is one implementation
    of "the server told us how long to wait" shared with the enrichment API
    clients, rather than two that can drift.  The exception object is passed
    through directly: LangChain buries the 429 headers in the exception message,
    which that helper handles via its string branch.

    The 65 s fallback outlasts a 60 s/1-min window when no header is present.
    """
    import pacing

    return pacing.retry_after_seconds(
        exc,
        fallback=_LLM_RATE_LIMIT_FALLBACK,
        floor=_LLM_RATE_LIMIT_MIN_WAIT,
        max_wait=_LLM_RATE_LIMIT_MAX_WAIT,
    )


async def _llm_with_backoff(fn, *args, max_retries: int = 4, investigation_id: "uuid.UUID | None" = None, **kwargs):
    """Run a synchronous LLM function in a thread, retrying on 429 rate-limit errors."""
    for attempt in range(max_retries):
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:
            if "429" in str(exc) and attempt < max_retries - 1:
                wait_secs = _parse_rate_limit_reset(exc)
                logger.info(
                    "[LLM] Rate limit hit — waiting %.0fs before retry (attempt %d/%d)",
                    wait_secs, attempt + 1, max_retries,
                )
                if investigation_id is not None:
                    await _update_progress(investigation_id, label=f"Rate limited — retrying in {wait_secs:.0f}s...")
                await asyncio.sleep(wait_secs)
            else:
                raise
    raise RuntimeError("LLM max retries exceeded")


# This module's sources_used keys that differ from the registered source ids.
_SOURCE_KEY_ALIASES = {
    "cisa_kev": "cisa",
    "shodan_internetdb": "shodan",
    "rss": "rss_feeds",
}


async def _run_investigation_task(
    investigation_id: str, run_id: str, query: str, model: str, run_crawler: bool
) -> None:
    """
    Background task that runs the investigation pipeline.

    The investigation DB record already exists (created by the HTTP handler) with
    status "pending".  This task updates status → processing → completed/failed.

    CRITICAL: Each DB operation uses its own short-lived session that commits
    and closes immediately. No session is held open across asyncio.to_thread()
    calls, which prevents SQLAlchemy session state corruption and connection
    pool exhaustion.

    Errors are logged — never propagated to the caller.
    """
    try:
        if not os.getenv("DATABASE_URL"):
            logger.warning("Background investigation: DATABASE_URL not set, skipping persist")
            return

        from db.models import Investigation
        from db.session import get_session, get_async_session
        from voidaccess.llm import filter_results, get_llm, refine_query
        from search.search import _search_async as _search_engines_async, _dedupe_links as _search_dedupe, ENGINE_WEIGHTS as _engine_weights
        from scraper.scrape import scrape_multiple, validate_urls_for_scraping
        from extractor import extract_entities_from_pages

        inv_uuid = uuid.UUID(investigation_id)

        # Shared cancel token + per-run source accounting, both bound to this
        # task's context so concurrent investigations stay independent.
        from sources import source_control
        from utils import cancel as _cancel

        source_control.validate_disabled_sources()
        source_control.reset_tracker(scoped=True)
        _cancel_token = _cancel.CancelToken()
        _cancel_tokens[investigation_id] = _cancel_token
        _cancel.set_current(_cancel_token)
        if _is_cancelled(investigation_id):
            _cancel_token.cancel("requested")

        from utils.investigation_metrics import InvestigationMetrics, persist as persist_metrics, set_current

        run_metrics = InvestigationMetrics(inv_uuid)
        set_current(run_metrics)
        persist_metrics(run_metrics)

        def _metric_start(step_name: str) -> None:
            run_metrics.start(step_name)

        def _metric_finish(step_name: str) -> None:
            run_metrics.finish(step_name)
            persist_metrics(run_metrics)

        async with get_async_session() as session:
            result = await session.execute(
                sa_select(Investigation).where(Investigation.id == inv_uuid)
            )
            inv_record = result.scalar_one_or_none()
            inv_user_id = inv_record.user_id if inv_record else None

        resolved_keys = {}
        if inv_user_id is not None:
            async with get_async_session() as session:
                from utils.user_keys import resolve_api_key
                for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                                "OPENROUTER_API_KEY", "GROQ_API_KEY", "OTX_API_KEY", "VT_API_KEY"):
                    resolved_keys[key_name] = await resolve_api_key(inv_user_id, key_name, session)

        # ===== STEP 0: Get model choice and mark as processing =====
        _metric_start("query_refinement")
        selected_model, _ = await _get_investigation_model_choice(model)
        logger.info(
            "Investigation %s: using model '%s'",
            inv_uuid,
            selected_model,
        )
        await _update_investigation_status(inv_uuid, "processing", model_used=selected_model)
        await _update_progress(inv_uuid, 0)
        logger.info("[%s] Starting investigation: %s", inv_uuid, query)

        # ===== STEP 1: Query refinement (no session held) =====
        logger.info("[%s] STEP 1: Refining query...", inv_uuid)
        llm_client = None
        refined_query = query
        try:
            llm_client = get_llm(selected_model, api_keys=resolved_keys)
            refined_query = await _llm_with_backoff(refine_query, llm_client, query, investigation_id=inv_uuid)
            logger.info("[%s] Refined query: %s", inv_uuid, refined_query)
        except Exception as exc:
            logger.exception("[%s] Query refinement failed, using original query: %s", inv_uuid, exc)
            refined_query = query

        def _persist_refined_query():
            with get_session() as session:
                inv = session.query(Investigation).filter_by(id=inv_uuid).first()
                if inv:
                    inv.refined_query = refined_query
                    session.commit()

        await asyncio.to_thread(_persist_refined_query)
        await _update_progress(inv_uuid, 1)
        _metric_finish("query_refinement")
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # ===== STEP 1.5: Multilingual Query Expansion (no session held) =====
        logger.info("[%s] STEP 1.5: Expanding query to multiple languages...", inv_uuid)
        expanded_queries: dict[str, str] = {"en": refined_query}
        try:
            from i18n.query_expand import expand_query

            expansion = expand_query(refined_query)

            if expansion and isinstance(expansion, dict) and len(expansion) > 1:
                expanded_queries = expansion
                lang_count = len(expanded_queries)
                logger.info(
                    "[%s] Query expanded to %d languages: %s",
                    inv_uuid,
                    lang_count,
                    list(expanded_queries.keys()),
                )
            else:
                logger.info("[%s] Query expansion returned no results, using English only", inv_uuid)

        except ImportError:
            logger.info("[%s] i18n module not available, using English only", inv_uuid)
        except Exception as e:
            logger.info("[%s] Query expansion failed (non-fatal): %s", inv_uuid, e)

        # ===== SEED URL INJECTION (runs before search engine fan-out) =====
        # Curated, known-active .onion intelligence sources are checked first
        # so we always visit relevant leak sites/forums even if search engines
        # don't surface them.  These bypass the LLM filter.
        relevant_seeds: list[dict] = []
        try:
            seed_manager = get_seed_manager()
            relevant_seeds = seed_manager.get_relevant_seeds(
                query=query,
                refined_query=refined_query or "",
                max_seeds=10,
            )
        except Exception as exc:
            logger.info("[%s] Seed manager unavailable (non-fatal): %s", inv_uuid, exc)
            relevant_seeds = []

        seed_urls: list[dict] = []
        if relevant_seeds:
            for s in relevant_seeds:
                url = s.get("url") or ""
                if not url:
                    continue
                seed_urls.append({
                    "link": url,
                    "title": s.get("name", "Seed source"),
                    "source": "seed",
                    "source_type": "seed",
                    "seed_category": s.get("category", "unknown"),
                    "seed_tags": s.get("tags", []),
                })
            categories = sorted({s.get("category", "unknown") for s in relevant_seeds})
            logger.info(
                "[%s] Injecting %d seed URLs into scrape queue (categories: %s)",
                inv_uuid,
                len(seed_urls),
                categories,
            )
            await _update_progress(
                inv_uuid,
                step=2,
                label=f"Checking {len(seed_urls)} known intelligence sources + searching Tor engines",
            )
        else:
            logger.info("[%s] No relevant seeds for query", inv_uuid)

        # ===== STEP 2, 3.5, 4: Parallel Pipeline =====
        logger.info("[%s] STEP 2/3.5/4: Launching Search, Enrichment, and Crawler concurrently...", inv_uuid)
        _metric_start("source_gathering")

        onionsearch_counts: dict[str, int] = {"Torch": 0, "Haystack": 0}
        onionsearch_error = False
        onionsearch_status: dict[str, str] = {}

        async def run_search_and_filter() -> list:
            logger.info("[%s] STEP 2: Searching dark web...", inv_uuid)
            
            async def search_single_language(lang_code: str, q: str) -> list[dict]:
                nonlocal onionsearch_error
                search_query = q.replace(" ", "+")
                logger.info("[%s] Searching [%s]: %s...", inv_uuid, lang_code, search_query[:60])
                try:
                    from sources.engines import search_onionsearch, get_last_onionsearch_status
                    engine_results, onion_results = await asyncio.gather(
                        _search_engines_async(search_query, llm_client=llm_client),
                        search_onionsearch(q),
                    )
                    onion_status = get_last_onionsearch_status()
                    onionsearch_status.update(onion_status)
                    if any(status.startswith("error_") or status.startswith("http_") for status in onion_status.values()):
                        onionsearch_error = True
                    all_links: list[dict] = []
                    for er in engine_results:
                        weight = 0.5
                        for known in _engine_weights:
                            if known in er.name.lower():
                                weight = _engine_weights[known]
                                break
                        for link in er.links:
                            link["source_engine"] = er.name
                            link["source_weight"] = weight
                            all_links.append(link)
                    for onion_result in onion_results:
                        source_name = onion_result.get("source", "")
                        if source_name in onionsearch_counts:
                            onionsearch_counts[source_name] += 1
                        all_links.append({
                            "link": onion_result.get("url", ""),
                            "title": onion_result.get("title", ""),
                            "snippet": onion_result.get("snippet", ""),
                            "source_engine": source_name,
                            "source_weight": 0.7,
                        })
                    from utils.content_safety import gate_search_results

                    all_links, _ = gate_search_results(all_links)
                    lang_results = _search_dedupe(all_links)
                    lang_results.sort(key=lambda r: r.get("source_weight", 0.5), reverse=True)
                    for result in lang_results:
                        result["search_language"] = lang_code
                    return lang_results
                except Exception as e:
                    onionsearch_error = True
                    logger.info("[%s] [%s] search failed: %s", inv_uuid, lang_code, e)
                    return []

            search_tasks = [
                search_single_language(lang, q)
                for lang, q in expanded_queries.items()
            ]
            try:
                results_by_language = await asyncio.wait_for(
                    asyncio.gather(*search_tasks, return_exceptions=True),
                    timeout=180,
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] Multilingual search timed out after 180s, using partial results", inv_uuid)
                results_by_language = []

            all_search_results = []
            seen_urls = set()
            for lang_results in results_by_language:
                if isinstance(lang_results, Exception):
                    continue
                for result in lang_results:
                    url = result.get("link", "")
                    normalized = url.lower().rstrip("/").replace("https://", "http://")
                    if normalized and normalized not in seen_urls:
                        seen_urls.add(normalized)
                        all_search_results.append(result)

            # P3.2 — merge the owned index into the fan-out and rank the union by
            # semantic relevance (replaces static source_weight ordering; now only
            # a tiebreak). Shared with the CLI path via merge_and_rank for API↔CLI
            # parity; no-ops to external-only when Meilisearch is unconfigured, and
            # returns owned-index results even when every external engine failed.
            try:
                from search.ranking import merge_and_rank

                search_results = await merge_and_rank(
                    refined_query or query, all_search_results
                )
            except Exception as _rank_exc:
                logger.info("[%s] Merge/semantic-rank failed (non-fatal): %s", inv_uuid, _rank_exc)
                search_results = all_search_results
            from utils.content_safety import gate_search_results

            search_results, _ = gate_search_results(search_results)
            logger.info("[%s] Total search results: %d (from %d languages)", inv_uuid, len(search_results), len(expanded_queries))

            if not search_results:
                logger.info("[%s] WARNING: No search results from any language", inv_uuid)

            logger.info("[%s] STEP 3: Filtering results...", inv_uuid)
            if llm_client is None:
                filtered_results = list(search_results[:100])
                logger.info("[%s] LLM unavailable; fallback to top %s search results", inv_uuid, len(filtered_results))
            else:
                try:
                    filtered_results = await _llm_with_backoff(filter_results, llm_client, refined_query, search_results, investigation_id=inv_uuid)
                except Exception as exc:
                    logger.exception("[%s] Filter step failed, falling back: %s", inv_uuid, exc)
                    filtered_results = list(search_results[:100])
            logger.info("[%s] Filtered to %s results", inv_uuid, len(filtered_results))
            
            _urls_to_scrape = list(filtered_results)
            if len(_urls_to_scrape) < 100:
                current_links = {res.get("link") for res in _urls_to_scrape if res.get("link")}
                for res in search_results:
                    if res.get("link") not in current_links:
                        _urls_to_scrape.append(res)
                        current_links.add(res.get("link"))
                    if len(_urls_to_scrape) >= 150:
                        break
            return _urls_to_scrape

        async def run_enrichment() -> list:
            logger.info("[%s] STEP 3.5: Running threat intel enrichment...", inv_uuid)
            try:
                from sources.enrichment import enrich_investigation

                queries_to_enrich = [query]
                if refined_query and refined_query.strip().lower() != query.strip().lower():
                    queries_to_enrich.append(refined_query)

                all_pages: list = []
                seen_urls: set = set()
                for eq in queries_to_enrich:
                    try:
                        # Hard 60s cap per enrichment query — individual requests already have 30s timeouts
                        batch = await asyncio.wait_for(
                            enrich_investigation(
                                query=eq,
                                otx_api_key=resolved_keys.get("OTX_API_KEY") or "",
                            ),
                            timeout=60,
                        )
                        for p in batch:
                            u = p.get("url") or p.get("link") or ""
                            if u not in seen_urls:
                                seen_urls.add(u)
                                all_pages.append(p)
                    except asyncio.TimeoutError:
                        logger.warning("[%s] Enrichment query '%s' timed out after 60s", inv_uuid, eq)
                    except Exception as exc:
                        logger.info("[%s] Enrichment batch failed for '%s': %s", inv_uuid, eq, exc)

                logger.info("[%s] Enrichment: %s pages (tried %s queries)", inv_uuid, len(all_pages), len(queries_to_enrich))
                return all_pages
            except Exception as exc:
                logger.info("[%s] Enrichment failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_crawler_task() -> list:
            if not run_crawler:
                logger.info("[%s] STEP 4: Crawler disabled", inv_uuid)
                return []
            try:
                logger.info("[%s] STEP 4: Running recursive crawler...", inv_uuid)
                seeds = await asyncio.to_thread(get_seeds, category="index", query=refined_query)
                seed_urls = [seed["url"] for seed in seeds if seed.get("url")]
                # max_depth=1 and max_pages=20 keep the crawler bounded;
                # 120s hard cap prevents dead Tor circuits from stalling the pipeline
                crawler_result = await asyncio.wait_for(
                    crawl(seed_urls=seed_urls, query=refined_query, max_depth=1, max_pages=20),
                    timeout=120,
                )
                logger.info("[%s] Crawler: %s pages, %s failed", inv_uuid, crawler_result.pages_crawled, crawler_result.pages_failed)
                return [{"link": item.get("url", ""), "title": "Crawler discovery"}
                        for item in crawler_result.results if isinstance(item, dict) and item.get("url")]
            except asyncio.TimeoutError:
                logger.warning("[%s] Crawler timed out after 120s, continuing without crawler results", inv_uuid)
                return []
            except Exception as exc:
                logger.exception("[%s] Crawler failed: %s", inv_uuid, str(exc))
                return []

        async def run_paste_scraping_task() -> list:
            # Clearnet paste-site sweep (Pastebin, dpaste, paste.ee, Rentry).
            # Opt-out via PASTE_SCRAPING_ENABLED=false.
            if not _paste_scraping_enabled():
                logger.info("[%s] Paste sites: disabled via env var", inv_uuid)
                return []
            try:
                paste_max = int(os.getenv("PASTE_MAX_RESULTS", "15") or 15)
            except ValueError:
                paste_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_paste_sites(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=paste_max,
                    ),
                    timeout=120,
                )
                logger.info(
                    "[%s] Paste sites: %d pastes found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] Paste scraping timed out after 120s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] Paste scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_github_scraping_task() -> list:
            # Clearnet GitHub sweep — code search + repo READMEs.
            # Opt-out via GITHUB_SCRAPING_ENABLED=false.
            if not _github_scraping_enabled():
                logger.info("[%s] GitHub: disabled via env var", inv_uuid)
                return []
            try:
                github_max = int(os.getenv("GITHUB_MAX_RESULTS", "15") or 15)
            except ValueError:
                github_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_github(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=github_max,
                    ),
                    timeout=180,
                )
                logger.info(
                    "[%s] GitHub: %d files found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] GitHub scraping timed out after 180s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] GitHub scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_gitlab_scraping_task() -> list:
            # Clearnet GitLab sweep — code search + project READMEs.
            # Opt-out via GITLAB_SCRAPING_ENABLED=false.
            if not _gitlab_scraping_enabled():
                logger.info("[%s] GitLab: disabled via env var", inv_uuid)
                return []
            try:
                gitlab_max = int(os.getenv("GITLAB_MAX_RESULTS", "15") or 15)
            except ValueError:
                gitlab_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_gitlab(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=gitlab_max,
                    ),
                    timeout=180,
                )
                logger.info(
                    "[%s] GitLab: %d results found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] GitLab scraping timed out after 180s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] GitLab scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_rss_scraping_task() -> list:
            if not _rss_scraping_enabled():
                logger.info("[%s] RSS feeds: disabled via env var", inv_uuid)
                return []
            try:
                rss_max = int(os.getenv("RSS_MAX_ARTICLES", "20") or 20)
            except ValueError:
                rss_max = 20
            try:
                pages = await asyncio.wait_for(
                    scrape_rss_feeds(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=rss_max,
                    ),
                    timeout=120,
                )
                logger.info("[%s] RSS feeds: %d articles found", inv_uuid, len(pages))
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] RSS scraping timed out after 120s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] RSS scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_telegram_task() -> list:
            if not _telegram_credentials_available():
                logger.info("[%s] Telegram: credentials not configured", inv_uuid)
                return []
            try:
                from sources.telegram import fetch_telegram_messages
                return await asyncio.wait_for(
                    fetch_telegram_messages(_telegram_channels(), query),
                    timeout=120,
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] Telegram timed out after 120s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] Telegram failed (non-fatal): %s", inv_uuid, exc)
                raise

        # Hard cap on the entire parallel phase (search + enrichment + crawler +
        # paste scraping + github + gitlab + RSS feeds).  Each inner function
        # also has its own timeout so a single slow source can't stall the phase.
        #
        # Issue 1 — we must NOT discard work that already finished when the
        # overall deadline fires.  Each source runs as its own task with its own
        # result slot; whatever has genuinely completed by the deadline is kept,
        # and only tasks still in flight are marked as timed out — never
        # conflated with sources that completed or errored.
        _parallel_specs = [
            ("tor_search", run_search_and_filter),
            ("enrichment", run_enrichment),
            ("crawler", run_crawler_task),
            ("paste_sites", run_paste_scraping_task),
            ("github", run_github_scraping_task),
            ("gitlab", run_gitlab_scraping_task),
            ("rss_feeds", run_rss_scraping_task),
            ("telegram", run_telegram_task),
        ]
        _parallel_tasks: dict[str, asyncio.Task] = {
            name: asyncio.ensure_future(fn()) for name, fn in _parallel_specs
        }
        _parallel_deadline = _phase_timeout("parallel_sources")
        _done, _pending = await asyncio.wait(
            _parallel_tasks.values(), timeout=_parallel_deadline
        )
        if _pending:
            logger.warning(
                "[%s] Parallel phase hit %ds cap — %d source(s) still running "
                "(marked timed_out); continuing with %d completed source(s)",
                inv_uuid, _parallel_deadline, len(_pending),
                len(_parallel_tasks) - len(_pending),
            )
            for _t in _pending:
                _t.cancel()
            # Await the cancellations so no source task is left orphaned.
            await asyncio.gather(*_pending, return_exceptions=True)

        # After the optional cancel-and-gather above, every task is now done —
        # either it completed (kept), raised (error), or was cancelled at the
        # deadline (timed_out).  A task that finished in the instant between the
        # deadline and cancel() lands here as done-with-result, so its work is
        # still preserved rather than discarded.
        _source_errors: set[str] = set()
        _source_timeouts: set[str] = set()
        _parallel_results: dict[str, list] = {}
        for _name, _task in _parallel_tasks.items():
            if _task.cancelled() or not _task.done():
                logger.warning("[%s] Source '%s' did not finish in time (timed_out)", inv_uuid, _name)
                _source_timeouts.add(_name)
                _parallel_results[_name] = []
                continue
            _exc = _task.exception()
            if _exc is not None:
                logger.warning("[%s] Source '%s' task raised: %s", inv_uuid, _name, _exc)
                _source_errors.add(_name)
                _parallel_results[_name] = []
            else:
                _parallel_results[_name] = _task.result()

        search_urls = _parallel_results["tor_search"]
        enrichment_pages = _parallel_results["enrichment"]
        crawler_urls = _parallel_results["crawler"]
        paste_pages = _parallel_results["paste_sites"]
        github_pages = _parallel_results["github"]
        gitlab_pages = _parallel_results["gitlab"]
        rss_pages = _parallel_results["rss_feeds"]
        telegram_pages = _parallel_results["telegram"]

        await _update_progress(inv_uuid, 2)
        _metric_finish("source_gathering")
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        if paste_pages:
            paste_sources_used = sorted({
                p.get("source_name") for p in paste_pages
                if p.get("source_name")
            })
            await _update_progress(
                inv_uuid,
                label=(
                    f"Found {len(paste_pages)} paste site results "
                    f"({', '.join(paste_sources_used)})"
                ),
            )

        # ── sources_used: record which sources ran and what they returned ──────
        _otx_key = (resolved_keys.get("OTX_API_KEY") or "").strip()
        _vt_key = os.getenv("VT_API_KEY", "").strip()
        _st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
        # abuse.ch (MalwareBazaar / ThreatFox / URLhaus) now require a free
        # Auth-Key.  Absence means those sources could not run at all (Issue 4).
        _abusech_key = os.getenv("ABUSECH_API_KEY", "").strip()

        def _src_status(count: int, error_key: str | None = None) -> str:
            if error_key and error_key in _source_timeouts:
                return "timed_out"
            if error_key and error_key in _source_errors:
                return "error"
            return f"ok_{count}_results" if count > 0 else "ok_0_results"

        sources_used: dict[str, str] = {}

        # Keyed sources — show "skipped_no_key" when the key is absent
        if not _otx_key:
            sources_used["otx"] = "skipped_no_key"
        else:
            n = sum(1 for p in enrichment_pages if p.get("source") == "alienvault_otx")
            sources_used["otx"] = _src_status(n, "enrichment")

        if not _vt_key:
            sources_used["virustotal"] = "skipped_no_key"
        else:
            n = sum(1 for p in enrichment_pages if p.get("source") == "virustotal")
            sources_used["virustotal"] = _src_status(n, "enrichment")

        sources_used["securitytrails"] = "skipped_no_key" if not _st_key else "skipped_not_implemented"

        # abuse.ch family (MalwareBazaar / ThreatFox / URLhaus) — these require a
        # free Auth-Key (ABUSECH_API_KEY).  When it's missing they cannot run, so
        # report skipped_no_key rather than ok_0_results, which would read as
        # "ran fine, found nothing" (Issue 4).  Same pattern as otx/virustotal.
        for _skey, _psrc in [
            ("malwarebazaar", "malwarebazaar"),
            ("threatfox", "threatfox"),
            ("urlhaus", "urlhaus"),
        ]:
            if not _abusech_key:
                sources_used[_skey] = "skipped_no_key"
            else:
                n = sum(1 for p in enrichment_pages if p.get("source") == _psrc)
                sources_used[_skey] = _src_status(n, "enrichment")

        _rl_n = sum(
            1 for p in enrichment_pages
            if p.get("source") == "ransomware_live" and not p.get("_scrape_seed")
        )
        sources_used["ransomware_live"] = _src_status(_rl_n, "enrichment")

        # ransomlook.io — second ransomware tracker (excludes .onion scrape seeds)
        _rlook_n = sum(
            1 for p in enrichment_pages
            if p.get("source") == "ransomlook" and not p.get("_scrape_seed")
        )
        sources_used["ransomlook"] = _src_status(_rlook_n, "enrichment")

        _cisa_n = sum(1 for p in enrichment_pages if p.get("source") in ("cisa_kev", "cisa_advisory"))
        sources_used["cisa"] = _src_status(_cisa_n, "enrichment")

        # NVD 2.0 — full CVE metadata (no key required; complements CISA KEV)
        _nvd_n = sum(1 for p in enrichment_pages if p.get("source") == "nvd")
        sources_used["nvd"] = _src_status(_nvd_n, "enrichment")

        # P1.3 — unified CVE intelligence (NVD + KEV + EPSS + Exploit-DB fused).
        _cve_intel_n = sum(1 for p in enrichment_pages if p.get("source") == "cve_intel")
        sources_used["cve_intel"] = _src_status(_cve_intel_n, "enrichment")

        # P1.4/P1.5 — blocklist matches (SSLBL / OpenPhish / PhishTank / ransomwhe.re).
        for _feed_name in ("sslbl", "openphish", "phishtank", "ransomwhere"):
            _feed_n = sum(1 for p in enrichment_pages if p.get("source") == _feed_name)
            sources_used[_feed_name] = _src_status(_feed_n, "enrichment")

        _shodan_n = sum(1 for p in enrichment_pages if p.get("source") == "shodan_internetdb")
        sources_used["shodan"] = _src_status(_shodan_n, "enrichment")

        # Tor search
        if "tor_search" in _source_timeouts:
            sources_used["tor_search"] = "timed_out"
        elif "tor_search" in _source_errors:
            sources_used["tor_search"] = "error"
        else:
            n = len(search_urls)
            sources_used["tor_search"] = f"ok_{n}_pages" if n > 0 else "ok_0_pages"

        # Clearnet scrapers
        if not _github_scraping_enabled():
            sources_used["github"] = "skipped_disabled"
        elif "github" in _source_timeouts:
            sources_used["github"] = "timed_out"
        elif "github" in _source_errors:
            sources_used["github"] = "error"
        else:
            sources_used["github"] = _src_status(len(github_pages))

        if not _gitlab_scraping_enabled():
            sources_used["gitlab"] = "skipped_disabled"
        elif "gitlab" in _source_timeouts:
            sources_used["gitlab"] = "timed_out"
        elif "gitlab" in _source_errors:
            sources_used["gitlab"] = "error"
        else:
            sources_used["gitlab"] = _src_status(len(gitlab_pages))

        if not _paste_scraping_enabled():
            sources_used["paste_sites"] = "skipped_disabled"
        elif "paste_sites" in _source_timeouts:
            sources_used["paste_sites"] = "timed_out"
        elif "paste_sites" in _source_errors:
            sources_used["paste_sites"] = "error"
        else:
            sources_used["paste_sites"] = _src_status(len(paste_pages))

        if not _rss_scraping_enabled():
            sources_used["rss_feeds"] = "skipped_disabled"
        elif "rss_feeds" in _source_timeouts:
            sources_used["rss_feeds"] = "timed_out"
        elif "rss_feeds" in _source_errors:
            sources_used["rss_feeds"] = "error"
        else:
            sources_used["rss_feeds"] = _src_status(len(rss_pages))

        for _engine_name, _engine_key in (("Torch", "torch"), ("Haystack", "haystack")):
            _status = onionsearch_status.get(_engine_name, "error" if onionsearch_error else "ok")
            sources_used[_engine_key] = (
                _status if _status.startswith("error_") or _status.startswith("http_")
                else _src_status(onionsearch_counts[_engine_name])
            )
        if not _telegram_credentials_available():
            sources_used["telegram"] = "skipped_no_key"
        elif "telegram" in _source_errors:
            sources_used["telegram"] = "error"
        else:
            sources_used["telegram"] = _src_status(len(telegram_pages))

        # DNS, domain, hash, and email reputation placeholders — updated after those steps complete
        # DNS, domain, hash, email, breach, and infostealer reputation placeholders
        # — updated after those post-extraction steps complete.
        sources_used["circl_pdns"] = "pending"
        sources_used["domain_reputation"] = "pending"
        sources_used["hash_reputation"] = "pending"
        sources_used["email_reputation"] = "pending"
        sources_used["xposedornot"] = "pending"
        sources_used["leakcheck"] = "pending"
        sources_used["hudsonrock"] = "pending"
        # VOIDACCESS_DISABLED_SOURCES / the enrichment allowlist: a source that
        # was switched off never reads ``ok_*`` here.
        source_control.overlay_status_strings(sources_used, _SOURCE_KEY_ALIASES)
        _sources_used_cache[investigation_id] = sources_used
        _update_investigation_metadata(
            investigation_id,
            {"sources_used": sources_used},
        )
        # ── end sources_used ──────────────────────────────────────────────────

        if len(search_urls) < 2:
            logger.warning(
                "[%s] Filtered results too small (%s INTELLIGENCE pages). "
                "Query may have returned only directory/index pages. "
                "Try a more specific query.",
                inv_uuid,
                len(search_urls),
            )
            no_result_summary = (
                f"Investigation for '{refined_query}' completed but found insufficient "
                f"intelligence content. Only {len(search_urls)} qualifying page(s) remained "
                f"after filtering out directory/index pages. This suggests the query "
                f"returned primarily link aggregators or marketplace indexes rather than "
                f"actual threat intelligence content. Try a more specific, targeted query "
                f"(e.g., specific malware names, actor handles, or infrastructure indicators) "
                f"instead of broad topic searches."
            )
            with get_session() as session:
                session.query(Investigation).filter_by(id=inv_uuid).update(
                    {"status": "completed_no_results", "summary": no_result_summary, "graph_status": "no_data"}
                )
                session.commit()
            logger.info("[%s] Investigation COMPLETED_NO_RESULTS (run_id=%s)", inv_uuid, run_id)
            return

        # Seed .onion leak-site URLs discovered by enrichment (e.g. ransomware.live)
        # into the scrape queue so they get visited even if search engines didn't find them
        enrichment_onion_seeds = [
            {"link": p.get("link") or p.get("url"), "title": p.get("title", "Enrichment seed")}
            for p in enrichment_pages
            if p.get("_scrape_seed") and ".onion" in (p.get("link") or p.get("url") or "")
        ]
        if enrichment_onion_seeds:
            logger.info(
                "[%s] Adding %d .onion seeds from enrichment to scrape queue",
                inv_uuid, len(enrichment_onion_seeds),
            )

        # Seed URLs go first — they're known intelligence sources and skip the LLM filter
        all_urls_to_scrape = seed_urls + search_urls + crawler_urls + enrichment_onion_seeds
        logger.info(
            "[%s] Total URLs to scrape: %s (%s seeds + %s search + %s crawler + %s enrichment)",
            inv_uuid,
            len(all_urls_to_scrape),
            len(seed_urls),
            len(search_urls),
            len(crawler_urls),
            len(enrichment_onion_seeds),
        )

        if enrichment_pages:
            try:
                from vector.store import store_page
                for ep in enrichment_pages:
                    u = ep.get("url") or ep.get("link") or ""
                    t = ep.get("text") or ep.get("content") or ""
                    if u and t:
                        store_page(url=u, content=t, metadata={"source": ep.get("source", "enrichment"), "investigation_id": str(inv_uuid)})
            except Exception:
                pass

        # ===== P4.2: Read-from-shared before scraping (serve-from-cache, zero re-scrape) =====
        # Consult the shared tier (populated by OTHER users' runs) for cached page
        # content, query-relevant seeds, and pre-extracted entities — reading ONLY
        # user-agnostic shared tables (never another user's investigation/query/
        # report). Served content skips the Tor re-scrape (point 2 of the four-point
        # standard). Consent-gated + non-fatal; a $0/no-corpus install serves nothing.
        shared_served: dict[str, str] = {}
        shared_entities: list[dict] = []
        try:
            from shared_corpus.read import read_shared_before_scrape

            with get_session() as shared_session:
                shared_bundle = await read_shared_before_scrape(
                    shared_session, refined_query, all_urls_to_scrape,
                )
            shared_served = shared_bundle.served
            shared_entities = shared_bundle.entities
            _remaining_links = {
                (u.get("link") if isinstance(u, dict) else u) for u in shared_bundle.remaining
            }
            seed_additions = [
                s for s in shared_bundle.seeds if s.get("link") not in _remaining_links
            ]
            all_urls_to_scrape = shared_bundle.remaining + seed_additions
            sources_used["shared_corpus"] = {
                "status": "skipped_private" if shared_bundle.skipped_private else "ok",
                "cached_served": shared_bundle.served_count,
                "seeds_added": len(seed_additions),
                "entities": len(shared_entities),
            }
            logger.info(
                "[%s] Shared read: %d cached served (skip re-scrape), %d seeds added, "
                "%d shared entities%s",
                inv_uuid, shared_bundle.served_count, len(seed_additions),
                len(shared_entities),
                " [private-mode: skipped]" if shared_bundle.skipped_private else "",
            )
        except Exception as _shared_exc:
            logger.info("[%s] Shared read failed (non-fatal): %s", inv_uuid, _shared_exc)

        # ===== STEP 4.5: Vector Cache Lookup (no session held) =====
        _metric_start("scraping")
        logger.info(
            "[%s] STEP 4.5: Checking vector cache for %d URLs...",
            inv_uuid,
            len(all_urls_to_scrape),
        )
        cached_dict: dict = {}
        uncached_url_dicts = list(all_urls_to_scrape)
        try:
            from vector.store import bulk_check_cache

            url_strings = [
                u.get("link", u) if isinstance(u, dict) else str(u)
                for u in all_urls_to_scrape
            ]
            cached_pages_list, urls_needing_scrape = bulk_check_cache(
                url_strings, max_age_hours=24, user_id=0
            )
            cached_dict = {p["link"]: p["content"] for p in cached_pages_list}
            uncached_set = set(urls_needing_scrape)
            uncached_url_dicts = [
                u for u in all_urls_to_scrape
                if (u.get("link", u) if isinstance(u, dict) else str(u))
                in uncached_set
            ]
            logger.info(
                "[%s] Cache: %d hits, %d misses (need Tor)",
                inv_uuid,
                len(cached_dict),
                len(uncached_url_dicts),
            )
        except Exception as exc:
            logger.info("[%s] Cache check failed (non-fatal): %s", inv_uuid, exc)
            cached_dict = {}
            uncached_url_dicts = list(all_urls_to_scrape)

        # ===== STEP 5: Scraping (no session held) =====
        uncached_url_dicts, ssrf_blocked = validate_urls_for_scraping(uncached_url_dicts)
        if ssrf_blocked:
            logger.info(
                "[%s] SSRF: blocked %d unsafe URLs",
                inv_uuid,
                len(ssrf_blocked),
            )
        logger.info(
            "[%s] STEP 5: Scraping %d URLs (skipped %d cached)...",
            inv_uuid,
            len(uncached_url_dicts),
            len(cached_dict),
        )
        freshly_scraped = await scrape_multiple(
            uncached_url_dicts,
            max_workers=12,
            investigation_id=str(inv_uuid),
        )
        await _update_progress(inv_uuid, 4, scraped_pages=freshly_scraped)
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # Shared cached content first, then local-cache, then freshly scraped.
        scraped_pages = {**shared_served, **cached_dict, **freshly_scraped}

        # ===== STEP 5.75: Content safety scan (Layer 4) — before cache/DB =====
        from utils.content_safety import gate_pages

        scraped_pages, blocked_count = gate_pages(
            scraped_pages, user_id=inv_user_id
        )
        if blocked_count > 0:
            logger.warning(
                "[%s] Blocked %d pages for prohibited content",
                inv_uuid,
                blocked_count,
            )

        # ===== STEP 5.5: Store new pages in vector cache (no session held) =====
        try:
            from vector.store import store_page

            stored_count = 0
            for page_url, page_text in freshly_scraped.items():
                if page_url not in scraped_pages:
                    continue
                page_text = scraped_pages[page_url]
                if page_text and len(page_text) > 100:
                    if store_page(url=page_url, content=page_text, metadata={"source": "scraper", "investigation_id": str(inv_uuid)}):
                        stored_count += 1
            logger.info("[%s] Stored %d new pages in vector cache", inv_uuid, stored_count)
        except Exception as exc:
            logger.info("[%s] Cache store failed (non-fatal): %s", inv_uuid, exc)
        run_metrics.record_scraping(
            attempted=len(all_urls_to_scrape) + len(shared_served),
            fetched=len(shared_served) + len(cached_dict)
            + sum(1 for text in freshly_scraped.values() if text),
            cache_hits=len(shared_served) + len(cached_dict),
        )
        _metric_finish("scraping")

        scraped_count = len(scraped_pages)
        logger.info(
            "[%s] Total for extraction: %d pages (%d cached + %d fresh, %d blocked)",
            inv_uuid,
            scraped_count,
            len(cached_dict),
            len(freshly_scraped),
            blocked_count,
        )

        page_records = [
            {"url": page_url, "text": page_text, "content": page_text}
            for page_url, page_text in scraped_pages.items()
        ]

        if enrichment_pages:
            enrichment_count = 0
            for ep in enrichment_pages:
                u = ep.get("url") or ep.get("link") or ""
                t = ep.get("text") or ep.get("content") or ""
                if u and (t or "").strip():
                    page_records.append({"url": u, "text": t, "content": t})
                    enrichment_count += 1

            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + %s enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
                enrichment_count,
            )
        else:
            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + 0 enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
            )

        # Paste-site pages already have fetched text — bypass scraping and
        # add them directly to the extraction pool, marked with their source.
        if paste_pages:
            paste_added = 0
            for pp in paste_pages:
                u = pp.get("url") or ""
                t = pp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "paste_site",
                        "source_name": pp.get("source_name"),
                    })
                    paste_added += 1
            logger.info(
                "[%s] Added %d paste-site pages to extraction pool",
                inv_uuid,
                paste_added,
            )

        # GitHub pages already have fetched text — bypass scraping and add
        # them directly to the extraction pool, marked source_type="github".
        if github_pages:
            github_added = 0
            for gp in github_pages:
                u = gp.get("url") or ""
                t = gp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "github",
                        "source_name": gp.get("source_name", "GitHub"),
                    })
                    github_added += 1
            logger.info(
                "[%s] Added %d GitHub pages to extraction pool",
                inv_uuid,
                github_added,
            )
        else:
            logger.info("[%s] GitHub: no results", inv_uuid)

        # GitLab pages already have fetched text — bypass scraping and add
        # them directly to the extraction pool, marked source_type="gitlab".
        if gitlab_pages:
            gitlab_added = 0
            for glp in gitlab_pages:
                u = glp.get("url") or ""
                t = glp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "gitlab",
                        "source_name": glp.get("source_name", "GitLab"),
                    })
                    gitlab_added += 1
            logger.info(
                "[%s] Added %d GitLab pages to extraction pool",
                inv_uuid,
                gitlab_added,
            )
        else:
            logger.info("[%s] GitLab: no results", inv_uuid)

        # RSS feed articles are pre-fetched — bypass scraping, add directly
        # to the extraction pool marked source_type="rss_feed".
        if rss_pages:
            rss_added = 0
            for rp in rss_pages:
                u = rp.get("url") or ""
                t = rp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "rss_feed",
                        "source_name": rp.get("source_name", "RSS Feed"),
                        "title": rp.get("title", ""),
                        "published_at": rp.get("published_at", ""),
                    })
                    rss_added += 1
            contributing_feeds = sorted({
                rp.get("source_name", "unknown") for rp in rss_pages
                if rp.get("source_name")
            })
            logger.info(
                "[%s] Added %d RSS articles to extraction pool (feeds: %s)",
                inv_uuid,
                rss_added,
                contributing_feeds,
            )
        else:
            logger.info("[%s] RSS feeds: no relevant articles", inv_uuid)

        if telegram_pages:
            for tp in telegram_pages:
                u = tp.get("url") or ""
                t = tp.get("text") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "telegram",
                        "source_name": "Telegram",
                    })
            logger.info("[%s] Added %d Telegram messages to extraction pool", inv_uuid, len(telegram_pages))

        # Apply the same content-safety gate to direct-source pages and collapse
        # mirrored material before entity extraction/page counting.
        from utils.content_safety import gate_pages
        from utils.content_dedup import deduplicate_page_records
        page_records, _side_blocked = gate_pages(
            page_records, user_id=inv_user_id
        )
        page_records = deduplicate_page_records(page_records)
        scraped_count = len(page_records)

        # P3.1 — usage-seeded auto-indexing. Feed the .onion pages this
        # investigation touched into the shared corpus (discovered_onions +
        # snapshot store + owned index), sanitized/consent-gated/provenance-
        # stamped at the unconfirmed tier. Non-fatal and a graceful no-op when
        # the store/index is unconfigured or in private mode (CC-3).
        try:
            from index_population import index_investigation_pages
            from db.session import get_session

            with get_session() as seed_session:
                usage_report = await index_investigation_pages(seed_session, page_records)
                seed_session.commit()
            logger.info(
                "[%s] Usage-seeded index: %d onions, %d snapshots, %d indexed (of %d pages)",
                inv_uuid,
                usage_report.onions,
                usage_report.snapshots,
                usage_report.indexed,
                usage_report.considered,
            )
        except Exception as _seed_exc:
            logger.info("[%s] Usage-seeded indexing failed (non-fatal): %s", inv_uuid, _seed_exc)

        non_empty_records = [r for r in page_records if len((r.get("text") or "").strip()) > 100]
        logger.info("[%s] Non-empty pages (>100 chars): %s", inv_uuid, len(non_empty_records))
        if not non_empty_records:
            first_length = len(page_records[0].get("text", "")) if page_records else 0
            logger.info("[%s] WARNING: All scraped pages are empty/short", inv_uuid)
            logger.info("[%s] First page content length: %s", inv_uuid, first_length)

        # ===== STEP 5.7: Detect content languages (no session held) =====
        try:
            from i18n.detect import detect_language

            lang_distribution: dict[str, int] = {}
            for page in page_records:
                text = page.get("content") or page.get("text") or ""
                if len(text) >= 50:
                    lang = detect_language(text[:500])
                    if lang:
                        lang_distribution[lang] = lang_distribution.get(lang, 0) + 1

            if lang_distribution:
                total_pages = sum(lang_distribution.values())
                non_english = {k: v for k, v in lang_distribution.items() if k != "en"}
                logger.info(
                    "[%s] Content languages: %s (%d/%d non-English pages)",
                    inv_uuid,
                    lang_distribution,
                    sum(non_english.values()),
                    total_pages,
                )
        except Exception as e:
            logger.info("[%s] Language detection failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6: Entity extraction (no session held) =====
        _metric_start("entity_extraction")
        logger.info("[%s] STEP 6: Extracting entities...", inv_uuid)
        extraction_input = non_empty_records if non_empty_records else page_records

        # Cap LLM-extraction pages per investigation.  Default 10 — enough
        # to cover the highest-value pages without burning the full
        # 45-66 LLM calls per investigation.  Override via env var.
        try:
            max_llm_pages = int(os.getenv("MAX_LLM_PAGES_PER_INV", "10") or 10)
        except ValueError:
            max_llm_pages = 10

        # Reuse the already-initialised llm_client.  When no client is
        # available the pipeline's internal `if run_llm_extraction and
        # llm is not None` guard keeps extraction at the regex+NER tier
        # (graceful degradation — see pipeline.py:129 and :254).
        run_llm_extraction = llm_client is not None

        async def _llm_extraction_progress(
            current: int,
            total: int,
            url: str,
        ) -> None:
            """SSE label update after each LLM-tier page completes."""
            label = f"Extracting entities (LLM tier — page {current}/{total})"
            logger.info(
                "[%s] LLM extraction progress: %d/%d — %s",
                inv_uuid, current, total, url,
            )
            try:
                await _update_progress(inv_uuid, label=label)
            except Exception as exc:
                logger.debug("LLM progress update failed (non-fatal): %s", exc)

        try:
            extraction_results = await extract_entities_from_pages(
                extraction_input,
                investigation_id=inv_uuid,
                llm=llm_client,
                run_llm_extraction=run_llm_extraction,
                max_llm_pages=max_llm_pages,
                llm_progress_callback=_llm_extraction_progress,
                # Graph construction is the dedicated STEP 7 phase below;
                # keeping the extractor's compatibility default enabled here
                # would build and persist the same graph twice.
                build_graph_on_complete=False,
            )
            total_entities = sum(r.entity_count for r in extraction_results)
            logger.info("[%s] Extracted %s entities", inv_uuid, total_entities)
            if total_entities == 0:
                logger.info("[%s] WARNING: No entities extracted", inv_uuid)
                logger.info(
                    "[%s] Pages passed to extractor: %s",
                    inv_uuid,
                    len(extraction_input),
                )
        except Exception as exc:
            logger.exception("[%s] Extraction failed: %s", inv_uuid, str(exc))
            extraction_results = []
            total_entities = 0

        await _update_progress(inv_uuid, 5, entity_count=total_entities)
        _metric_finish("entity_extraction")

        # HIBP Pwned Passwords (k-anonymity, presence-only) — runs on the in-memory
        # page text after extraction; the raw credential is hashed-and-discarded and
        # only a presence flag+count persist (as tags on the email entity).
        try:
            from credential_presence import scan_pages_for_pwned_credentials
            _hibp_page, _hibp_stats = await scan_pages_for_pwned_credentials(extraction_input)
            sources_used["hibp_pwned_passwords"] = {
                "status": _hibp_stats.get("status", "ok"),
                "count": _hibp_stats.get("pwned", 0),
            }
        except Exception as _hibp_exc:
            logger.debug("[%s] HIBP scan skipped: %s", inv_uuid, _hibp_exc)

        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # ===== Phase 6.2: Wrapped enrichment cluster =====
        _metric_start("enrichment")
        # Steps 6.1, 6.8, 6.2, 6.3, 6.4 are all reputation enrichment with
        # per-step timeouts.  The outer _run_with_timeout cap is the final
        # safety net if every sub-timeout fires.  Returns updated state.
        enrichment_result = await _run_with_timeout(
            _run_enrichment_phase(
                extraction_results, inv_uuid, investigation_id, sources_used,
            ),
            PHASE_TIMEOUTS["enrichment"],
            "enrichment",
            investigation_id,
        )
        if enrichment_result is None:
            logger.warning(
                "[%s] Enrichment phase hit %ds cap — continuing with partial results",
                inv_uuid, PHASE_TIMEOUTS["enrichment"],
            )
        else:
            extraction_results, sources_used = enrichment_result
            try:
                total_entities = sum(r.entity_count for r in extraction_results)
            except Exception:
                pass
        _metric_finish("enrichment")

        # ===== P4.1: Promote observed entities into the shared corpus =====
        # Byproduct of normal use (2.3): each observed entity/IOC is run through
        # the full P4.0 eight-step trust gate and persisted into global_entities
        # at the gate-assigned tier (unconfirmed by default; corroborated on ≥N
        # independent sources; feed_validated on a platform-derived trusted-feed
        # cross-hit). Consent-gated (private mode writes nothing), collision-safe,
        # and strictly non-fatal — like the P3.1 usage hook.
        try:
            from shared_corpus.promote import promote_investigation

            with get_session() as promo_session:
                promo_report = promote_investigation(promo_session, investigation_id)
                promo_session.commit()
            logger.info(
                "[%s] Shared-corpus promotion: considered %d, promoted %d "
                "(corroborated %d, feed_validated %d), rejected %d%s",
                inv_uuid,
                promo_report.considered,
                promo_report.promoted,
                promo_report.corroborated,
                promo_report.feed_validated,
                promo_report.rejected,
                " [private-mode: skipped]" if promo_report.skipped_private else "",
            )
        except Exception as _promo_exc:
            logger.info("[%s] Shared-corpus promotion failed (non-fatal): %s", inv_uuid, _promo_exc)

        # ===== STEP 6.5: Cross-reference against seed data (short-lived session) =====
        logger.info("[%s] STEP 6.5: Cross-referencing with historical data...", inv_uuid)
        try:
            from db.queries import cross_reference_with_seeds

            with get_session() as session:
                seed_matches = cross_reference_with_seeds(session, inv_uuid)
                logger.info("[%s] Found %s historical matches", inv_uuid, seed_matches)
        except Exception as e:
            logger.info("[%s] Cross-reference failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6.6: Build Stylometry Profiles (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.6: Building actor style profiles...")
        try:
            profiles_built = await asyncio.to_thread(
                _build_investigation_profiles,
                inv_uuid,
            )
            logger.info(f"[{inv_uuid}] Built {profiles_built} actor profiles")
        except Exception as e:
            logger.info(f"[{inv_uuid}] Profile building failed (non-fatal): {e}")

        # ===== STEP 6.7: Blockchain Wallet Enrichment (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.7: Enriching wallet entities...")
        try:
            from config import BLOCKCYPHER_TOKEN, ETHERSCAN_API_KEY

            blockchain_stats = await asyncio.to_thread(
                _enrich_wallets_sync,
                inv_uuid,
                BLOCKCYPHER_TOKEN,
                ETHERSCAN_API_KEY,
            )

            logger.info(
                f"[{inv_uuid}] Blockchain enrichment: "
                f"{blockchain_stats['successful_lookups']}/{blockchain_stats['wallets_looked_up']} lookups successful, "
                f"{blockchain_stats['edges_created']} PAID_TO edges created, "
                f"{blockchain_stats['connected_wallets_found']} connected wallets found"
            )
        except Exception as e:
            logger.info(f"[{inv_uuid}] Blockchain enrichment failed (non-fatal): {e}")

        await _update_progress(inv_uuid, 6)

        # ===== STEP 6.9: Update persistent actor profiles (non-blocking) =====
        # Aggregate the investigation's THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP
        # entities into the long-lived actor_profiles table.  Fire-and-forget
        # so a slow DB write never stalls the pipeline; errors are logged at
        # WARNING and never propagated.
        try:
            actor_entities: list = []
            for _r in extraction_results:
                actor_entities.extend(getattr(_r, "entities", []) or [])
            if actor_entities:
                _ap_task = asyncio.create_task(
                    _update_actor_profiles(actor_entities, inv_uuid),
                    name=f"actor-profiles-{inv_uuid}",
                )
                # Best-effort: we don't await the task here, but we make sure
                # any exception (other than CancelledError) is observed.
                def _log_actor_task_result(t: "asyncio.Task") -> None:
                    try:
                        t.result()
                    except asyncio.CancelledError:
                        pass
                    except Exception as exc:
                        logger.warning(
                            "[%s] Actor profile update task raised (non-fatal): %s",
                            inv_uuid,
                            exc,
                        )
                _ap_task.add_done_callback(_log_actor_task_result)
                logger.info(
                    "[%s] Actor profile update scheduled (%d entities, non-blocking)",
                    inv_uuid,
                    len(actor_entities),
                )
        except Exception as _ap_exc:
            logger.info(
                "[%s] Actor profile schedule failed (non-fatal): %s", inv_uuid, _ap_exc
            )

        # ===== STEP 6.91: Cross-alias resolution (non-blocking) =====
        # After the actor profile rows are in place, run the cross-alias
        # scoring pass to detect handle variants that share infrastructure,
        # PGP keys, or string similarity.  Findings are persisted as
        # ``likely_same_actor`` / ``confirmed_same_actor`` rows in
        # ``actor_aliases`` (the analyst can override via the API).
        # Scheduled as a separate task so the main pipeline never waits
        # on alias resolution latency.
        try:
            _alias_task = asyncio.create_task(
                _run_alias_resolution(inv_uuid),
                name=f"alias-resolution-{inv_uuid}",
            )
            def _log_alias_task_result(t: "asyncio.Task") -> None:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.warning(
                        "[%s] Alias resolution task raised (non-fatal): %s",
                        inv_uuid, exc,
                    )
            _alias_task.add_done_callback(_log_alias_task_result)
            logger.info(
                "[%s] Alias resolution scheduled (non-blocking)",
                inv_uuid,
            )
        except Exception as _alias_exc:
            logger.info(
                "[%s] Alias resolution schedule failed (non-fatal): %s",
                inv_uuid, _alias_exc,
            )

        # ===== Phase 6.2: Wrapped graph build (STEP 7) =====
        _metric_start("graph_build")
        await _run_with_timeout(
            _build_graph_phase(extraction_results, inv_uuid, investigation_id),
            PHASE_TIMEOUTS["graph_build"],
            "graph_build",
            investigation_id,
        )
        _metric_finish("graph_build")
        await _update_progress(inv_uuid, 7)

        # ===== Phase 6.2: Wrapped summary (STEP 8) =====
        _metric_start("summary_generation")
        summary = await _run_with_timeout(
            _generate_summary_phase(
                extraction_results,
                page_records,
                refined_query,
                llm_client,
                inv_uuid,
                investigation_id,
                scraped_count,
                total_entities,
            ),
            PHASE_TIMEOUTS["summary"],
            "summary",
            investigation_id,
        )
        if summary is None:
            summary = "Summary generation timed out."
        _metric_finish("summary_generation")
        logger.info("[%s] Summary preview: %s", inv_uuid, (summary or "")[:100])
        await _update_progress(inv_uuid, 8)

        # ===== Phase 6.2: Wrapped finalize (Final: DB update) =====
        _metric_start("finalization")
        await _run_with_timeout(
            _finalize_phase(inv_uuid, summary),
            PHASE_TIMEOUTS["finalize"],
            "finalize",
            investigation_id,
        )
        _metric_finish("finalization")
        persist_metrics(run_metrics)
        await _update_progress(inv_uuid, 9)
        logger.info("[%s] Investigation COMPLETED (run_id=%s)", inv_uuid, run_id)

    except Exception as exc:
        logger.exception("[%s] Investigation FAILED with exception: %s", investigation_id, exc)
        try:
            if "run_metrics" in locals():
                for _step_name in list(run_metrics.steps):
                    run_metrics.finish(_step_name)
                persist_metrics(run_metrics)
        except Exception:
            pass
        try:
            from db.models import Investigation
            from db.session import get_session

            with get_session() as session:
                session.query(Investigation).filter_by(id=uuid.UUID(investigation_id)).update(
                    {"status": "failed", "summary": f"Investigation failed: {exc!s}"[:500]}
                )
                session.commit()
        except Exception as update_exc:
            logger.warning("Failed to persist investigation failure status: %s", update_exc)
    finally:
        _cancel_tokens.pop(investigation_id, None)


def _enrich_wallets_sync(investigation_id, blockcypher_token, etherscan_key):
    """Sync wrapper for blockchain enrichment - creates its own session."""
    from sources.blockchain import enrich_wallets_for_investigation
    from db.session import get_session

    with get_session() as session:
        return enrich_wallets_for_investigation(
            investigation_id=investigation_id,
            session=session,
            blockcypher_token=blockcypher_token,
            etherscan_key=etherscan_key,
            max_wallets=10,
        )


async def _update_actor_profiles(
    entities: list,
    investigation_id: "uuid.UUID",
) -> None:
    """Persist extracted THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entities into
    the cross-investigation actor profile tables.

    Designed to be scheduled via ``asyncio.create_task`` so it never
    blocks the main pipeline.  Every step inside the manager swallows
    its own errors; we wrap the whole call in try/except so any
    unexpected failure (e.g. schema drift, missing module) is logged
    at WARNING and never propagated.
    """
    try:
        from sources.actor_profiles import ActorProfileManager

        manager = ActorProfileManager()
        stats = await manager.update_from_extraction(
            entities=entities or [],
            investigation_id=investigation_id,
        )
        logger.info(
            "[%s] Actor profile update: %s",
            investigation_id,
            stats,
        )
    except Exception as exc:
        logger.warning(
            "[%s] Actor profile update failed (non-fatal): %s",
            investigation_id,
            exc,
        )


async def _run_alias_resolution(investigation_id: "uuid.UUID") -> None:
    """Cross-alias resolution pass for actors found in *investigation_id*.

    Wraps :func:`sources.actor_profiles.run_alias_resolution` in a
    non-blocking, non-fatal shell so the investigation pipeline can
    schedule it via ``asyncio.create_task`` and move on.  Any error is
    logged at WARNING and never propagated.

    The pass is purely additive — it never modifies the actor's
    canonical handle, only inserts rows into ``actor_aliases`` with
    ``alias_type`` ∈ {``likely_same_actor``, ``confirmed_same_actor``}.
    """
    try:
        from sources.actor_profiles import run_alias_resolution

        new_count = await run_alias_resolution(str(investigation_id))
        logger.info(
            "[%s] Alias resolution: %d new alias relationships",
            investigation_id, new_count,
        )
    except Exception as exc:
        logger.warning(
            "[%s] Alias resolution failed (non-fatal): %s",
            investigation_id, exc,
        )


def _persist_graph_edges_sync(graph_obj, investigation_id):
    """Sync wrapper for graph edge persistence - creates its own session."""
    from graph.builder import persist_graph_edges
    from db.session import get_session

    with get_session() as session:
        return persist_graph_edges(
            graph_obj,
            investigation_id,
            session,
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("")
async def create_investigation(
    request: Request,
    body: InvestigationRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(require_password_not_reset_pending),
    _rl: None = Depends(_create_investigation_limit),
) -> dict:
    """Trigger an investigation asynchronously.

    Creates the investigation row in the DB synchronously before returning so
    that GET /investigations/{run_id} returns a valid record immediately while
    the pipeline runs. Dispatch goes onto the durable job queue (P2.3) so an
    in-flight investigation survives an API restart (a worker resumes/re-queues
    it) instead of being orphaned. Without a DB (degraded/no-persistence mode)
    it falls back to in-process BackgroundTasks.
    """
    from utils.content_safety import is_blocked_query, log_content_safety_event

    blocked, reason = is_blocked_query(body.query)
    if blocked:
        logger.warning(
            "Investigation blocked — prohibited content detected. User: %s",
            current_user.user.id,
        )
        log_content_safety_event(
            event_type="query_blocked",
            content_hash=hashlib.sha256(body.query.encode()).hexdigest()[:16],
            user_id=current_user.user.id,
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prohibited_content",
                "message": (
                    "This query cannot be processed. VoidAccess is intended "
                    "for legitimate security research only."
                ),
                "code": "CONTENT_BLOCKED",
            },
        )

    run_id = str(uuid.uuid4())
    payload = {
        "investigation_id": None,
        "run_id": run_id,
        "query": body.query,
        "model": body.model,
        "run_crawler": body.run_crawler,
    }

    if os.getenv("DATABASE_URL"):
        try:
            from db.session import get_session
            from db.queries import create_investigation as db_create
            from jobqueue import enqueue

            with get_session() as session:
                inv = db_create(session, query=body.query, user_id=current_user.user.id)
                inv.run_id = uuid.UUID(run_id)
                inv.status = "pending"
                session.flush()
                investigation_id = str(inv.id)
                payload["investigation_id"] = investigation_id
                # Durable dispatch: a worker (this process, or a fresh one after
                # a restart) claims and runs it. dedup_key ties the job to the
                # investigation so the startup sweep won't orphan it.
                enqueue(
                    session,
                    task_type="investigation",
                    payload=payload,
                    dedup_key=investigation_id,
                )
                session.commit()
        except Exception as exc:
            raise internal_http_exception(
                exc, context="create investigation record"
            )
    else:
        # No persistence configured — fall back to in-process BackgroundTasks
        # (single-shot, non-durable) so the tool still runs without a DB.
        investigation_id = str(uuid.uuid4())
        payload["investigation_id"] = investigation_id
        background_tasks.add_task(
            _run_investigation_task,
            investigation_id=investigation_id,
            run_id=run_id,
            query=body.query,
            model=body.model,
            run_crawler=body.run_crawler,
        )
    return {"run_id": run_id, "status": "pending", "query": body.query}


@router.get("")
async def list_investigations(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: "CurrentUser" = Depends(get_current_user),
) -> list[dict]:
    """Return a paginated list of the caller's own investigation summaries."""
    if not os.getenv("DATABASE_URL"):
        return []

    from db.session import get_session
    from db.models import Investigation
    from shared_corpus import filter_investigations_for_user

    # Scope to the authenticated owner. Previously this used ``current_user.id``
    # (which does not exist on CurrentUser — the numeric id is
    # ``current_user.user.id``); the AttributeError was swallowed by a broad
    # except that returned [], so callers always got an empty list. Both the bad
    # attribute reference and the swallowing except are removed; ownership is
    # scoped through the P2.0 fail-closed helper.
    user_id = current_user.user.id
    with get_session() as session:
        base = (
            session.query(Investigation)
            .filter(Investigation.is_seed == False)  # noqa: E712
        )
        invs = (
            filter_investigations_for_user(base, user_id)
            .order_by(Investigation.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [
            {
                "id": str(inv.id),
                "run_id": str(inv.run_id),
                "query": inv.query,
                "status": inv.status,
                "model_used": inv.model_used,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "entity_count": inv.entity_count or 0,
                "page_count": inv.page_count or 0,
            }
            for inv in invs
        ]


@router.post("/{investigation_id}/cancel")
async def cancel_investigation(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(require_password_not_reset_pending),
) -> dict:
    """Request cooperative cancellation of a running investigation.

    Sets a cancellation flag that the pipeline checks at each checkpoint.
    Returns 200 immediately — the pipeline may still be running; poll the
    investigation status to confirm it reaches 'cancelled'.
    Returns 409 if the investigation is already in a terminal state.
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    from db.session import get_session
    from db.queries import get_investigation_by_id_or_run

    try:
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=404, detail="Not found")
            terminal = {"completed", "failed", "cancelled", "completed_no_results"}
            if inv.status in terminal:
                raise HTTPException(
                    status_code=409,
                    detail=f"Investigation cannot be cancelled (current status: {inv.status})",
                )
            # Set flag by both run_id and inv.id — the pipeline task uses inv.id
            from db.models import Investigation
            session.query(Investigation).filter_by(id=inv.id).update(
                {"cancellation_requested": True}
            )
            session.commit()
            _set_cancelled(investigation_id)
            _set_cancelled(str(inv.id))
            logger.info(
                "[%s] Cancellation requested by user %s",
                inv_uuid,
                current_user.user.id,
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise internal_http_exception(exc, context="cancel_investigation")

    return _get_db_investigation(investigation_id)


@router.get("/{investigation_id}/progress")
async def investigation_progress(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(get_current_user),
) -> StreamingResponse:
    """
    SSE stream of investigation pipeline progress.
    Emits step updates every 5 seconds until a terminal state is reached.
    """
    from db.session import get_async_session
    from db.models import Investigation

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    # Verify existence and ownership before opening the stream
    async with get_async_session() as session:
        result = await session.execute(sa_select(Investigation).where(Investigation.id == inv_uuid))
        inv_check = result.scalar_one_or_none()
    if inv_check is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if str(inv_check.user_id) != str(current_user.user.id):
        raise HTTPException(status_code=404, detail="Not found")

    async def event_stream():
        last_step = None
        last_status = None
        timeout_count = 0
        max_timeout = 360
        data: dict = {}

        while timeout_count < max_timeout:
            try:
                async with get_async_session() as session:
                    result = await session.execute(
                        sa_select(Investigation).where(Investigation.id == inv_uuid)
                    )
                    inv = result.scalar_one_or_none()
            except Exception:
                break

            if inv is None:
                yield f"data: {json.dumps({'error': 'not_found'})}\n\n"
                break

            step = inv.current_step or 0
            label = inv.current_step_label or ""
            status = inv.status

            if step != last_step or status != last_status:
                data = {
                    "step": step,
                    "total_steps": 13,
                    "label": label,
                    "progress": int((step / 13) * 100),
                    "status": status,
                    "entity_count": inv.entity_count or 0,
                    "page_count": inv.page_count or 0,
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_step = step
                last_status = status

            if status in ("completed", "failed", "completed_no_results", "cancelled"):
                yield f"data: {json.dumps({**data, 'done': True})}\n\n"
                break

            timeout_count += 1
            await asyncio.sleep(5)

        yield ": stream closed\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{investigation_id}/analysis/temporal")
async def get_temporal_analysis(investigation_id: str) -> dict:
    """
    Run temporal analysis on pages from this investigation.

    Returns activity patterns by hour/day, anomalies, and silence breaks.
    Returns {"error": "insufficient_data"} (not 500) when there is not enough data.
    """
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        from db.session import get_session
        from db.models import Entity, Page
        from db.queries import get_investigation_by_id_or_run
        from collections import defaultdict
        from analysis.temporal import detect_anomalies, detect_silence_breaks, POISSON_ALPHA

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")

            from db.queries import get_entities_for_investigation
            from db.entity_views import entity_views
            entities = entity_views(session, get_entities_for_investigation(session, inv.id), investigation_id=inv.id)

            if not entities:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No entities found for this investigation",
                }

            page_ids = list({e.page_id for e in entities if e.page_id is not None})
            if not page_ids:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No page timestamps available",
                }

            pages = session.query(Page).filter(Page.id.in_(page_ids)).all()
            real_post_ts = sum(1 for p in pages if p.posted_at is not None)
            skipped_no_posted_at = len(pages) - real_post_ts
            if skipped_no_posted_at > 0:
                logger.debug(
                    "Temporal analysis: skipped %d pages due to missing posted_at (using content timestamp, not scrape time)",
                    skipped_no_posted_at,
                )
            timestamps = []
            for p in pages:
                if p.posted_at is not None:
                    timestamps.append(p.posted_at)

            if len(timestamps) < 3:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": f"Only {len(timestamps)} timestamps available (minimum 3)",
                    "data_points": len(timestamps),
                }

            by_hour: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_hour[ts.hour] += 1
            activity_by_hour = {str(h): int(by_hour.get(h, 0)) for h in range(24)}

            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            by_day: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_day[ts.weekday()] += 1
            activity_by_day = {day_names[d]: int(by_day.get(d, 0)) for d in range(7)}

            peak_hour_key = max(activity_by_hour, key=lambda h: activity_by_hour[h], default=None)
            peak_day_key = max(activity_by_day, key=lambda d: activity_by_day[d], default=None)

            daily_counts: dict = defaultdict(int)
            for ts in timestamps:
                daily_counts[ts.date()] += 1
            timeline = [
                {"date": d, "count": c} for d, c in sorted(daily_counts.items())
            ]

            anomalies_raw = detect_anomalies(timeline, alpha=POISSON_ALPHA)
            anomalies = [
                {
                    "date": str(a["date"]),
                    "count": a["count"],
                    "poisson_p_value": round(a["poisson_p_value"], 6),
                    "expected_rate": round(a["expected_rate"], 4),
                    "type": a["type"],
                    "description": (
                        f"Activity {'spike' if a['type'] == 'spike' else 'drop'}: "
                        f"observed {a['count']} vs expected ~{a['expected_rate']:.1f}/day "
                        f"(p={a['poisson_p_value']:.4f})"
                    ),
                }
                for a in anomalies_raw
            ]

            silence_raw = detect_silence_breaks(timeline, silence_days=7)
            silence_breaks = [
                {
                    "before": str(s["silent_from"]),
                    "after": str(s["silent_to"]),
                    "gap_days": s["gap_days"],
                    "significance": "high" if s["gap_days"] >= 14 else "medium",
                }
                for s in silence_raw
            ]

            all_dates = sorted(daily_counts.keys())
            timespan_days = (
                (all_dates[-1] - all_dates[0]).days if len(all_dates) >= 2 else 0
            )

            return {
                "investigation_id": investigation_id,
                "activity_by_hour": activity_by_hour,
                "activity_by_day": activity_by_day,
                "anomalies": anomalies,
                "silence_breaks": silence_breaks,
                "peak_hour": int(peak_hour_key) if peak_hour_key is not None else None,
                "peak_day": peak_day_key,
                "total_timespan_days": timespan_days,
                "data_points": len(timestamps),
            }
    except HTTPException:
        raise
    except Exception as exc:
        correlation_id = log_exception(exc, context="get_temporal_analysis")
        return {
            "error": "analysis_failed",
            "message": GENERIC_ERROR_MESSAGE,
            "correlation_id": correlation_id,
        }


@router.get("/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(get_current_user),
) -> dict:
    """Return full investigation record including entity count. 404 if not found."""
    if os.getenv("DATABASE_URL"):
        try:
            from db.session import get_session
            from db.queries import get_investigation_by_id_or_run
            inv_uuid = uuid.UUID(investigation_id)
            with get_session() as session:
                inv = get_investigation_by_id_or_run(session, inv_uuid)
                if inv is None:
                    raise HTTPException(status_code=404, detail="Investigation not found")
                if str(inv.user_id) != str(current_user.user.id):
                    raise HTTPException(status_code=404, detail="Not found")
        except HTTPException:
            raise
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    return _get_db_investigation(investigation_id)


@router.get("/{investigation_id}/entities")
async def get_investigation_entities(
    investigation_id: str,
    entity_type: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.75, ge=0.0, le=1.0),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    defang: bool = Query(default=True),
    freshness_exclude: Optional[str] = Query(default=None),
    include_suppressed: bool = Query(default=False),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return prioritized entities for an investigation, optionally filtered by type and confidence.

    Low-noise by default: entities are ordered by ``priority_score`` (high-signal
    first) and low-signal entities are collapsed behind ``include_suppressed`` —
    non-destructive, they are still returned (and counted in ``suppressed_count``)
    when the caller opts in.
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session
        from db.models import Entity, EntityRelationship, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from graph.builder import _make_node_id
        from utils.ioc_freshness import get_freshness_tag, get_freshness_display
        from utils.defang import defang_value, defang_value_checked, defang_text

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=404, detail="Not found")

            linked_ids_select = (
                sa_select(InvestigationEntityLink.entity_id)
                .where(InvestigationEntityLink.investigation_id == inv.id)
            )
            scoped_query = session.query(Entity).filter(
                (Entity.investigation_id == inv.id)
                | Entity.id.in_(linked_ids_select)
            )
            # Scores are normalized against the complete investigation, not
            # the current page or confidence/type filter.  This keeps ranking
            # stable across pagination and makes it comparable to the CLI
            # export for the same investigation.
            from db.entity_views import entity_views
            score_entities = entity_views(session, scoped_query.all(), investigation_id=inv.id)
            relationships = (
                session.query(EntityRelationship)
                .filter(EntityRelationship.investigation_id == inv.id)
                .all()
            )
            from utils.entity_priority import rank_map
            priority_by_id = rank_map(score_entities, relationships)

            query = scoped_query
            if entity_type:
                query = query.filter(Entity.entity_type == entity_type)
            if min_confidence > 0.0:
                pass  # Confidence is per-investigation and filtered after projection.

            candidates = [e for e in entity_views(session, query.all(), investigation_id=inv.id) if e.confidence >= min_confidence]

            # Safety net: filter prohibited entity values from the response.
            # Catches values that may have been stored before FIX 2 was deployed.
            from utils.content_safety import entity_value_is_blocked
            candidates = [
                e for e in candidates
                if not entity_value_is_blocked(e.entity_type, e.value)
            ]

            # Apply freshness exclusion before pagination so ``total`` and paging
            # stay correct.
            if freshness_exclude == "expired":
                candidates = [
                    e for e in candidates
                    if get_freshness_tag(
                        e.entity_type, e.last_seen_at, e.first_seen_at
                    ).value != "expired"
                ]

            # Low-noise default: order by priority (high-signal first) and collapse
            # suppressed low-signal entities behind ``include_suppressed`` — they
            # stay reachable, never deleted.
            def _rank_of(e):
                return priority_by_id.get(str(e.id), {}).get("rank", 1 << 30)

            candidates.sort(key=_rank_of)
            suppressed_count = sum(
                1 for e in candidates
                if priority_by_id.get(str(e.id), {}).get("suppressed", False)
            )
            if include_suppressed:
                visible = candidates
            else:
                visible = [
                    e for e in candidates
                    if not priority_by_id.get(str(e.id), {}).get("suppressed", False)
                ]

            total = len(visible)
            entities = visible[offset:offset + limit]

            out: list[dict] = []
            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass

                freshness_tag = get_freshness_tag(
                    e.entity_type,
                    e.last_seen_at,
                    e.first_seen_at,
                )

                graph_node_id = _make_node_id(e.entity_type, e.value, source_url)

                display_value = e.value
                display_context = e.context
                value_defanged = False
                if defang:
                    display_value, value_defanged = defang_value_checked(
                        e.entity_type, e.value or ""
                    )
                    if e.context:
                        display_context = defang_text(e.context)

                freshness_display = get_freshness_display(freshness_tag)

                out.append(
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "canonical_value": e.canonical_value,
                        "value": display_value,
                        "confidence": e.confidence,
                        "context_snippet": e.context_snippet,
                        "context": display_context,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                        "first_seen_at": e.first_seen_at.isoformat() if e.first_seen_at else None,
                        "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
                        "freshness_tag": freshness_tag.value,
                        "freshness_label": freshness_display["label"],
                        "freshness_color": freshness_display["color"],
                        "source_count": e.source_count or 1,
                        "investigation_count": getattr(e, "investigation_count", 1) or 1,
                        "corroborating_sources": json.loads(e.corroborating_sources or '["dark_web_scrape"]'),
                        "cross_referenced": (getattr(e, "investigation_count", 1) or 1) > 1,
                        "graph_node_id": graph_node_id,
                        "priority_score": priority_by_id.get(str(e.id), {}).get(
                            "priority_score", 0.0
                        ),
                        "priority_score_components": priority_by_id.get(
                            str(e.id), {}
                        ).get("priority_score_components", {}),
                        "priority_score_centrality_contribution": priority_by_id.get(
                            str(e.id), {}
                        ).get("priority_score_centrality_contribution", 0.0),
                        "typed_relationship_degree": priority_by_id.get(
                            str(e.id), {}
                        ).get("typed_relationship_degree", 0),
                        "rank": priority_by_id.get(str(e.id), {}).get("rank", 0),
                        "suppressed": priority_by_id.get(str(e.id), {}).get(
                            "suppressed", False
                        ),
                        "suppression_reason": priority_by_id.get(str(e.id), {}).get(
                            "suppression_reason"
                        ),
                        "defanged": value_defanged,
                    }
                )
            return {
                "items": out,
                "total": total,
                "skip": offset,
                "limit": limit,
                "suppressed_count": suppressed_count,
            }
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        raise internal_http_exception(exc, context="get_investigation_entities")

@router.get("/{investigation_id}/entities/export/csv")
async def export_investigation_entities_csv(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Export entities for an investigation as a CSV file download.

    Returns CSV with columns: entity_type, canonical_value, confidence,
    occurrence_count, first_seen_page, context_snippet
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.session import get_session
        from db.models import Entity, EntityRelationship, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from utils.entity_priority import rank_map

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=404, detail="Not found")

            linked_ids_select = (
                sa_select(InvestigationEntityLink.entity_id)
                .where(InvestigationEntityLink.investigation_id == inv.id)
            )
            entities = (
                session.query(Entity)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_select)
                )
                .all()
            )
            relationships = (
                session.query(EntityRelationship)
                .filter(EntityRelationship.investigation_id == inv.id)
                .all()
            )
            from db.entity_views import entity_views
            entities = entity_views(session, entities, investigation_id=inv.id)
            priority_by_id = rank_map(entities, relationships)
            # Export the full set (non-destructive) but ordered high-signal-first
            # so the CSV leads with the entities that matter.
            entities.sort(
                key=lambda e: priority_by_id.get(str(e.id), {}).get("rank", 1 << 30)
            )

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "entity_type",
                "canonical_value",
                "confidence",
                "priority_score",
                "occurrence_count",
                "first_seen_page",
                "context_snippet",
            ])

            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                context = (e.context_snippet or "").replace(
                    "\n", " "
                ).replace(
                    "\r", " "
                ).strip()
                writer.writerow([
                    e.entity_type,
                    e.canonical_value or e.value,
                    e.confidence,
                    priority_by_id.get(str(e.id), {}).get("priority_score", 0.0),
                    1,
                    source_url,
                    context[:500],
                ])

            csv_content = output.getvalue()

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=voidaccess_{investigation_id}_entities.csv"
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise internal_http_exception(
            exc, context="export_investigation_entities_csv"
        )


MAX_GRAPH_NODES = 500


def _rebuild_networkx_graph(nodes: list, edges: list) -> "nx.DiGraph":
    """
    Rebuild an ``nx.DiGraph`` from the API response's ``nodes`` and ``edges``.

    The frontend previously re-ran Louvain on a graphology copy of this data,
    which broke on large graphs and produced non-deterministic results across
    renders.  The backend now performs community detection server-side, so we
    just need a minimal graph that ``graph.builder.detect_communities`` can
    consume.

    Each node carries:
        - entity_type (str, may be empty for stubs)
        - confidence  (float)

    Each edge carries:
        - relationship_type (str, may be empty)
        - confidence        (float)
    """
    import networkx as nx

    G = nx.DiGraph()
    for n in nodes:
        nid = n.get("id")
        if not nid:
            continue
        G.add_node(
            nid,
            entity_type=n.get("type") or "",
            confidence=float(n.get("confidence") or 0.0),
        )
    for e in edges:
        src = e.get("source")
        tgt = e.get("target")
        if not src or not tgt:
            continue
        G.add_edge(
            src,
            tgt,
            relationship_type=e.get("type") or "",
            confidence=float(e.get("confidence") or 0.0),
        )
    return G


def _detect_communities_for_graph(graph_obj) -> dict[str, int]:
    """Run the shared detector over the complete API graph.

    ``_rebuild_networkx_graph`` is the API representation adapter.  It is
    correct here because it receives the full ``to_json`` graph, not the
    endpoint's presentation slice.  Its directed graph is equivalent to the
    CLI helper's simple undirected graph for detection: ``detect_communities``
    projects either input to an undirected graph before running the algorithm.
    """
    from graph.builder import detect_communities
    from graph.export import to_json

    graph_data = to_json(graph_obj)
    rebuilt = _rebuild_networkx_graph(graph_data["nodes"], graph_data["edges"])
    partition = detect_communities(rebuilt)
    return {
        str(node_id): int(community_id)
        for node_id, community_id in partition.items()
    }


@router.get("/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    include_viz: bool = Query(default=False),
    force_rebuild: bool = False,
) -> dict:
    """Return graph JSON for the investigation."""
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.queries import get_investigation_by_id_or_run
        from db.session import get_session
        from graph import build_graph_from_db, build_graph_from_db_cached, build_pyvis_network, get_html_string
        from graph.export import summary_stats, to_json

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            graph_status = getattr(inv, "graph_status", "pending")
            if graph_status not in ("built", "complete", "skipped_overflow", "no_data"):
                return {"status": "pending"}
            internal_id = inv.id
            graph_communities = _communities_cache.get(str(internal_id), {})
            if not graph_communities:
                graph_metadata = getattr(inv, "metadata_json", None)
                if isinstance(graph_metadata, str):
                    try:
                        graph_metadata = json.loads(graph_metadata)
                    except (ValueError, TypeError):
                        graph_metadata = {}
                if isinstance(graph_metadata, dict):
                    graph_communities = graph_metadata.get("communities") or {}
            graph_communities = {
                str(node_id): int(community_id)
                for node_id, community_id in graph_communities.items()
            }

        graph = build_graph_from_db_cached(investigation_id=internal_id) if not force_rebuild else build_graph_from_db(investigation_id=internal_id)
        graph_data = to_json(graph)
        nodes = sorted(graph_data["nodes"], key=lambda n: graph.degree(n["id"]), reverse=True)[:20]
        edges = sorted(graph_data["edges"], key=lambda e: e.get("confidence", 0.0), reverse=True)[:50]
        viz_html = None
        if include_viz:
            viz_html = get_html_string(build_pyvis_network(graph)) or None
        return {
            "status": "complete",
            "summary_stats": summary_stats(graph),
            "nodes": nodes,
            "edges": edges,
            "communities": graph_communities,
            "community_count": (
                len(set(graph_communities.values()))
                if graph_communities
                else 0
            ),
            "visualization_html": viz_html,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise internal_http_exception(exc, context="get_investigation_graph")


@router.get("/{investigation_id}/graph/stats")
async def get_investigation_graph_stats(investigation_id: str) -> dict:
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    from db.queries import get_investigation_by_id_or_run
    from db.session import get_session
    from graph import build_graph_from_db_cached
    from graph.export import summary_stats

    with get_session() as session:
        inv = get_investigation_by_id_or_run(session, inv_uuid)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if getattr(inv, "graph_status", "pending") != "complete":
            return {"status": "pending"}
        graph = build_graph_from_db_cached(investigation_id=inv.id)
    return {"status": "complete", "summary_stats": summary_stats(graph)}


@router.get("/{investigation_id}/graph/actor/{node_id}")
async def get_investigation_graph_actor(investigation_id: str, node_id: str) -> dict:
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    from db.queries import get_investigation_by_id_or_run
    from db.session import get_session
    from graph import build_graph_from_db_cached, get_actor_profile

    with get_session() as session:
        inv = get_investigation_by_id_or_run(session, inv_uuid)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if getattr(inv, "graph_status", "pending") != "complete":
            return {"status": "pending"}
        graph = build_graph_from_db_cached(investigation_id=inv.id)
    profile = get_actor_profile(graph, node_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Graph node not found")
    return profile


@router.get("/{investigation_id}/graph/path")
async def get_investigation_graph_path(
    investigation_id: str,
    source: Optional[str] = Query(default=None),
    target: Optional[str] = Query(default=None),
) -> dict:
    if not source or not target:
        raise HTTPException(status_code=400, detail="source and target are required")
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    from db.queries import get_investigation_by_id_or_run
    from db.session import get_session
    from graph import build_graph_from_db_cached
    from graph.queries import get_shortest_path

    with get_session() as session:
        inv = get_investigation_by_id_or_run(session, inv_uuid)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if getattr(inv, "graph_status", "pending") != "complete":
            return {"status": "pending"}
        graph = build_graph_from_db_cached(investigation_id=inv.id)

    path = get_shortest_path(graph, source, target)
    if path is None:
        return {"status": "complete", "path": None}
    return {
        "status": "complete",
        "path": [n.model_dump() if hasattr(n, "model_dump") else getattr(n, "__dict__", n) for n in path],
    }


# ---------------------------------------------------------------------------
# Shortest path between two entities
# ---------------------------------------------------------------------------


def _best_edge_between(
    G: "nx.MultiDiGraph",
    source: str,
    target: str,
    directed: bool,
) -> dict:
    """
    Return the best edge between source and target (either direction when
    directed=False, source→target only when directed=True).

    Picks the edge with the highest confidence when multiple parallel edges
    exist (MultiDiGraph).  Returns a dict with type + confidence, or an empty
    dict when no edge exists (shouldn't happen for a real path, but guard
    anyway).
    """
    candidates: list[dict] = []
    if directed:
        if G.has_edge(source, target):
            for data in G.get_edge_data(source, target).values():
                candidates.append(data)
    else:
        if G.has_edge(source, target):
            for data in G.get_edge_data(source, target).values():
                candidates.append(data)
        if G.has_edge(target, source):
            for data in G.get_edge_data(target, source).values():
                candidates.append(data)

    if not candidates:
        return {}

    best = max(candidates, key=lambda d: float(d.get("confidence") or 0.0))
    return {
        "type": best.get("edge_type", ""),
        "confidence": float(best.get("confidence") or 0.0),
    }


def _build_investigation_profiles(investigation_id) -> int:
    """
    For each THREAT_ACTOR entity in this investigation,
    build/update their style profile from available text.

    Uses context_snippets collected across all appearances
    of the same canonical entity.

    NOTE: This function creates its own session - never pass a session
    across thread boundaries.
    """
    from db.models import Entity
    from db.session import get_session
    from fingerprint.profiler import build_actor_profile, save_profile_to_db
    from sqlalchemy import func

    count = 0
    with get_session() as session:
        actors = (
            session.query(Entity.canonical_value, Entity.entity_type)
            .filter(
                Entity.investigation_id == investigation_id,
                Entity.entity_type.in_(["THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"]),
                Entity.canonical_value.isnot(None),
            )
            .distinct()
            .all()
        )

        for canonical_value, entity_type in actors:
            texts = (
                session.query(Entity.context_snippet)
                .filter(
                    Entity.entity_type == entity_type,
                    Entity.canonical_value == canonical_value,
                    Entity.context_snippet.isnot(None),
                    func.length(Entity.context_snippet) >= 50,
                )
                .all()
            )

            text_list = [t[0] for t in texts if t[0]]
            total_chars = sum(len(t) for t in text_list)

            if len(text_list) < 2 or total_chars < 200:
                continue

            try:
                profile = build_actor_profile(text_list)
                if profile:
                    save_profile_to_db(
                        profile=profile,
                        canonical_value=canonical_value,
                        entity_type=entity_type,
                        session=session,
                    )
                    count += 1
            except Exception as e:
                logger.debug(f"Profile build failed for {canonical_value}: {e}")
                continue

        session.commit()

    return count
