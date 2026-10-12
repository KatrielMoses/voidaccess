"""
cli/commands/investigate.py — voidaccess investigate "<query>"

Orchestrates the existing pipeline modules (search, sources, scraper,
extractor, llm) from a fresh async entry point. Re-implements the
sequencing that api.routes.investigations._run_investigation_task did
under FastAPI — minus auth, SSE, rate limiting, Postgres.

Outputs
    ~/.voidaccess/results/<slug>-<YYYYMMDD-HHMMSS>.json
    ~/.voidaccess/results/<slug>-<YYYYMMDD-HHMMSS>.md
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import typer
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typer entry point
# ---------------------------------------------------------------------------


def run(
    query: str = typer.Argument(..., help="Investigation query (e.g. 'LockBit ransomware')"),
    output: Optional[Path] = typer.Option(None, "--output", help="Override output directory"),
    model: Optional[str] = typer.Option(None, "--model", help="Override LLM model"),
    no_tor: bool = typer.Option(False, "--no-tor", help="Clearnet-only mode (skip Tor)"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM (query refinement, filtering, summary)"),
    use_scraping_api: bool = typer.Option(
        False,
        "--use-scraping-api",
        help=(
            "Clearnet only — activate the ScrapingAnt Web Scraping API REST transport "
            "(non-rotating, request-based billing, api.scrapingant.com/v2/general) "
            "for this run. One-shot override; does not touch on-disk config. Requires "
            "SCRAPINGANT_API_KEY to already be configured via `voidaccess configure` "
            "or another config surface. Falls back silently to direct clearnet fetch "
            "if the key is missing. Never affects Tor or .onion."
        ),
    ),
    use_proxies: bool = typer.Option(
        False,
        "--use-proxies",
        help=(
            "Clearnet only — activate the ScrapingAnt residential proxy transport "
            "(rotating IPs through residential.scrapingant.com:8080) for this run. "
            "One-shot override; does not touch on-disk config. Requires "
            "SCRAPINGANT_PROXY_USERNAME and SCRAPINGANT_PROXY_PASSWORD to have been "
            "configured once via `voidaccess configure`. Falls back silently to "
            "direct clearnet fetch if the proxy credentials are missing. Never "
            "affects Tor or .onion."
        ),
    ),
    pace: Optional[str] = typer.Option(
        None,
        "--pace",
        help=(
            "quiet | normal | aggressive — how patient and polite this run is with "
            "every scraped target (Tor, clearnet, search engines, source scrapers, "
            "the JS renderer). 'quiet' uses longer timeouts, longer gaps between "
            "retries, fewer retries and much longer politeness delays; 'aggressive' "
            "trades completeness for wall-clock. One-shot override; does not touch "
            "on-disk config, and wins over the persistent default set by "
            "`voidaccess configure pace`. Defaults to that persisted value, or "
            "'normal' if none is set."
        ),
    ),
    depth: str = typer.Option("normal", "--depth", help="shallow | normal | deep"),
    fmt: str = typer.Option("both", "--format", help="json | md | both"),
    quiet: bool = typer.Option(False, "--quiet", help="No live display; print final summary only"),
    events_jsonl: Optional[Path] = typer.Option(
        None,
        "--events-jsonl",
        help=(
            "Append one JSON progress event per line to this file (stage start/end "
            "with numeric counts, refined queries, completion). Does not change the "
            "terminal display."
        ),
    ),
) -> None:
    """Run an investigation: query → search → scrape → extract → enrich → report."""
    from voidaccess_cli import config as cli_config

    # --pace must be resolved BEFORE apply_env(): apply_env() only sets
    # VOIDACCESS_PACE when it is not already set, which is exactly what makes
    # the one-shot flag beat the persisted config for this invocation. Same
    # precedence rule as --use-proxies vs `configure proxy --enable`.
    #
    # A bad value is a hard error here, unlike the library-side silent
    # fallback: at the CLI the user is right there to fix the typo, and
    # silently running at a different pace than they asked for would make the
    # measured behaviour of the run a lie.
    if pace is not None:
        if not cli_config.PACE_PROFILES or pace.strip().lower() not in cli_config.PACE_PROFILES:
            console.print(
                f"[red]Invalid pace:[/red] {pace}. "
                f"Choose one of: {', '.join(cli_config.PACE_PROFILES)}."
            )
            raise typer.Exit(code=2)
        os.environ[cli_config.PACE_ENV_VAR] = pace.strip().lower()

    cli_config.apply_env()

    # Validate the query BEFORE any network activity.  An empty/whitespace-only
    # or trivially short query cannot yield real intelligence — accepting it
    # silently produces a report that looks identical to a genuine one but is
    # just noise from an essentially meaningless search.  Reject up front.
    MIN_QUERY_LENGTH = 3
    MAX_QUERY_LENGTH = 500
    stripped_query = (query or "").strip()
    if not stripped_query:
        console.print(
            "[red]Empty query.[/red] Provide something to investigate, e.g. "
            '[bold]voidaccess investigate "LockBit ransomware"[/bold].'
        )
        raise typer.Exit(code=2)
    if len(stripped_query) < MIN_QUERY_LENGTH:
        console.print(
            f"[red]Query too short.[/red] '{stripped_query}' is only "
            f"{len(stripped_query)} character(s); provide at least {MIN_QUERY_LENGTH} "
            "characters of meaningful context so results reflect a real query, "
            "not generic noise."
        )
        raise typer.Exit(code=2)
    if len(stripped_query) > MAX_QUERY_LENGTH:
        console.print(
            f"[red]Query too long.[/red] Your query contains "
            f"{len(stripped_query)} character(s); the maximum is "
            f"{MAX_QUERY_LENGTH}. Please shorten it and try again."
        )
        raise typer.Exit(code=2)

    # v1.6.2 — --use-scraping-api and --use-proxies are one-shot CLI flags
    # for activating the two independent clearnet transports in-process
    # only.  The REST API flag sets VOIDACCESS_USE_PROXIES=true; the
    # residential proxy flag sets VOIDACCESS_USE_PROXY=true.
    #
    # SCRAPINGANT_API_KEY / SCRAPINGANT_PROXY_USERNAME / SCRAPINGANT_PROXY_PASSWORD
    # are loaded into the environment from ~/.voidaccess/config.json by
    # apply_env() above, so the user does NOT need to `export` anything for
    # either flag to take effect — they only need to have configured the
    # required credentials once via `voidaccess configure`.  If the relevant
    # credential is missing, the chokepoint returns None and we silently fall
    # back to direct clearnet fetch exactly as before — investigation
    # completes normally, no error, no crash.
    #
    # The REST API transport (VOIDACCESS_USE_PROXIES, plural) is still
    # reachable via `voidaccess configure proxy --enable` for users who
    # specifically want the non-rotating REST transport set as a persistent
    # config option.
    if use_scraping_api:
        os.environ["VOIDACCESS_USE_PROXIES"] = "true"
    if use_proxies:
        os.environ["VOIDACCESS_USE_PROXY"] = "true"

    try:
        import spacy
        spacy.load("en_core_web_sm")
    except Exception:
        import subprocess
        import sys
        from rich.console import Console
        Console().print(
            "  [dim]→[/dim] Installing spaCy NER model (one-time)..."
        )
        subprocess.run(
            [sys.executable, "-m", "spacy",
             "download", "en_core_web_sm"],
            capture_output=True
        )

    if quiet:
        logging.getLogger().setLevel(logging.ERROR)

    from utils.content_safety import is_blocked_query
    blocked, reason = is_blocked_query(query)
    if blocked:
        console.print(f"[red]Query blocked:[/red] {reason}")
        if events_jsonl is not None:
            from progress import JsonlSink, ProgressEmitter

            _emitter = ProgressEmitter([JsonlSink(events_jsonl)])
            _emitter.failed("blocked_query", "query blocked by content policy")
            _emitter.close()
        raise typer.Exit(code=1)

    # A bad VOIDACCESS_ENRICHMENT_SOURCES must fail before any network work.
    from sources.enrichment_allowlist import EnrichmentAllowlistError, validate_enrichment_allowlist

    try:
        validate_enrichment_allowlist()
    except EnrichmentAllowlistError as exc:
        console.print(f"[red]Invalid VOIDACCESS_ENRICHMENT_SOURCES:[/red] {exc}")
        raise typer.Exit(code=2)

    if not cli_config.is_configured() and not no_llm:
        console.print("[yellow]No LLM configured.[/yellow] Run [bold]voidaccess configure[/bold] first, or pass --no-llm.")
        raise typer.Exit(code=2)

    if depth not in ("shallow", "normal", "deep"):
        console.print(f"[red]Invalid depth:[/red] {depth}")
        raise typer.Exit(code=2)
    if fmt not in ("json", "md", "both"):
        console.print(f"[red]Invalid format:[/red] {fmt}")
        raise typer.Exit(code=2)

    out_dir = Path(output).expanduser() if output else cli_config.get_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        from voidaccess_cli.adapters.sqlite import DatabaseSchemaError
        asyncio.run(
            _run_investigation(
                query=query,
                out_dir=out_dir,
                model=model,
                no_tor=no_tor,
                no_llm=no_llm,
                depth=depth,
                fmt=fmt,
                quiet=quiet,
                events_jsonl=events_jsonl,
            )
        )
    except DatabaseSchemaError as exc:
        console.print(f"[red]Database schema error:[/red] {exc}")
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130)


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


DEPTH_PRESETS = {
    "shallow": {"top_n": 10, "max_workers": 3, "extract_concurrency": 3},
    "normal":  {"top_n": 20, "max_workers": 5, "extract_concurrency": 5},
    "deep":    {"top_n": 40, "max_workers": 8, "extract_concurrency": 6},
}

# Opt-in speed controls (all unset by default, so self-hosters see no change).
# Each overrides one DEPTH_PRESETS value; the preset stays the named default.
SCRAPE_WORKERS_ENV = "VOIDACCESS_SCRAPE_WORKERS"
SEARCH_WORKERS_ENV = "VOIDACCESS_SEARCH_WORKERS"
EXTRACT_CONCURRENCY_ENV = "VOIDACCESS_EXTRACT_CONCURRENCY"
# Run the side sources (paste, GitHub, GitLab, RSS, Torch/Haystack, Telegram)
# concurrently with the Tor engine fan-out instead of after it.
CONCURRENT_COLLECT_ENV = "VOIDACCESS_CONCURRENT_COLLECT"
# The extraction LLM-page cap; the same variable and default the API path reads.
MAX_LLM_PAGES_ENV = "MAX_LLM_PAGES_PER_INV"
MAX_LLM_PAGES_DEFAULT = 10

# Summary phase: the first attempt gets this share of the phase budget, the
# retry (reduced context) gets the rest.
SUMMARY_FIRST_ATTEMPT_SHARE = 0.67
SUMMARY_RETRY_TOP_PAGES = 4
SUMMARY_RETRY_MAX_CHARS = 4000


def _env_positive_int(name: str) -> Optional[int]:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r - ignoring", name, raw)
        return None
    return value if value > 0 else None


def _preset_workers(preset: dict, key: str, env_name: str) -> int:
    """A DEPTH_PRESETS value, overridden by *env_name* when set."""
    return _env_positive_int(env_name) or preset[key]


def _max_llm_pages() -> int:
    return _env_positive_int(MAX_LLM_PAGES_ENV) or MAX_LLM_PAGES_DEFAULT


def _explicit_enrichment_timeout() -> Optional[int]:
    """The enrichment phase cap, only when the operator set it explicitly.

    The default (120 s) was documented but never applied on the CLI path.
    Applying it by default would change self-hoster results, so it is opt-in.
    """
    return _env_positive_int(_CLI_PHASE_TIMEOUT_ENV_VARS["enrichment"])


# Pages kept after LLM relevance filter (must match voidaccess.llm.filter_results cap).
LLM_FILTER_TOP_N = 15

INVESTIGATION_STEPS = [
    "Refining query",
    "Searching dark web",
    "Filtering results",
    "Scraping pages",
    "Discovering seeds",
    "Extracting entities",
    "Enriching intelligence",
    "Enriching domains",
    "Enriching hashes",
    "Enriching emails",
    "Building graph",
    "Community detection",
    "Generating summary",
    "Finalizing results",
]

# ---------------------------------------------------------------------------
# Phase 6.2 — per-phase timeouts (CLI mirror of API PHASE_TIMEOUTS)
# ---------------------------------------------------------------------------
# Defaults mirror the API.  All values are env-var-overridable so ops can
# loosen the cap on a slow host without code changes.
_CLI_PHASE_TIMEOUT_DEFAULTS = {
    "enrichment": 120,
    "graph_build": 60,
    "summary": 90,
    "finalize": 30,
}

_CLI_PHASE_TIMEOUT_ENV_VARS = {
    "enrichment": "VOIDACCESS_ENRICHMENT_TIMEOUT",
    "graph_build": "VOIDACCESS_GRAPH_TIMEOUT",
    "summary": "VOIDACCESS_SUMMARY_TIMEOUT",
    "finalize": "VOIDACCESS_FINALIZE_TIMEOUT",
}


def _cli_phase_timeout(name: str) -> int:
    """Resolve a single CLI phase timeout from env vars (read at call time)."""
    default = _CLI_PHASE_TIMEOUT_DEFAULTS.get(name, 60)
    env_var = _CLI_PHASE_TIMEOUT_ENV_VARS.get(name)
    if env_var:
        raw = os.getenv(env_var)
        if raw:
            try:
                return int(raw)
            except ValueError:
                logger.warning(
                    "[cli-phase-timeout] Invalid %s=%r — using default %ds",
                    env_var, raw, default,
                )
    return default


CLI_PHASE_TIMEOUTS: dict[str, int] = {
    name: _cli_phase_timeout(name) for name in _CLI_PHASE_TIMEOUT_DEFAULTS
}


def _clearnet_page_text(page: dict) -> str:
    """Return the text field used both for scoring and later extraction."""
    return (
        page.get("text")
        or page.get("content")
        or page.get("cleaned_text")
        or page.get("text_content")
        or ""
    )


def _append_enrichment_pages_to_manifest(
    scraped_pages: list[dict],
    enrichment_pages: list[dict],
) -> list[dict]:
    """Add enrichment page records to the final page manifest.

    Enrichment pages are extracted in a second pass, after the core scraped
    pages have been assembled.  They still create entities and co-occurrence
    edges, so omitting them from ``pages_scraped`` makes the user-facing page
    count disagree with the graph's provenance.  Keep one manifest entry per
    URL while preserving the existing core-page records when a URL overlaps.
    """
    seen_urls = {
        str(page.get("url") or page.get("link") or "")
        for page in scraped_pages
        if page.get("url") or page.get("link")
    }
    for page in enrichment_pages:
        url = str(page.get("url") or page.get("link") or "").strip()
        if not url or url in seen_urls:
            continue
        scraped_pages.append(
            {
                "url": url,
                "text": _clearnet_page_text(page),
                "source": page.get("source") or page.get("source_type") or "enrichment",
                "source_type": page.get("source_type"),
            }
        )
        seen_urls.add(url)
    return scraped_pages


def _annotate_no_llm_dependency_relationships(
    pages: list[dict],
    route: str,
) -> list[dict]:
    """Run dependency extraction for connectors that bypass ``scrape.py``."""
    from extractor.dependency_relationship import (
        extract_dependency_relationships_from_page,
    )

    annotated: list[dict] = []
    for page in pages:
        item = dict(page)
        text = _clearnet_page_text(item)
        claims = extract_dependency_relationships_from_page(text) if text else []
        item["dependency_relationships"] = claims
        item["dependency_extraction_invoked"] = True
        item["dependency_extraction_route"] = route
        logger.info(
            "Dependency extractor invoked for %s route: %d chars, %d claims",
            route,
            len(text),
            len(claims),
        )
        annotated.append(item)
    return annotated


def _filter_clearnet_pages(
    pages: list[dict],
    query: str,
    top_n: int,
    llm: Any = None,
) -> list[dict]:
    """Filter side-source pages without changing the Tor candidate path."""
    candidates: list[dict] = []
    unique_pages: list[dict] = []
    seen_urls: set[str] = set()
    for page in pages:
        url = page.get("url") or page.get("link")
        text = _clearnet_page_text(page)
        if not url or not text or url in seen_urls:
            continue
        seen_urls.add(url)
        unique_pages.append(page)
        candidates.append({
            "link": url,
            "title": page.get("title") or "",
            "content": text,
        })

    if not unique_pages:
        return []

    try:
        if llm is None:
            from voidaccess.llm import _heuristic_filter
            picked = _heuristic_filter(candidates, query, top_n)
            return [unique_pages[index - 1] for index in picked]

        from voidaccess.llm import filter_results
        selected = filter_results(llm, query, candidates, top_n) or candidates
        selected_urls = {
            item.get("link") or item.get("url")
            for item in selected
        }
        return [
            page for page in unique_pages
            if (page.get("url") or page.get("link")) in selected_urls
        ]
    except Exception as exc:
        # Side-source enrichment is best effort; retain the previous behavior
        # if a secondary filter pass fails.
        logger.warning(
            "Clearnet relevance filter failed (%s); retaining all side pages",
            exc,
        )
        return unique_pages


async def _cli_run_with_timeout(coro, timeout_seconds: int, phase_name: str, investigation_id: str):
    """Phase 6.2 timeout wrapper for the CLI.

    On timeout: logs a warning and returns ``None``.  Never raises
    ``TimeoutError`` to the caller — the pipeline must always be able to
    continue with partial results.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] CLI phase '%s' timed out after %ds — continuing with partial results",
            investigation_id, phase_name, timeout_seconds,
        )
        return None


async def _run_investigation(
    query: str,
    out_dir: Path,
    model: Optional[str],
    no_tor: bool,
    no_llm: bool,
    depth: str,
    fmt: str,
    quiet: bool,
    events_jsonl: Optional[Path] = None,
    sinks: Optional[list] = None,
) -> None:
    """Run the pipeline, reporting progress to the Rich display and any extra
    sinks (``events_jsonl`` path, or ``sinks`` such as a ``CallbackSink``)."""
    from progress import JsonlSink, ProgressEmitter

    emitter = ProgressEmitter()
    extra_sinks = list(sinks or [])
    if events_jsonl is not None:
        extra_sinks.append(JsonlSink(events_jsonl))
    for sink in extra_sinks:
        emitter.add_sink(sink)
    try:
        await _run_investigation_impl(
            query, out_dir, model, no_tor, no_llm, depth, fmt, quiet, emitter
        )
    except BaseException as exc:
        if not emitter.terminal_sent:
            reason = "cancelled" if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt)) else "error"
            if reason == "cancelled":
                emitter.cancelled()
            else:
                emitter.failed(reason, type(exc).__name__)
        raise
    finally:
        emitter.close()


async def _run_investigation_impl(
    query: str,
    out_dir: Path,
    model: Optional[str],
    no_tor: bool,
    no_llm: bool,
    depth: str,
    fmt: str,
    quiet: bool,
    emitter: Any,
) -> None:
    from progress import Stage
    from voidaccess_cli import config as cli_config
    from voidaccess_cli.reporter import PipelineReporter
    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    from voidaccess_cli.display import InvestigationDisplay
    from voidaccess_cli.tor_detect import detect_tor, tor_unavailable_message

    cfg = cli_config.load_config()
    preset = DEPTH_PRESETS[depth]

    # v1.6.2 — reset per-run transport counters so the live display and
    # final summary reflect THIS run, not a lifetime aggregate from any
    # previous investigation that ran in the same Python process.
    try:
        from sources.proxy_client import reset_run_counters
        reset_run_counters()
    except Exception:
        # Never let a counter-reset glitch break the run; the counters
        # default to 0 so absence is safe.
        pass

    from voidaccess_cli.display import RichDisplaySink

    emitter.add_sink(RichDisplaySink(InvestigationDisplay(quiet=quiet)))
    display = PipelineReporter(emitter)

    # v1.6.2 — set the rotating-proxies indicator row BEFORE start() so
    # it's visible from the first refresh of the live display, not
    # appended after the run completes.  Use the proxy transport gate
    # (proxy transport gate) per the v1.6.2 fix that aligns
    # --use-proxies with the actual rotating-proxy transport the flag
    # name and the CLI banner promise.
    try:
        from sources.proxy_client import is_proxy_transport_enabled
        display.set_proxy_state("on" if is_proxy_transport_enabled() else "off")
    except Exception:
        pass

    display.start(query, steps=INVESTIGATION_STEPS)

    # Background tasks scheduled during the pipeline that must be awaited
    # before asyncio.run() exits, otherwise they get cancelled mid-write.
    # Populated by ``asyncio.create_task(...)`` calls that want to remain
    # non-blocking from the perspective of the main pipeline, but still
    # need a deterministic drain before the process exits.
    _background_tasks: list[asyncio.Task] = []

    # --- DB init ----------------------------------------------------------
    sqlite_adapter.init_db()
    # Validate the migrated schema before Tor/LLM/network work and before the
    # investigation row is created.  A stale SQLite schema used to let every
    # entity merge fail inside isolated savepoints, leaving a silent running
    # investigation with no report.
    sqlite_adapter.validate_schema()
    _patch_llm_extraction_cache(sqlite_adapter)

    # Phase 6.3 — clean up CLI investigations that were interrupted by a
    # prior Ctrl-C / kill -9 / power loss.  asyncio.run() can't leave rows
    # mid-flight the way FastAPI BackgroundTasks can, but Ctrl-C during a
    # long pipeline can — this is the safety net.
    try:
        cleaned = await sqlite_adapter.cleanup_stuck_investigations(cutoff_minutes=None)
        if cleaned and not quiet:
            console.print(
                f"[yellow]Marked {cleaned} interrupted investigation(s) as failed.[/yellow]"
            )
    except Exception as exc:
        logger.debug("CLI stuck-investigation cleanup failed (non-fatal): %s", exc)

    # --- Tor preflight ----------------------------------------------------
    tor_proxy: Optional[str] = None
    if not no_tor:
        status = detect_tor()
        if status.proxy_url:
            tor_proxy = status.proxy_url
            os.environ["TOR_PROXY_HOST"] = status.host or "127.0.0.1"
            os.environ["TOR_PROXY_PORT"] = str(status.port or 9050)
        else:
            display.error(tor_unavailable_message())
            emitter.failed("error", "tor unavailable")
            return

    # --- LLM instance -----------------------------------------------------
    llm = None
    chosen_model = model or cli_config.get_llm_model(cfg)
    if not no_llm:
        try:
            from voidaccess.llm import get_llm
            provider = cli_config.get_llm_provider(cfg)
            provider_env = cli_config.PROVIDER_ENV.get(provider)
            api_key = cli_config.get_llm_key(cfg)
            api_keys = {provider_env: api_key} if provider_env and api_key else {}
            llm = get_llm(chosen_model, api_keys=api_keys)
        except Exception as exc:
            display.update_step("Refining query", "fail", f"LLM init failed: {exc}")
            llm = None

    # --- Create investigation row -----------------------------------------
    investigation_id = sqlite_adapter.save_investigation(
        query=query,
        model_used=chosen_model if llm is not None else None,
        status="running",
    )
    inv_uuid = uuid.UUID(investigation_id)
    from utils.investigation_metrics import InvestigationMetrics, persist as persist_metrics, set_current
    pipeline_metrics = InvestigationMetrics(inv_uuid)
    set_current(pipeline_metrics)

    # Step-cost instrumentation.  ``start``/``finish`` bracket each phase so
    # duration_ms is recorded, and — critically — so ``record_llm_call`` (which
    # only credits steps that are currently *active*) attributes LLM calls to
    # the right step.  Mirrors the API pipeline's _metric_start/_metric_finish.
    def _metric_start(step_name: str) -> None:
        pipeline_metrics.start(step_name)

    def _metric_finish(step_name: str) -> None:
        pipeline_metrics.finish(step_name)

    sources_used: dict[str, dict[str, Any]] = {}
    page_count_by_url: dict[str, dict[str, Any]] = {}

    # --- Step 1 — refine query -------------------------------------------
    _metric_start("query_refinement")
    display.stage_start(Stage.REFINE)
    display.update_step("Refining query", "active")
    refined = query
    if llm is not None:
        try:
            from voidaccess.llm import refine_query
            refined = await asyncio.to_thread(refine_query, llm, query) or query
        except Exception as exc:
            display.update_step("Refining query", "fail", str(exc))
            refined = query
        else:
            display.update_step("Refining query", "ok", f"→ {refined!r}")
    else:
        display.update_step("Refining query", "skip", "--no-llm")
    sqlite_adapter.update_investigation(investigation_id, {"refined_query": refined})
    _metric_finish("query_refinement")
    emitter.refined([refined])
    display.stage_end(Stage.REFINE, "skipped" if llm is None else "end")

    # --- Step 2 — search fan-out -----------------------------------------
    _metric_start("source_gathering")
    display.stage_start(Stage.COLLECT)
    display.update_step("Searching dark web", "active")
    search_links: list[dict] = []
    paste_pages: list[dict] = []
    github_pages: list[dict] = []
    gitlab_pages: list[dict] = []
    rss_pages: list[dict] = []
    telegram_pages: list[dict] = []
    onion_pages: list[dict] = []
    search_summary: dict[str, int] = {}

    async def _tor_search() -> None:
        nonlocal search_links, search_summary
        if not no_tor:
            try:
                from search import get_last_search_summary, get_search_results_async
                display.update_substep("Searching dark web", "Tor engines", "active")
                search_links = await asyncio.to_thread(
                    get_search_results_async,
                    refined,
                    _preset_workers(preset, "max_workers", SEARCH_WORKERS_ENV),
                    llm,
                )
                display.update_substep("Searching dark web", "Tor engines", "ok")
                search_summary = get_last_search_summary()
                sources_used["tor_search"] = {"status": "ok", "count": len(search_links)}
            except Exception as exc:
                display.update_substep("Searching dark web", "Tor engines", "fail")
                search_summary = {}
                sources_used["tor_search"] = {"status": "fail", "error": str(exc)}
        else:
            display.update_substep("Searching dark web", "Tor engines", "skip")
            sources_used["tor_search"] = {"status": "skipped"}

    # Opt-in: overlap the Tor engine fan-out with the side sources.
    concurrent_collect = (os.getenv(CONCURRENT_COLLECT_ENV) or "").strip().lower() in ("1", "true", "on", "yes")
    tor_task = asyncio.ensure_future(_tor_search()) if concurrent_collect else None
    if tor_task is None:
        await _tor_search()

    # Parallel clearnet sources
    async def _safe(coro_factory, label, key):
        display.update_substep("Searching dark web", label, "active")
        try:
            res = await coro_factory()
            display.update_substep("Searching dark web", label, "ok")
            sources_used[key] = {"status": "ok", "count": len(res) if res else 0}
            return res or []
        except Exception as exc:
            display.update_substep("Searching dark web", label, "fail")
            sources_used[key] = {"status": "fail", "error": str(exc)}
            return []

    async def _onionsearch():
        # --no-tor means NO Tor traffic for the entire run.  Torch and
        # Haystack are .onion search engines fetched over the Tor SOCKS proxy,
        # and they return real .onion result URLs that would otherwise be
        # appended to the scrape list and routed back through Tor.  Skipping
        # the lookup entirely is what makes "zero Tor traffic" a direct
        # consequence rather than a downstream filter after Tor was contacted.
        if no_tor:
            return []
        from sources.engines import search_onionsearch
        return await search_onionsearch(refined)

    async def _telegram():
        if not os.getenv("TELEGRAM_API_ID", "").strip() or not os.getenv("TELEGRAM_API_HASH", "").strip():
            return []
        from sources.telegram import fetch_telegram_messages
        channels = [c.strip() for c in os.getenv("TELEGRAM_CHANNELS", "").split(",") if c.strip()]
        return await fetch_telegram_messages(channels, refined)

    side_tasks = await asyncio.gather(
        _safe(lambda: _scrape_pastes(refined), "Paste sites", "paste_sites"),
        _safe(lambda: _scrape_github(refined), "GitHub", "github"),
        _safe(lambda: _scrape_gitlab(refined), "GitLab", "gitlab"),
        _safe(lambda: _scrape_rss(refined), "RSS feeds", "rss"),
        _safe(_onionsearch, "Torch + Haystack", "onion_search"),
        _safe(_telegram, "Telegram", "telegram"),
    )
    paste_pages, github_pages, gitlab_pages, rss_pages, onion_pages, telegram_pages = side_tasks
    if tor_task is not None:
        await tor_task
    for onion in onion_pages:
        search_links.append({
            "link": onion.get("url", ""),
            "title": onion.get("title", ""),
            "snippet": onion.get("snippet", ""),
            "source_engine": onion.get("source", ""),
        })
    if not os.getenv("TELEGRAM_API_ID", "").strip() or not os.getenv("TELEGRAM_API_HASH", "").strip():
        sources_used["telegram"] = {"status": "skipped_no_key"}
    for _engine_name in ("Torch", "Haystack"):
        if no_tor:
            # Onion search engines are never contacted in --no-tor mode.
            sources_used[_engine_name.lower()] = {"status": "skipped", "count": 0}
            continue
        _count = sum(1 for item in onion_pages if item.get("source") == _engine_name)
        from sources.engines import get_last_onionsearch_status
        _engine_status = get_last_onionsearch_status().get(_engine_name, "ok")
        sources_used[_engine_name.lower()] = {
            "status": "ok" if _engine_status.startswith("ok_") else _engine_status,
            "count": _count,
        }

    # --no-tor defence-in-depth: even though the Tor search branch and the
    # onion search engines are both skipped above, strip any .onion URL that
    # may have reached the link list from ANY other side-source before it can
    # be handed to the scraper (the scraper correctly routes .onion links
    # through Tor, which is exactly what --no-tor must prevent).  This runs
    # BEFORE any scrape, so no Tor connection is ever attempted.
    if no_tor:
        _before = len(search_links)
        search_links = [
            _l for _l in search_links
            if ".onion" not in str(_l.get("link", "")).lower()
        ]
        _stripped = _before - len(search_links)
        if _stripped:
            logger.warning(
                "[no-tor] Stripped %d .onion link(s) from search results before scraping",
                _stripped,
            )

    if not no_tor and search_summary:
        display.update_step(
            "Searching dark web",
            "ok",
            (
                f"{search_summary.get('active', 0)}/{search_summary.get('total', 0)} engines active, "
                f"{search_summary.get('circuits_open', 0)} circuits open, {len(search_links)} results"
            ),
        )
    else:
        display.update_step("Searching dark web", "ok", f"{len(search_links)} links + side sources")
    _side_attempted = 4 + (0 if no_tor else 1) + (
        1 if os.getenv("TELEGRAM_API_ID", "").strip() and os.getenv("TELEGRAM_API_HASH", "").strip() else 0
    )
    display.stage_end(
        Stage.COLLECT,
        sources_queried=(0 if no_tor else int(search_summary.get("active", 0))) + _side_attempted,
        results_found=(
            len(search_links) + len(paste_pages) + len(github_pages)
            + len(gitlab_pages) + len(rss_pages) + len(telegram_pages)
        ),
    )

    # --- Step 3 — filter results ------------------------------------------
    display.stage_start(Stage.FILTER)
    display.update_step("Filtering results", "active")
    filter_top_n = LLM_FILTER_TOP_N
    filtered_links = search_links[: filter_top_n * 2] if search_links else []
    if llm is not None and search_links:
        try:
            from voidaccess.llm import filter_results
            filtered_links = await asyncio.to_thread(filter_results, llm, refined, search_links, filter_top_n) or search_links
            filtered_links = filtered_links[:filter_top_n]
            display.update_step("Filtering results", "ok", f"top {len(filtered_links)}")
        except Exception as exc:
            display.update_step("Filtering results", "fail", str(exc))
            filtered_links = search_links[:filter_top_n]
    elif no_llm and search_links:
        # No LLM: pick pages via the heuristic ranker instead of just
        # taking the first N (which are usually search-engine index
        # pages and low-value landing pages).
        try:
            from voidaccess.llm import _heuristic_filter
            picked = _heuristic_filter(search_links, refined or query, filter_top_n)
            filtered_links = [search_links[i - 1] for i in picked]
            display.update_step(
                "Filtering results",
                "ok",
                f"heuristic top {len(filtered_links)}",
            )
        except Exception as exc:
            logger.warning("Heuristic filter failed (%s); falling back to first-N", exc)
            filtered_links = (search_links or [])[:filter_top_n]
            display.update_step("Filtering results", "skip", f"{len(filtered_links)} kept")
    else:
        filtered_links = (search_links or [])[:filter_top_n]
        display.update_step("Filtering results", "skip" if no_llm else "ok", f"{len(filtered_links)} kept")

    # Keep the existing Tor/onion list and scoring path untouched. Clearnet
    # source pages are scored separately before they reach the merge below.
    clearnet_pages = [
        page
        for extra in (paste_pages, github_pages, gitlab_pages, rss_pages)
        for page in extra
    ]
    filtered_clearnet_pages = await asyncio.to_thread(
        _filter_clearnet_pages,
        clearnet_pages,
        refined or query,
        filter_top_n,
        llm,
    )

    display.update_step(
        "Filtering results",
        "ok" if (search_links or clearnet_pages) else ("skip" if no_llm else "ok"),
        f"{len(filtered_links) + len(filtered_clearnet_pages)} kept",
    )
    display.stage_end(
        Stage.FILTER,
        "skipped" if (no_llm or llm is None) else "end",
        message=f"{len(filtered_links) + len(filtered_clearnet_pages)} kept",
    )

    _metric_finish("source_gathering")

    # --- Step 3.9 — read-from-shared before scraping (P4.2) --------------
    # Consult the shared tier (populated by OTHER users' runs) for cached page
    # content, query-relevant seeds, and pre-extracted entities — reading ONLY
    # user-agnostic shared tables. Served content skips the Tor re-scrape.
    # Consent-gated + non-fatal; a $0/no-corpus install serves nothing.
    display.stage_start(Stage.FETCH)
    shared_served_pages: dict[str, str] = {}
    shared_entities: list[dict] = []
    try:
        from db.session import get_session
        from shared_corpus.read import read_shared_before_scrape

        with get_session() as shared_session:
            shared_bundle = await read_shared_before_scrape(
                shared_session, refined, filtered_links
            )
        shared_served_pages = shared_bundle.served
        shared_entities = shared_bundle.entities
        _rem_links = {
            (u.get("link") if isinstance(u, dict) else u) for u in shared_bundle.remaining
        }
        seed_additions = [
            s for s in shared_bundle.seeds if s.get("link") not in _rem_links
        ]
        filtered_links = shared_bundle.remaining + seed_additions
        if shared_bundle.skipped_private:
            display.update_step("Reading shared corpus", "skip", "private mode")
        elif shared_bundle.served_count or seed_additions:
            display.update_step(
                "Reading shared corpus", "ok",
                f"{shared_bundle.served_count} cached served, {len(seed_additions)} seeds",
            )
    except Exception as exc:
        logger.debug("Shared read failed (non-fatal): %s", exc)

    # --- Step 4 — scrape pages -------------------------------------------
    _metric_start("scraping")
    display.update_step("Scraping pages", "active")
    scraped_pages: list[dict] = []
    # Shared cached content served without a Tor re-scrape (point-2 win).
    for _url, _text in shared_served_pages.items():
        if _text:
            scraped_pages.append({"url": _url, "text": _text, "source": "shared_corpus"})
    if filtered_links:
        try:
            from scraper.scrape import scrape_multiple

            async def _scrape_with_progress():
                # scrape_multiple does its own batching; we surface current URL
                # by intercepting via a side ticker since the underlying API
                # doesn't expose per-URL callbacks. Best effort: just show the
                # first URL while the gather runs.
                display.update_current_url(
                    (filtered_links[0].get("link") if filtered_links else "") or ""
                )
                return await scrape_multiple(
                    filtered_links,
                    max_workers=_preset_workers(preset, "max_workers", SCRAPE_WORKERS_ENV),
                    investigation_id=investigation_id,
                    extract_typed_relationships=no_llm,
                )

            results = await _scrape_with_progress()
            display.update_current_url("")
            relationship_claims_by_url = getattr(
                results, "relationship_claims_by_url", {}
            )
            for url, text in results.items():
                if text:
                    page_record = {
                        "url": url,
                        "text": text,
                        "source": "tor_search",
                        "dependency_extraction_invoked": no_llm,
                        "dependency_extraction_route": "core-scraper" if no_llm else None,
                    }
                    if relationship_claims_by_url.get(url):
                        page_record["dependency_relationships"] = (
                            relationship_claims_by_url[url]
                        )
                    scraped_pages.append(page_record)
            _fetched = sum(1 for _t in results.values() if _t)
            pipeline_metrics.record_scraping(
                attempted=len(filtered_links) + len(shared_served_pages),
                fetched=_fetched + len(shared_served_pages),
                cache_hits=len(shared_served_pages),
            )
            display.update_step("Scraping pages", "ok", f"{len(scraped_pages)} pages")
        except Exception as exc:
            display.update_step("Scraping pages", "fail", str(exc))
    else:
        if shared_served_pages:
            pipeline_metrics.record_scraping(
                attempted=len(shared_served_pages),
                fetched=len(shared_served_pages),
                cache_hits=len(shared_served_pages),
            )
            display.update_step(
                "Scraping pages", "skip",
                f"{len(shared_served_pages)} served from shared cache",
            )
        else:
            display.update_step("Scraping pages", "skip", "no links")
    _metric_finish("scraping")

    # Merge only clearnet pages that passed the relevance filter.
    if no_llm:
        filtered_clearnet_pages = _annotate_no_llm_dependency_relationships(
            filtered_clearnet_pages,
            "clearnet-side-source",
        )
    for page in filtered_clearnet_pages:
        url = page.get("url") or page.get("link")
        text = _clearnet_page_text(page)
        if not url or not text:
            continue
        scraped_pages.append({
            "url": url,
            "text": text,
            "source": page.get("source") or page.get("source_type") or "clearnet",
            "source_type": page.get("source_type"),
            "dependency_relationships": page.get("dependency_relationships", []),
            "dependency_extraction_invoked": page.get(
                "dependency_extraction_invoked", False
            ),
            "dependency_extraction_route": page.get("dependency_extraction_route"),
        })

    if no_llm:
        telegram_pages = _annotate_no_llm_dependency_relationships(
            telegram_pages,
            "telegram-side-source",
        )
    for page in telegram_pages:
        url = page.get("url") or ""
        text = page.get("text") or ""
        if url and text:
            scraped_pages.append({
                "url": url,
                "text": text,
                "source": "telegram",
                "source_type": "telegram",
                "dependency_relationships": page.get("dependency_relationships", []),
                "dependency_extraction_invoked": page.get(
                    "dependency_extraction_invoked", False
                ),
                "dependency_extraction_route": page.get(
                    "dependency_extraction_route"
                ),
            })

    from utils.content_safety import gate_pages
    from utils.content_dedup import deduplicate_page_records

    scraped_pages, _safety_dropped = gate_pages(scraped_pages)
    scraped_pages = deduplicate_page_records(scraped_pages)

    # --- Step 4.1 — discover seeds from gated pages only -----------------
    # scrape_multiple already submits discovered seeds fire-and-forget, but
    # the CLI also wants an explicit count to show in the progress display
    # and to surface in the final report payload.
    seeds_discovered = 0
    try:
        seeds_discovered = await _discover_seeds_from_pages(
            scraped_pages,
            investigation_id=investigation_id,
        )
        if seeds_discovered > 0:
            display.update_step(
                "Discovering seeds",
                "ok",
                f"{seeds_discovered} new .onion addresses",
            )
    except Exception as exc:
        logger.debug("Seed discovery from CLI pages failed (non-fatal): %s", exc)
        display.update_step("Discovering seeds", "skip", "no new seeds")

    # Resolve page_ids from DB (scrape_multiple persisted .onion pages)
    page_ids = await asyncio.to_thread(_lookup_page_ids, [p["url"] for p in scraped_pages])
    for page in scraped_pages:
        pid = page_ids.get(page["url"])
        if pid is not None:
            page["page_id"] = pid

    # --- Step 4.2 — usage-seeded auto-indexing (P3.1) --------------------
    # Feed the .onion pages this investigation touched into the shared corpus
    # (discovered_onions + snapshot store + owned index), sanitized/consent-
    # gated/provenance-stamped at the unconfirmed tier. Non-fatal and a graceful
    # no-op when the store/index is unconfigured or in private mode (CC-3).
    try:
        from index_population import index_investigation_pages
        from db.session import get_session

        with get_session() as seed_session:
            usage_report = await index_investigation_pages(seed_session, scraped_pages)
            seed_session.commit()
        if usage_report.indexed or usage_report.snapshots:
            display.update_step(
                "Indexing corpus",
                "ok",
                f"{usage_report.onions} onions, {usage_report.indexed} indexed",
            )
    except Exception as exc:
        logger.debug("Usage-seeded indexing failed (non-fatal): %s", exc)

    page_count_by_url = {p["url"]: p for p in scraped_pages}
    display.stage_end(Stage.FETCH, pages_fetched=len(scraped_pages))

    # --- Step 5 — extract entities ---------------------------------------
    _metric_start("entity_extraction")
    display.stage_start(Stage.EXTRACT)
    display.update_step("Extracting entities", "active")
    extraction_results = []
    try:
        from extractor.pipeline import extract_entities_from_pages
        extraction_results = await extract_entities_from_pages(
            pages=scraped_pages,
            investigation_id=inv_uuid,
            llm=llm,
            run_llm_extraction=llm is not None,
            max_concurrent=_preset_workers(preset, "extract_concurrency", EXTRACT_CONCURRENCY_ENV),
            max_llm_pages=_max_llm_pages(),
        )
        total_entities = sum(len(r.entity_ids) for r in extraction_results)
        display.update_step("Extracting entities", "ok", f"{total_entities} entities")
        extract_failed = False
    except Exception as exc:
        display.update_step("Extracting entities", "fail", str(exc))
        extract_failed = True
    _metric_finish("entity_extraction")
    _extracted_actors = sum(
        count
        for _r in extraction_results
        for _etype, count in (getattr(_r, "entities_by_type", {}) or {}).items()
        if "ACTOR" in str(_etype).upper() or str(_etype).upper() == "RANSOMWARE_GROUP"
    )
    display.stage_end(
        Stage.EXTRACT,
        "failed" if extract_failed else "end",
        entities_found=sum(len(r.entity_ids) for r in extraction_results),
        actors_found=_extracted_actors,
    )

    # --- Step 6 — enrich intelligence (OTX + IP) ---------------------------
    _metric_start("enrichment")
    display.stage_start(Stage.ENRICH)
    enrichment_pages: list[dict] = []
    async def _enrichment_phase() -> None:
        nonlocal enrichment_pages, extraction_results
        display.update_step("Enriching intelligence", "active")
        try:
            from sources.enrichment import enrich_investigation as _enrich_inv
            otx_key = os.getenv("OTX_API_KEY", "") or ""
            entity_dicts = sqlite_adapter.get_entities(investigation_id)
            enrichment_pages = await _enrich_inv(refined, otx_api_key=otx_key, entities=entity_dicts)
            sources_used["enrichment"] = {"status": "ok", "count": len(enrichment_pages)}
            for _source_name in ("nvd", "ransomlook", "cve_intel", "sslbl", "openphish", "phishtank", "ransomwhere"):
                _count = sum(
                    1 for _page in enrichment_pages
                    if (_page.get("source") or _page.get("source_type")) == _source_name
                )
                sources_used[_source_name] = {"status": "ok", "count": _count}
            display.update_step("Enriching intelligence", "ok", f"{len(enrichment_pages)} pages added")
        except Exception as exc:
            sources_used["enrichment"] = {"status": "fail", "error": str(exc)}
            sources_used["nvd"] = {"status": "error"}
            sources_used["ransomlook"] = {"status": "error"}
            display.update_step("Enriching intelligence", "fail", str(exc))

        # --- HIBP Pwned Passwords (k-anonymity, presence-only) ----------------
        # Runs after extraction (email entities exist) on the in-memory scraped text;
        # the raw credential is hashed-and-discarded, only a presence flag+count persist.
        try:
            from credential_presence import scan_pages_for_pwned_credentials
            _hibp_page, _hibp_stats = await scan_pages_for_pwned_credentials(scraped_pages)
            if _hibp_page is not None:
                enrichment_pages.append(_hibp_page)
            sources_used["hibp_pwned_passwords"] = {
                "status": _hibp_stats.get("status", "ok"),
                "count": _hibp_stats.get("pwned", 0),
            }
        except Exception as _hibp_exc:
            logger.debug("HIBP pwned-password scan skipped: %s", _hibp_exc)

        try:
            from sources.ip_reputation import enrich_ip_entities
            await enrich_ip_entities(extraction_results, investigation_id=inv_uuid)
        except Exception as ip_exc:
            logger.debug("ip_reputation skipped: %s", ip_exc)

        # --- Step 6.2–6.4 — domain / hash / email (before graph) -------------
        # Phase 6.2 — per-step timeouts so a hung reputation source doesn't
        # wedge the whole CLI run.  The outer enrichment cap (CLI_PHASE_TIMEOUTS
        # ["enrichment"]) is a defence-in-depth safety net applied around the
        # whole cluster further down.
        display.update_step("Enriching domains", "active")
        try:
            from sources.domain_reputation import enrich_domain_entities
            # enrich_*_entities return (extraction_results, stats) — unpack so the
            # threaded list isn't clobbered into a tuple for the next step.
            extraction_results, _ = await asyncio.wait_for(
                enrich_domain_entities(extraction_results, inv_uuid),
                timeout=60,
            )
            domain_count = sum(
                1
                for e in sqlite_adapter.get_entities(investigation_id)
                if (e.get("entity_type") or "").upper() == "DOMAIN"
            )
            detail = f"{domain_count} domains enriched" if domain_count else ""
            display.update_step("Enriching domains", "ok", detail)
        except asyncio.TimeoutError:
            logger.warning("[%s] Domain enrichment timed out after 60s", inv_uuid)
            display.update_step("Enriching domains", "fail", "timeout")
        except Exception as exc:
            logger.debug("Domain enrichment: %s", exc)
            display.update_step("Enriching domains", "fail", str(exc))

        display.update_step("Enriching hashes", "active")
        try:
            from sources.hash_reputation import enrich_hash_entities
            extraction_results, _ = await asyncio.wait_for(
                enrich_hash_entities(extraction_results, inv_uuid),
                timeout=45,
            )
            display.update_step("Enriching hashes", "ok")
        except asyncio.TimeoutError:
            logger.warning("[%s] Hash enrichment timed out after 45s", inv_uuid)
            display.update_step("Enriching hashes", "fail", "timeout")
        except Exception as exc:
            logger.debug("Hash enrichment: %s", exc)
            display.update_step("Enriching hashes", "fail", str(exc))

        display.update_step("Enriching emails", "active")
        try:
            from sources.email_reputation import enrich_email_entities
            extraction_results, _ = await asyncio.wait_for(
                enrich_email_entities(extraction_results, inv_uuid),
                timeout=30,
            )
            display.update_step("Enriching emails", "ok")
        except asyncio.TimeoutError:
            logger.warning("[%s] Email enrichment timed out after 30s", inv_uuid)
            display.update_step("Enriching emails", "fail", "timeout")
        except Exception as exc:
            logger.debug("Email enrichment: %s", exc)
            display.update_step("Enriching emails", "fail", str(exc))

        display.update_step("Breach exposure lookup", "active")
        try:
            from sources.breach_lookup import enrich_breach_entities
            extraction_results, _breach_stats = await asyncio.wait_for(
                enrich_breach_entities(extraction_results, inv_uuid),
                timeout=60,
            )
            sources_used["xposedornot"] = {
                "status": "ok",
                "count": _breach_stats.get("xon_breached", 0),
            }
            sources_used["leakcheck"] = {
                "status": "ok",
                "count": _breach_stats.get("leakcheck_breached", 0),
            }
            display.update_step("Breach exposure lookup", "ok")
        except asyncio.TimeoutError:
            logger.warning("[%s] Breach lookup timed out after 60s", inv_uuid)
            sources_used["xposedornot"] = {"status": "timed_out"}
            sources_used["leakcheck"] = {"status": "timed_out"}
            display.update_step("Breach exposure lookup", "fail", "timeout")
        except Exception as exc:
            logger.debug("Breach lookup: %s", exc)
            sources_used["xposedornot"] = {"status": "error"}
            sources_used["leakcheck"] = {"status": "error"}
            display.update_step("Breach exposure lookup", "fail", str(exc))

        display.update_step("Infostealer intel", "active")
        try:
            from sources.infostealer import enrich_infostealer_entities
            extraction_results, _infostealer_stats = await asyncio.wait_for(
                enrich_infostealer_entities(extraction_results, inv_uuid),
                timeout=60,
            )
            sources_used["hudsonrock"] = {
                "status": "ok",
                "count": _infostealer_stats.get("emails_infected", 0),
            }
            display.update_step("Infostealer intel", "ok")
        except asyncio.TimeoutError:
            logger.warning("[%s] Infostealer enrichment timed out after 60s", inv_uuid)
            sources_used["hudsonrock"] = {"status": "timed_out"}
            display.update_step("Infostealer intel", "fail", "timeout")
        except Exception as exc:
            logger.debug("Infostealer enrichment: %s", exc)
            sources_used["hudsonrock"] = {"status": "error"}
            display.update_step("Infostealer intel", "fail", str(exc))


    _enrich_cap = _explicit_enrichment_timeout()
    if _enrich_cap is None:
        await _enrichment_phase()
    else:
        # Opt-in cap (VOIDACCESS_ENRICHMENT_TIMEOUT): keep partial results.
        try:
            await asyncio.wait_for(_enrichment_phase(), timeout=_enrich_cap)
        except asyncio.TimeoutError:
            logger.warning(
                "[%s] Enrichment phase timed out after %ds - continuing with partial results",
                inv_uuid, _enrich_cap,
            )
            display.update_step("Enriching intelligence", "fail", "timeout")

    if enrichment_pages:
        try:
            from extractor.pipeline import extract_entities_from_pages as _extr2
            await _extr2(
                pages=enrichment_pages,
                investigation_id=inv_uuid,
                llm=None,
                run_llm_extraction=False,
                max_concurrent=preset["extract_concurrency"],
            )
        except Exception as exc:
            console.print(f"[grey50]Enrichment extraction failed: {exc}[/grey50]")
    # Enrichment pages participate in entity extraction and graph construction
    # just like the core scraped pages.  Add them to the final manifest before
    # page IDs, page_count, and the JSON payload are finalized; otherwise the
    # report's page count describes only the 15 core RSS pages while the graph
    # also contains enrichment-provenance entities and edges.
    _append_enrichment_pages_to_manifest(scraped_pages, enrichment_pages)
    _metric_finish("enrichment")
    display.stage_end(Stage.ENRICH)

    # --- Step 6.9 — Update persistent actor profiles (non-blocking) -------
    # Aggregate THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entities from the
    # extraction results into the cross-investigation actor profile tables.
    # Fire-and-forget so a slow DB write never stalls the pipeline.
    try:
        actor_entities: list = []
        for _r in extraction_results:
            actor_entities.extend(getattr(_r, "entities", []) or [])
        if actor_entities:
            _ap_task = asyncio.create_task(
                _update_cli_actor_profiles(actor_entities, inv_uuid),
                name=f"actor-profiles-{inv_uuid}",
            )
            _background_tasks.append(_ap_task)
            def _log_actor_task_result(t: "asyncio.Task") -> None:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.debug(
                        "Actor profile CLI task raised (non-fatal): %s", exc
                    )
            _ap_task.add_done_callback(_log_actor_task_result)
            logger.debug(
                "Actor profile update scheduled (%d entities, non-blocking)",
                len(actor_entities),
            )
    except Exception as _ap_exc:
        logger.debug("Actor profile schedule failed (non-fatal): %s", _ap_exc)

    # --- Step 7 — build graph (co-occurrence) ----------------------------
    # Phase 6.2 — capped by CLI_PHASE_TIMEOUTS["graph_build"] so a large
    # entity table doesn't pin the CLI thread indefinitely.
    _metric_start("graph_build")
    display.stage_start(Stage.GRAPH)
    display.update_step("Building graph", "active")
    loop = asyncio.get_running_loop()

    def _graph_progress(label: str) -> None:
        # The graph work runs in a worker thread; marshal display updates back
        # onto the event-loop thread so Rich's live renderer remains safe.
        loop.call_soon_threadsafe(display.update_step, "Building graph", "active", label)

    def _graph_metrics(metrics: dict[str, int]) -> None:
        detail = (
            f"entities: {metrics.get('entity_rows_loaded', 0)} | "
            f"intra-page edges: {metrics.get('intra_page_edges', 0)} | "
            f"cross-page edges: {metrics.get('cross_page_edges', 0)}"
        )
        loop.call_soon_threadsafe(display.update_step, "Building graph", "active", detail)

    try:
        edges_written = await asyncio.wait_for(
            asyncio.to_thread(
                _build_cooccurrence_edges,
                investigation_id,
                _graph_progress,
                _graph_metrics,
            ),
            timeout=CLI_PHASE_TIMEOUTS["graph_build"],
        )
        if no_llm:
            persisted_relationships = sqlite_adapter.get_relationships(investigation_id)
            typed_count = sum(
                1
                for relationship in persisted_relationships
                if relationship.get("relationship_type") != "CO_APPEARED_ON"
            )
            graph_detail = (
                f"{edges_written} relationships; typed relationships: {typed_count}"
            )
        elif edges_written == 0:
            graph_detail = "0 relationships found (build completed; none detected)"
        else:
            graph_detail = f"{edges_written} relationships"
        display.update_step("Building graph", "ok", graph_detail)
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] Graph build timed out after %ds",
            inv_uuid, CLI_PHASE_TIMEOUTS["graph_build"],
        )
        display.update_step("Building graph", "fail", "timeout")
    except Exception as exc:
        display.update_step("Building graph", "fail", str(exc))

    # --- Step 7.5 — community detection (server-side Louvain alt) ---------
    # Runs against the same entity/relationship set the graph was built from,
    # using greedy modularity from networkx.  Same algorithm as the API uses
    # in ``graph.builder.detect_communities`` so the CLI JSON and the web UI
    # colour the same communities identically.
    communities: dict[str, int] = {}
    display.update_step("Community detection", "active")
    try:
        communities = await asyncio.to_thread(
            _detect_communities_for_investigation, investigation_id
        )
        if communities:
            display.update_step(
                "Community detection", "ok",
                f"{len(set(communities.values()))} communities",
            )
        else:
            display.update_step("Community detection", "skip", "no relationships to group")
    except Exception as exc:
        logger.warning("Community detection failed: %s", exc)
        display.update_step("Community detection", "fail", str(exc))
    _metric_finish("graph_build")
    display.stage_end(Stage.GRAPH)

    # --- Step 7.5 — promote observed entities into the shared corpus (P4.1) ---
    # Byproduct of normal use: each observed entity/IOC runs through the full
    # P4.0 trust gate and lands in global_entities at the gate-assigned tier
    # (unconfirmed by default; corroborated on ≥N independent sources;
    # feed_validated on a platform-derived trusted-feed cross-hit). Consent-gated,
    # collision-safe, and strictly non-fatal — same posture as the P3.1 usage hook.
    try:
        from db.session import get_session
        from shared_corpus.promote import promote_investigation

        with get_session() as promo_session:
            promo_report = promote_investigation(promo_session, investigation_id)
            promo_session.commit()
        if promo_report.skipped_private:
            display.update_step("Shared-corpus promotion", "skip", "private mode")
        elif promo_report.promoted or promo_report.rejected:
            display.update_step(
                "Shared-corpus promotion", "ok",
                f"{promo_report.promoted} promoted "
                f"({promo_report.corroborated} corroborated, "
                f"{promo_report.feed_validated} feed-validated), "
                f"{promo_report.rejected} rejected",
            )
    except Exception as exc:
        logger.info("Shared-corpus promotion failed (non-fatal): %s", exc)

    # --- Step 8 — summary -------------------------------------------------
    # Phase 6.2 — capped by CLI_PHASE_TIMEOUTS["summary"] so a slow LLM
    # call never holds the CLI process open past its budget.
    _metric_start("summary_generation")
    display.stage_start(Stage.SUMMARIZE)
    display.update_step("Generating summary", "active")
    summary_text = ""
    summary_kind = "none"
    pages_to_summarize = scraped_pages[:10]
    if llm is not None:
        try:
            from voidaccess.llm import generate_summary
            if pages_to_summarize:
                summary_budget = CLI_PHASE_TIMEOUTS["summary"]
                first_budget = summary_budget * SUMMARY_FIRST_ATTEMPT_SHARE
                try:
                    summary_text = await asyncio.wait_for(
                        asyncio.to_thread(
                            generate_summary, llm, refined, pages_to_summarize, preset="threat_intel"
                        ),
                        timeout=first_budget,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "[%s] Summary generation timed out after %.0fs - retrying with reduced context",
                        inv_uuid, first_budget,
                    )
                    summary_text = await asyncio.wait_for(
                        asyncio.to_thread(
                            generate_summary,
                            llm,
                            refined,
                            pages_to_summarize[:SUMMARY_RETRY_TOP_PAGES],
                            max_summary_chars=SUMMARY_RETRY_MAX_CHARS,
                            preset="threat_intel",
                        ),
                        timeout=max(summary_budget - first_budget, 1),
                    )
                if (summary_text or "").strip():
                    summary_kind = "llm"
            display.update_step("Generating summary", "ok")
        except asyncio.TimeoutError:
            logger.warning(
                "[%s] Summary generation (retry) timed out within the %ds budget",
                inv_uuid, CLI_PHASE_TIMEOUTS["summary"],
            )
            display.update_step("Generating summary", "fail", "timeout")
        except Exception as exc:
            display.update_step("Generating summary", "fail", str(exc))
        if pages_to_summarize and not (summary_text or "").strip():
            # Never ship an empty summary when pages were found.
            from voidaccess.summary_fallback import build_fallback_summary

            summary_text = build_fallback_summary(
                refined, sqlite_adapter.get_entities(investigation_id), pages_to_summarize
            )
            summary_kind = "fallback"
            display.update_step("Generating summary", "ok", "fallback (no AI summary)")
    else:
        display.update_step("Generating summary", "skip", "--no-llm")
    _metric_finish("summary_generation")
    display.stage_end(Stage.SUMMARIZE, "skipped" if llm is None else "end")

    # --- Step 9 — finalize & write outputs --------------------------------
    _metric_start("finalization")
    display.update_step("Finalizing results", "active")
    final_entities = sqlite_adapter.get_entities(investigation_id)
    final_relationships = sqlite_adapter.get_relationships(investigation_id)
    # Entity persistence may create Page rows for side-source pages after the
    # initial pre-extraction lookup. Refresh the lightweight manifest so it
    # agrees with relationship provenance and the persisted DB state.
    refreshed_page_ids = await asyncio.to_thread(
        _lookup_page_ids, [p["url"] for p in scraped_pages]
    )
    for page in scraped_pages:
        if page.get("page_id") is None:
            page_id = refreshed_page_ids.get(page["url"])
            if page_id is not None:
                page["page_id"] = page_id
    sqlite_adapter.update_investigation(
        investigation_id,
        {
            "status": "completed",
            "summary": summary_text or None,
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "current_step": 9,
            "current_step_label": "Completed",
        },
    )

    # Persist seeds_discovered count in the summary metadata so admin/
    # show commands can surface it without re-querying the seed manager.
    try:
        from sources.seed_manager import get_seed_manager as _gsm

        _sm = _gsm()
        _discovered_count = sum(
            1
            for s in _sm.list_seeds()
            if s.get("category") == "discovered"
            and s.get("investigation_id") == investigation_id
        )
    except Exception:
        _discovered_count = seeds_discovered

    slug = _slugify(query)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"{slug}-{ts}.json"
    md_path = out_dir / f"{slug}-{ts}.md"

    dependency_invoked_pages = [
        page for page in scraped_pages
        if page.get("dependency_extraction_invoked")
    ]
    dependency_claims = [
        claim
        for page in dependency_invoked_pages
        for claim in (page.get("dependency_relationships") or [])
    ]
    dependency_routes: dict[str, int] = {}
    for page in dependency_invoked_pages:
        route = page.get("dependency_extraction_route") or "unknown"
        dependency_routes[route] = dependency_routes.get(route, 0) + 1

    payload = {
        "id": investigation_id,
        "query": query,
        "refined_query": refined,
        "model_used": chosen_model if llm is not None else None,
        "status": "completed" if final_entities or scraped_pages else "completed_no_results",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary_text,
        "summary_kind": summary_kind,
        "sources_used": sources_used,
        "entities": final_entities,
        "relationships": final_relationships,
        "dependency_extraction": {
            "invoked_pages": len(dependency_invoked_pages),
            "claims_before_persistence": len(dependency_claims),
            "routes": dependency_routes,
        },
        # Keep the lightweight output manifest needed to resolve relationship
        # provenance.  Text is intentionally omitted; the DB remains the
        # source of page content while each relationship can point to a real
        # page in this investigation.
        "pages_scraped": [
            {
                "page_id": p.get("page_id"),
                "url": p["url"],
                "source": p.get("source", ""),
            }
            for p in scraped_pages
        ],
        "communities": communities,
        "community_count": len(set(communities.values())) if communities else 0,
        "seeds_discovered": _discovered_count,
    }

    if fmt in ("json", "both"):
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if fmt in ("md", "both"):
        md_path.write_text(_render_markdown(payload), encoding="utf-8")

    display.update_step("Finalizing results", "ok")
    _metric_finish("finalization")

    # Drain any background tasks scheduled during the pipeline (e.g. the
    # actor-profile aggregator).  This keeps the "fire-and-forget"
    # semantics for the main pipeline while still guaranteeing the task
    # completes before asyncio.run() exits and cancels pending work.
    if _background_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*_background_tasks, return_exceptions=True),
                timeout=30,
            )
        except asyncio.TimeoutError:
            logger.debug(
                "Background tasks did not finish in 30s — letting them cancel"
            )

    persist_metrics(pipeline_metrics)
    set_current(None)

    c2_count = sum(
        1 for e in final_entities
        if e["entity_type"] == "IP_ADDRESS"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    )
    relationship_type_counts: dict[str, int] = {}
    for relationship in final_relationships:
        relationship_type = relationship.get("relationship_type") or "UNKNOWN"
        relationship_type_counts[relationship_type] = (
            relationship_type_counts.get(relationship_type, 0) + 1
        )
    actor_count = sum(
        1 for entity in final_entities
        if "ACTOR" in str(entity.get("entity_type", ""))
        or entity.get("entity_type") == "RANSOMWARE_GROUP"
    )

    # v1.6.2 — snapshot the per-run transport counters from the proxy
    # chokepoint so the final summary box can show real via-proxy /
    # fallback counts.  Reflects exactly what happened during THIS run,
    # not a static "enabled" label.
    proxy_summary: dict = {"state": "off", "via_proxy": 0, "fallback": 0}
    try:
        from sources.proxy_client import (
            get_run_counters,
            is_proxy_transport_enabled,
        )
        counters = get_run_counters()
        proxy_summary = {
            "state": "on" if is_proxy_transport_enabled() else "off",
            "via_proxy": int(counters.get("proxy", 0)),
            "fallback": int(counters.get("proxy_failures", 0)),
        }
    except Exception:
        pass

    display.complete(
        {
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "c2_ips": c2_count,
            "seeds_discovered": _discovered_count,
            "sources_used": sum(
                1 for v in sources_used.values()
                if str(v.get("status", "")).startswith("ok")
            ),
            "relationship_count": len(final_relationships),
            "relationships_by_type": relationship_type_counts,
            "typed_relationship_count": sum(
                count for kind, count in relationship_type_counts.items()
                if kind != "CO_APPEARED_ON"
            ),
            "actor_count": actor_count,
            "community_count": len(set(communities.values())) if communities else 0,
            "source_details": sources_used,
            "no_llm": no_llm,
            "report_path": str(md_path) if fmt in ("md", "both") else None,
            "data_path": str(json_path) if fmt in ("json", "both") else None,
            "proxy_summary": proxy_summary,
        }
    )

    emitter.set_counts(
        pages_fetched=len(scraped_pages),
        entities_found=len(final_entities),
        actors_found=actor_count,
    )
    if final_entities or scraped_pages:
        emitter.completed()
    else:
        emitter.failed("no_results", "no entities or pages found")

    # Close any cached aiohttp sessions so the event loop exits cleanly
    # (otherwise aiohttp prints "Unclosed client session" warnings).
    await _close_cached_sessions()


def _patch_llm_extraction_cache(sqlite_adapter: Any) -> None:
    """Use sqlite adapter for cache reads (naive ISO strings from SQLite)."""
    try:
        import extractor.llm_extract as llm_extract
    except Exception:
        return
    llm_extract._load_from_cache = sqlite_adapter.get_page_extraction_cache


# Cap per-investigation seed discovery (mirrors the scraper's constant).
_SEED_DISCOVERY_MAX_PER_INVESTIGATION = 100


async def _discover_seeds_from_pages(
    pages: list[dict],
    investigation_id: str,
) -> int:
    """
    Extract .onion URLs from a batch of scraped pages and submit them
    to the seed manager.  Reuses scraper.scrape._discover_seeds_from_one_page
    so the per-page/per-investigation cap and fire-and-forget semantics
    stay identical to the API pipeline.

    Only onion pages are mined (matches the scraper's gate).

    Returns the number of new seeds successfully submitted.
    """
    if not pages:
        return 0

    try:
        from scraper.scrape import _discover_seeds_from_one_page  # noqa: WPS437
    except Exception:
        return 0

    counter: dict = {"count": 0}

    async def _run(page: dict) -> int:
        page_url = page.get("url") or ""
        page_text = page.get("text") or page.get("content") or ""
        if not page_url or not page_text:
            return 0
        if ".onion" not in page_url.lower():
            return 0
        if counter["count"] >= _SEED_DISCOVERY_MAX_PER_INVESTIGATION:
            return 0
        return await _discover_seeds_from_one_page(
            page_url=page_url,
            content=page_text,
            investigation_id=investigation_id,
            investigation_counter=counter,
        )

    results = await asyncio.gather(
        *[_run(p) for p in pages],
        return_exceptions=True,
    )
    total = 0
    for r in results:
        if isinstance(r, int):
            total += r
    return total


async def _close_cached_sessions() -> None:
    try:
        from scraper.scrape import close_cached_sessions as _close_scrape
        await _close_scrape()
    except Exception:
        pass
    try:
        from search import close_search_session as _close_search
        await _close_search()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Side-source helpers (each gracefully degrades if module missing/disabled)
# ---------------------------------------------------------------------------


async def _scrape_pastes(query: str) -> list[dict]:
    try:
        from sources.paste_scraper import scrape_paste_sites
    except Exception:
        return []
    if os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_paste_sites(query) or []
    except Exception:
        return []


async def _scrape_github(query: str) -> list[dict]:
    try:
        from sources.github_scraper import scrape_github
    except Exception:
        return []
    if os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_github(query) or []
    except Exception:
        return []


async def _scrape_gitlab(query: str) -> list[dict]:
    try:
        from sources.gitlab_scraper import scrape_gitlab
    except Exception:
        return []
    if os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_gitlab(query) or []
    except Exception:
        return []


async def _scrape_rss(query: str) -> list[dict]:
    try:
        from sources.rss_scraper import scrape_rss_feeds
    except Exception:
        return []
    if os.getenv("RSS_FEEDS_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_rss_feeds(query) or []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _lookup_page_ids(urls: list[str]) -> dict[str, uuid.UUID]:
    if not urls:
        return {}
    try:
        from db.models import Page
        from db.session import get_session
    except Exception:
        return {}
    out: dict[str, uuid.UUID] = {}
    with get_session() as session:
        rows = session.query(Page).filter(Page.url.in_(urls)).all()
        for r in rows:
            out[r.url] = r.id
    return out


def _build_cooccurrence_edges(
    investigation_id: str,
    progress_callback: Optional[Callable[[str], None]] = None,
    metrics_callback: Optional[Callable[[dict[str, int]], None]] = None,
) -> int:
    """Generate CO_APPEARED_ON edges for entities sharing a page.

    Entity membership is resolved the same way ``sqlite_adapter.get_entities``
    and ``graph.builder`` resolve it: ``Entity.investigation_id`` **OR**
    ``InvestigationEntityLink.investigation_id``.  Under the project's global
    entity-dedup model ``Entity.investigation_id`` only records the
    investigation that first *created* the row — every later investigation
    that re-encounters the same canonical entity is attached through
    ``InvestigationEntityLink`` instead.  Filtering on the column alone made
    this builder see only the handful of entities newly inserted by the
    current run (3 of 221 in a measured run), so the graph it produced was
    almost entirely isolated nodes.
    """
    from db.models import Entity, InvestigationEntityLink
    from db.session import get_session
    from sqlalchemy.orm import joinedload
    from graph.builder import (
        _ENTITY_TYPE_TO_NODE_TYPE,
        _iter_semantic_cooccurrence_pairs,
        _link_cross_page_entities,
        _make_node_id,
    )
    import networkx as nx
    from voidaccess_cli.adapters.sqlite import save_relationships

    edges: list[dict] = []
    inv_uuid = uuid.UUID(investigation_id)

    if progress_callback:
        progress_callback("loading entities")
    with get_session() as session:
        matched = (
            session.query(Entity)
            .options(joinedload(Entity.page))
            .outerjoin(
                InvestigationEntityLink,
                InvestigationEntityLink.entity_id == Entity.id,
            )
            .filter(
                (Entity.investigation_id == inv_uuid)
                | (InvestigationEntityLink.investigation_id == inv_uuid)
            )
            .all()
        )
        # The outer join fans out one row per link, so an entity shared with
        # other investigations comes back more than once.  Collapse on the
        # primary key: an entity must not co-occur with itself.
        seen_ids: set = set()
        rows = []
        for ent in matched:
            if ent.id in seen_ids:
                continue
            seen_ids.add(ent.id)
            rows.append(ent)
        entity_rows_loaded = len(rows)
        by_page: dict[uuid.UUID, list] = {}
        for ent in rows:
            page_id = getattr(ent, "page_id", None)
            if page_id is None:
                continue
            by_page.setdefault(page_id, []).append(ent)

        # Consume ORM rows while their session is open.  ``joinedload`` avoids
        # a query for ``page`` but does not make detached relationship access
        # safe after the session closes.
        if progress_callback:
            progress_callback("building intra-page edges")
        for page_entities in by_page.values():
            if len(page_entities) < 2:
                continue
            for ent_a, ent_b in _iter_semantic_cooccurrence_pairs(page_entities):
                edges.append(
                    {
                        "entity_a_id": str(ent_a.id),
                        "entity_b_id": str(ent_b.id),
                        "relationship_type": "CO_APPEARED_ON",
                        "confidence": 0.8,
                    }
                )
        intra_page_edges = len(edges)

        # Calculate the same cross-page bridge metric used by the graph
        # builder, while the ORM rows are still attached to their pages. The
        # CLI continues to persist its bounded co-occurrence set below, but
        # the live UI now exposes all three already-computed graph metrics.
        graph = nx.MultiDiGraph()
        for ent in rows:
            page_url = ent.page.url if ent.page else ""
            node_id = _make_node_id(ent.entity_type, ent.value, page_url)
            graph.add_node(
                node_id,
                node_type=_ENTITY_TYPE_TO_NODE_TYPE.get(ent.entity_type, ""),
                confidence=float(ent.confidence or 0.0),
                metadata={"confidence": float(ent.confidence or 0.0)},
            )
        cross_page_edges = _link_cross_page_entities(graph, rows, inv_uuid)
        if metrics_callback:
            metrics_callback(
                {
                    "entity_rows_loaded": entity_rows_loaded,
                    "intra_page_edges": intra_page_edges,
                    "cross_page_edges": cross_page_edges,
                }
            )
    if progress_callback:
        progress_callback("loading persisted relationships")
    written = save_relationships(investigation_id, edges)
    if progress_callback:
        progress_callback("graph build complete")
    return written


def _detect_communities_for_investigation(investigation_id: str) -> dict[str, int]:
    """Detect communities over the SAME canonical graph the API partitions.

    Returns ``{entity_id_str: community_id}``.

    An investigation's community grouping must be surface-independent: the CLI
    JSON/TUI and the FastAPI graph endpoint must place the same entities in the
    same communities.  Achieving that requires both surfaces to run detection
    over one graph model.  The authoritative model is
    ``graph.builder.build_graph_from_db`` — the exact graph
    ``api.routes.investigations`` detects on — whose nodes are *canonical
    identity* nodes (one node per ``entity_graph_id``, collapsing the same
    entity observed on multiple pages) joined by semantically-filtered
    CO_APPEARED_ON edges, with graph-unmapped entity types excluded.

    Historically the CLI built a *different* graph here — one node per entity
    **UUID** joined by every persisted relationship row — which produced a
    partition that could not even be compared to the API's (different node
    identity, different edge set).  We now partition the canonical graph and
    translate the result back to per-entity UUIDs through the shared
    ``entity_graph_id`` (the sanctioned identity accessor, byte-for-byte
    compatible with the builder's node ids): every entity row that resolves to
    a canonical node inherits that node's community.  The *grouping* is then
    identical to the API's; only the key representation differs (UUID here for
    the CLI's entity-keyed consumers, canonical node id on the API for its
    node-keyed graph JSON).
    """
    import uuid as _uuid

    from graph.builder import build_graph_from_db, detect_communities
    from extractor.identity import entity_graph_id

    try:
        inv_uuid = _uuid.UUID(str(investigation_id))
    except (ValueError, TypeError, AttributeError):
        return {}

    graph = build_graph_from_db(investigation_id=inv_uuid)
    if graph.number_of_nodes() == 0:
        return {}
    partition = detect_communities(graph)  # keyed by canonical node id
    if not partition:
        return {}

    from db.models import Entity, InvestigationEntityLink
    from db.session import get_session
    from sqlalchemy.orm import joinedload

    communities: dict[str, int] = {}
    with get_session() as session:
        rows = (
            session.query(Entity)
            .outerjoin(
                InvestigationEntityLink,
                InvestigationEntityLink.entity_id == Entity.id,
            )
            .filter(
                (Entity.investigation_id == inv_uuid)
                | (InvestigationEntityLink.investigation_id == inv_uuid)
            )
            .options(joinedload(Entity.page))
            .all()
        )
        for ent in rows:
            node_id = entity_graph_id(ent)
            if node_id in partition:
                communities[str(ent.id)] = int(partition[node_id])
    return communities


async def _update_cli_actor_profiles(
    entities: list,
    investigation_id: "uuid.UUID",
) -> None:
    """Persist THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entities to long-lived
    actor profile tables.  Mirrors the API-side
    ``api/routes/investigations._update_actor_profiles``.

    Wrapped in try/except so any failure is logged at DEBUG and never
    raised — this is fire-and-forget.
    """
    try:
        from sources.actor_profiles import ActorProfileManager

        manager = ActorProfileManager()
        return await manager.update_from_extraction(
            entities=entities or [],
            investigation_id=investigation_id,
        )
    except Exception as exc:
        logger.debug(
            "CLI actor profile update failed (non-fatal): %s", exc
        )
        return None


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s[:50] or "investigation"


def _render_markdown(payload: dict[str, Any]) -> str:
    from extractor.identity import entity_display_id

    lines: list[str] = []
    lines.append(f"# Investigation: {payload['query']}")
    lines.append(
        f"**Date:** {payload['created_at']}  |  **Model:** {payload.get('model_used') or '—'}"
    )
    if payload.get("refined_query") and payload["refined_query"] != payload["query"]:
        lines.append(f"**Refined:** {payload['refined_query']}")
    lines.append("")
    lines.append("## Summary")
    lines.append(payload.get("summary") or "_(no summary — LLM disabled or unavailable)_")
    lines.append("")

    entities = payload.get("entities", [])
    by_type: dict[str, list[dict]] = {}
    for e in entities:
        by_type.setdefault(e["entity_type"], []).append(e)

    c2_ips = [
        e for e in entities
        if e["entity_type"] == "IP_ADDRESS"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    ]
    lines.append("## Key findings")
    lines.append(f"- {len(c2_ips)} confirmed C2 IP addresses")
    lines.append(
        f"- {len(by_type.get('RANSOMWARE_GROUP', []))} ransomware group(s) identified"
    )
    lines.append(f"- {len(by_type.get('ONION_URL', []))} .onion URLs mapped")
    lines.append(f"- {len(entities)} entities total")
    lines.append(f"- {payload.get('seeds_discovered', 0)} new .onion seeds discovered")
    lines.append("")

    lines.append(f"## Entities ({len(entities)} total)")
    for etype in sorted(by_type.keys()):
        rows = by_type[etype]
        lines.append(f"\n### {etype} ({len(rows)})")
        lines.append("| Value | Priority | Confidence | Method | Tags |")
        lines.append("|---|---|---|---|---|")
        for r in rows[:50]:
            tags = (r.get("corroborating_sources") or "").replace("|", "/")
            val = entity_display_id(r).replace("|", "/")
            conf = r.get("confidence")
            lines.append(
                f"| {val} | {(r.get('priority_score') or 0):.3f} | "
                f"{conf:.2f} | {r.get('extraction_method') or ''} | {tags} |"
            )
        if len(rows) > 50:
            lines.append(f"\n_…and {len(rows) - 50} more (see JSON)_")
    lines.append("")

    lines.append("## Sources used")
    for name, info in payload.get("sources_used", {}).items():
        glyph = "✓" if info.get("status") == "ok" else ("↷" if info.get("status") == "skipped" else "✗")
        detail = f" ({info.get('count', 0)} results)" if "count" in info else ""
        lines.append(f"- {glyph} {name}{detail}")

    return "\n".join(lines) + "\n"
