"""
api/main.py — FastAPI application entry point for VoidAccess Intelligence API.

Exposes the VoidAccess platform programmatically.
Runs alongside Streamlit on a different port (8000 vs 8501).

Usage:
    uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from fastapi import FastAPI, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import entities, export, investigations, monitors, search, auth, admin, settings, actors
from api.auth import get_current_user, require_admin
from api.errors import log_exception, safe_error_body
from api.rate_limit import global_rate_limit_middleware
from monitor.scheduler import start_scheduler

from config import TOR_PROXY_HOST, TOR_PROXY_PORT, PLAYWRIGHT_ENABLED, JWT_SECRET

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


# ---------------------------------------------------------------------------
# Durable job-queue helpers (P2.3)
# ---------------------------------------------------------------------------

def _worker_count() -> int:
    return max(1, int(os.getenv("VOIDACCESS_QUEUE_WORKERS", "1") or 1))


def _worker_disabled() -> bool:
    return (
        os.getenv("VOIDACCESS_DISABLE_QUEUE_WORKER", "false") or "false"
    ).strip().lower() == "true"


_handlers_registered = False


def _register_job_handlers() -> None:
    """Register the durable-queue task handlers (idempotent).

    The ``investigation`` handler runs the existing, self-contained pipeline task
    with the payload the create endpoint enqueued — so a worker (this process, or
    a fresh one after a restart) executes exactly what BackgroundTasks used to.
    """
    global _handlers_registered
    if _handlers_registered:
        return
    from jobqueue import register_handler
    from api.routes.investigations import _run_investigation_task

    async def _investigation_handler(payload: dict) -> None:
        await _run_investigation_task(
            investigation_id=payload["investigation_id"],
            run_id=payload["run_id"],
            query=payload["query"],
            model=payload.get("model"),
            run_crawler=bool(payload.get("run_crawler", False)),
        )

    register_handler("investigation", _investigation_handler)

    # P3.3 — freshness loop (owned-index re-crawl) on the same durable queue.
    try:
        from freshness import register_handlers as _register_freshness_handlers

        _register_freshness_handlers()
    except Exception as e:  # never let freshness break server startup
        logger.warning(f"Freshness handler registration failed (non-fatal): {e}")

    _handlers_registered = True


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# Enforcement lives in api/rate_limit.py over the in-process ``ratelimit``
# substrate (no Redis, no slowapi). The global per-IP cap is applied as an HTTP
# middleware (registered below); stricter per-route limits (login, create
# investigation) are FastAPI dependencies. Honors DISABLE_RATE_LIMIT.


# ---------------------------------------------------------------------------
# Lifespan handler (replaces deprecated on_event)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    logger.info("VoidAccess API started")

    if JWT_SECRET is None:
        raise RuntimeError(
            "JWT_SECRET is not set. Set JWT_SECRET in your .env file. "
            "Generate a secure secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # Run Alembic migrations (idempotent — safe to call on every boot)
    _run_migrations()

    _check_db_connectivity()

    # Pre-warm Playwright browser (avoids cold start on first JS page)
    if PLAYWRIGHT_ENABLED:
        try:
            from scraper.scrape_js import get_browser

            await get_browser(TOR_PROXY_HOST, TOR_PROXY_PORT)
            logger.warning("Playwright browser pre-warmed")
        except ImportError:
            logger.warning("Playwright not installed — JS rendering disabled")
        except Exception as e:
            logger.warning(f"Playwright pre-warm failed (non-fatal): {e}")

    # Pre-warm vector store embedding model (avoids 5-15s cold start on first search)
    try:
        from vector.store import get_collection
        from vector.model_singleton import get_embedding_model

        get_collection()
        get_embedding_model()
        logger.warning("Vector store and embedding model pre-warmed")
    except Exception as e:
        logger.warning(f"Vector store pre-warm failed (non-fatal): {e}")

    # P3-HARDEN / DRIFT-1 — fail loud on the central path if real MiniLM did not
    # load. When the owned index is configured (MEILI_HOST set), semantic ranking
    # + index vectors are the differentiator; silently serving the SHA-256
    # fallback as "semantic" embeddings is a silent product failure. A local/$0
    # install (no index) has no such requirement and keeps the graceful fallback.
    try:
        from vector.model_singleton import (
            assert_real_embeddings,
            semantic_embeddings_required,
        )

        _semantic_required = semantic_embeddings_required()
    except Exception as e:
        logger.warning("Embedding-backend health check unavailable (non-fatal): %s", e)
        _semantic_required = False
        assert_real_embeddings = None

    if _semantic_required and assert_real_embeddings is not None:
        try:
            assert_real_embeddings(context="MEILI_HOST is set")
            logger.warning(
                "Embedding backend verified: real MiniLM active (semantic ranking enabled)"
            )
        except Exception as e:
            logger.error(
                "Refusing to start: semantic embeddings required (owned index "
                "configured) but unavailable. %s",
                e,
            )
            raise

    # Load curated .onion seed catalogue (no Tor validation on startup — too slow)
    try:
        from sources.seed_manager import get_seed_manager

        logger.info("Loading seed database...")
        seed_manager = get_seed_manager()
        logger.warning(
            "Seed database loaded: %d seeds",
            len(seed_manager.list_seeds()),
        )
    except Exception as e:
        logger.warning(f"Seed database load failed (non-fatal): {e}")

    # Durable job queue (P2.3): register the investigation handler and recover
    # orphaned jobs BEFORE the sweep. Every 'running' job belonged to the now-dead
    # previous process, so requeue them wholesale — a worker will resume/re-run
    # them, and the sweep below skips investigations that still have a live job.
    _register_job_handlers()
    try:
        if os.getenv("DATABASE_URL"):
            from jobqueue import requeue_orphans
            from db.session import get_session

            def _reboot_requeue() -> int:
                with get_session() as session:
                    return requeue_orphans(session, all_running=True)

            requeued = await asyncio.to_thread(_reboot_requeue)
            if requeued:
                logger.warning(
                    "Requeued %d interrupted job(s) for restart recovery.", requeued
                )
    except Exception as e:
        logger.warning(f"Job-queue reboot recovery failed (non-fatal): {e}")

    # P3.3 — seed the singleton freshness-scan chain on the durable queue. It is
    # idempotent (skips if a scan is already pending) and no-ops when the owned
    # index is unconfigured, so it is safe to call on every startup.
    try:
        if os.getenv("DATABASE_URL"):
            from freshness import bootstrap as _freshness_bootstrap
            from db.session import get_session

            def _seed_freshness() -> bool:
                with get_session() as session:
                    seeded = _freshness_bootstrap(session)
                    session.commit()
                    return seeded

            if await asyncio.to_thread(_seed_freshness):
                logger.info("Freshness scan chain seeded on the durable queue.")
    except Exception as e:
        logger.warning(f"Freshness bootstrap failed (non-fatal): {e}")

    # Stuck-investigation sweep is now a BACKSTOP (P2.3): it only fails
    # investigations that have NO live queue job (truly orphaned / legacy). Ones
    # with a queued/running job are left for a worker to resume.
    try:
        if os.getenv("DATABASE_URL"):
            swept = await _sweep_stuck_investigations(cutoff_minutes=None)
            if swept:
                logger.warning(
                    "Backstop-swept %d stranded investigations with no live job.",
                    swept,
                )
    except Exception as e:
        logger.warning(f"Failed to recover stranded investigations: {e}")

    # Start background scheduler (monitoring watches + weekly seed refresh)
    try:
        scheduler = start_scheduler()
        if scheduler:
            monitors.set_scheduler(scheduler)
            logger.warning("APScheduler started: monitoring watches active")
        else:
            logger.warning("APScheduler background service disabled")
    except Exception as e:
        logger.error(f"APScheduler failed to start: {e}")
        scheduler = None

    # Start periodic stuck-investigation sweeper (Phase 6.3). Runs every
    # 5 minutes and marks investigations stuck in 'processing' for more
    # than INVESTIGATION_HARD_TIMEOUT_MINUTES as 'failed'.  Cancelled on
    # shutdown below.
    _periodic_sweep_task: Optional[asyncio.Task] = None
    if os.getenv("DATABASE_URL"):
        try:
            _periodic_sweep_task = asyncio.create_task(
                _periodic_stuck_sweep(),
                name="voidaccess-stuck-investigation-sweeper",
            )
            logger.info("Periodic stuck-investigation sweeper started (every 5 min).")
        except Exception as e:
            logger.warning(f"Failed to start periodic sweeper: {e}")

    # Start durable-queue workers (server only; the CLI stays synchronous).
    _worker_tasks: list[asyncio.Task] = []
    if os.getenv("DATABASE_URL") and not _worker_disabled():
        try:
            from jobqueue import start_workers

            _worker_tasks = start_workers(n=_worker_count())
            logger.warning("Durable job-queue workers started: %d", _worker_count())
        except Exception as e:
            logger.error(f"Failed to start job-queue workers: {e}")

    yield

    # --- Shutdown ---
    for _t in _worker_tasks:
        if not _t.done():
            _t.cancel()
    for _t in _worker_tasks:
        try:
            await _t
        except (asyncio.CancelledError, Exception):
            pass

    if _periodic_sweep_task is not None and not _periodic_sweep_task.done():
        _periodic_sweep_task.cancel()
        try:
            await _periodic_sweep_task
        except (asyncio.CancelledError, Exception):
            pass

    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)
        logger.warning("APScheduler stopped")

# Close Playwright browser
    if PLAYWRIGHT_ENABLED:
        try:
            from scraper.scrape_js import close_browser

            await close_browser()
        except Exception:
            pass

    # Close cached scrape sessions (Tor and direct) - always, regardless of PLAYWRIGHT_ENABLED
    try:
        from scraper.scrape import close_cached_sessions

        await close_cached_sessions()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Stuck-investigation sweeper (Phase 6.3)
# ---------------------------------------------------------------------------
# FastAPI BackgroundTasks runs in the same process as the HTTP handler.
# If the worker crashes mid-investigation, the row stays at status='processing'
# forever.  This sweeper marks them 'failed' on two schedules:
#
#   1. Startup  — cutoff_minutes=None → every 'processing' row is swept
#                 (the prior process is gone, no legitimate owner).
#   2. Periodic — every 5 minutes, cutoff = INVESTIGATION_HARD_TIMEOUT_MINUTES
#                 (configurable via env).  Defends against in-process hangs.
#
# The sweep only ever UPDATES status; it never deletes rows.

# Hard timeout after which an investigation is considered permanently stuck.
# Default 30 min — generous enough to cover the slowest legitimate run
# (parallel_sources 300s + enrichment 120s + graph 60s + summary 90s + finalize
# 30s ≈ 10 min on a healthy host; 30 min is 3x that to absorb transient
# network slowness without false positives).
INVESTIGATION_HARD_TIMEOUT_MINUTES = int(
    os.getenv("VOIDACCESS_INVESTIGATION_HARD_TIMEOUT_MINUTES", "30") or 30
)
# Periodic sweep interval. 5 min is a good default — catches stuck rows
# quickly without flooding the DB.
SWEEP_INTERVAL_SECONDS = int(
    os.getenv("VOIDACCESS_SWEEP_INTERVAL_SECONDS", "300") or 300
)


async def _sweep_stuck_investigations(cutoff_minutes: Optional[int] = 30) -> int:
    """Mark investigations stuck in 'processing' as 'failed'.

    Args:
        cutoff_minutes: Only sweep rows older than this many minutes.
            ``None`` → startup mode: sweep *all* processing rows (the prior
            process is gone, no legitimate owner remains).
            ``int``  → periodic mode: sweep only rows older than the cutoff.

    Returns the number of rows swept.  Returns 0 when DB is unconfigured,
    the table is missing, or no rows match — never raises.
    """
    if not os.getenv("DATABASE_URL"):
        return 0
    try:
        from db.session import get_session
        from db.models import Investigation

        # Build the query in a short-lived session, do the UPDATE in another.
        with get_session() as session:
            query = session.query(Investigation).filter(
                Investigation.status == "processing"
            )
            if cutoff_minutes is not None:
                cutoff_dt = datetime.now(timezone.utc) - timedelta(
                    minutes=cutoff_minutes
                )
                query = query.filter(Investigation.created_at < cutoff_dt)

            stuck = query.all()
            if not stuck:
                return 0

            # Backstop only (P2.3): an investigation that still has a live
            # (queued/running) job in the durable queue is NOT orphaned — a
            # worker will resume/re-run it. Exclude those from the sweep.
            try:
                from jobqueue import active_dedup_keys

                live_keys = active_dedup_keys(session, task_type="investigation")
            except Exception:
                live_keys = set()
            stuck = [inv for inv in stuck if str(inv.id) not in live_keys]
            if not stuck:
                return 0

            cancelled_ids = [inv.id for inv in stuck if inv.cancellation_requested]
            failed_ids = [inv.id for inv in stuck if not inv.cancellation_requested]
            sweep_reason = (
                "Server restarted mid-investigation"
                if cutoff_minutes is None
                else f"Investigation timed out after {cutoff_minutes} min — "
                     "server may have restarted or pipeline may be hung"
            )

        # Update outside the read session.
        from sqlalchemy import update
        with get_session() as session:
            if cancelled_ids:
                session.execute(
                    update(Investigation)
                    .where(Investigation.id.in_(cancelled_ids))
                    .values(
                        status="cancelled",
                        summary="Investigation cancelled by user before worker termination",
                    )
                )
            if failed_ids:
                session.execute(
                    update(Investigation)
                    .where(Investigation.id.in_(failed_ids))
                    .values(status="failed", summary=sweep_reason)
                )
            session.commit()

        for inv_id in cancelled_ids:
            logger.warning("Resolved cancelled investigation after worker termination: %s", inv_id)
        for inv_id in failed_ids:
            logger.warning("Swept stuck investigation: %s", inv_id)
        logger.info(
            "Swept %d stuck investigations (cancelled=%d, failed=%d, cutoff=%s)",
            len(stuck), len(cancelled_ids), len(failed_ids), cutoff_minutes,
        )
        return len(stuck)
    except Exception as exc:
        logger.warning("Swept-investigation sweep failed: %s", exc)
        return 0


async def _periodic_stuck_sweep() -> None:
    """Background task: every SWEEP_INTERVAL_SECONDS, sweep stuck rows.

    Runs until cancelled by the lifespan teardown.  Sleeps in a loop so
    cancelling the task is the only stop signal — never raises.
    """
    try:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            try:
                await _sweep_stuck_investigations(
                    cutoff_minutes=INVESTIGATION_HARD_TIMEOUT_MINUTES,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Periodic stuck-investigation sweep iteration failed: %s", exc)
    except asyncio.CancelledError:
        logger.info("Periodic stuck-investigation sweep cancelled.")
        return


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VoidAccess Intelligence API",
    description="VoidAccess: Dark Web Intelligence Platform",
    version="2.0.3",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Allowed origins: explicit list from env, or localhost defaults
CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,          # Explicit list, never wildcard
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for error in exc.errors():
        field = ".".join(str(x) for x in error.get("loc", []) if x != "body")
        msg = error.get("msg", "Invalid value")
        errors.append(f"{field}: {msg}")
    return JSONResponse(
        status_code=422,
        content={
            "detail": "; ".join(errors),
            "errors": errors,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Public error, private log: log the full exception (message + traceback)
    # server-side tagged with a correlation ID, and return only a generic
    # message + that same ID to the client. Never leak raw exception text.
    correlation_id = log_exception(exc, request=request)
    return JSONResponse(
        status_code=500,
        content=safe_error_body(correlation_id),
    )


# ---------------------------------------------------------------------------
# Global rate limit middleware — a real per-IP cap (no longer a no-op).
# Implemented over the in-process ``ratelimit`` substrate in api/rate_limit.py.
# ---------------------------------------------------------------------------
app.middleware("http")(global_rate_limit_middleware)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

# Public routes (no auth required)
app.include_router(auth.router)

# Protected routes (require valid JWT)
app.include_router(
    investigations.router,
    prefix="/investigations",
    tags=["investigations"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    entities.router,
    prefix="/entities",
    tags=["entities"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    search.router,
    prefix="/search",
    tags=["search"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    export.router,
    prefix="/export",
    tags=["export"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    monitors.router,
    prefix="/monitors",
    tags=["monitors"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    actors.router,
    prefix="/actors",
    tags=["actors"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    admin.router,
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
app.include_router(
    settings.router,
    tags=["settings"],
    dependencies=[Depends(get_current_user)],
)

# Cross-install ingest (P4.3) — mounted ONLY on a central-service install
# (VOIDACCESS_INGEST_ENABLED). Absent/inert on $0/local installs, so there is no
# regression there. Its own per-key auth (not JWT) — no get_current_user dep.
import config as _config  # noqa: E402

if getattr(_config, "INGEST_ENABLED", False):
    from api.routes import ingest as _ingest  # noqa: E402

    app.include_router(_ingest.router)


# ---------------------------------------------------------------------------
# Startup event
# ---------------------------------------------------------------------------


def _run_migrations() -> None:
    """Apply any pending Alembic migrations at startup.

    Safe to call on every boot — Alembic is idempotent (already-applied
    migrations are skipped).  Logs a warning and continues on failure so a
    migration error never hard-crashes the API process.
    """
    if not os.getenv("DATABASE_URL"):
        logger.info("DATABASE_URL not set — skipping migrations")
        return
    try:
        from alembic.config import Config  # noqa: PLC0415
        from alembic import command  # noqa: PLC0415
        from alembic.util import CommandError  # noqa: PLC0415
        import pathlib  # noqa: PLC0415

        project_root = pathlib.Path(__file__).resolve().parents[1]
        ini_path = project_root / "alembic.ini"
        if not ini_path.exists():
            # Wheel data-files are installed at the virtualenv prefix, while
            # api/ and db/ live under site-packages.  Locate the shipped
            # config there for non-editable/API deployments.
            ini_path = pathlib.Path(sys.prefix) / "alembic.ini"
        if not ini_path.exists():
            raise FileNotFoundError(f"Alembic config not found: {ini_path}")
        alembic_cfg = Config(str(ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
        alembic_cfg.set_main_option("script_location", str(project_root / "db" / "migrations"))

        try:
            command.upgrade(alembic_cfg, "head")
            logger.info("Alembic migrations applied")
        except CommandError as e:
            if "already up to date" in str(e).lower():
                logger.info("Alembic migrations already at head")
            else:
                raise
    except Exception as exc:
        logger.warning("Migration failed — proceeding without applying: %s", exc)


async def _check_db_connectivity_async() -> str:
    """Return 'ok' if DB is reachable, error message otherwise."""
    if not os.getenv("DATABASE_URL"):
        return "error: DATABASE_URL not configured"
    try:
        from db.session import get_async_session  # noqa: PLC0415
        from sqlalchemy import text

        async with get_async_session() as session:
            await session.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        # /health and /healthz/ready are unauthenticated — never echo the raw
        # DB error (can contain connection-string fragments). Log it, return
        # a generic status.
        log_exception(exc, context="db connectivity check")
        return "error: database unreachable"


async def _check_tor_connectivity_async() -> str:
    """Return 'ok' if Tor proxy is reachable, 'unreachable' otherwise."""
    host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("TOR_PROXY_PORT", "9050"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
        writer.close()
        await writer.wait_closed()
        return "ok"
    except Exception:
        return "unreachable"


def _check_db_connectivity() -> bool:
    """Return True if DB is reachable, False otherwise. Sync wrapper for startup."""
    if not os.getenv("DATABASE_URL"):
        return False
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import db_health_check  # noqa: PLC0415

        with get_session() as session:
            return db_health_check(session)
    except Exception as exc:
        logger.warning("DB connectivity check failed: %s", exc)
        return False


def _check_tor_connectivity() -> bool:
    """Return True if Tor proxy appears to be reachable. Sync wrapper for startup."""
    import socket  # noqa: PLC0415
    host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("TOR_PROXY_PORT", "9050"))
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Returns API, DB, and Tor connectivity status (async)."""
    checks = {}
    db_result, tor_result = await asyncio.gather(
        _check_db_connectivity_async(),
        _check_tor_connectivity_async(),
    )
    checks["database"] = db_result
    checks["tor"] = tor_result

    status = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, "checks": checks}


@app.get("/healthz/live", tags=["health"])
async def liveness() -> dict:
    """Liveness probe — always 200 unless process is wedged."""
    return {"status": "alive"}


@app.get("/healthz/ready", tags=["health"])
async def readiness() -> dict:
    """Readiness probe — checks DB and Tor are reachable."""
    checks = {}
    db_result, tor_result = await asyncio.gather(
        _check_db_connectivity_async(),
        _check_tor_connectivity_async(),
    )
    checks["database"] = db_result
    checks["tor"] = tor_result

    is_ready = all(v == "ok" for v in checks.values())
    status = "ready" if is_ready else "not_ready"
    return {"status": status, "checks": checks}


@app.get("/debug/tor-test", tags=["health"])
async def tor_test(_=Depends(get_current_user)) -> dict:
    """
    Test Tor connectivity.
    TODO: Remove or protect in production.
    """
    try:
        import aiohttp  # noqa: PLC0415
        from aiohttp_socks import ProxyConnector  # noqa: PLC0415

        # Deliberately NOT the shared pool in scraper/tor_pool.py, and the one
        # justified exception to the "no private Tor connector" rule: this
        # endpoint exists to test whether the Tor transport itself works, so it
        # must not report health through the very session cache whose health is
        # in question — a pooled session would make a stale or broken cached
        # connector look like a working Tor.  It also fetches one fixed clearnet
        # URL, so no .onion stream isolation is at stake here.
        connector = ProxyConnector.from_url(f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}")
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get("https://check.torproject.org") as resp:
                text = await resp.text()
                return {
                    "tor_working": True,
                    "status_code": resp.status,
                    "response": text[:100],
                }
    except Exception as exc:
        return {"tor_working": False, "error": str(exc)}


@app.get("/debug/search-test", tags=["health"])
async def search_test(_=Depends(get_current_user)) -> dict:
    """
    Test search engine connectivity.
    TODO: Remove or protect in production.
    """
    try:
        from search.search import get_search_results  # noqa: PLC0415

        results = get_search_results("bitcoin+dark+web")
        return {
            "search_working": True,
            "results_count": len(results),
            "first_result": results[0] if results else None,
        }
    except Exception as exc:
        return {"search_working": False, "error": str(exc)}


@app.get("/debug/stack", tags=["health"])
async def debug_stack(_=Depends(require_admin)) -> dict:
    """Returns a list of all running asyncio tasks and their stack traces.

    Authenticated-only: exposes internal runtime state (filenames, coroutine
    names, in-flight task stacks), matching the auth gate on its sibling
    /debug/tor-test and /debug/search-test endpoints.
    """
    import asyncio

    tasks = asyncio.all_tasks()
    out = []
    for i, t in enumerate(tasks):
        stack = []
        for f in t.get_stack():
            stack.append(f"{f.f_code.co_filename}:{f.f_lineno} in {f.f_code.co_name}")
        out.append({
            "task_id": i,
            "name": t.get_name(),
            "coro": str(t.get_coro()),
            "stack": stack,
        })
    return {"tasks": out}
