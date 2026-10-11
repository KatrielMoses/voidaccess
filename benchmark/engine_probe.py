"""Read-only live engine health probe (Engineering Requirement 1.1).

Runs the full search fan-out over Tor across the benchmark query set and records,
per engine: success rate, mean result count, latency, and error class. Produces
the 18-engine report table that P1.1's cull decision needs (``darksearch.io``
expected among the 0% flags).

READ-ONLY by construction. It reuses only the *pure* fetch primitive
``search.search._fetch_engine`` and the Tor-isolation session helpers; it never
calls ``record_engine_attempt`` / ``should_skip_engine`` and never touches
``search/engine_catalog.py`` or the ``search_engine_stats`` circuit-breaker table.
That is the whole difference between a probe (measures every engine as-is, even a
circuit-open one) and the live pipeline (skips circuit-open engines and mutates
their stats).

Tor safety (CC-4): every engine — including the two clearnet ones — is fetched
through the Tor SOCKS proxy via ``tor_isolation``. Timing (CC-4): the one outer
timeout is derived from the same pacing-aware knobs the fetch primitive uses.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

import pacing
from search import config as search_config
from search import tor_isolation
from search.engine_catalog import SEARCH_ENGINES
from search.search import EngineResult, _fetch_engine, _normalize_for_dedup

from benchmark import artifact as _artifact
from benchmark.queries import QuerySet, load_query_set

logger = logging.getLogger(__name__)

PROBE_CONCURRENCY = 8

# Additive slack over the fetch primitive's own (pacing-driven) attempt budget: a
# hard ceiling so a wedged Tor circuit can't stall the probe, NOT the expected
# per-engine duration. ``_fetch_engine`` bounds normal fetches internally.
PROBE_CEILING_MARGIN_SECONDS = 5.0

ERROR_CLASSES: tuple[str, ...] = (
    "ok",
    "timeout",
    "http_error",
    "parse_error",
    "connection_error",
    "circuit_open",
    "max_retries",
    "other",
)


def engine_ceiling_seconds() -> float:
    """Outer per-(engine, query) timeout. Derived from the same pacing-aware knobs
    ``_fetch_engine`` uses (search_timeout × attempts), so it scales with --pace and
    never undercuts the primitive's own attempt budget."""
    attempts = search_config.engine_retry_count() + 1
    return search_config.search_timeout() * attempts + PROBE_CEILING_MARGIN_SECONDS


def classify_error(error: Optional[str]) -> str:
    """Normalize a raw ``EngineResult.error`` string into a stable class."""
    if error is None:
        return "ok"
    e = error.lower()
    if "circuit_open" in e:
        return "circuit_open"
    if "timeout" in e:
        return "timeout"
    if e.startswith("http "):
        return "http_error"
    if "json parse" in e:
        return "parse_error"
    if "max retries" in e:
        return "max_retries"
    if any(t in e for t in ("proxy", "connect", "socks", "connection", "reset", "refused")):
        return "connection_error"
    return "other"


def _preflight_tor() -> str:
    """Confirm a live Tor SOCKS proxy and point the env at it (mirrors the CLI's
    investigate preflight). Raises with guidance if Tor is unreachable."""
    from voidaccess_cli.tor_detect import detect_tor, tor_unavailable_message

    status = detect_tor()
    if not status.proxy_url:
        raise RuntimeError(tor_unavailable_message())
    os.environ["TOR_PROXY_HOST"] = status.host or "127.0.0.1"
    os.environ["TOR_PROXY_PORT"] = str(status.port or 9050)
    return status.source


async def _probe_one(
    engine: dict,
    query: str,
    probe_sem: asyncio.Semaphore,
    inner_sem: asyncio.Semaphore,
    ceiling: float,
) -> dict[str, Any]:
    """Probe one engine with one query. Never records stats. The probe-level
    semaphore gates real concurrency; ``inner_sem`` (effectively unbounded) is what
    ``_fetch_engine`` acquires internally, so the ceiling clock only runs while this
    task actually holds a slot rather than while it waits for one."""
    async with probe_sem:
        url = engine["url"].format(query=query)
        start = time.monotonic()
        try:
            session, iso_key = tor_isolation.acquire_engine_session(url)
            try:
                result: EngineResult = await asyncio.wait_for(
                    _fetch_engine(engine, query, session, inner_sem),
                    timeout=ceiling,
                )
            finally:
                tor_isolation.release_engine_session(iso_key)
            return {
                "success": result.error is None,
                "result_count": len(result.links),
                "latency_ms": (time.monotonic() - start) * 1000.0,
                "error_class": classify_error(result.error),
                "urls": [_normalize_for_dedup(l.get("link", "")) for l in result.links],
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "result_count": 0,
                "latency_ms": (time.monotonic() - start) * 1000.0,
                "error_class": "timeout",
            }
        except Exception as exc:  # a probe never crashes the run
            logger.warning("probe error for %s: %s", engine.get("name"), exc)
            return {
                "success": False,
                "result_count": 0,
                "latency_ms": (time.monotonic() - start) * 1000.0,
                "error_class": classify_error(str(exc)),
            }


async def _run_all(queries: list) -> dict[str, list[dict[str, Any]]]:
    engines = list(SEARCH_ENGINES)
    ceiling = engine_ceiling_seconds()
    probe_sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    inner_sem = asyncio.Semaphore(len(engines) * max(1, len(queries)) + 1)

    tasks = []
    index: list[tuple[str, str]] = []
    for engine in engines:
        for q in queries:
            tasks.append(_probe_one(engine, q.query, probe_sem, inner_sem, ceiling))
            index.append((engine["name"], q.id))

    try:
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        # Drain the shared Tor session pool so this short-lived probe process
        # doesn't leak the per-circuit sessions it borrowed (the pool is normally
        # closed at API shutdown, which a one-shot probe never reaches).
        try:
            from scraper.tor_pool import close_pool

            await close_pool()
        except Exception:
            pass

    per: dict[str, list[dict[str, Any]]] = {e["name"]: [] for e in engines}
    for (name, _qid), outcome in zip(index, outcomes):
        if isinstance(outcome, Exception):
            outcome = {"success": False, "result_count": 0, "latency_ms": 0.0, "error_class": "other"}
        per.setdefault(name, []).append(outcome)
    return per


def _percentile(values: list[float], p: float) -> float:
    """Linear-interpolated percentile (0 <= p <= 1); 0.0 for an empty list."""
    if not values:
        return 0.0
    v = sorted(values)
    k = (len(v) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def _unique_contribution(per: dict) -> tuple[dict[str, tuple[int, int]], int]:
    """Per engine: (results found by no other engine for the same query, all its
    results), plus the count of distinct (query, url) results across all engines."""
    seen_by: dict[tuple[int, str], set[str]] = {}
    for name, outcomes in per.items():
        for qi, o in enumerate(outcomes):
            for url in o.get("urls") or []:
                if url:
                    seen_by.setdefault((qi, url), set()).add(name)
    out: dict[str, tuple[int, int]] = {}
    for name, outcomes in per.items():
        unique = total = 0
        for qi, o in enumerate(outcomes):
            for url in set(u for u in (o.get("urls") or []) if u):
                total += 1
                if seen_by[(qi, url)] == {name}:
                    unique += 1
        out[name] = (unique, total)
    return out, len(seen_by)


def _build_artifact(query_set: QuerySet, queries: list, per: dict, tor_source: str) -> dict:
    engines_report = []
    flagged: list[str] = []
    unique_by_engine, total_unique = _unique_contribution(per)

    for engine in SEARCH_ENGINES:
        name = engine["name"]
        outcomes = per.get(name, [])
        attempts = len(outcomes)
        successes = sum(1 for o in outcomes if o["success"])
        success_rate = (successes / attempts) if attempts else 0.0

        succ_counts = [o["result_count"] for o in outcomes if o["success"]]
        mean_result_count = (sum(succ_counts) / len(succ_counts)) if succ_counts else 0.0
        latencies = [o["latency_ms"] for o in outcomes]
        mean_latency_ms = (sum(latencies) / len(latencies)) if latencies else 0.0

        err_counts = {c: 0 for c in ERROR_CLASSES}
        for o in outcomes:
            cls = o["error_class"]
            err_counts[cls] = err_counts.get(cls, 0) + 1
        non_ok = {c: n for c, n in err_counts.items() if c != "ok" and n > 0}
        if non_ok:
            dominant_error = max(non_ok, key=non_ok.get)
        elif attempts:
            dominant_error = "ok"
        else:
            dominant_error = "none"

        flagged_zero = attempts > 0 and success_rate == 0.0
        if flagged_zero:
            flagged.append(name)

        engines_report.append({
            "name": name,
            "url": engine["url"],
            "status": engine.get("status", "active"),
            "attempts": attempts,
            "successes": successes,
            "success_rate": round(success_rate, 4),
            "mean_result_count": round(mean_result_count, 2),
            "mean_latency_ms": round(mean_latency_ms, 1),
            "latency_p90_ms": round(_percentile(latencies, 0.9), 1),
            "unique_result_count": unique_by_engine.get(name, (0, 0))[0],
            "unique_result_share": round(
                unique_by_engine.get(name, (0, 0))[0] / total_unique, 4
            ) if total_unique else 0.0,
            "error_class_counts": err_counts,
            "dominant_error": dominant_error,
            "flagged_zero": flagged_zero,
        })

    engines_report.sort(key=lambda r: r["name"])

    return {
        "artifact_type": "engine_health_probe",
        "schema_version": _artifact.SCHEMA_VERSION,
        "run": {
            "generated_at": _artifact.now_iso(),
            "pace_profile": pacing.get_profile(),
            "tor_source": tor_source,
            "query_set_version": query_set.version,
            "queries_used": [q.id for q in queries],
            "engine_count": len(SEARCH_ENGINES),
            "git_commit": _artifact.git_commit(),
        },
        "summary": {
            "engines_total": len(SEARCH_ENGINES),
            "engines_flagged_zero": len(flagged),
            "flagged_engine_names": sorted(flagged),
        },
        "engines": engines_report,
    }


def _render_table(console, artifact: dict) -> None:
    from rich.table import Table

    table = Table(title="Engine health probe (read-only)", show_lines=False)
    table.add_column("Engine", overflow="fold")
    table.add_column("Success", justify="right")
    table.add_column("Mean results", justify="right")
    table.add_column("Mean latency", justify="right")
    table.add_column("Dominant error")
    table.add_column("Flag")
    for e in artifact["engines"]:
        flag = "[red]0%[/red]" if e["flagged_zero"] else ""
        pct = f"{e['success_rate'] * 100:.0f}%"
        table.add_row(
            e["name"],
            pct,
            f"{e['mean_result_count']:.1f}",
            f"{e['mean_latency_ms']:.0f} ms",
            e["dominant_error"],
            flag,
        )
    console.print(table)
    s = artifact["summary"]
    console.print(
        f"[bold]{s['engines_flagged_zero']}/{s['engines_total']}[/bold] engines flagged 0% "
        f"over the sample: {', '.join(s['flagged_engine_names']) or '(none)'}"
    )


def probe_engines(
    query_set: Optional[QuerySet] = None,
    *,
    sample_size: Optional[int] = None,
    no_tor: bool = False,
    out_path: Optional[Path] = None,
    console=None,
) -> dict:
    """Run the read-only probe and write a canonical artifact. Returns the artifact.

    ``no_tor`` skips the Tor preflight (used by the offline test suite with mocked
    fetch/isolation seams); a live probe always keeps it on.
    """
    query_set = query_set or load_query_set()
    queries = list(query_set.queries)
    if sample_size is not None:
        queries = queries[: max(1, sample_size)]

    tor_source = "disabled" if no_tor else _preflight_tor()

    per = asyncio.run(_run_all(queries))
    artifact = _build_artifact(query_set, queries, per, tor_source)

    path = Path(out_path) if out_path else (_artifact.DEFAULT_ARTIFACT_DIR / "engine-health-latest.json")
    _artifact.write_artifact(artifact, path)

    if console is not None:
        _render_table(console, artifact)
    return artifact
