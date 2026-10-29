"""Per-engine outcome of a search run (23B-B2).

Every engine attempt ends in exactly one outcome:

* ``ok``           answered with results (after the safety gate and clean-up);
* ``empty``        answered, 0 results;
* ``unreachable``  no answer: connection/SOCKS failure, timeout, or cut by the
                   search deadline;
* ``rate_limited`` answered HTTP 429;
* ``error``        answered with another HTTP error, or failed otherwise.

An engine the circuit breaker skipped, or that a cancel stopped, was not
attempted and has no outcome (the breaker skip stays in ``circuits_open``).

The trace keeps its existing ``status`` field unchanged (the cloud runner's
reachability rule reads ``ok`` there for "answered", including 0 links) and
carries the outcome in a new ``outcome`` field.
"""

from __future__ import annotations

import asyncio
from typing import Iterable, Optional

OK = "ok"
EMPTY = "empty"
UNREACHABLE = "unreachable"
RATE_LIMITED = "rate_limited"
ERROR = "error"
ENGINE_OUTCOMES = (OK, EMPTY, UNREACHABLE, RATE_LIMITED, ERROR)

# Errors that mean "not attempted", not an engine outcome.
NOT_ATTEMPTED = frozenset({"circuit_open", "cancelled"})

# When an engine is tried more than once in a run (refined query, exact query,
# alternatives), its run-level outcome is the best one seen.
_RANK = {OK: 5, EMPTY: 4, RATE_LIMITED: 3, ERROR: 2, UNREACHABLE: 1}


def _unreachable_exceptions() -> tuple[type, ...]:
    import aiohttp  # noqa: PLC0415

    types: list[type] = [asyncio.TimeoutError, TimeoutError, ConnectionError, aiohttp.ClientConnectionError]
    try:
        from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError  # noqa: PLC0415

        types += [ProxyError, ProxyConnectionError, ProxyTimeoutError]
    except Exception:  # noqa: BLE001 - optional transport package
        pass
    return tuple(types)


def failure_for_exception(exc: BaseException) -> str:
    """``unreachable`` for transport failures, ``error`` for anything else."""
    if isinstance(exc, _unreachable_exceptions()):
        return UNREACHABLE
    if isinstance(exc, OSError):
        return UNREACHABLE
    name = type(exc).__name__.lower()
    if "proxy" in name or "socks" in name or "connect" in name or "timeout" in name:
        return UNREACHABLE
    return ERROR


def failure_for_http(status: int) -> str:
    return RATE_LIMITED if status == 429 else ERROR


def outcome_of(result) -> Optional[str]:
    """The outcome of one ``EngineResult``; None when it was not attempted."""
    error = getattr(result, "error", None)
    if error in NOT_ATTEMPTED:
        return None
    if error is None:
        return OK if getattr(result, "links", None) else EMPTY
    failure = getattr(result, "failure", None)
    if failure in ENGINE_OUTCOMES:
        return failure
    text = str(error).lower()
    if text in ("timeout", "deadline"):
        return UNREACHABLE
    if text == "http 429" or text == "rate_limited":
        return RATE_LIMITED
    return ERROR


def summarize(results: Iterable) -> dict:
    """Per-engine run outcome plus counts.

    ``engines``: ``{name: {"status", "results", "attempts", "ms"}}`` where
    ``results`` sums every attempt's links and ``status`` is the best outcome.
    ``engine_status_counts``: engines per outcome; ``engines_attempted``: M."""
    engines: dict[str, dict] = {}
    for result in results:
        if isinstance(result, BaseException):
            continue
        outcome = outcome_of(result)
        if outcome is None:
            continue
        entry = engines.setdefault(
            result.name, {"status": outcome, "results": 0, "attempts": 0, "ms": 0}
        )
        entry["attempts"] += 1
        entry["results"] += len(result.links or [])
        entry["ms"] = max(entry["ms"], int(getattr(result, "took_ms", 0) or 0))
        if _RANK[outcome] > _RANK[entry["status"]]:
            entry["status"] = outcome
        pages = int(getattr(result, "pages", 0) or 0)
        if pages > 1:
            entry["pages"] = max(entry.get("pages", 1), pages)
    counts = {outcome: 0 for outcome in ENGINE_OUTCOMES}
    for entry in engines.values():
        counts[entry["status"]] += 1
    return {
        "engines": engines,
        "engine_status_counts": counts,
        "engines_attempted": len(engines),
    }


def describe(summary: dict, results_found: int) -> str:
    """User-facing line for the engine fan-out.

    With results: "4 of 7 engines returned results". With none it says which
    case it was: "3 of 7 engines unreachable" (nobody answered) versus
    "engines answered but found nothing" (with the unreachable count when some
    were)."""
    counts = summary.get("engine_status_counts") or {}
    total = int(summary.get("engines_attempted") or 0)
    if total == 0:
        return "no search engine was queried"
    ok = int(counts.get(OK, 0))
    answered = ok + int(counts.get(EMPTY, 0))
    unreachable = int(counts.get(UNREACHABLE, 0))
    rate_limited = int(counts.get(RATE_LIMITED, 0))
    failed = int(counts.get(ERROR, 0))
    extras = []
    if rate_limited:
        extras.append(f"{rate_limited} rate-limited")
    if failed:
        extras.append(f"{failed} failed")
    if results_found > 0:
        text = f"{ok} of {total} engines returned results"
        if unreachable:
            extras.insert(0, f"{unreachable} unreachable")
    elif answered:
        text = "engines answered but found nothing"
        if unreachable:
            extras.insert(0, f"{unreachable} of {total} engines unreachable")
    elif unreachable:
        text = f"{unreachable} of {total} engines unreachable"
    else:
        text = "no engine answered with results"
    return text + (f" ({', '.join(extras)})" if extras else "")


def nothing_found_reason(summary: dict, results_found: int) -> Optional[str]:
    """Why the fan-out found nothing, else None (machine-readable twin of
    :func:`describe`): ``no_results`` (engines answered), ``engines_unreachable``
    (none answered, some unreachable) or ``engines_failed`` (none answered,
    every attempt rate-limited or failed)."""
    if results_found > 0 or not summary.get("engines_attempted"):
        return None
    counts = summary.get("engine_status_counts") or {}
    answered = int(counts.get(OK, 0)) + int(counts.get(EMPTY, 0))
    if answered:
        return "no_results"
    return "engines_unreachable" if int(counts.get(UNREACHABLE, 0)) else "engines_failed"
