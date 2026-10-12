"""Deterministic, non-LLM fallback summary.

Used when the LLM summary times out or fails so a run that found pages never
ends with an empty summary. Built only from already-extracted entities and the
page list; the output is marked ``summary_kind: "fallback"`` by the caller.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

# The first attempt gets this share of the phase budget; the reduced-context
# retry gets the rest. Shared by the CLI and the API.
SUMMARY_FIRST_ATTEMPT_SHARE = 0.67
SUMMARY_RETRY_TOP_PAGES = 4
SUMMARY_RETRY_MAX_CHARS = 4000

# Inclusion list, not an exclusion list: credential, key, email, phone and
# personal-name entities must never be echoed into a summary.
FALLBACK_ENTITY_TYPES = (
    "THREAT_ACTOR_HANDLE",
    "THREAT_ACTOR",
    "RANSOMWARE_GROUP",
    "MALWARE_FAMILY",
    "MALWARE",
    "CVE",
    "CVE_NUMBER",
    "MITRE_TECHNIQUE",
    "ORGANIZATION_NAME",
    "DOMAIN",
    "IP_ADDRESS",
)
FALLBACK_PER_TYPE = 5
FALLBACK_MAX_SOURCES = 5


def build_fallback_summary(
    query: str,
    entities: Iterable[dict[str, Any]],
    pages: Iterable[dict[str, Any]],
) -> str:
    entity_list = list(entities or [])
    page_list = list(pages or [])
    lines = [
        f"Automated summary for '{query}' "
        "(the AI summary was unavailable for this run, so this was built "
        "from extracted entities and sources only).",
        "",
        f"Pages analysed: {len(page_list)}. Entities extracted: {len(entity_list)}.",
    ]

    by_type: dict[str, list[dict[str, Any]]] = {}
    for ent in entity_list:
        etype = str(ent.get("entity_type") or "").upper()
        if etype in FALLBACK_ENTITY_TYPES and ent.get("value") and not ent.get("suppressed"):
            by_type.setdefault(etype, []).append(ent)

    for etype in FALLBACK_ENTITY_TYPES:
        items = by_type.get(etype)
        if not items:
            continue
        items = sorted(items, key=lambda e: -float(e.get("confidence") or 0.0))
        values = [str(e["value"]) for e in items[:FALLBACK_PER_TYPE]]
        label = etype.replace("_", " ").title()
        lines.append(f"- {label}: {', '.join(values)}")

    sources = []
    for page in page_list:
        url = page.get("url") or page.get("link")
        if url and url not in sources:
            sources.append(url)
        if len(sources) >= FALLBACK_MAX_SOURCES:
            break
    if sources:
        lines.append("")
        lines.append("Top sources:")
        lines.extend(f"- {u}" for u in sources)
    return "\n".join(lines)


@dataclass
class SummaryOutcome:
    """Result of the summary phase: the text and where it came from."""

    text: str
    kind: str  # "llm" | "fallback" | "none"
    attempts: int = 0
    failure: Optional[str] = None  # exception CLASS name only, never its message


async def summarize_with_fallback(
    call: Callable[..., Awaitable[str]],
    pages: list[dict[str, Any]],
    *,
    query: str,
    budget_s: float,
    fallback_entities: Callable[[], Iterable[dict[str, Any]]],
    first_share: float = SUMMARY_FIRST_ATTEMPT_SHARE,
    retry_top_pages: int = SUMMARY_RETRY_TOP_PAGES,
    retry_max_chars: int = SUMMARY_RETRY_MAX_CHARS,
    log_id: str = "",
) -> SummaryOutcome:
    """The summary phase for every entry point: attempt, retry once, fall back.

    ``call(pages, **kwargs)`` runs ONE LLM summary attempt and returns its text;
    it raises ``voidaccess.llm.SummaryUnavailable`` (or anything else, or times
    out) on failure. On a failed or empty first attempt the call is repeated once
    with reduced context (``retry_top_pages`` pages, ``max_summary_chars``), and
    when that also fails the deterministic fallback summary is built. ``kind`` is
    ``llm`` only when the model actually produced text, so a failed LLM can
    never surface as ``llm``. ``failure`` carries the exception class name for
    logs; no exception message ever reaches the result.
    """
    if not pages:
        return SummaryOutcome("", "none")

    started = time.monotonic()
    first_budget = max(budget_s * first_share, 1.0)
    attempts = 0
    failure: Optional[str] = None

    async def _attempt(call_pages: list, timeout: float, **kwargs: Any) -> str:
        return await asyncio.wait_for(call(call_pages, **kwargs), timeout=timeout)

    text = ""
    try:
        attempts += 1
        text = await _attempt(pages, first_budget)
    except asyncio.TimeoutError:
        failure = "TimeoutError"
        logger.warning(
            "[%s] summary attempt timed out after %.0fs - retrying with reduced context",
            log_id, first_budget,
        )
    except Exception as exc:
        failure = type(exc).__name__
        logger.warning(
            "[%s] summary attempt failed (%s) - retrying with reduced context",
            log_id, failure,
        )

    if not (text or "").strip():
        remaining = max(budget_s - (time.monotonic() - started), 1.0)
        try:
            attempts += 1
            text = await _attempt(
                pages[:retry_top_pages], remaining, max_summary_chars=retry_max_chars
            )
        except asyncio.TimeoutError:
            failure = "TimeoutError"
            logger.warning(
                "[%s] summary retry timed out within the %.0fs budget", log_id, budget_s
            )
        except Exception as exc:
            failure = type(exc).__name__
            logger.warning("[%s] summary retry failed (%s)", log_id, failure)

    if (text or "").strip():
        return SummaryOutcome(text, "llm", attempts, None)

    fallback = build_fallback_summary(query, list(fallback_entities() or []), pages)
    return SummaryOutcome(fallback, "fallback", attempts, failure)
