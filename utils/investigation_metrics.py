"""Additive per-investigation pipeline metrics.

The collector is deliberately process-local while a run is active.  Database
writes happen through the explicit ``persist`` helper so instrumentation never
changes pipeline control flow when the database is unavailable.
"""

from __future__ import annotations

import contextvars
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class StepMetric:
    duration_ms: float = 0.0
    llm_calls: int = 0
    extraction_llm_pages: int = 0
    extraction_cache_hits: int = 0
    pages_attempted: int = 0
    pages_fetched: int = 0
    pages_failed: int = 0
    pages_cache_hits: int = 0
    pages_fresh: int = 0
    # HTTP calls made per source id during this step. In-memory only (not a DB
    # column): surfaced through the progress hook's ``completed`` metrics.
    source_requests: dict[str, int] = field(default_factory=dict)
    _started: float | None = field(default=None, repr=False)


class InvestigationMetrics:
    def __init__(self, investigation_id: Any):
        self.investigation_id = investigation_id
        # Pages the summary flagged as likely prompt-injection attempts
        # (voidaccess.fence.looks_like_injection). In-memory only, not a DB
        # column: surfaced through the progress hook's ``completed`` metrics.
        # Keyed by page URL so a summary retry does not count a page twice.
        self.prompt_injection_suspect_pages: set[str] = set()
        self.steps: dict[str, StepMetric] = {
            name: StepMetric()
            for name in (
                "query_refinement", "source_gathering", "scraping",
                "entity_extraction", "enrichment", "graph_build",
                "summary_generation", "finalization",
            )
        }

    def start(self, step_name: str) -> None:
        metric = self.steps.setdefault(step_name, StepMetric())
        metric._started = time.perf_counter()

    def finish(self, step_name: str) -> None:
        metric = self.steps.setdefault(step_name, StepMetric())
        if metric._started is not None:
            metric.duration_ms += (time.perf_counter() - metric._started) * 1000
            metric._started = None

    def record_llm_call(self) -> None:
        for metric in self._active_metrics():
            metric.llm_calls += 1

    def record_extraction(self, cache_hit: bool) -> None:
        metric = self.steps.setdefault("entity_extraction", StepMetric())
        if cache_hit:
            metric.extraction_cache_hits += 1
        else:
            metric.extraction_llm_pages += 1

    def record_scraping(self, attempted: int, fetched: int, cache_hits: int) -> None:
        metric = self.steps.setdefault("scraping", StepMetric())
        metric.pages_attempted = attempted
        metric.pages_fetched = fetched
        metric.pages_failed = max(0, attempted - fetched)
        metric.pages_cache_hits = cache_hits
        metric.pages_fresh = max(0, attempted - cache_hits)

    def record_source_requests(self, step_name: str, requests: dict[str, int]) -> None:
        metric = self.steps.setdefault(step_name, StepMetric())
        for source_id, n in requests.items():
            metric.source_requests[source_id] = metric.source_requests.get(source_id, 0) + n

    def source_requests_total(self) -> dict[str, int]:
        total: dict[str, int] = {}
        for metric in self.steps.values():
            for source_id, n in metric.source_requests.items():
                total[source_id] = total.get(source_id, 0) + n
        return total

    @property
    def prompt_injection_suspects(self) -> int:
        return len(self.prompt_injection_suspect_pages)

    def _active_metrics(self) -> list[StepMetric]:
        return [metric for metric in self.steps.values() if metric._started is not None]

    def rows(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        return [
            {
                "investigation_id": self.investigation_id,
                "step_name": name,
                "duration_ms": metric.duration_ms,
                "llm_calls": metric.llm_calls,
                "extraction_llm_pages": metric.extraction_llm_pages,
                "extraction_cache_hits": metric.extraction_cache_hits,
                "pages_attempted": metric.pages_attempted,
                "pages_fetched": metric.pages_fetched,
                "pages_failed": metric.pages_failed,
                "pages_cache_hits": metric.pages_cache_hits,
                "pages_fresh": metric.pages_fresh,
                "recorded_at": now,
            }
            for name, metric in self.steps.items()
        ]


_current: contextvars.ContextVar[InvestigationMetrics | None] = contextvars.ContextVar(
    "voidaccess_investigation_metrics", default=None
)


def set_current(metrics: InvestigationMetrics | None) -> None:
    _current.set(metrics)


def current() -> InvestigationMetrics | None:
    return _current.get()


def record_llm_call() -> None:
    metrics = current()
    if metrics is not None:
        metrics.record_llm_call()


def record_prompt_injection_suspects(pages: list[str]) -> None:
    metrics = current()
    if metrics is not None:
        metrics.prompt_injection_suspect_pages.update(pages)


def record_extraction(cache_hit: bool) -> None:
    metrics = current()
    if metrics is not None:
        metrics.record_extraction(cache_hit)


def persist(metrics: InvestigationMetrics) -> None:
    """Best-effort upsert; metrics must never affect pipeline behavior."""
    try:
        from db.models import InvestigationStepMetric
        from db.session import get_session

        with get_session() as session:
            for row in metrics.rows():
                existing = session.query(InvestigationStepMetric).filter_by(
                    investigation_id=row["investigation_id"],
                    step_name=row["step_name"],
                ).first()
                if existing is None:
                    session.add(InvestigationStepMetric(**row))
                else:
                    for key, value in row.items():
                        if key not in ("investigation_id", "step_name"):
                            setattr(existing, key, value)
            session.commit()
    except Exception:
        # Observability must not turn a successful investigation into a failure.
        return
