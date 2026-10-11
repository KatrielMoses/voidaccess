"""Official progress hook for the investigation pipeline.

See ``progress/README.md``. The pipeline reports to a :class:`ProgressEmitter`;
sinks (Rich display, JSONL file, a callback) subscribe to it. A sink can never
hurt a run: every sink call is wrapped, and out-of-process sinks are fed through
a bounded queue drained by a daemon thread, so a slow or raising sink cannot
block or break a stage.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

STAGE_TOTAL = 8

# Bounded buffer for queued sinks. Intermediate ``counts`` events are dropped
# when it is full; ``stage`` / ``refined`` / terminal events never are.
EVENT_QUEUE_MAX = 256
# How long ``close()`` waits for queued sinks to drain before giving up.
EVENT_FLUSH_TIMEOUT_S = 5.0


class Stage(str, Enum):
    """The eight pipeline stages, in the order the pipeline runs them.

    ``extract`` runs before ``enrich`` because enrichment is driven by the
    extracted entities. ``stage_index`` is 1-based (1..8).
    """

    REFINE = "refine"
    COLLECT = "collect"
    FILTER = "filter"
    FETCH = "fetch"
    EXTRACT = "extract"
    ENRICH = "enrich"
    GRAPH = "graph"
    SUMMARIZE = "summarize"


STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)

EVENT_TYPES = ("stage", "counts", "refined", "completed", "failed", "cancelled")
TERMINAL_TYPES = ("completed", "failed", "cancelled")
# ``display`` events carry UI calls for the Rich sink only. They are not part
# of the external contract and never reach JSONL / callback sinks by default.
DISPLAY_TYPE = "display"

COUNT_KEYS = (
    "sources_queried",
    "results_found",
    "pages_fetched",
    "entities_found",
    "actors_found",
)


def stage_index(stage: Stage) -> int:
    return STAGE_ORDER.index(stage) + 1


@dataclass
class ProgressEvent:
    """Matches ENGINE-CONTRACT §2 ``ProgressEvent`` plus additive fields.

    Additive (not in the contract): ``status`` (``start`` | ``end`` |
    ``skipped`` | ``failed`` on ``stage`` events), ``duration_ms`` (on a stage
    ``end``), ``call`` / ``args`` (``display`` events only).
    """

    type: str
    run_id: str = ""
    seq: int = 0
    at: str = ""
    stage: Optional[Stage] = None
    stage_index: Optional[int] = None
    stage_total: int = STAGE_TOTAL
    refined_queries: Optional[list[str]] = None
    counts: Optional[dict[str, int]] = None
    message: Optional[str] = None
    stages_completed: Optional[list[str]] = None
    reason: Optional[str] = None
    metrics: Optional[dict[str, Any]] = None
    status: Optional[str] = None
    duration_ms: Optional[int] = None
    call: Optional[str] = None
    args: Optional[list[Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict with ``None`` fields omitted."""
        out = {k: v for k, v in asdict(self).items() if v is not None}
        if self.stage is not None:
            out["stage"] = self.stage.value
        return out


@runtime_checkable
class EventSink(Protocol):
    """Anything that can consume progress events.

    Set ``inline = True`` on a sink to run it synchronously on the emitting
    thread (used only by the Rich display, whose output must stay ordered with
    the console). All other sinks run on the emitter's worker thread.
    """

    def handle(self, event: ProgressEvent) -> None: ...


class JsonlSink:
    """Appends one JSON object per contract event to *path*."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def handle(self, event: ProgressEvent) -> None:
        if event.type == DISPLAY_TYPE:
            return
        self._fh.write(json.dumps(event.to_dict(), default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # pragma: no cover - best effort
            pass


class CallbackSink:
    """Calls ``fn(event)`` for every contract event."""

    def __init__(self, fn: Callable[[ProgressEvent], None]):
        self.fn = fn

    def handle(self, event: ProgressEvent) -> None:
        if event.type == DISPLAY_TYPE:
            return
        self.fn(event)


class ProgressEmitter:
    """Fan-out of progress events to sinks, isolated from the pipeline."""

    def __init__(
        self,
        sinks: Optional[list[EventSink]] = None,
        run_id: str = "",
        queue_max: int = EVENT_QUEUE_MAX,
    ):
        self.run_id = run_id
        self.counts: dict[str, int] = {k: 0 for k in COUNT_KEYS}
        self.stages_completed: list[str] = []
        self._seq = 0
        self._stage_started: dict[Stage, float] = {}
        self._stage_ms: dict[str, int] = {}
        self._queue_max = max(1, queue_max)
        self._inline: list[EventSink] = []
        self._queued: list[EventSink] = []
        self._buf: deque[ProgressEvent] = deque()
        self._cv = threading.Condition()
        self._closed = False
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.dropped = 0
        self.terminal_sent = False
        for sink in sinks or []:
            self.add_sink(sink)

    # -- sinks ---------------------------------------------------------------

    def add_sink(self, sink: EventSink) -> None:
        if getattr(sink, "inline", False):
            self._inline.append(sink)
            return
        self._queued.append(sink)
        if self._worker is None:
            self._worker = threading.Thread(
                target=self._drain, name="va-progress", daemon=True
            )
            self._worker.start()

    # -- emitting ------------------------------------------------------------

    def emit(self, event: ProgressEvent) -> None:
        """Stamp and dispatch *event*. Never raises."""
        try:
            if event.type in TERMINAL_TYPES:
                self.terminal_sent = True
            with self._lock:
                if event.type != DISPLAY_TYPE:  # keep contract seq contiguous
                    self._seq += 1
                    event.seq = self._seq
                event.run_id = event.run_id or self.run_id
                event.at = datetime.now(timezone.utc).isoformat()
            for sink in self._inline:
                self._call(sink, event)
            if self._queued and event.type != DISPLAY_TYPE:
                self._enqueue(event)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("progress emit failed (ignored): %s", exc)

    def _enqueue(self, event: ProgressEvent) -> None:
        with self._cv:
            if len(self._buf) >= self._queue_max:
                if event.type == "counts":
                    self.dropped += 1
                    return
                # Make room by evicting the oldest droppable counts event.
                for i, queued in enumerate(self._buf):
                    if queued.type == "counts":
                        del self._buf[i]
                        self.dropped += 1
                        break
                # Otherwise keep the must-deliver event; only a flood of
                # stage/terminal events can grow the buffer, and there are
                # at most a few dozen per run.
            self._buf.append(event)
            self._cv.notify()

    def _drain(self) -> None:
        while True:
            with self._cv:
                while not self._buf and not self._closed:
                    self._cv.wait()
                if not self._buf and self._closed:
                    return
                event = self._buf.popleft()
            for sink in self._queued:
                self._call(sink, event)

    @staticmethod
    def _call(sink: EventSink, event: ProgressEvent) -> None:
        try:
            sink.handle(event)
        except Exception as exc:
            logger.warning(
                "progress sink %s raised %s (ignored)", type(sink).__name__, exc
            )

    def close(self, timeout: float = EVENT_FLUSH_TIMEOUT_S) -> None:
        """Flush queued sinks (bounded wait) and release file handles."""
        with self._cv:
            self._closed = True
            self._cv.notify_all()
        if self._worker is not None:
            self._worker.join(timeout)
        for sink in self._inline + self._queued:
            closer = getattr(sink, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass

    # -- pipeline helpers ------------------------------------------------------

    def set_counts(self, **counts: int) -> None:
        for key, value in counts.items():
            if key in self.counts and value is not None:
                self.counts[key] = int(value)

    def _snapshot(self) -> dict[str, int]:
        return dict(self.counts)

    def display(self, call: str, *args: Any) -> None:
        self.emit(ProgressEvent(type=DISPLAY_TYPE, call=call, args=list(args)))

    def stage_start(self, stage: Stage, message: Optional[str] = None) -> None:
        import time

        self._stage_started[stage] = time.monotonic()
        self.emit(
            ProgressEvent(
                type="stage",
                stage=stage,
                stage_index=stage_index(stage),
                status="start",
                counts=self._snapshot(),
                message=message,
            )
        )

    def stage_end(
        self,
        stage: Stage,
        status: str = "end",
        message: Optional[str] = None,
        **counts: int,
    ) -> None:
        """End *stage* (``status`` = ``end`` | ``skipped`` | ``failed``)."""
        import time

        self.set_counts(**counts)
        started = self._stage_started.pop(stage, None)
        duration_ms = (
            int((time.monotonic() - started) * 1000) if started is not None else 0
        )
        self._stage_ms[stage.value] = duration_ms
        if status != "failed":
            self.stages_completed.append(stage.value)
        self.emit(
            ProgressEvent(
                type="stage",
                stage=stage,
                stage_index=stage_index(stage),
                status=status,
                counts=self._snapshot(),
                message=message,
                duration_ms=duration_ms,
            )
        )

    def refined(self, queries: list[str]) -> None:
        self.emit(
            ProgressEvent(
                type="refined",
                refined_queries=list(queries),
                stage=Stage.REFINE,
                stage_index=stage_index(Stage.REFINE),
            )
        )

    def completed(self, metrics: Optional[dict[str, Any]] = None) -> None:
        payload = dict(metrics or {})
        payload.setdefault("stage_ms", dict(self._stage_ms))
        self.emit(
            ProgressEvent(
                type="completed",
                counts=self._snapshot(),
                stages_completed=list(self.stages_completed),
                metrics=payload,
            )
        )

    def cancelled(self) -> None:
        self.emit(
            ProgressEvent(
                type="cancelled",
                reason="cancelled",
                counts=self._snapshot(),
                stages_completed=list(self.stages_completed),
                metrics={"stage_ms": dict(self._stage_ms)},
            )
        )

    def failed(self, reason: str, message: Optional[str] = None) -> None:
        self.emit(
            ProgressEvent(
                type="failed",
                reason=reason,
                message=message,
                counts=self._snapshot(),
                stages_completed=list(self.stages_completed),
                metrics={"stage_ms": dict(self._stage_ms)},
            )
        )


__all__ = [
    "COUNT_KEYS",
    "CallbackSink",
    "DISPLAY_TYPE",
    "EVENT_FLUSH_TIMEOUT_S",
    "EVENT_QUEUE_MAX",
    "EventSink",
    "JsonlSink",
    "ProgressEmitter",
    "ProgressEvent",
    "STAGE_ORDER",
    "STAGE_TOTAL",
    "Stage",
    "stage_index",
]
