"""Pipeline reporter: one call site for the live display and progress events.

The pipeline talks to a :class:`PipelineReporter` with the same method names as
:class:`voidaccess_cli.display.InvestigationDisplay`. Each display call is
forwarded to the emitter as an internal ``display`` event (consumed in order by
the Rich sink), and the reporter also exposes the 8-stage helpers that produce
the contract events (see ``progress/README.md``).
"""

from __future__ import annotations

from typing import Any, Optional

from progress import ProgressEmitter, Stage


class PipelineReporter:
    def __init__(self, emitter: ProgressEmitter):
        self.emitter = emitter

    # -- InvestigationDisplay-compatible surface ---------------------------

    def start(self, query: str, steps: Optional[list[str]] = None) -> None:
        self.emitter.display("start", query, steps)

    def update_step(self, step_name: str, status: str, detail: str = "") -> None:
        self.emitter.display("update_step", step_name, status, detail)

    def update_substep(self, step_name: str, label: str, status: str) -> None:
        self.emitter.display("update_substep", step_name, label, status)

    def update_current_url(self, url: str) -> None:
        self.emitter.display("update_current_url", url)

    def set_proxy_state(self, state: str) -> None:
        self.emitter.display("set_proxy_state", state)

    def complete(self, summary: dict) -> None:
        self.emitter.display("complete", summary)

    def error(self, msg: str) -> None:
        self.emitter.display("error", msg)

    # -- stage events ------------------------------------------------------

    def stage_start(self, stage: Stage, message: Optional[str] = None) -> None:
        self.emitter.stage_start(stage, message)

    def stage_end(self, stage: Stage, status: str = "end", message: Optional[str] = None, **counts: Any) -> None:
        self.emitter.stage_end(stage, status, message, **counts)

    def set_counts(self, **counts: int) -> None:
        self.emitter.set_counts(**counts)
