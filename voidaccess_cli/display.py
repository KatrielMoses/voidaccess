"""
cli/display.py — Rich live display for investigations.

Three-zone layout:
    title bar            — query + elapsed timer
    step table           — pipeline stages with status icons
    rotating-proxies row — live indicator (blinking green when ON, solid red when OFF)
    activity line        — current URL / sub-task detail

Status icons:
    pending  · gray dot
    active   ⠹ spinner (cycles in tick())
    ok       ✓ green
    fail     ✗ red
    skip     ↷ yellow

Rotating-proxies indicator:
    The "Rotating proxies" row is rendered with the green dot using
    Rich's blink style attribute when ON.  If the terminal does not
    support blink rendering (most modern terminals render blink as
    steady), the dot still appears as a solid green dot with "ON"
    next to it.  The OFF state uses a solid red dot (no blink needed
    because the OFF state is static).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

STATUS_GLYPH = {
    "pending": ("·", "grey50"),
    "active":  ("⠹", "cyan"),
    "ok":      ("✓", "green"),
    "fail":    ("✗", "red"),
    "skip":    ("↷", "yellow"),
}


@dataclass
class StepRow:
    name: str
    status: str = "pending"
    detail: str = ""
    substeps: list[tuple[str, str]] = field(default_factory=list)  # (label, status)


class InvestigationDisplay:
    """Live terminal display driven by .update_step() and .update_current_url()."""

    def __init__(self, console: Optional[Console] = None, quiet: bool = False):
        self.console = console or Console()
        self.quiet = quiet
        self._live: Optional[Live] = None
        self._query: str = ""
        self._start_ts: float = time.monotonic()
        self._steps: list[StepRow] = []
        self._current_url: str = ""
        self._spinner_index = 0
        self._final_summary: Optional[dict] = None
        self._error: Optional[str] = None
        # v1.6.2 — rotating-proxies indicator.  Set via set_proxy_state().
        # When None, the row is omitted (back-compat: callers that never
        # touch it keep the pre-v1.6.2 layout).  When set, the row is
        # always present from the start of the run.
        self._proxy_state: Optional[str] = None  # "on" | "off"

    # -- lifecycle ----------------------------------------------------------

    def start(self, query: str, steps: Optional[list[str]] = None) -> None:
        self._query = query
        self._start_ts = time.monotonic()
        names = steps or [
            "Refining query",
            "Searching dark web",
            "Filtering results",
            "Scraping pages",
            "Extracting entities",
            "Enriching intelligence",
            "Building graph",
            "Generating summary",
            "Finalizing results",
        ]
        self._steps = [StepRow(name=n) for n in names]
        if self.quiet:
            self.console.print(f"[bold]VoidAccess[/bold] — {query}")
            return
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.update(self._render(), refresh=True)
            self._live.stop()
            self._live = None

    # -- updates ------------------------------------------------------------

    def update_step(self, step_name: str, status: str, detail: str = "") -> None:
        row = self._find_step(step_name)
        if row is None:
            row = StepRow(name=step_name)
            self._steps.append(row)
        row.status = status
        if detail:
            row.detail = detail
        self._refresh()
        if self.quiet:
            icon = STATUS_GLYPH.get(status, ("·", "grey50"))[0]
            d = f" — {detail}" if detail else ""
            self.console.print(f"  {icon} {step_name}{d}")

    def update_substep(self, step_name: str, label: str, status: str) -> None:
        row = self._find_step(step_name)
        if row is None:
            return
        for idx, (existing, _) in enumerate(row.substeps):
            if existing == label:
                row.substeps[idx] = (label, status)
                self._refresh()
                return
        row.substeps.append((label, status))
        self._refresh()

    def update_current_url(self, url: str) -> None:
        self._current_url = url
        self._refresh()

    def set_proxy_state(self, state: str) -> None:
        """Toggle the live rotating-proxies indicator.

        state: "on" (proxy transport active for this run) or "off".
        Call this BEFORE display.start() if you want the row to be
        present from the first refresh — otherwise call it any time
        during the run and the row will appear/refresh.
        """
        if state not in ("on", "off"):
            return
        self._proxy_state = state
        self._refresh()

    def complete(self, summary: dict) -> None:
        self._final_summary = summary
        self.stop()
        self._print_completion(summary)

    def error(self, msg: str) -> None:
        self._error = msg
        self.stop()
        self.console.print(f"[bold red]Investigation failed:[/bold red] {msg}")

    # -- render -------------------------------------------------------------

    def _refresh(self) -> None:
        self._spinner_index = (self._spinner_index + 1) % len(SPINNER_FRAMES)
        if self._live is not None:
            self._live.update(self._render(), refresh=True)

    def _find_step(self, name: str) -> Optional[StepRow]:
        for row in self._steps:
            if row.name == name:
                return row
        return None

    def _render_proxy_row(self) -> Text:
        """Render the "Rotating proxies" indicator row.

        ON  → green dot with blink style + "ON"  (terminals that don't
              support blink fall back to a plain solid green dot — never
              breaks the display, blink is purely visual).
        OFF → solid red dot (no blink; OFF is static so no need to animate).
        """
        line = Text()
        if self._proxy_state == "on":
            # Blink attribute: Rich translates to ANSI 5 (blink) on
            # terminals that support it.  On terminals that don't (most
            # modern terminals render blink as a steady color or ignore
            # it entirely), the dot still renders as a solid green dot
            # because we also pass color="green" — never breaks display.
            line.append("● ", style="blink bold green")
            line.append("ON", style="bold green")
        else:
            line.append("● ", style="red")
            line.append("OFF", style="bold red")
        return line

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self._start_ts
        title = Text()
        title.append("VoidAccess", style="bold magenta")
        title.append(f" — \"{self._query}\"", style="bold white")
        title.append(f"   Elapsed: {self._fmt_elapsed(elapsed)}", style="grey50")

        table = Table.grid(padding=(0, 1))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        for row in self._steps:
            glyph, colour = STATUS_GLYPH.get(row.status, ("·", "grey50"))
            if row.status == "active":
                glyph = SPINNER_FRAMES[self._spinner_index]
            line = Text()
            line.append(f"{glyph} ", style=colour)
            line.append(row.name, style="white" if row.status != "pending" else "grey50")
            if row.detail:
                line.append(f"  ({row.detail})", style="grey62")
            table.add_row("", line)
            for sub_label, sub_status in row.substeps:
                sg, sc = STATUS_GLYPH.get(sub_status, ("·", "grey50"))
                sub = Text(f"   {sg} {sub_label}", style=sc)
                table.add_row("", sub)

        # v1.6.2 — rotating-proxies indicator row, present from the start
        # of the run, so the user sees it while scraping is actually
        # happening (not just appended at the end).
        if self._proxy_state is not None:
            label = Text()
            label.append("Rotating proxies  ", style="white")
            label.append(self._render_proxy_row())
            table.add_row("", label)

        activity = Text()
        if self._current_url:
            activity.append("Fetching: ", style="bold")
            activity.append(self._current_url, style="cyan")
        else:
            activity.append("", style="grey50")

        body = Group(title, Text(""), table, Text(""), activity)
        return Panel(body, border_style="magenta", padding=(1, 2))

    @staticmethod
    def _fmt_elapsed(secs: float) -> str:
        m, s = divmod(int(secs), 60)
        return f"{m}m {s:02d}s"

    def _print_completion(self, summary: dict) -> None:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold")
        table.add_column()

        # v1.6.2 — "Rotating proxies" line.  This is the actual verifiable
        # proof the user asked for, drawn from the per-run counters in
        # sources.proxy_client, not just a static enabled/disabled label.
        # Summary passes "proxy_summary": {"state": "on"|"off",
        # "via_proxy": int, "fallback": int} — see _run_investigation.
        proxy_summary = summary.get("proxy_summary") or {}
        proxy_state = proxy_summary.get("state", "off")
        if proxy_state == "on":
            via_proxy = int(proxy_summary.get("via_proxy", 0))
            fallback = int(proxy_summary.get("fallback", 0))
            if via_proxy > 0:
                row_text = (
                    f"[green]\u25cf ON[/green]  "
                    f"([bold]{via_proxy}[/bold] via proxy, "
                    f"[bold]{fallback}[/bold] fallback to direct)"
                )
            else:
                # Proxies were ON for this run but every attempt failed
                # and fell back.  Show the diagnostic hint so the user
                # doesn't silently think everything is fine — a "proxies
                # on but zero successes" state almost always means a bad
                # or missing proxy credentials and the user deserves to know.
                row_text = (
                    f"[yellow]\u25cf ON[/yellow]  "
                    f"([bold]0[/bold] via proxy, "
                    f"[bold]{fallback}[/bold] fallback to direct "
                    f"\u2014 check your proxy username/password)"
                )
        else:
            row_text = "[red]\u25cf OFF[/red]"
        table.add_row("Rotating Proxies", row_text)

        table.add_row("Entities", str(summary.get("entity_count", "—")))
        table.add_row("Pages", str(summary.get("page_count", "—")))
        if "relationship_count" in summary:
            table.add_row("Relationships", str(summary["relationship_count"]))
            by_type = summary.get("relationships_by_type") or {}
            if by_type:
                breakdown = ", ".join(f"{kind}: {count}" for kind, count in sorted(by_type.items()))
                table.add_row("Relationship types", breakdown)
            if summary.get("no_llm"):
                typed_count = summary.get("typed_relationship_count", 0)
                table.add_row(
                    "Typed relationships",
                    f"{typed_count} (dependency parser; --no-llm)",
                )
            elif not by_type:
                table.add_row("Typed relationships", "0 (build completed; none found)")
        if "actor_count" in summary:
            table.add_row("Actors", str(summary["actor_count"]))
        if "community_count" in summary:
            table.add_row("Communities", str(summary["community_count"]))
        if "c2_ips" in summary:
            table.add_row("C2 IPs", f"{summary['c2_ips']} confirmed")
        table.add_row("Sources", str(summary.get("sources_used", "—")))
        source_details = summary.get("source_details") or {}
        if source_details:
            source_table = Table(show_header=True, header_style="bold")
            source_table.add_column("Source")
            source_table.add_column("Status")
            source_table.add_column("Detail")
            for name, info in sorted(source_details.items()):
                status = str(info.get("status") or "unknown")
                if status.startswith("ok"):
                    status_text = "[green]ran[/green]"
                    detail = f"{info.get('count', 0)} results"
                elif status.startswith("skipped") or status == "skipped":
                    status_text = "[yellow]skipped[/yellow]"
                    detail = status.removeprefix("skipped_").replace("_", " ") or "disabled"
                else:
                    status_text = "[red]failed[/red]"
                    detail = str(info.get("error") or status)
                source_table.add_row(name, status_text, detail)
            table.add_row("Source details", source_table)
        if summary.get("report_path"):
            table.add_row("Report", str(summary["report_path"]))
        if summary.get("data_path"):
            table.add_row("Data", str(summary["data_path"]))

        panel = Panel(
            Group(Text("✓ Investigation complete", style="bold green"), Text(""), table),
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(panel)


class RichDisplaySink:
    """The Rich live display as a progress sink.

    Replays the pipeline's UI calls (``update_step``, ``update_substep``, ...)
    on an :class:`InvestigationDisplay`, in order and synchronously, so terminal
    output is identical to calling the display directly. It is the one inline
    sink: rendering must stay ordered with the console prints around it.
    """

    inline = True

    def __init__(self, display: "InvestigationDisplay"):
        self.display = display

    def handle(self, event) -> None:
        if event.type != "display" or not event.call:
            return
        getattr(self.display, event.call)(*(event.args or []))

