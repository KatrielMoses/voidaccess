"""
cli/main.py — typer entry point exposed as the `voidaccess` script.

Defined as the [project.scripts] target in pyproject.toml:
    voidaccess = "voidaccess_cli.main:app"
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows consoles so rich glyphs render reliably
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table

from voidaccess_cli import __version__
from voidaccess_cli import config as cli_config
from voidaccess_cli.commands import admin, actors, benchmark, configure, enrich, export, investigate, show

console = Console()
BANNER = """\
[color(183)]     ░░░░░[color(141)]█[color(183)]░░░░░[/]
[color(183)]  ░░[color(141)]█████████████[color(183)]░░[/]
[color(183)] ░[color(141)]█████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(141)]██████[/]  [bright_white]void[/]  [color(141)]███████[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)] ░[color(141)]█████████████████[color(183)]░[/]
[color(183)]  ░░[color(141)]█████████████[color(183)]░░[/]
[color(183)]     ░░░░░[color(141)]█[color(183)]░░░░░[/]
[dim white]dark web osint intelligence[/dim white]
[dim cyan]━━━ Partnered with ScrapingAnt ━━━[/dim cyan]
[bright_cyan]Web Scraping with Rotating Proxies[/bright_cyan]
[link=https://scrapingant.com/?ref=mzliyzh][dim italic]↗ scrapingant.com[/dim italic][/link]"""

app = typer.Typer(
    name="voidaccess",
    help="Dark web OSINT — query to intelligence report.",
    no_args_is_help=True,
    add_completion=False,
)

# Sub-commands
app.add_typer(admin.app, name="admin")
app.add_typer(configure.app, name="configure", help="Configure the CLI (LLM, keys, Tor).")
app.add_typer(benchmark.app, name="benchmark", help="Measurement harness: pipeline metrics + engine health probe.")
app.command("investigate", help="Run a new investigation.")(investigate.run)
app.command("show", help="Open the entity browser TUI.")(show.run)
app.command("export", help="Export an investigation to STIX/MISP/Sigma/package/CSV/MD/JSON.")(export.run)
app.command("enrich", help="Re-enrich a stored investigation against current feeds.")(enrich.run)
app.command("actors", help="List persistent actor profiles.")(actors.run)
app.command("actor", help="Show or annotate a single actor profile.")(actors.run)


@app.command("package")
def package(
    target: str = typer.Argument(..., help="Investigation id or .json file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output ZIP path"),
    tlp: str = typer.Option(
        "white",
        "--tlp",
        help="TLP marker: white|green|amber|red",
    ),
    redact_credentials: bool = typer.Option(
        True,
        "--redact-credentials/--no-redact-credentials",
        help="Partially redact credential values",
    ),
    include_raw: bool = typer.Option(
        False,
        "--include-raw/--no-include-raw",
        help="Include raw scraped page content",
    ),
) -> None:
    """Shortcut: build an IOC package ZIP for an investigation.

    Equivalent to `voidaccess export <target> --format package`.
    """
    export.run(
        target=target,
        fmt="package",
        output=output,
        tlp=tlp,
        redact_credentials=redact_credentials,
        include_raw=include_raw,
    )


@app.command("timeline")
def timeline(
    handle: str = typer.Argument(..., help="Actor handle or UUID"),
    limit: int = typer.Option(
        50, "--limit", "-n",
        help="Maximum number of timeline events to show",
    ),
    event_types: Optional[str] = typer.Option(
        None, "--event-types",
        help=(
            "Comma-separated event types to include "
            "(FIRST_SEEN, INVESTIGATION, NEW_ALIAS, "
            "NEW_INFRASTRUCTURE, NOTE_ADDED)"
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Shortcut: show the chronological activity timeline for an actor.

    Equivalent to ``voidaccess actor <handle> --timeline
    [--event-types …] [--limit N] [--json]``.
    """
    actors.run(
        handle=handle,
        timeline=True,
        limit=limit,
        event_types=event_types,
        as_json=as_json,
    )


def _ensure_first_run() -> None:
    """Auto-launch wizard on first invocation when no config exists."""
    if cli_config.CONFIG_PATH.exists():
        return
    console.print(
        "[bold magenta]Welcome to voidaccess.[/bold magenta] "
        "Let's get you configured first."
    )
    # Invoke wizard via Typer
    try:
        configure.configure_default(ctx=typer.Context(configure.app))
    except Exception:
        pass


@app.command("status")
def status(
    engines: bool = typer.Option(False, "--engines", help="Show search engine performance stats"),
    cache: bool = typer.Option(False, "--cache", help="Show enrichment cache stats"),
    seeds: bool = typer.Option(False, "--seeds", help="Show seed pool breakdown (permanent + discovered)"),
) -> None:
    """Show current config, Tor status, and detected API keys."""
    from voidaccess_cli.tor_detect import detect_tor
    cli_config.apply_env()
    if engines:
        _show_engine_status()
        return

    cfg = cli_config.load_config()

    table = Table(title="voidaccess status", show_lines=False)
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Version", __version__)
    table.add_row("Config path", str(cli_config.CONFIG_PATH))
    table.add_row("DB path", str(cli_config.DB_PATH))
    table.add_row("Output dir", str(cli_config.get_output_dir(cfg)))

    llm = cfg.get("llm", {})
    table.add_row("LLM provider", llm.get("provider") or "—")
    table.add_row("LLM model", llm.get("model") or "—")
    table.add_row("LLM key", "[green]set[/green]" if llm.get("api_key") else "[red]missing[/red]")

    table.add_row("Tor host", cfg.get("tor", {}).get("host", "—"))
    table.add_row("Tor port", str(cfg.get("tor", {}).get("port", "—")))

    tor_status = detect_tor()
    if tor_status.proxy_url:
        table.add_row("Tor reachable", f"[green]{tor_status.source}[/green] at {tor_status.proxy_url}")
    else:
        table.add_row("Tor reachable", "[red]no proxy responded[/red]")

    try:
        import spacy

        spacy.load("en_core_web_sm")
        spacy_status = "ready"
    except Exception:
        spacy_status = "not installed"
    table.add_row("spaCy NER", spacy_status)

    keys = cfg.get("enrichment_keys", {})
    set_count = sum(1 for v in keys.values() if v)
    table.add_row("Enrichment keys", f"{set_count}/{len(keys)} set")

    # Phase 1.6 (corrected per architect review) — show the clearnet-routing
    # state.  Per https://docs.scrapingant.com/proxy-mode §Introduction
    # ("the proxy transport is a light front-end for the scraping API") the two
    # transports are mutually exclusive alternates — there is no
    # combined "chained" state.  We delegate to the chokepoint's
    # transport selector so the display ALWAYS matches what
    # clearnet_fetch() will actually do.  Never reveals raw keys.
    #
    #   both off          → red    "disabled"           (direct — pre-1.6.2 behavior)
    #   proxy only        → cyan   "proxy transport"         (HTTP CONNECT through the configured ScrapingAnt proxy endpoint)
    #   api only          → green  "REST API"          (POST api.scrapingant.com/v2/general)
    #   both on (proxy wins) → magenta "proxy transport (api would be overridden)"
    proxy_username = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_USERNAME", "")
    proxy_password = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_PASSWORD", "")
    proxy_ready = bool(proxy_username and proxy_password)
    from sources.proxy_client import (
        is_api_transport_enabled,
        is_proxy_transport_enabled,
        select_transport,
    )
    api_gate = is_api_transport_enabled()
    proxy_gate = is_proxy_transport_enabled()
    selected = select_transport()
    if selected == "proxy" and proxy_ready:
        if api_gate:
            routing_state = "[magenta]proxy transport (REST API overridden)[/magenta]"
            routing_detail = "proxy transport; REST API gate was also on but proxy wins"
        else:
            routing_state = "[cyan]proxy transport[/cyan]"
            routing_detail = "HTTP CONNECT through the configured ScrapingAnt proxy endpoint"
    elif selected == "api":
        routing_state = "[green]REST API[/green]"
        routing_detail = "POST api.scrapingant.com/v2/general"
    else:
        routing_state = "[red]disabled[/red]"
        routing_detail = "direct fetch (no ScrapingAnt or missing proxy credentials)"
    table.add_row(
        "Clearnet routing",
        f"{routing_state} ({routing_detail}) — paste + RSS only, never Tor",
    )

    # Inline enrichment-cache summary (always shown when --cache is set,
    # otherwise the row is omitted). Never raises — cache is best-effort.
    if cache:
        cache_stats = _get_enrichment_cache_stats_sync()
        backend = cache_stats.get("backend", "n/a")
        hits = cache_stats.get("hits", 0)
        misses = cache_stats.get("misses", 0)
        hit_rate = cache_stats.get("hit_rate_pct", 0.0)
        size = cache_stats.get("size", 0)
        table.add_row(
            "Enrichment cache",
            f"backend=[cyan]{backend}[/cyan] "
            f"hits={hits} misses={misses} "
            f"rate=[green]{hit_rate}%[/green] "
            f"entries={size}",
        )

    console.print(table)

    if cache:
        _show_cache_detail_table()

    if seeds:
        _show_seed_pool_table()


def _show_seed_pool_table() -> None:
    """Render the seed-pool breakdown table used by `voidaccess status --seeds`."""
    try:
        from sources.seed_manager import get_seed_manager

        sm = get_seed_manager()
        breakdown = sm.count_by_type()
        last_validated = sm.summary().get("last_validated")

        seed_table = Table(title="Seed pool", show_lines=False)
        seed_table.add_column("Bucket", style="bold")
        seed_table.add_column("Count", justify="right")
        seed_table.add_row(
            "Permanent",
            f"[cyan]{breakdown.get('permanent', 0)}[/cyan]",
        )
        seed_table.add_row(
            "Discovered (total)",
            f"[cyan]{breakdown.get('discovered_total', 0)}[/cyan]",
        )
        seed_table.add_row(
            "  pending validation",
            f"[yellow]{breakdown.get('discovered_pending', 0)}[/yellow]",
        )
        seed_table.add_row(
            "  validated",
            f"[green]{breakdown.get('discovered_validated', 0)}[/green]",
        )
        seed_table.add_row(
            "Last validation",
            str(last_validated) if last_validated else "never",
        )
        console.print(seed_table)
    except Exception as exc:
        console.print(f"[red]Seed pool unavailable: {exc}[/red]")


def _get_enrichment_cache_stats_sync() -> dict:
    """Synchronously fetch enrichment cache stats (cache errors → empty dict)."""
    try:
        from utils.async_utils import run_async
        from utils.enrichment_cache import get_enrichment_cache

        async def _fetch() -> dict:
            cache = await get_enrichment_cache()
            return await cache.stats()

        return run_async(_fetch()) or {}
    except Exception as exc:
        logger_msg = exc  # noqa: F841 — logged in caller if needed
        return {"backend": "unavailable", "hits": 0, "misses": 0,
                "hit_rate_pct": 0.0, "size": 0, "error": str(exc)[:120]}


def _show_cache_detail_table() -> None:
    """Print a per-source TTL table under the main status table."""
    from utils.enrichment_cache import DEFAULT_TTL

    ttl_table = Table(title="Enrichment cache TTL defaults", show_lines=False)
    ttl_table.add_column("Source", style="bold")
    ttl_table.add_column("TTL (seconds)", justify="right")
    ttl_table.add_column("TTL (human)")

    def _human(seconds: int) -> str:
        if seconds < 3600:
            return f"{seconds // 60}m"
        if seconds < 86400:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"

    for source, ttl in sorted(DEFAULT_TTL.items()):
        ttl_table.add_row(source, str(ttl), _human(ttl))
    console.print(ttl_table)


def _show_engine_status() -> None:
    import asyncio
    from voidaccess_cli.adapters import sqlite as sqlite_adapter

    sqlite_adapter.init_db()
    rows = asyncio.run(sqlite_adapter.get_all_engine_stats())
    if not rows:
        console.print("[grey50]No search engine stats recorded yet.[/grey50]")
        return

    table = Table(title="Search engine status", show_lines=False)
    table.add_column("Engine Name", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Success Rate", justify="right")
    table.add_column("Avg Time", justify="right")
    table.add_column("Circuit")
    table.add_column("Last Success")

    for row in sorted(rows, key=lambda r: r.get("score", 0), reverse=True):
        attempts = int(row.get("total_attempts") or 0)
        successes = int(row.get("total_successes") or 0)
        success_rate = int(round((successes / attempts) * 100)) if attempts else 0
        avg_ms = float(row.get("avg_response_time_ms") or 0)
        avg_time = f"{avg_ms / 1000:.1f}s" if avg_ms else "-"
        circuit = "[red]OPEN[/red]" if row.get("is_circuit_open") else "[green]CLOSED[/green]"
        last_success = _relative_time(row.get("last_success_at"), datetime.now(timezone.utc))
        table.add_row(
            str(row.get("engine_name") or ""),
            f"{float(row.get('score') or 0):.2f}",
            f"{success_rate}%",
            avg_time,
            circuit,
            last_success,
        )

    console.print(table)


def _relative_time(value, now) -> str:
    if not value:
        return "never"
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except Exception:
            return "unknown"
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


@app.command("list")
def list_investigations(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of rows"),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """List saved investigations."""
    cli_config.apply_env()
    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    rows = sqlite_adapter.list_investigations(limit=limit)
    if as_json:
        console.print_json(json.dumps(rows, default=str))
        return
    if not rows:
        console.print("[grey50]No saved investigations.[/grey50]")
        return
    table = Table(title="Saved investigations")
    table.add_column("Id", style="cyan")
    table.add_column("Query")
    table.add_column("Status")
    table.add_column("Entities", justify="right")
    table.add_column("Created")
    for r in rows:
        table.add_row(
            r["id"][:8],
            (r["query"] or "")[:60],
            r["status"] or "",
            str(r["entity_count"]),
            (r["created_at"] or "")[:19],
        )
    console.print(table)


@app.command("version")
def version() -> None:
    """Print the installed version."""
    console.print(f"voidaccess {__version__}")


def _banner_line_visible_width(line: str) -> int:
    """Return the visible character width of a banner line.

    Strips Rich markup tags (e.g. ``[color(141)]``, ``[/]``, ``[link=URL]``,
    ``[bold]``) so block-character art and text lines can both be measured
    for proper centering.  Each remaining character counts as 1 width unit
    (the banner is ASCII-only, so wcwidth isn't needed).
    """
    import re as _re
    return len(_re.sub(r"\[/?[^\]]*\]", "", line))


def show_banner(console: Console) -> None:
    # v1.7 — respect both VOIDACCESS_NO_BANNER=1 and --no-banner.
    # VOIDACCESS_NO_BANNER=1 suppresses the banner for an entire session
    # without needing --no-banner on every command.  --no-banner overrides
    # it per-invocation (same precedence as git -C / --no-verify).
    if os.environ.get("VOIDACCESS_NO_BANNER") == "1":
        return
    if os.environ.get("TERM") == "dumb":
        return
    if not sys.stdout.isatty() and "PS1" not in os.environ and os.name != "nt":
        return
    console.print()
    # v1.6.2 — center every line to the same vertical axis.
    #
    # The previous implementation centered each line independently on
    # its own visible width — that *usually* worked but produced up to
    # a half-column of horizontal drift between lines of odd vs even
    # visible widths at certain terminal widths, because `(W - width) // 2`
    # truncates when `W - width` is odd.  That drift was the "left-shifted"
    # ScrapingAnt block seen in the v1.6.2 banner: its lines are wider
    # than the circle above, so the integer-truncation rounding on its
    # pads differed from the circle's pads by up to 0.5 column.
    #
    # The fix is to compute the center column of the widest line first,
    # then pad every other line so its center lands on EXACTLY that same
    # column.  Width and centering of the void circle are unchanged —
    # this only re-routes the ScrapingAnt partnership block through the
    # exact same centering logic that already centered the circle.
    widths = [_banner_line_visible_width(line) for line in BANNER.split("\n")]
    if not widths:
        console.print()
        return
    max_width = max(widths)
    # Center column for the widest line under integer padding.
    max_pad = max(0, (console.width - max_width) // 2)
    max_center = max_pad + max_width / 2.0
    for line, width in zip(BANNER.split("\n"), widths):
        # Pad such that this line's center matches max_center.
        # `(max_center - width/2)` may be a fractional value; round to
        # the nearest integer so the visible center is as close to
        # max_center as integer padding allows.  Use `round()` (banker's
        # rounding via Python's built-in) so .5 ties go to even.
        raw_pad = max_center - width / 2.0
        pad = max(0, int(round(raw_pad)))
        console.print(" " * pad + line)
    console.print()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version",
        is_eager=True,
        help="Print version and exit.",
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner",
        help="Skip banner.  Set VOIDACCESS_NO_BANNER=1 in the environment "
             "to suppress the banner for an entire session without passing "
             "--no-banner on every command."
    ),
) -> None:
    """Set env vars and render banner before command execution."""
    if version:
        console.print(f"voidaccess {__version__}")
        raise typer.Exit()
    cli_config.apply_env()
    quiet = _is_quiet_invocation(ctx)
    if quiet:
        # `investigate --quiet` prints nothing: not even the optional-key warning
        # config.validate_config() logs below, nor the banner.
        import logging

        logging.getLogger().setLevel(logging.ERROR)
    # Validate after the CLI has injected its runtime environment. This keeps
    # --help/--version cold-start safe while preserving the required-key and
    # once-per-process optional-key checks for real command invocations.
    import config as runtime_config
    runtime_config.validate_config()
    if not no_banner and not quiet and ctx.invoked_subcommand:
        show_banner(console)


def _is_quiet_invocation(ctx: typer.Context) -> bool:
    """True for ``voidaccess investigate ... --quiet`` run from the command line.

    The group callback runs before the subcommand's own options are parsed (and
    Click does not expose them to it), so the process argv is the only place to
    look. A programmatic ``app([...])`` call is therefore not covered; it only
    matters for the banner and the config warning, both of which are already off
    when stdout is not a terminal.
    """
    if ctx.invoked_subcommand != "investigate":
        return False
    return "--quiet" in sys.argv[1:]


def run() -> None:
    """Console-script entry point.

    Wraps the Typer app so a stale local database surfaces as a single clean,
    actionable line and a non-zero exit code on *every* command — instead of a
    raw ``OperationalError`` traceback (or a misleading exit 0) on the read
    paths that never had explicit handling.  ``init_db`` raises
    ``DatabaseSchemaError`` for a schema behind the code; we render it here once
    for all commands.  Typer's pretty-exception handler is disabled for this
    type so the message reaches this wrapper cleanly.
    """
    from voidaccess_cli.adapters.sqlite import DatabaseSchemaError
    try:
        app()
    except DatabaseSchemaError as exc:
        console.print(f"[red]Database schema error:[/red] {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    run()
