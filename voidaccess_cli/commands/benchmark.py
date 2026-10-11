"""CLI wrappers for the P1.0 measurement harness.

Two one-command invocations:
  voidaccess benchmark metrics   # run the benchmark set through the real pipeline
  voidaccess benchmark probe     # read-only live engine health probe over Tor

All heavy imports are deferred into the command bodies to keep CLI cold-start and
``--help`` fast (matches the rest of voidaccess_cli).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    help="Measurement foundation (P1.0): pipeline metrics + engine health probe.",
    no_args_is_help=True,
)
console = Console()


def _apply_pace(pace: Optional[str]) -> None:
    """One-shot pacing override — pacing reads VOIDACCESS_PACE fresh on every call."""
    if pace:
        os.environ["VOIDACCESS_PACE"] = pace


@app.command("metrics", help="Run the benchmark set through the real pipeline and write a metrics artifact.")
def metrics_cmd(
    llm: bool = typer.Option(False, "--llm", help="Enable LLM stages (costs API spend). Default is $0 / no-LLM."),
    no_tor: bool = typer.Option(False, "--no-tor", help="Skip Tor preflight (dry-run; onion scraping won't work)."),
    pace: Optional[str] = typer.Option(None, "--pace", help="Pacing profile: quiet | normal | aggressive."),
    out: Optional[Path] = typer.Option(None, "--out", help="Artifact output path."),
    queries: Optional[Path] = typer.Option(None, "--queries", help="Custom query-set JSON path."),
) -> None:
    from voidaccess_cli import config as cli_config

    cli_config.apply_env()
    _apply_pace(pace)

    from benchmark.metrics import run_metrics
    from benchmark.queries import load_query_set

    qs = load_query_set(queries) if queries else None
    run_metrics(qs, use_llm=llm, no_tor=no_tor, out_path=out, console=console)
    dest = out or "benchmark/artifacts/metrics-latest.json"
    console.print(f"[green]Metrics artifact written:[/green] {dest}")


@app.command("probe", help="Read-only live engine health probe over Tor across the benchmark set.")
def probe_cmd(
    sample: Optional[int] = typer.Option(None, "--sample", help="Use only the first N benchmark queries."),
    no_tor: bool = typer.Option(False, "--no-tor", help="Skip Tor preflight (records connection errors instead)."),
    pace: Optional[str] = typer.Option(None, "--pace", help="Pacing profile: quiet | normal | aggressive."),
    out: Optional[Path] = typer.Option(None, "--out", help="Artifact output path."),
    queries: Optional[Path] = typer.Option(None, "--queries", help="Custom query-set JSON path."),
) -> None:
    from voidaccess_cli import config as cli_config

    cli_config.apply_env()
    _apply_pace(pace)

    from benchmark.engine_probe import probe_engines
    from benchmark.queries import load_query_set

    qs = load_query_set(queries) if queries else None
    probe_engines(qs, sample_size=sample, no_tor=no_tor, out_path=out, console=console)
    dest = out or "benchmark/artifacts/engine-health-latest.json"
    console.print(f"[green]Engine-health artifact written:[/green] {dest}")
