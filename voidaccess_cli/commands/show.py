"""
cli/commands/show.py — Launch the Textual entity browser.

Argument can be:
    a path to a saved .json investigation file
    an investigation id (UUID stored in SQLite)
    omitted → interactive picker over recent runs

Flags
-----
--no-tui                  print summary instead of launching the TUI
--path <from> <to>        print shortest path between two entities, no TUI
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from extractor.identity import entity_canonical_id

console = Console()


def run(
    target: Optional[str] = typer.Argument(
        None, help="Investigation id or path to a .json export"
    ),
    no_tui: bool = typer.Option(False, "--no-tui", help="Print summary table without launching TUI (for scripted use)."),
    path: Optional[list[str]] = typer.Option(
        None,
        "--path",
        help="Find shortest path between two entities. Pass two values after --path: --path <from> <to>.",
    ),
) -> None:
    """Open the entity browser TUI."""
    from voidaccess_cli import config as cli_config
    cli_config.apply_env()

    data: Optional[dict] = None

    if target is None:
        if no_tui:
            console.print("[yellow]No target specified.[/yellow]")
            raise typer.Exit(code=1)
        target = _pick_recent()
        if target is None:
            console.print("[yellow]No investigations found. Run `voidaccess investigate` first.[/yellow]")
            raise typer.Exit(code=1)

    candidate_path = Path(target).expanduser()
    if candidate_path.exists() and candidate_path.suffix == ".json":
        data = json.loads(candidate_path.read_text(encoding="utf-8"))
    else:
        from voidaccess_cli.adapters import sqlite as sqlite_adapter
        sqlite_adapter.init_db()
        resolved = sqlite_adapter.resolve_investigation_id(target) or target
        data = sqlite_adapter.investigation_to_export_dict(resolved)
        if not data or not data.get("investigation"):
            console.print(f"[red]Unknown investigation:[/red] {target}")
            raise typer.Exit(code=1)

    # --path takes precedence: print path to terminal, no TUI.
    if path:
        if len(path) != 2:
            console.print(
                "[red]--path requires exactly two values:[/red] "
                "--path <from> <to>"
            )
            raise typer.Exit(code=2)
        _print_path(data, path[0], path[1])
        return

    if no_tui:
        _print_summary(data)
        return

    from voidaccess_cli.browser import EntityBrowserApp
    app = EntityBrowserApp(data=data)
    app.run()


def _print_path(data: dict, from_value: str, to_value: str) -> None:
    """Print shortest path between two entities to the terminal (no TUI)."""
    try:
        import networkx as nx
        from graph.builder import find_shortest_path
    except Exception as exc:
        console.print(f"[red]Path query unavailable:[/red] {exc}")
        raise typer.Exit(code=1)

    entities = data.get("entities", []) or []
    relationships = data.get("relationships", []) or []

    ents_by_id = {str(e["id"]): e for e in entities}
    value_to_id: dict[str, str] = {}
    for e in entities:
        cv = entity_canonical_id(e)
        v = (e.get("value") or "").strip()
        # EIP-55 checksums are case-sensitive.  Keep only the exact observed
        # spelling for Ethereum addresses; canonical fallback is intentionally
        # reserved for case-insensitive identity types.
        if (e.get("entity_type") or "").upper() in {
            "ETHEREUM_ADDRESS", "ETH_ADDRESS"
        }:
            cv = ""
        if cv:
            value_to_id[cv] = str(e["id"])
        if v and v not in value_to_id:
            value_to_id[v] = str(e["id"])

    G = nx.MultiDiGraph()
    for e in entities:
        G.add_node(
            str(e["id"]),
            entity_type=e.get("entity_type", ""),
            canonical_value=entity_canonical_id(e),
        )
    for r in relationships:
        src = str(r.get("entity_a_id", ""))
        tgt = str(r.get("entity_b_id", ""))
        if not src or not tgt:
            continue
        if not G.has_node(src) or not G.has_node(tgt):
            continue
        G.add_edge(
            src,
            tgt,
            edge_type=r.get("relationship_type", ""),
            confidence=float(r.get("confidence") or 0.0),
        )

    def _resolve(value: str) -> Optional[str]:
        if value in G:
            return value
        if value in value_to_id:
            return value_to_id[value]
        for entity in entities:
            if (entity.get("entity_type") or "").upper() in {
                "ETHEREUM_ADDRESS", "ETH_ADDRESS"
            }:
                continue
            if entity_canonical_id({
                "entity_type": entity.get("entity_type") or "",
                "value": value,
            }) == entity_canonical_id(entity):
                return str(entity["id"])
        return None

    a_id = _resolve(from_value)
    b_id = _resolve(to_value)
    if a_id is None:
        console.print(f"[red]Source entity not found:[/red] {from_value}")
        raise typer.Exit(code=1)
    if b_id is None:
        console.print(f"[red]Target entity not found:[/red] {to_value}")
        raise typer.Exit(code=1)
    if a_id == b_id:
        console.print("[yellow]Source and target are the same entity.[/yellow]")
        return

    node_path = find_shortest_path(G, a_id, b_id, max_hops=6)
    if node_path is None:
        console.print("[yellow]No path found within 6 hops.[/yellow]")
        return

    values = [
        ents_by_id[n].get("canonical_value")
        or ents_by_id[n].get("value")
        or n
        for n in node_path
    ]
    chain = " → ".join(values)
    hops = len(node_path) - 1
    console.print(f"[b]Path:[/b] {chain}")
    console.print(f"[b]Hops:[/b] {hops}")


def _print_summary(data: dict) -> None:
    inv = data.get("investigation") or data
    entities = data.get("entities", [])
    relationships = data.get("relationships", []) or []
    table = Table(title="Investigation summary")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Query", str(inv.get("query") or ""))
    table.add_row("Status", str(inv.get("status") or ""))
    table.add_row("Entities", str(len(entities)))
    table.add_row("Relationships", str(len(relationships)))
    if any(e.get("relevance") for e in entities):
        tiers = {t: sum(1 for e in entities if e.get("relevance") == t) for t in ("direct", "related", "background")}
        table.add_row("Tiers", ", ".join(f"{n} {t}" for t, n in tiers.items()))
    table.add_row("Created", str(inv.get("created_at") or "")[:19])
    table.add_row("Summary", (str(inv.get("summary") or "—"))[:120])
    console.print(table)


def _pick_recent() -> Optional[str]:
    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    rows = sqlite_adapter.list_investigations(limit=20)
    if not rows:
        return None

    table = Table(title="Recent investigations")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Query")
    table.add_column("Status")
    table.add_column("Entities", justify="right")
    table.add_column("Date")
    for idx, r in enumerate(rows, 1):
        table.add_row(
            str(idx),
            (r["query"] or "")[:50],
            r["status"] or "",
            str(r["entity_count"]),
            (r["created_at"] or "")[:19],
        )
    console.print(table)
    from rich.prompt import Prompt
    choice = Prompt.ask("Pick #", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(rows):
            return rows[idx]["id"]
    except ValueError:
        pass
    return None
