"""
cli/browser.py — Textual TUI for browsing an investigation's entities.

Two-pane layout:
    Left  (30%)  — entity list, type-filter, badges
    Right (70%)  — entity detail + top connections

Keys:
    /  search                f  filter by type
    p  shortest path         c  clusters view
    e  export selected       q  quit
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from extractor.identity import entity_canonical_id, entity_display_id


# Relevance tier (22R) shown per entity; "—" for exports made before 2.2.
_TIER_LABELS = {
    "direct": "[green]direct[/green]",
    "related": "[yellow]related[/yellow]",
    "background": "[grey50]background[/grey50]",
}

# NOTE: keys are UPPERCASE to match the normalized entity_type returned by
# voidaccess_cli.adapters.sqlite._entity_row. If you add a new type here,
# use the canonical UPPERCASE name (e.g., "BITCOIN_ADDRESS", not "bitcoin_address").
TYPE_SHORT = {
    "IP_ADDRESS":       ("I", "cyan"),
    "DOMAIN":           ("D", "green"),
    "ONION_URL":        ("O", "magenta"),
    "EMAIL_ADDRESS":    ("E", "yellow"),
    "FILE_HASH_MD5":    ("H", "blue"),
    "FILE_HASH_SHA1":   ("H", "blue"),
    "FILE_HASH_SHA256": ("H", "blue"),
    "BITCOIN_ADDRESS":  ("W", "yellow"),
    "RANSOMWARE_GROUP": ("R", "red"),
    "MALWARE_FAMILY":   ("M", "red"),
    "CVE_NUMBER":       ("C", "red"),
    "PHONE_NUMBER":     ("P", "grey50"),
    "THREAT_ACTOR_HANDLE": ("@", "yellow"),
    "PGP_KEY_BLOCK":    ("K", "grey50"),
}


def _badges_for_entity(entity: dict) -> list[str]:
    tags = (entity.get("corroborating_sources") or "").lower()
    badges: list[str] = []
    if "c2" in tags:
        badges.append("[C2]")
    if "breached" in tags or "hibp" in tags:
        badges.append("[Breached]")
    if "malicious" in tags or "abuseipdb" in tags:
        badges.append("[Malicious]")
    if "fresh" in tags:
        badges.append("[Fresh]")
    freshness = entity.get("freshness_tag")
    if freshness and freshness != "unknown" and not any(
        freshness in badge.lower() for badge in badges
    ):
        badges.append(f"[{freshness.title()}]")
    return badges


class EntityBrowserApp(App):
    """Textual app over an investigation export dict."""

    CSS = """
    Screen { layout: horizontal; }
    #left  { width: 35%; border-right: solid $accent; }
    #right { width: 65%; padding: 1 2; }
    #detail { height: 100%; }
    DataTable { height: 1fr; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_search", "Search"),
        Binding("f", "cycle_filter", "Filter"),
        Binding("c", "clusters_view", "Clusters"),
        Binding("p", "path_view", "Path"),
        Binding("e", "export_selected", "Export"),
        Binding("r", "refresh_table", "Refresh"),
    ]

    search_query: reactive[str] = reactive("")
    type_filter: reactive[Optional[str]] = reactive(None)

    def __init__(self, data: dict[str, Any]):
        super().__init__()
        self.data = data
        inv = data.get("investigation") or {}
        self._title_text = inv.get("query") or data.get("query") or "investigation"
        self.entities: list[dict] = list(data.get("entities", []))
        self.relationships: list[dict] = list(data.get("relationships", []))
        # Backend-computed community partition: {entity_id (str) → community_id (int)}.
        # Stored in __init__ so _populate_table + ClustersScreen share the same view.
        raw_communities = data.get("communities") or {}
        self.communities: dict[str, int] = {
            str(k): int(v) for k, v in raw_communities.items() if v is not None
        }
        self.community_count = int(data.get("community_count") or 0) or len(
            set(self.communities.values())
        )
        # Connection counts
        counts: Counter[str] = Counter()
        for r in self.relationships:
            counts[r["entity_a_id"]] += 1
            counts[r["entity_b_id"]] += 1
        self.connection_count = counts
        # Priority is the primary user-facing sort.  Community and connection
        # count remain stable secondary context, never the ranking signal.
        self.entities.sort(
            key=lambda e: (
                -(e.get("priority_score") or 0),
                self.communities.get(str(e.get("id")), -1),
                -counts.get(e["id"], 0),
            )
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="left"):
                yield Input(placeholder="search… (press / to focus)", id="search")
                yield Label(f"[{self._title_text}]", id="title")
                yield DataTable(id="entity_table", zebra_stripes=True, cursor_type="row")
            with Vertical(id="right"):
                yield Static("Select an entity on the left.", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"voidaccess — {self._title_text}"
        table: DataTable = self.query_one("#entity_table", DataTable)
        table.add_columns("Cm", "T", "Tier", "Value", "Priority", "Conn", "Badges")
        self._populate_table()

    # -- helpers -----------------------------------------------------------

    def _filtered(self) -> list[dict]:
        out = self.entities
        if self.type_filter:
            out = [e for e in out if e["entity_type"] == self.type_filter]
        if self.search_query:
            q = self.search_query.lower()
            out = [
                e for e in out
                if q in (e.get("value") or "").lower()
                or q in (e.get("canonical_value") or "").lower()
                or q in (e.get("corroborating_sources") or "").lower()
            ]
        return out

    def _populate_table(self) -> None:
        table: DataTable = self.query_one("#entity_table", DataTable)
        table.clear()
        for e in self._filtered():
            glyph, _colour = TYPE_SHORT.get(e["entity_type"], ("?", "white"))
            val = entity_display_id(e)[:42]
            conn = self.connection_count.get(e["id"], 0)
            badges = " ".join(_badges_for_entity(e))
            # Cm column: community id from the backend partition; blank when
            # the entity isn't in any community (older investigations).
            cm = self.communities.get(str(e.get("id")))
            cm_label = f"[cyan]C{cm}[/cyan]" if cm is not None else ""
            priority = f"{(e.get('priority_score') or 0):.3f}"
            tier = _TIER_LABELS.get(e.get("relevance") or "", "—")
            table.add_row(cm_label, glyph, tier, val, priority, str(conn), badges, key=e["id"])

    # -- input handlers ----------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self.search_query = event.value
            self._populate_table()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        eid = str(event.row_key.value) if hasattr(event.row_key, "value") else str(event.row_key)
        entity = next((e for e in self.entities if e["id"] == eid), None)
        if entity:
            self._render_detail(entity)

    # -- actions -----------------------------------------------------------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_cycle_filter(self) -> None:
        types = sorted({e["entity_type"] for e in self.entities})
        if not types:
            return
        if self.type_filter is None:
            self.type_filter = types[0]
        else:
            try:
                idx = types.index(self.type_filter)
                self.type_filter = types[idx + 1] if idx + 1 < len(types) else None
            except ValueError:
                self.type_filter = None
        self._populate_table()

    def action_refresh_table(self) -> None:
        self._populate_table()

    def action_clusters_view(self) -> None:
        self.push_screen(ClustersScreen(self))

    def action_path_view(self) -> None:
        self.push_screen(PathScreen(self))

    def action_export_selected(self) -> None:
        table: DataTable = self.query_one("#entity_table", DataTable)
        row = table.cursor_row
        rows = list(self._filtered())
        if row < 0 or row >= len(rows):
            return
        entity = rows[row]
        from pathlib import Path
        out = Path.home() / ".voidaccess" / "results" / f"entity-{entity['id']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        import json
        out.write_text(json.dumps(entity, indent=2, default=str), encoding="utf-8")
        self.notify(f"Exported to {out}")

    # -- detail pane -------------------------------------------------------

    def _render_detail(self, entity: dict) -> None:
        lines: list[str] = []
        val = entity_display_id(entity)
        lines.append(f"[b]Entity:[/b] {val}")
        lines.append(
            f"Type: {entity['entity_type']}  |  Confidence: "
            f"{(entity.get('confidence') or 0):.2f}"
        )
        lines.append(
            f"Priority: {(entity.get('priority_score') or 0):.3f}  |  "
            f"Freshness: {entity.get('freshness_tag') or 'unknown'}"
        )
        tags = entity.get("corroborating_sources") or ""
        if tags:
            lines.append(f"Tags: {tags}")
        if entity.get("investigation_count"):
            lines.append(f"Investigations: {entity['investigation_count']}")
        lines.append("")
        if entity.get("first_seen") or entity.get("last_seen"):
            lines.append(
                f"First seen: {entity.get('first_seen') or '—'}   "
                f"Last seen: {entity.get('last_seen') or '—'}"
            )
        if entity.get("extraction_method"):
            lines.append(f"Extraction: {entity['extraction_method']}")
        lines.append("")
        ctx = (entity.get("context_snippet") or "").strip()
        if ctx:
            lines.append("[b]Context:[/b]")
            lines.append(ctx[:1500])
            lines.append("")

        neighbours = self._neighbours_of(entity["id"])
        if neighbours:
            lines.append("[b]Connected to (top 10):[/b]")
            for other_id, edge_type, conf in neighbours[:10]:
                other = next((e for e in self.entities if e["id"] == other_id), None)
                if other:
                    other_val = entity_display_id(other)[:48]
                    lines.append(f"  → {other_val:50} {edge_type:18} {conf:.2f}")
        detail: Static = self.query_one("#detail", Static)
        detail.update("\n".join(lines))

    def _neighbours_of(self, entity_id: str) -> list[tuple[str, str, float]]:
        out: list[tuple[str, str, float]] = []
        for r in self.relationships:
            if r["entity_a_id"] == entity_id:
                out.append((r["entity_b_id"], r["relationship_type"], r.get("confidence") or 0.0))
            elif r["entity_b_id"] == entity_id:
                out.append((r["entity_a_id"], r["relationship_type"], r.get("confidence") or 0.0))
        out.sort(key=lambda t: -t[2])
        return out


# ---------------------------------------------------------------------------
# Cluster overlay
# ---------------------------------------------------------------------------


class ClustersScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("q", "dismiss", "Close")]

    def __init__(self, parent_app: EntityBrowserApp):
        super().__init__()
        self._parent_app = parent_app

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[b]Infrastructure clusters[/b]   (esc to close)"),
            Static(self._render_clusters(), id="clusters_body"),
        )

    def _render_clusters(self) -> str:
        # Prefer the backend-computed community partition (deterministic
        # greedy-modularity).  Falls back to connected-component clustering
        # only when the investigation pre-dates the communities payload —
        # i.e. for legacy exports loaded from older JSON files.
        backend = self._parent_app.communities
        entity_by_id = {str(e["id"]): e for e in self._parent_app.entities}

        adj: dict[str, set[str]] = defaultdict(set)
        for r in self._parent_app.relationships:
            adj[r["entity_a_id"]].add(r["entity_b_id"])
            adj[r["entity_b_id"]].add(r["entity_a_id"])

        if backend:
            by_comm: dict[int, list[str]] = defaultdict(list)
            for eid, cid in backend.items():
                by_comm[cid].append(eid)
            clusters = [sorted(members) for members in by_comm.values()]
            clusters.sort(key=len, reverse=True)
        else:
            # Legacy fallback: greedy connected components.
            seen: set[str] = set()
            clusters_legacy: list[list[str]] = []
            for eid in adj:
                if eid in seen:
                    continue
                stack = [eid]
                comp: list[str] = []
                while stack:
                    node = stack.pop()
                    if node in seen:
                        continue
                    seen.add(node)
                    comp.append(node)
                    stack.extend(adj.get(node, ()))
                clusters_legacy.append(comp)
            clusters = sorted(clusters_legacy, key=len, reverse=True)

        lines: list[str] = []
        for idx, members in enumerate(clusters[:10], start=1):
            hub_id = max(members, key=lambda x: len(adj.get(x, ())))
            hub = entity_by_id.get(hub_id, {})
            hub_val = (
                hub.get("canonical_value")
                or hub.get("value")
                or hub_id[:8]
            )
            type_counts: Counter[str] = Counter()
            for nid in members:
                ent = entity_by_id.get(nid)
                if ent:
                    type_counts[ent["entity_type"]] += 1
            header = (
                f"Community {idx}: {hub_val}"
                f"  (hub, {len(adj.get(hub_id, ()))} conn, {len(members)} entities)"
            )
            lines.append(header)
            for etype, count in type_counts.most_common():
                lines.append(f"  └── {count} {etype}")
            lines.append("")
        return "\n".join(lines) or "No clusters detected."


# ---------------------------------------------------------------------------
# Path finder overlay
# ---------------------------------------------------------------------------


class PathScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, parent_app: EntityBrowserApp):
        super().__init__()
        self._parent_app = parent_app

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[b]Shortest path between two entities[/b]   (esc to close)"),
            Input(placeholder="first entity value or id", id="path_a"),
            Input(placeholder="second entity value or id", id="path_b"),
            Static("", id="path_result"),
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        a = self.query_one("#path_a", Input).value.strip()
        b = self.query_one("#path_b", Input).value.strip()
        if not a or not b:
            return
        result = self._find_path(a, b)
        self.query_one("#path_result", Static).update(result)

    def _find_path(self, a_val: str, b_val: str) -> str:
        # Build a NetworkX MultiDiGraph from the loaded JSON so we use the same
        # directed→undirected fallback that the API path endpoint uses.  This
        # lets the CLI match the backend's behaviour for analysts who run it
        # offline (no server round-trip required).
        try:
            import networkx as nx
            from graph.builder import find_shortest_path
        except Exception as exc:  # pragma: no cover — defensive
            return f"Path query unavailable: {exc}"

        ents = self._parent_app.entities
        ents_by_id = {str(e["id"]): e for e in ents}

        G = nx.MultiDiGraph()
        for e in ents:
            G.add_node(
                str(e["id"]),
                entity_type=e.get("entity_type", ""),
                canonical_value=entity_canonical_id(e),
            )
        # Build a stable lookup from the user-typed value → entity id.
        value_to_id: dict[str, str] = {}
        for e in ents:
            cv = entity_canonical_id(e)
            v = entity_display_id(e)
            if (e.get("entity_type") or "").upper() in {"ETHEREUM_ADDRESS", "ETH_ADDRESS"}:
                cv = ""
            if cv:
                value_to_id[cv] = str(e["id"])
            if v and v not in value_to_id:
                value_to_id[v] = str(e["id"])

        for r in self._parent_app.relationships:
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

        def _resolve(value: str) -> "str | None":
            if value in G:
                return value  # already an entity id
            if value in value_to_id:
                return value_to_id[value]
            for entity in ents:
                if (entity.get("entity_type") or "").upper() in {"ETHEREUM_ADDRESS", "ETH_ADDRESS"}:
                    continue
                if entity_canonical_id({"entity_type": entity.get("entity_type") or "", "value": value}) == entity_canonical_id(entity):
                    return str(entity["id"])
            return None

        a_id = _resolve(a_val)
        b_id = _resolve(b_val)
        if a_id is None or b_id is None:
            missing = []
            if a_id is None:
                missing.append(f"source: {a_val!r}")
            if b_id is None:
                missing.append(f"target: {b_val!r}")
            return "Entity not found in this investigation: " + ", ".join(missing)

        if a_id == b_id:
            return "Source and target are the same entity."

        node_path = find_shortest_path(G, a_id, b_id, max_hops=6)
        if node_path is None:
            return "No path found within 6 hops."

        # Build a labelled chain with type glyphs and edge confidences, plus a
        # plain arrow-only line for piping to other tools.
        lines: list[str] = []
        arrow_values: list[str] = []
        for nid in node_path:
            ent = ents_by_id.get(nid, {})
            val = entity_display_id(ent) or nid
            arrow_values.append(val)

        chain = " → ".join(arrow_values)
        hops = len(node_path) - 1
        lines.append(f"[b]Path:[/b] {chain}")
        lines.append(f"[b]Hops:[/b] {hops}")
        lines.append("")

        # Visual card — uses TYPE_SHORT for the per-entity glyph + colour and
        # pulls confidence + edge_type from the graph for the hop arrows.
        lines.append("┌──────────────────────────────────────────────────────────┐")
        for idx, nid in enumerate(node_path):
            ent = ents_by_id.get(nid, {})
            etype = ent.get("entity_type", "")
            glyph, colour = TYPE_SHORT.get(etype, ("?", "white"))
            val = (entity_display_id(ent) or nid)[:32]
            conf = float(ent.get("confidence") or 0.0)

            if idx > 0:
                prev = node_path[idx - 1]
                edge_info = self._best_edge(G, prev, nid)
                et = edge_info.get("type", "") or "RELATED"
                ec = float(edge_info.get("confidence") or 0.0)
                lines.append(f"│      ↓ {et} ({ec:.2f})")
            tags = " ".join(_badges_for_entity(ent))
            tag_suffix = f"  {tags}" if tags else ""
            lines.append(f"│ [{colour}][{glyph}][/] {val:42} conf={conf:.2f}{tag_suffix}")
        lines.append("└──────────────────────────────────────────────────────────┘")
        return "\n".join(lines)

    @staticmethod
    def _best_edge(G, source: str, target: str) -> dict:
        """Pick the highest-confidence edge between source and target (either direction)."""
        candidates: list[dict] = []
        for u, v in ((source, target), (target, source)):
            if G.has_edge(u, v):
                # MultiDiGraph → dict-of-keys; flat-iterate
                edge_dict = G.get_edge_data(u, v) or {}
                for data in edge_dict.values():
                    candidates.append(data)
        if not candidates:
            return {}
        best = max(candidates, key=lambda d: float(d.get("confidence") or 0.0))
        return {
            "type": best.get("edge_type", ""),
            "confidence": float(best.get("confidence") or 0.0),
        }
