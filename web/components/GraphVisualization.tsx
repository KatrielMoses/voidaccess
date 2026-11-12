"use client";

import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import Graph from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";
import { inferSettings } from "graphology-layout-forceatlas2";
import louvain from "graphology-communities-louvain";
import Sigma from "sigma";
import {
  CATEGORY_META,
  graphNodeTypeToCategory,
  type EntityCategoryKey,
  type GraphNodeJSON,
  type InvestigationGraphResponse,
} from "@/lib/types/investigation";
import { GraphContextMenu } from "./GraphContextMenu";
import { NodeDetailPanel, type SelectedNodeData } from "./NodeDetailPanel";

// ─── Palette ───────────────────────────────────────────────────────────────────

const CAT_COLOR: Record<EntityCategoryKey, string> = {
  THREAT_ACTOR: "#ff6b6b",
  WALLET:       "#9B9FEE",
  MALWARE:      "#f0a050",
  FORUM:        "#79b8ff",
  C2_SERVER:    "#c678dd",
  CVE:          "#e5c07b",
  PASTE_URL:    "#56b6c2",
  ONION_URL:    "#88aaff",
  EMAIL:        "#d4a96a",
  PGP_KEY:      "#73d397",
  OTHER:        "#4a5260",
};

// Twelve visually distinct hues chosen for the dark VoidAccess canvas.
// `nodeReducer` still overlays NODE_DIM when a node is filtered out by
// community, so these only need to be distinguishable from each other and
// from the pinned/selected states.
const COMMUNITY_COLORS: readonly string[] = [
  "#6366f1", // indigo
  "#ec4899", // pink
  "#14b8a6", // teal
  "#f59e0b", // amber
  "#8b5cf6", // violet
  "#06b6d4", // cyan
  "#f97316", // orange
  "#10b981", // emerald
  "#ef4444", // red
  "#3b82f6", // blue
  "#a855f7", // purple
  "#22c55e", // green
];

const EDGE_DEFAULT  = "rgba(90,110,140,0.12)";
const EDGE_ACTIVE   = "#9B9FEE";
const NODE_DIM      = "#181d26";
const COLOR_PINNED  = "#F59E0B";  // amber — pinned node indicator

// ─── FA2 Settings ─────────────────────────────────────────────────────────────

const FA2_SETTINGS = {
  gravity:                        0.5,
  scalingRatio:                   20,
  slowDown:                       10,
  barnesHutOptimize:              true,
  barnesHutTheta:                 0.5,
  adjustSizes:                    true,
  edgeWeightInfluence:            0,
  linLogMode:                     true,
  outboundAttractionDistribution: false,
  strongGravityMode:              false,
};

// ─── Smart label truncation ────────────────────────────────────────────────────

function smartLabel(raw: string): string {
  const s = raw.trim();
  if (s.toLowerCase().includes(".onion")) {
    const m = s.match(/([a-z2-7]{8,})/i);
    return m ? m[1].slice(0, 10) + "….onion" : s.slice(0, 14) + "….onion";
  }
  if (s.toLowerCase().includes("otx.alienvault") || s.toLowerCase().includes("otx.")) {
    const part = s.split("/").filter(Boolean).pop() ?? s;
    return "OTX · " + part.slice(0, 18);
  }
  if (s.startsWith("http")) {
    try {
      const u = new URL(s.toLowerCase());
      return u.hostname.replace(/^www\./, "").slice(0, 22);
    } catch { /* fall through */ }
  }
  return s.length > 30 ? s.slice(0, 28) + "…" : s;
}

// ─── Graph builder ─────────────────────────────────────────────────────────────

function buildGraph(data: InvestigationGraphResponse, strongOnly: boolean): Graph {
  const g = new Graph({ multi: true, type: "directed" });

  // Backend-provided community partition (preferred — deterministic, server-side).
  // Falls back to client-side Louvain for older API responses that don't ship
  // the communities dict yet.
  const backendCommunities: Record<string, number> = data.communities ?? {};
  const useBackend =
    Object.keys(backendCommunities).length > 0 &&
    // Guard against an empty / placeholder object from a stale server
    Object.values(backendCommunities).some((v) => Number.isFinite(v));

  for (const n of data.nodes) {
    if (g.hasNode(n.id)) continue;
    const cat = graphNodeTypeToCategory(String(n.type ?? ""));
    // Seed community index from the backend payload so the per-node colour
    // picker below has something to read.  Final community is applied after
    // the Louvain fallback path runs.
    const seededCommunity = useBackend
      ? String(backendCommunities[n.id] ?? 0)
      : "0";
    const seedColor = COMMUNITY_COLORS[
      Number(seededCommunity) % COMMUNITY_COLORS.length
    ];
    g.addNode(n.id, {
      label:      smartLabel(n.id),
      size:       5,
      color:      seedColor,
      origColor:  CAT_COLOR[cat],
      vaCategory: cat,
      community:  seededCommunity,
      raw:        n as GraphNodeJSON,
    });
  }

  let ei = 0;
  for (const e of data.edges) {
    if (strongOnly && e.type === "CO_INVESTIGATION") continue;
    if (!g.hasNode(e.source) || !g.hasNode(e.target)) continue;
    const conf = (e as Record<string, unknown>).confidence as number ?? 0.5;
    g.addEdgeWithKey(`e${ei++}`, e.source, e.target, {
      size:       0.6,
      color:      EDGE_DEFAULT,
      confidence: conf,
    });
  }

  // Size by degree — linear scale 8 → 25
  const maxDeg = Math.max(...g.nodes().map(n => g.degree(n)), 1);
  g.forEachNode((n) => {
    const deg = g.degree(n);
    const sz  = 8 + (deg / maxDeg) * (25 - 8);
    g.setNodeAttribute(n, "size",     sz);
    g.setNodeAttribute(n, "origSize", sz);
  });

  // Community assignment.  Preferred: server-computed (deterministic, fast).
  // Fallback: client-side Louvain — only kicks in for older investigations
  // whose API response predates the `communities` field.
  if (useBackend) {
    g.forEachNode((nodeId) => {
      const communityId = backendCommunities[nodeId] ?? 0;
      const color =
        COMMUNITY_COLORS[communityId % COMMUNITY_COLORS.length];
      g.setNodeAttribute(nodeId, "community", String(communityId));
      g.setNodeAttribute(nodeId, "color",     color);
    });
  } else {
    try {
      louvain.assign(g, { nodeCommunityAttribute: "community" });
      // Louvain doesn't colour nodes — do that ourselves so the rest of the
      // reducer logic (pinned / selected / filtered) keeps working unchanged.
      g.forEachNode((nodeId) => {
        const communityId = Number(
          g.getNodeAttribute(nodeId, "community") ?? 0
        );
        g.setNodeAttribute(
          nodeId,
          "color",
          COMMUNITY_COLORS[communityId % COMMUNITY_COLORS.length],
        );
      });
    } catch {
      /* ok — visualisation degrades to all-community-0 colour */
    }
  }

  // Pre-position nodes by community sector so FA2 starts well-separated
  const commSet: Record<string, boolean> = {};
  g.forEachNode((n) => { commSet[g.getNodeAttribute(n, "community") as string] = true; });
  const allComms  = Object.keys(commSet);
  const numComms  = Math.max(1, allComms.length);
  const RING      = 180;

  g.forEachNode((n) => {
    const c     = g.getNodeAttribute(n, "community") as string;
    const idx   = allComms.indexOf(c);
    const angle = (idx / numComms) * 2 * Math.PI - Math.PI / 2;
    g.setNodeAttribute(n, "x", Math.cos(angle) * RING + (Math.random() - 0.5) * 40);
    g.setNodeAttribute(n, "y", Math.sin(angle) * RING + (Math.random() - 0.5) * 40);
  });

  // 500-iteration pre-layout for stable initial positioning
  try {
    const sensible = inferSettings(g);
    forceAtlas2.assign(g, {
      iterations: 500,
      settings: { ...sensible, ...FA2_SETTINGS },
    });
  } catch (e) { console.warn("FA2 pre-layout failed", e); }

  return g;
}

// ─── Cluster data ──────────────────────────────────────────────────────────────

interface Cluster {
  id:        string;
  label:     string;
  cx:        number;
  cy:        number;
  labelGX:   number;
  labelGY:   number;
  radius:    number;
  color:     string;
  nodeCount: number;
  members:   string[];
}

function buildClusters(g: Graph): Cluster[] {
  const buckets: Record<string, string[]> = {};
  g.forEachNode((n) => {
    const c = (g.getNodeAttribute(n, "community") as string) ?? "0";
    (buckets[c] ??= []).push(n);
  });

  let gcx = 0, gcy = 0, total = 0;
  g.forEachNode((n) => {
    gcx += g.getNodeAttribute(n, "x") as number;
    gcy += g.getNodeAttribute(n, "y") as number;
    total++;
  });
  if (total > 0) { gcx /= total; gcy /= total; }

  const clusters: Cluster[] = [];

  for (const [cid, members] of Object.entries(buckets)) {
    if (members.length < 3) continue;

    let cx = 0, cy = 0;
    for (const n of members) {
      cx += g.getNodeAttribute(n, "x") as number;
      cy += g.getNodeAttribute(n, "y") as number;
    }
    cx /= members.length;
    cy /= members.length;

    let radius = 0;
    for (const n of members) {
      const dx = (g.getNodeAttribute(n, "x") as number) - cx;
      const dy = (g.getNodeAttribute(n, "y") as number) - cy;
      radius = Math.max(radius, Math.sqrt(dx * dx + dy * dy));
    }
    radius = Math.max(radius, 12);

    const catCount: Record<string, number> = {};
    let topNode = members[0], topDeg = -1;
    for (const n of members) {
      const cat = g.getNodeAttribute(n, "vaCategory") as EntityCategoryKey;
      catCount[cat] = (catCount[cat] ?? 0) + 1;
      const d = g.degree(n);
      if (d > topDeg) { topDeg = d; topNode = n; }
    }
    const domCat  = Object.entries(catCount).sort((a, b) => b[1] - a[1])[0][0] as EntityCategoryKey;
    const color   = CAT_COLOR[domCat] ?? "#9B9FEE";
    const numCats = Object.keys(catCount).length;
    const hubRaw  = (g.getNodeAttribute(topNode, "label") as string ?? topNode);
    const label   = numCats === 1
      ? `${CATEGORY_META[domCat]?.short ?? domCat} · ${hubRaw}`
      : hubRaw;

    const dirX   = cx - gcx, dirY = cy - gcy;
    const dirLen = Math.sqrt(dirX * dirX + dirY * dirY) || 1;
    const nx = dirX / dirLen, ny = dirY / dirLen;
    const PUSH = radius * 2.8 + 90;

    clusters.push({
      id: cid, label, cx, cy,
      labelGX: cx + nx * PUSH,
      labelGY: cy + ny * PUSH,
      radius, color, nodeCount: members.length, members,
    });
  }

  return clusters;
}

// ─── Screen-space label positions + collision avoidance ────────────────────────

interface LabelPos {
  id:        string;
  label:     string;
  color:     string;
  nodeCount: number;
  opacity:   number;
  anchorX:   number;
  anchorY:   number;
  labelX:    number;
  labelY:    number;
  members:   string[];
}

const PILL_W = 185, PILL_H = 26;

function resolveCollisions(labels: LabelPos[], cw: number, ch: number): void {
  const MW = PILL_W + 12, MH = PILL_H + 10;
  for (let iter = 0; iter < 60; iter++) {
    let moved = false;
    for (let i = 0; i < labels.length; i++) {
      for (let j = i + 1; j < labels.length; j++) {
        const a = labels[i], b = labels[j];
        const dx = b.labelX - a.labelX;
        const dy = b.labelY - a.labelY;
        const ox = MW - Math.abs(dx);
        const oy = MH - Math.abs(dy);
        if (ox > 0 && oy > 0) {
          const sx = (dx >= 0 ? 1 : -1);
          const sy = (dy >= 0 ? 1 : -1);
          if (ox < oy) {
            a.labelX -= sx * (ox / 2 + 1);
            b.labelX += sx * (ox / 2 + 1);
          } else {
            a.labelY -= sy * (oy / 2 + 1);
            b.labelY += sy * (oy / 2 + 1);
          }
          moved = true;
        }
      }
    }
    for (const p of labels) {
      p.labelX = Math.max(PILL_W / 2 + 6, Math.min(cw - PILL_W / 2 - 6, p.labelX));
      p.labelY = Math.max(PILL_H / 2 + 6, Math.min(ch - PILL_H / 2 - 6, p.labelY));
    }
    if (!moved) break;
  }
}

function calcLabelPositions(sigma: Sigma, clusters: Cluster[], cw: number, ch: number): LabelPos[] {
  const ratio   = sigma.getCamera().ratio;
  const opacity = ratio < 0.08 ? 0
    : ratio < 0.25 ? (ratio - 0.08) / 0.17
    : ratio > 2.2  ? Math.max(0, 1 - (ratio - 2.2) / 1.2)
    : 1;

  const positions: LabelPos[] = clusters.map((cl) => {
    const anchor = sigma.graphToViewport({ x: cl.cx,     y: cl.cy });
    const raw    = sigma.graphToViewport({ x: cl.labelGX, y: cl.labelGY });
    return {
      id:        cl.id,
      label:     cl.label,
      color:     cl.color,
      nodeCount: cl.nodeCount,
      opacity,
      anchorX:   anchor.x,
      anchorY:   anchor.y,
      labelX:    Math.max(PILL_W / 2 + 6, Math.min(cw - PILL_W / 2 - 6, raw.x)),
      labelY:    Math.max(PILL_H / 2 + 6, Math.min(ch - PILL_H / 2 - 6, raw.y)),
      members:   cl.members,
    };
  });

  positions.sort((a, b) => b.nodeCount - a.nodeCount);
  resolveCollisions(positions, cw, ch);
  return positions;
}

// ─── Types ─────────────────────────────────────────────────────────────────────

interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  nodeId: string;
}

interface GraphStats {
  nodes:  number;
  edges:  number;
  pinned: number;
  hidden: number;
}

// ─── Component ─────────────────────────────────────────────────────────────────

export type GraphVisualizationProps = {
  data:             InvestigationGraphResponse | null;
  loading:          boolean;
  error:            string | null;
  selectedNodeId:   string | null;
  hiddenCategories: Set<EntityCategoryKey>;
  strongEdgesOnly:  boolean;
  onNodeClick:      (nodeId: string, payload: GraphNodeJSON | null) => void;
  focusNodeId:      string | null;
  onFocusHandled:   () => void;
  searchQuery?:     string;
  /** Optional — enables the "Find Path" button + modal. */
  investigationId?: string;
};

// ─── Path-finding types ──────────────────────────────────────────────────────

interface PathHop {
  entity_id:    string | null;
  node_id:      string;
  entity_type:  string;
  canonical_value: string;
  confidence:   number;
  relationship_to_previous?: {
    type: string;
    confidence: number;
  };
}

interface PathResponse {
  found:         boolean;
  path_length:   number | null;
  hops:          PathHop[];
  from_entity:   { entity_id: string; entity_type: string; canonical_value: string } | null;
  to_entity:     { entity_id: string; entity_type: string; canonical_value: string } | null;
  message?:      string | null;
  directed?:     boolean;
}

export function GraphVisualization({
  data,
  loading,
  error,
  selectedNodeId,
  hiddenCategories,
  strongEdgesOnly,
  onNodeClick,
  focusNodeId,
  onFocusHandled,
  searchQuery,
  investigationId,
}: GraphVisualizationProps) {
  const containerRef  = useRef<HTMLDivElement>(null);
  const sigmaRef      = useRef<Sigma | null>(null);
  const graphRef      = useRef<Graph | null>(null);
  const clustersRef   = useRef<Cluster[]>([]);
  const onClickRef    = useRef(onNodeClick);
  onClickRef.current  = onNodeClick;

  // Reducer state refs (avoid stale closures)
  const selNodeRef    = useRef(selectedNodeId);
  const hidCatsRef    = useRef(hiddenCategories);
  const selCommRef    = useRef<string | null>(null);
  selNodeRef.current  = selectedNodeId;
  hidCatsRef.current  = hiddenCategories;

  // Drag
  const draggedNodeRef = useRef<string | null>(null);
  const isDraggingRef  = useRef(false);


  // Hover tracking (for keyboard shortcuts H / P)
  const hoveredNodeRef = useRef<string | null>(null);

  // Graph canvas focus (for keyboard shortcuts)
  const graphFocusedRef = useRef(false);

  // Highlighted node (focus action)
  const highlightedNodeRef = useRef<string | null>(null);

  const [selectedComm,    setSelectedComm]    = useState<string | null>(null);
  const [labelPositions,  setLabelPositions]  = useState<LabelPos[]>([]);
  const [contextMenu,     setContextMenu]     = useState<ContextMenuState>({ visible: false, x: 0, y: 0, nodeId: "" });
  const [highlightedNode, setHighlightedNode] = useState<string | null>(null);
  const [graphStats,      setGraphStats]      = useState<GraphStats>({ nodes: 0, edges: 0, pinned: 0, hidden: 0 });
  // FIX 1: selected node detail panel
  const [selectedNodeDetail, setSelectedNodeDetail] = useState<SelectedNodeData | null>(null);
  // FIX 4: legend collapsed state
  const [legendCollapsed,    setLegendCollapsed]    = useState(false);
  // Path-finding: dialog visibility, request state, and the highlighted subgraph.
  const [pathDialogOpen, setPathDialogOpen]     = useState(false);
  const [pathQuerying,   setPathQuerying]       = useState(false);
  const [pathResult,     setPathResult]         = useState<PathResponse | null>(null);
  const [pathNodes,      setPathNodes]          = useState<Set<string>>(new Set());
  const [pathEdgeKeys,   setPathEdgeKeys]       = useState<Set<string>>(new Set());

  // Refs that mirror path state so the graph reducers can read the current
  // highlight sets without taking new dependencies on them (refs are updated
  // synchronously in a useEffect, but the reducers run inside Sigma's draw
  // cycle which is detached from React's render flow).
  const pathNodesRef  = useRef<Set<string>>(new Set());
  const pathEdgesRef  = useRef<Set<string>>(new Set());
  useEffect(() => { pathNodesRef.current = pathNodes; }, [pathNodes]);
  useEffect(() => { pathEdgesRef.current = pathEdgeKeys; }, [pathEdgeKeys]);

  useEffect(() => { selCommRef.current = selectedComm; }, [selectedComm]);
  useEffect(() => { highlightedNodeRef.current = highlightedNode; }, [highlightedNode]);

  const rebuildKey = useMemo(() => {
    if (!data) return "empty";
    return `${data.nodes.length}-${data.edges.length}-${strongEdgesOnly}`;
  }, [data, strongEdgesOnly]);

  // ── Derived helpers ──────────────────────────────────────────────────────────

  function refreshLabels() {
    const sigma = sigmaRef.current;
    const el    = containerRef.current;
    if (!sigma || !el || !clustersRef.current.length) return;
    setLabelPositions(calcLabelPositions(sigma, clustersRef.current, el.offsetWidth, el.offsetHeight));
  }

  const refreshStats = useCallback(() => {
    const g = graphRef.current;
    if (!g) return;
    let pinned = 0, hidden = 0;
    g.forEachNode((_, attrs) => {
      if (attrs.pinned) pinned++;
      if (attrs.hidden) hidden++;
    });
    setGraphStats({ nodes: g.order, edges: g.size, pinned, hidden });
  }, []);

  // ── Action functions ─────────────────────────────────────────────────────────

  const focusNode = useCallback((nodeId: string) => {
    const sigma = sigmaRef.current;
    if (!sigma) return;
    const pos = sigma.getNodeDisplayData(nodeId);
    if (pos) sigma.getCamera().animate({ x: pos.x, y: pos.y, ratio: 0.3 }, { duration: 500 });
    setHighlightedNode(nodeId);
    sigma.refresh();
  }, []);

  const togglePin = useCallback((nodeId: string) => {
    const g = graphRef.current;
    if (!g?.hasNode(nodeId)) return;
    const pinned = !!(g.getNodeAttribute(nodeId, "pinned") as boolean);
    g.setNodeAttribute(nodeId, "pinned", !pinned);
    g.setNodeAttribute(nodeId, "fixed",  !pinned);
    sigmaRef.current?.refresh();
    refreshStats();
  }, [refreshStats]);

  const hideNode = useCallback((nodeId: string) => {
    const g = graphRef.current;
    if (!g?.hasNode(nodeId)) return;
    g.setNodeAttribute(nodeId, "hidden", true);
    g.edges(nodeId).forEach(edge => g.setEdgeAttribute(edge, "hidden", true));
    sigmaRef.current?.refresh();
    refreshStats();
  }, [refreshStats]);

  const isolateNeighbors = useCallback((nodeId: string) => {
    const g = graphRef.current;
    if (!g?.hasNode(nodeId)) return;
    const keep = new Set(g.neighbors(nodeId));
    keep.add(nodeId);
    g.forEachNode((node) => {
      const hide = !keep.has(node);
      g.setNodeAttribute(node, "hidden", hide);
    });
    g.forEachEdge((edge) => {
      const src = g.source(edge);
      const tgt = g.target(edge);
      g.setEdgeAttribute(edge, "hidden", !keep.has(src) || !keep.has(tgt));
    });
    sigmaRef.current?.refresh();
    refreshStats();
  }, [refreshStats]);

  const showAll = useCallback(() => {
    const g = graphRef.current;
    if (!g) return;
    g.forEachNode((n) => g.setNodeAttribute(n, "hidden", false));
    g.forEachEdge((e) => g.setEdgeAttribute(e, "hidden", false));
    sigmaRef.current?.refresh();
    refreshStats();
  }, [refreshStats]);

  const unpinAll = useCallback(() => {
    const g = graphRef.current;
    if (!g) return;
    g.forEachNode((n) => {
      g.setNodeAttribute(n, "pinned", false);
      g.setNodeAttribute(n, "fixed",  false);
    });
    sigmaRef.current?.refresh();
    refreshStats();
  }, [refreshStats]);

  const resetView = useCallback(() => {
    sigmaRef.current?.getCamera().animate({ x: 0, y: 0, ratio: 1, angle: 0 }, { duration: 400 });
  }, []);

  // Path-finding: query the backend and update the highlight sets.
  // Backend returns ordered hops; we convert that to a node-id set + edge-key
  // set so the reducers can light up just the path subgraph.
  const runPathQuery = useCallback(async (fromValue: string, toValue: string, maxHops: number = 6) => {
    if (!investigationId) return;
    setPathQuerying(true);
    setPathResult(null);
    try {
      const qs = new URLSearchParams({
        from: fromValue,
        to: toValue,
        max_hops: String(maxHops),
      });
      const res = await fetch(
        `/api/investigations/${encodeURIComponent(investigationId)}/graph/path?${qs.toString()}`,
      );
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        setPathResult({
          found: false,
          path_length: null,
          hops: [],
          from_entity: null,
          to_entity: null,
          message: text || `HTTP ${res.status}`,
          directed: false,
        });
        setPathNodes(new Set());
        setPathEdgeKeys(new Set());
        return;
      }
      const json: PathResponse = await res.json();
      setPathResult(json);
      if (json.found && json.hops && json.hops.length > 0) {
        const nodes = new Set<string>();
        const edges = new Set<string>();
        for (let i = 0; i < json.hops.length; i++) {
          nodes.add(json.hops[i].node_id);
          if (i > 0) {
            // Build the edge key the same way the graph builder did.
            edges.add(`${json.hops[i - 1].node_id}__${json.hops[i].node_id}`);
          }
        }
        setPathNodes(nodes);
        setPathEdgeKeys(edges);
        // Frame the camera on the midpoint of the path so the analyst sees it.
        const g = graphRef.current;
        const sigma = sigmaRef.current;
        if (g && sigma) {
          let sx = 0, sy = 0, cnt = 0;
          for (const nid of nodes) {
            if (!g.hasNode(nid)) continue;
            const pos = g.getNodeAttribute(nid, "x") as number;
            const posy = g.getNodeAttribute(nid, "y") as number;
            if (typeof pos === "number" && typeof posy === "number") {
              sx += pos; sy += posy; cnt++;
            }
          }
          if (cnt > 0) {
            sigma.getCamera().animate(
              { x: sx / cnt, y: sy / cnt, ratio: 0.3 },
              { duration: 600 },
            );
          }
        }
      } else {
        setPathNodes(new Set());
        setPathEdgeKeys(new Set());
      }
      sigmaRef.current?.refresh();
    } catch (e) {
      setPathResult({
        found: false,
        path_length: null,
        hops: [],
        from_entity: null,
        to_entity: null,
        message: e instanceof Error ? e.message : String(e),
        directed: false,
      });
      setPathNodes(new Set());
      setPathEdgeKeys(new Set());
    } finally {
      setPathQuerying(false);
    }
  }, [investigationId]);

  const clearPath = useCallback(() => {
    setPathResult(null);
    setPathNodes(new Set());
    setPathEdgeKeys(new Set());
    sigmaRef.current?.refresh();
  }, []);

  const startLayout = useCallback(() => {
    const g     = graphRef.current;
    const sigma = sigmaRef.current;
    if (!g || !sigma) return;
    try {
      const sensible = inferSettings(g);
      forceAtlas2.assign(g, {
        iterations: 200,
        settings: { ...sensible, ...FA2_SETTINGS },
      });
    } catch (e) { console.warn("Re-layout failed", e); }
    sigma.refresh();
  }, []);

  const resetAll = useCallback(() => {
    showAll();
    unpinAll();
    resetView();
    startLayout();
  }, [showAll, unpinAll, resetView, startLayout]);

  // ── Build sigma ───────────────────────────────────────────────────────────────
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !data || data.nodes.length === 0) return;

    // Tear down old instance
    sigmaRef.current?.kill();
    setLabelPositions([]);
    setContextMenu({ visible: false, x: 0, y: 0, nodeId: "" });

    const g = buildGraph(data, strongEdgesOnly);
    graphRef.current    = g;
    clustersRef.current = buildClusters(g);

    const sigma = new Sigma(g, el, {
      renderLabels:               true,
      labelFont:                  "JetBrains Mono, monospace",
      labelSize:                  15,
      labelWeight:                "600",
      labelColor:                 { color: "#FFFFFF" },
      defaultNodeColor:           "#4a5260",
      defaultEdgeColor:           EDGE_DEFAULT,
      stagePadding:               90,
      labelRenderedSizeThreshold: 18,
      labelRenderer: (context, data, settings) => {
        const { x, y, label, size } = data;
        if (!label) return;

        const fontSize = settings.labelSize ?? 15;
        const fontStr  = `${settings.labelWeight ?? "600"} ${fontSize}px ${settings.labelFont ?? "JetBrains Mono, monospace"}`;
        context.font   = fontStr;

        const textWidth = context.measureText(label).width;
        const pad = 5;
        const bx  = x + size + 4;
        const by  = y - fontSize / 2 - pad;
        const bw  = textWidth + pad * 2;
        const bh  = fontSize + pad * 2;
        const br  = 4;

        context.fillStyle = "rgba(0, 0, 0, 0.88)";
        context.beginPath();
        if (context.roundRect) {
          context.roundRect(bx, by, bw, bh, br);
        } else {
          context.rect(bx, by, bw, bh);
        }
        context.fill();

        context.fillStyle = "#FFFFFF";
        context.textBaseline = "middle";
        context.fillText(label, bx + pad, y);
      },

      // Override hover renderer — same black pill, white text, blue accent border
      hoverRenderer: (context, data, settings) => {
        const { x, y, label, size, color } = data;

        // Subtle ring around node (no gray disc)
        context.beginPath();
        context.arc(x, y, size + 4, 0, Math.PI * 2);
        context.fillStyle = `${(color as string) ?? "#4a5260"}22`;
        context.fill();
        context.strokeStyle = `${(color as string) ?? "#4a5260"}88`;
        context.lineWidth = 1.5;
        context.stroke();

        if (!label) return;

        const fontSize = (settings.labelSize ?? 15) + 1;
        const fontStr  = `700 ${fontSize}px ${settings.labelFont ?? "JetBrains Mono, monospace"}`;
        context.font   = fontStr;

        const textWidth = context.measureText(label).width;
        const pad = 6;
        const bx  = x + size + 6;
        const by  = y - fontSize / 2 - pad;
        const bw  = textWidth + pad * 2;
        const bh  = fontSize + pad * 2;
        const br  = 4;

        // Black pill
        context.fillStyle = "rgba(0, 0, 0, 0.95)";
        context.beginPath();
        if (context.roundRect) {
          context.roundRect(bx, by, bw, bh, br);
        } else {
          context.rect(bx, by, bw, bh);
        }
        context.fill();

        // Blue accent border
        context.strokeStyle = "rgba(155, 159, 238, 0.55)";
        context.lineWidth = 1;
        context.beginPath();
        if (context.roundRect) {
          context.roundRect(bx, by, bw, bh, br);
        } else {
          context.rect(bx, by, bw, bh);
        }
        context.stroke();

        // White text
        context.fillStyle = "#FFFFFF";
        context.textBaseline = "middle";
        context.fillText(label, bx + pad, y);
      },

      nodeReducer: (node, attrs) => {
        const res  = { ...attrs };
        // FIX 2: Always white label
        res.labelColor = "#FFFFFF";
        const cat  = g.getNodeAttribute(node, "vaCategory") as EntityCategoryKey;
        const comm = g.getNodeAttribute(node, "community") as string;

        if (hidCatsRef.current.has(cat)) { res.hidden = true; return res; }
        if (attrs.hidden) return res;

        const sn = selNodeRef.current;
        const sc = selCommRef.current;
        const hn = highlightedNodeRef.current;
        const pathNodes = pathNodesRef.current;

        // Path-highlight takes precedence over every other visual state.
        // A path is active whenever the node set is non-empty (the dialog
        // shows the same set, so the reducer's behaviour is consistent with
        // what the analyst sees in the panel).
        if (pathNodes.size > 0) {
          if (pathNodes.has(node)) {
            res.size   = (attrs.origSize as number) * 2.0;
            res.color  = "#ffffff";
            res.zIndex = 20;
          } else {
            // Non-path nodes are dimmed (opacity via reduced colour).
            res.color  = NODE_DIM;
            res.size   = (attrs.origSize as number) * 0.45;
            res.label  = "";
          }
          return res;
        }

        // Pinned visual — amber tint when no active selection
        if (attrs.pinned && !sn && !sc && !hn) {
          res.color = COLOR_PINNED;
        }

        if (sn) {
          if (node === sn) {
            res.size   = (attrs.origSize as number) * 2.2;
            res.color  = "#ffffff";
            res.zIndex = 10;
          } else if (g.areNeighbors(node, sn)) {
            res.size   = (attrs.origSize as number) * 1.5;
            res.zIndex = 5;
          } else {
            res.color  = NODE_DIM;
            res.size   = (attrs.origSize as number) * 0.45;
            res.label  = "";
          }
        } else if (hn) {
          if (node === hn) {
            res.size   = (attrs.origSize as number) * 2.2;
            res.color  = "#ffffff";
            res.zIndex = 10;
          } else if (g.areNeighbors(node, hn)) {
            res.size   = (attrs.origSize as number) * 1.5;
            res.zIndex = 5;
          } else {
            res.color  = NODE_DIM;
            res.size   = (attrs.origSize as number) * 0.45;
            res.label  = "";
          }
        } else if (sc) {
          if (comm !== sc) {
            res.color  = NODE_DIM;
            res.size   = (attrs.origSize as number) * 0.4;
            res.label  = "";
          } else {
            res.size   = (attrs.origSize as number) * 1.2;
            res.zIndex = 3;
          }
        }
        return res;
      },

      edgeReducer: (edge, attrs) => {
        const res  = { ...attrs };
        if (attrs.hidden) return res;

        // Confidence-based width and colour
        const conf = (attrs.confidence as number) ?? 0.5;
        res.size  = 0.5 + conf * 2;
        if (conf > 0.90) {
          res.color = "rgba(155, 159, 238, 0.85)";
        } else if (conf > 0.75) {
          res.color = "rgba(155, 159, 238, 0.45)";
        } else {
          res.color = "rgba(150,150,150,0.3)";
        }

        const sn = selNodeRef.current;
        const sc = selCommRef.current;
        const pathEdges = pathEdgesRef.current;

        // Path-highlight: bright yellow + thick for edges that lie on the
        // current path; transparent otherwise.  Same precedence rule as the
        // node reducer — path mode wins over selection/community focus.
        if (pathEdges.size > 0) {
          const src = g.source(edge);
          const tgt = g.target(edge);
          if (pathEdges.has(`${src}__${tgt}`) || pathEdges.has(`${tgt}__${src}`)) {
            res.color = "#FACC15"; // bright yellow
            res.size  = 4;
            res.zIndex = 15;
          } else {
            res.color = "rgba(0,0,0,0)";
            res.size  = 0;
          }
          return res;
        }

        if (sn) {
          if (g.hasExtremity(edge, sn)) {
            res.color = EDGE_ACTIVE; res.size = 2; res.zIndex = 5;
          } else {
            res.color = "rgba(0,0,0,0)"; res.size = 0;
          }
        } else if (sc) {
          const srcComm = g.getNodeAttribute(g.source(edge), "community");
          const tgtComm = g.getNodeAttribute(g.target(edge), "community");
          if (srcComm === sc && tgtComm === sc) {
            res.color = EDGE_ACTIVE; res.size = 1.2;
          } else {
            res.color = "rgba(0,0,0,0)"; res.size = 0;
          }
        }
        return res;
      },
    });

    sigmaRef.current = sigma;

    // ── Click / hover ──────────────────────────────────────────────────────────
    sigma.on("clickNode", (ev) => {
      const raw    = g.getNodeAttribute(ev.node, "raw") as GraphNodeJSON | null;
      const attrs  = g.getNodeAttributes(ev.node);
      const degree = g.degree(ev.node);
      // FIX 1: open detail panel
      setSelectedNodeDetail({
        id:     ev.node,
        label:  attrs.label as string | undefined,
        vaCategory: attrs.vaCategory as string | undefined,
        color:  attrs.color as string | undefined,
        origColor: attrs.origColor as string | undefined,
        raw:    raw ?? undefined,
        freshness_tag:       attrs.freshness_tag as string | undefined,
        freshness_label:     attrs.freshness_label as string | undefined,
        freshness_color:     attrs.freshness_color as string | undefined,
        source_count:        attrs.source_count as number | undefined,
        corroborating_sources: attrs.corroborating_sources as string[] | undefined,
        context_snippet:     attrs.context_snippet as string | undefined,
        context:             attrs.context as string | undefined,
        degree,
      });
      onClickRef.current(ev.node, raw);
    });
    sigma.on("clickStage", () => {
      setSelectedComm(null);
      selCommRef.current = null;
      setHighlightedNode(null);
      // FIX 1: clear detail panel on stage click
      setSelectedNodeDetail(null);
      sigma.refresh();
    });
    sigma.on("enterNode", (ev) => {
      hoveredNodeRef.current = ev.node;
      g.setNodeAttribute(ev.node, "forceLabel", true);
      el.style.cursor = "grab";
      sigma.refresh();
    });
    sigma.on("leaveNode", (ev) => {
      if (hoveredNodeRef.current === ev.node) hoveredNodeRef.current = null;
      g.setNodeAttribute(ev.node, "forceLabel", false);
      el.style.cursor = "default";
      sigma.refresh();
    });

    // ── Right-click context menu ───────────────────────────────────────────────
    sigma.on("rightClickNode", (ev) => {
      (ev.event.original as MouseEvent).preventDefault();
      setContextMenu({
        visible: true,
        x:       (ev.event.original as MouseEvent).clientX,
        y:       (ev.event.original as MouseEvent).clientY,
        nodeId:  ev.node,
      });
    });

    // ── Double-click to unpin ──────────────────────────────────────────────────
    sigma.on("doubleClickNode", (ev) => {
      g.setNodeAttribute(ev.node, "pinned", false);
      g.setNodeAttribute(ev.node, "fixed",  false);
      sigma.refresh();
      refreshStats();
    });

    // ── Drag: start ────────────────────────────────────────────────────────────
    // downNode is a sigma event (sigma wraps the captor's "mousedown" on a node)
    sigma.on("downNode", (ev) => {
      isDraggingRef.current  = true;
      draggedNodeRef.current = ev.node;
      el.style.cursor        = "grabbing";
    });

    // ── Drag: move ─────────────────────────────────────────────────────────────
    // mousemovebody and mouseup are MouseCaptor events (sigma does not relay them)
    const captor = sigma.getMouseCaptor();
    const handleCaptorMove = (ev: { x: number; y: number; preventSigmaDefault: () => void }) => {
      if (!isDraggingRef.current || !draggedNodeRef.current) return;
      ev.preventSigmaDefault();
      const pos = sigma.viewportToGraph({ x: ev.x, y: ev.y });
      // Fix node before updating position to prevent FA2 worker race
      g.setNodeAttribute(draggedNodeRef.current, "fixed",  true);
      g.setNodeAttribute(draggedNodeRef.current, "pinned", true);
      g.setNodeAttribute(draggedNodeRef.current, "x",     pos.x);
      g.setNodeAttribute(draggedNodeRef.current, "y",     pos.y);
    };
    const handleCaptorUp = () => {
      if (isDraggingRef.current) refreshStats();
      isDraggingRef.current  = false;
      draggedNodeRef.current = null;
      el.style.cursor        = "default";
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (captor as any).on("mousemovebody", handleCaptorMove);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (captor as any).on("mouseup", handleCaptorUp);

    // ── Drag: end (released outside canvas) ───────────────────────────────────
    const handleDocMouseUp = () => {
      if (isDraggingRef.current) refreshStats();
      isDraggingRef.current  = false;
      draggedNodeRef.current = null;
      el.style.cursor        = "default";
    };
    document.addEventListener("mouseup", handleDocMouseUp);

    // ── Label refresh ──────────────────────────────────────────────────────────
    sigma.on("afterRender",          refreshLabels);
    sigma.getCamera().on("updated",  refreshLabels);
    setTimeout(refreshLabels, 100);

    // ── Initial stats ──────────────────────────────────────────────────────────
    setGraphStats({ nodes: g.order, edges: g.size, pinned: 0, hidden: 0 });

    return () => {
      document.removeEventListener("mouseup", handleDocMouseUp);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (captor as any).off("mousemovebody", handleCaptorMove);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (captor as any).off("mouseup", handleCaptorUp);
      sigma.kill();
      sigmaRef.current = null;
      graphRef.current = null;
      setLabelPositions([]);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rebuildKey]);

  // ── Reactive sigma refresh ────────────────────────────────────────────────────
  useEffect(() => { sigmaRef.current?.refresh(); }, [selectedNodeId, hiddenCategories, selectedComm, highlightedNode]);

  // ── External focus (from entity sidebar) ─────────────────────────────────────
  useEffect(() => {
    if (!focusNodeId || !sigmaRef.current || !graphRef.current) return;
    const sigma = sigmaRef.current;
    if (!graphRef.current.hasNode(focusNodeId)) { onFocusHandled(); return; }
    const pos = sigma.getNodeDisplayData(focusNodeId);
    if (pos) sigma.getCamera().animate({ x: pos.x, y: pos.y, ratio: 0.1 }, { duration: 650 });
    onFocusHandled();
  }, [focusNodeId, onFocusHandled]);

  // ── Keyboard shortcuts (graph canvas focused) ─────────────────────────────────
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!graphFocusedRef.current) return;
      // Don't fire when typing in inputs
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;

      const key = e.key.toLowerCase();
      if (key === "f") {
        e.preventDefault();
        resetView();
      } else if (key === "r") {
        e.preventDefault();
        resetAll();
      } else if (key === "p") {
        e.preventDefault();
        if (hoveredNodeRef.current) togglePin(hoveredNodeRef.current);
      } else if (key === "h") {
        e.preventDefault();
        if (hoveredNodeRef.current) hideNode(hoveredNodeRef.current);
      } else if (key === "escape") {
        e.preventDefault();
        setHighlightedNode(null);
        setSelectedComm(null);
        selCommRef.current = null;
        showAll();
        sigmaRef.current?.refresh();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [resetView, resetAll, togglePin, hideNode, showAll]);

  // ── Cluster interaction ────────────────────────────────────────────────────────
  function handleClusterClick(lp: LabelPos) {
    const sigma = sigmaRef.current;
    if (!sigma) return;
    if (selectedComm === lp.id) {
      setSelectedComm(null);
      selCommRef.current = null;
      sigma.refresh();
      return;
    }
    setSelectedComm(lp.id);
    selCommRef.current = lp.id;
    let sx = 0, sy = 0, cnt = 0;
    for (const n of lp.members) {
      const d = sigma.getNodeDisplayData(n);
      if (d && !d.hidden) { sx += d.x; sy += d.y; cnt++; }
    }
    if (cnt > 0) sigma.getCamera().animate({ x: sx / cnt, y: sy / cnt, ratio: 0.22 }, { duration: 650 });
    sigma.refresh();
  }

  // ── Context menu helpers ───────────────────────────────────────────────────────
  const ctxNodeId = contextMenu.nodeId;
  const ctxIsPinned = ctxNodeId
    ? !!(graphRef.current?.getNodeAttribute(ctxNodeId, "pinned") as boolean)
    : false;

  // ── States ────────────────────────────────────────────────────────────────────
  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-8 bg-[var(--bg-void)]">
        <p className="font-mono text-[13px] text-[var(--danger)]">Intelligence feed error: {error}</p>
      </div>
    );
  }
  if (loading && (!data || data.nodes.length === 0)) {
    return (
      <div className="flex h-full items-center justify-center bg-[var(--bg-void)]">
        <div className="flex flex-col items-center gap-4">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent" />
          <p className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)]">Mapping Node Set</p>
        </div>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="relative h-full w-full bg-[var(--bg-void)] overflow-hidden">

      {/* Sigma canvas — tabIndex makes it keyboard-focusable for graph shortcuts */}
      <div
        ref={containerRef}
        className="absolute inset-0 outline-none"
        tabIndex={0}
        onFocus={() => { graphFocusedRef.current = true; }}
        onBlur={() => { graphFocusedRef.current = false; }}
        onContextMenu={(e) => e.preventDefault()}
      />

      {/* Vignette */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(ellipse 80% 80% at 50% 50%, transparent 45%, rgba(5,8,13,0.8) 100%)" }}
      />

      {/* SVG leader lines */}
      <svg
        className="pointer-events-none absolute inset-0"
        style={{ width: "100%", height: "100%", overflow: "visible" }}
      >
        {labelPositions.map((lp) => {
          const active = selectedComm === lp.id;
          const dx = lp.labelX - lp.anchorX;
          const dy = lp.labelY - lp.anchorY;
          const len = Math.sqrt(dx * dx + dy * dy) || 1;
          const ex = lp.labelX - (dx / len) * (PILL_W / 2 + 2);
          const ey = lp.labelY - (dy / len) * (PILL_H / 2 + 2);
          return (
            <g key={lp.id} style={{ opacity: lp.opacity * (active ? 1 : 0.5) }}>
              <line x1={lp.anchorX} y1={lp.anchorY} x2={ex} y2={ey}
                stroke={lp.color} strokeWidth={4} strokeOpacity={0.1} />
              <line x1={lp.anchorX} y1={lp.anchorY} x2={ex} y2={ey}
                stroke={lp.color}
                strokeWidth={active ? 1.2 : 0.7}
                strokeOpacity={active ? 0.75 : 0.3}
                strokeDasharray={active ? "none" : "5 4"} />
              <circle cx={lp.anchorX} cy={lp.anchorY} r={3} fill={lp.color} fillOpacity={active ? 0.8 : 0.5} />
            </g>
          );
        })}
      </svg>

      {/* Cluster pill labels */}
      {labelPositions.map((lp) => {
        const active = selectedComm === lp.id;
        return (
          <button
            key={lp.id}
            onClick={() => handleClusterClick(lp)}
            className="absolute"
            style={{
              left: lp.labelX, top: lp.labelY,
              transform:     "translate(-50%, -50%)",
              opacity:       lp.opacity,
              transition:    "opacity 0.2s ease",
              cursor:        "pointer",
              pointerEvents: lp.opacity > 0.1 ? "auto" : "none",
              zIndex:        active ? 20 : 10,
            }}
          >
            <div
              className="flex items-center gap-1.5 rounded-full transition-all duration-200"
              style={{
                padding:        "4px 10px 4px 7px",
                background:     active ? `${lp.color}20` : "rgba(7,11,17,0.88)",
                border:         `1px solid ${lp.color}${active ? "88" : "40"}`,
                backdropFilter: "blur(8px)",
                boxShadow:      active
                  ? `0 0 18px ${lp.color}44, inset 0 0 8px ${lp.color}11`
                  : "0 2px 12px rgba(0,0,0,0.5)",
                whiteSpace: "nowrap",
              }}
            >
              <span className="flex-shrink-0 rounded-full"
                style={{ width: 7, height: 7, background: lp.color, boxShadow: active ? `0 0 6px ${lp.color}` : "none" }}
              />
              <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "9.5px", fontWeight: 700,
                letterSpacing: "0.08em", textTransform: "uppercase",
                color: active ? lp.color : `${lp.color}cc`,
                maxWidth: 148, overflow: "hidden", textOverflow: "ellipsis" }}>
                {lp.label}
              </span>
              <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "8px",
                color: active ? lp.color : `${lp.color}bb`,
                background: active ? `${lp.color}22` : "transparent",
                padding: active ? "0 4px" : "0", borderRadius: 99, marginLeft: 2 }}>
                {lp.nodeCount}
              </span>
            </div>
          </button>
        );
      })}

      {/* ── Controls bar ───────────────────────────────────────────────────────── */}
      <div className="absolute bottom-4 left-4 flex flex-col gap-1.5 z-20">
        {/* Action buttons */}
        <div className="flex flex-col gap-1">
          {[
            { label: "Reset view",  title: "Fit graph to screen (F)",       action: resetView  },
            { label: "Re-layout",   title: "Recalculate layout",             action: () => startLayout() },
            { label: "Show all",    title: "Unhide all hidden nodes",        action: showAll    },
            { label: "Unpin all",   title: "Release all pinned nodes",       action: unpinAll   },
            {
              label:      "Find Path",
              title:      investigationId ? "Find shortest path between two entities" : "Path query requires an investigation id",
              action:     () => setPathDialogOpen(true),
              disabled:   !investigationId,
              highlight:  true,
            },
            ...(pathResult?.found ? [{ label: "Clear Path", title: "Clear the highlighted path", action: clearPath, highlight: true }] : []),
          ].map((btn) => (
            <button
              key={btn.label}
              title={btn.title}
              onClick={btn.action}
              disabled={"disabled" in btn && btn.disabled}
              className="flex h-6 items-center justify-center rounded border bg-[rgba(7,11,17,0.82)] px-2.5 backdrop-blur-sm transition-all"
              style={{
                fontFamily:    "'IBM Plex Mono', monospace",
                fontSize:      9,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                whiteSpace:    "nowrap",
                color:         "highlight" in btn && btn.highlight
                  ? "#FACC15"
                  : "rgba(200,220,240,0.75)",
                borderColor:   "highlight" in btn && btn.highlight
                  ? "rgba(250, 204, 21, 0.35)"
                  : "rgba(255,255,255,0.10)",
                opacity:       "disabled" in btn && btn.disabled ? 0.4 : 1,
                cursor:        "disabled" in btn && btn.disabled ? "not-allowed" : "pointer",
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>

        {/* Zoom controls */}
        <button
          title="Fit graph in view"
          onClick={resetView}
          className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-[rgba(7,11,17,0.82)] text-[rgba(200,220,240,0.85)] backdrop-blur-sm hover:border-white/20 hover:text-white transition-all"
          style={{ fontFamily: "monospace", fontSize: 12 }}
        >
          ⊙
        </button>
        <button
          title="Zoom in"
          onClick={() => {
            const cam = sigmaRef.current?.getCamera();
            if (cam) cam.animate({ ratio: cam.ratio * 0.6 }, { duration: 300 });
          }}
          className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-[rgba(7,11,17,0.82)] text-[rgba(200,220,240,0.85)] backdrop-blur-sm hover:border-white/20 hover:text-white transition-all"
          style={{ fontFamily: "monospace", fontSize: 16 }}
        >
          +
        </button>
        <button
          title="Zoom out"
          onClick={() => {
            const cam = sigmaRef.current?.getCamera();
            if (cam) cam.animate({ ratio: cam.ratio * 1.6 }, { duration: 300 });
          }}
          className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-[rgba(7,11,17,0.82)] text-[rgba(200,220,240,0.85)] backdrop-blur-sm hover:border-white/20 hover:text-white transition-all"
          style={{ fontFamily: "monospace", fontSize: 16 }}
        >
          −
        </button>
      </div>

      {/* Node count indicator */}
      {graphStats.nodes > 0 && (
        <div className="pointer-events-none absolute bottom-4 left-1/2 -translate-x-1/2 z-20">
          <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, letterSpacing: "0.1em", color: "rgba(165,185,210,0.5)" }}>
            {graphStats.nodes} nodes · {graphStats.edges} edges
            {graphStats.pinned > 0 && ` · ${graphStats.pinned} pinned`}
            {graphStats.hidden > 0 && ` · ${graphStats.hidden} hidden`}
          </span>
        </div>
      )}

      {/* Interaction hint */}
      {labelPositions.length > 0 && (
        <div className="pointer-events-none absolute top-4 left-1/2 -translate-x-1/2">
          <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", color: "rgba(165,185,210,0.45)" }}>
            drag to move · right-click for options · double-click to unpin · F to fit
          </span>
        </div>
      )}

      {/* FIX 4: Redesigned legend — collapsible floating card */}
      {(() => {
        const gr = graphRef.current;
        const presentCats = (Object.entries(CAT_COLOR) as [EntityCategoryKey, string][])
          .filter(([cat]) => !hiddenCategories.has(cat))
          .filter(([cat]) => gr ? gr.someNode((_, a) => (a.vaCategory as EntityCategoryKey) === cat) : false);

        if (presentCats.length === 0) return null;

        return (
          <div
            className="absolute bottom-4 right-4 z-20"
            style={{
              background:   "rgba(8, 11, 17, 0.92)",
              border:       "1px solid rgba(155, 159, 238, 0.20)",
              borderRadius: 8,
              padding:      legendCollapsed ? "8px 14px" : "10px 16px 12px",
              minWidth:     152,
              boxShadow:    "0 4px 24px rgba(0,0,0,0.55)",
              backdropFilter: "blur(12px)",
              transition:   "padding 0.2s ease",
            }}
          >
            {/* Title row with collapse toggle */}
            <button
              onClick={() => setLegendCollapsed((v) => !v)}
              style={{
                display:        "flex",
                alignItems:     "center",
                justifyContent: "space-between",
                width:          "100%",
                background:     "transparent",
                border:         "none",
                cursor:         "pointer",
                padding:        0,
                marginBottom:   legendCollapsed ? 0 : 8,
              }}
            >
              <span
                style={{
                  fontFamily:    "'JetBrains Mono', 'IBM Plex Mono', monospace",
                  fontSize:      10,
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color:         "rgba(255,255,255,0.4)",
                }}
              >
                Entity Types
              </span>
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize:   10,
                  color:      "rgba(255,255,255,0.3)",
                  marginLeft: 8,
                  transform:  legendCollapsed ? "rotate(0deg)" : "rotate(90deg)",
                  transition: "transform 0.2s ease",
                  display:    "inline-block",
                }}
              >
                ›
              </span>
            </button>

            {/* Expanded content */}
            {!legendCollapsed && (
              <>
                <div style={{ borderTop: "1px solid rgba(255,255,255,0.08)", marginBottom: 8 }} />
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {presentCats.map(([cat, color]) => (
                    <div key={cat} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span
                        style={{
                          width: 8, height: 8,
                          borderRadius: "50%",
                          background: color,
                          display: "inline-block",
                          flexShrink: 0,
                          boxShadow: `0 0 4px ${color}88`,
                        }}
                      />
                      <span
                        style={{
                          fontFamily: "Inter, sans-serif",
                          fontSize:   12,
                          color:      "rgba(255,255,255,0.80)",
                        }}
                      >
                        {CATEGORY_META[cat]?.short ?? cat}
                      </span>
                    </div>
                  ))}
                  {/* Pinned indicator */}
                  {graphStats.pinned > 0 && (
                    <>
                      <div style={{ borderTop: "1px solid rgba(255,255,255,0.08)", margin: "3px 0" }} />
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span
                          style={{
                            width: 8, height: 8,
                            borderRadius: "50%",
                            border: `2px solid ${COLOR_PINNED}`,
                            background: `${COLOR_PINNED}44`,
                            display: "inline-block",
                            flexShrink: 0,
                          }}
                        />
                        <span
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize:   12,
                            color:      "rgba(255,255,255,0.80)",
                          }}
                        >
                          Pinned node
                        </span>
                      </div>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        );
      })()}

      {/* Cluster filter hint */}
      {selectedComm && (
        <div className="pointer-events-none absolute bottom-14 left-1/2 -translate-x-1/2">
          <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, letterSpacing: "0.15em", textTransform: "uppercase", color: "rgba(165,185,210,0.72)" }}>
            click canvas to clear filter
          </span>
        </div>
      )}

      {/* Context menu */}
      {contextMenu.visible && (
        <GraphContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          nodeId={contextMenu.nodeId}
          isPinned={ctxIsPinned}
          onFocus={() => focusNode(contextMenu.nodeId)}
          onTogglePin={() => togglePin(contextMenu.nodeId)}
          onHide={() => hideNode(contextMenu.nodeId)}
          onIsolate={() => isolateNeighbors(contextMenu.nodeId)}
          onCopy={() => {
            const g = graphRef.current;
            if (!g?.hasNode(contextMenu.nodeId)) return;
            const val = g.getNodeAttribute(contextMenu.nodeId, "label") as string ?? contextMenu.nodeId;
            navigator.clipboard.writeText(val).catch(() => {/* ok */});
          }}
          onClose={() => setContextMenu((s) => ({ ...s, visible: false }))}
        />
      )}

      {/* Node detail panel — slides in from left */}
      <NodeDetailPanel
        node={selectedNodeDetail}
        graph={graphRef.current}
        searchQuery={searchQuery}
        onClose={() => setSelectedNodeDetail(null)}
        onIsolateNeighbors={isolateNeighbors}
      />

      {/* Find Path dialog */}
      {pathDialogOpen && investigationId && (
        <PathFindDialog
          entities={data?.nodes ?? []}
          querying={pathQuerying}
          result={pathResult}
          onClose={() => setPathDialogOpen(false)}
          onSubmit={(from, to) => {
            setPathDialogOpen(false);
            void runPathQuery(from, to);
          }}
        />
      )}

      {/* Path result panel — appears below the graph when a path was found */}
      {pathResult && (
        <PathResultPanel
          result={pathResult}
          onClear={clearPath}
        />
      )}
    </div>
  );
}

// ─── Path-finding dialog ─────────────────────────────────────────────────────

interface PathFindDialogProps {
  entities:   GraphNodeJSON[];
  querying:   boolean;
  result:     PathResponse | null;
  onClose:    () => void;
  onSubmit:   (from: string, to: string) => void;
}

function PathFindDialog({ entities, querying, result, onClose, onSubmit }: PathFindDialogProps) {
  const [from, setFrom] = useState("");
  const [to, setTo]     = useState("");
  const [err, setErr]   = useState<string | null>(null);

  const suggestions = useMemo(() => {
    return entities
      .map((n) => ({
        id:      n.id,
        label:   n.id,
        type:    n.type,
      }))
      .filter((n) => n.id)
      .sort((a, b) => a.label.localeCompare(b.label))
      .slice(0, 200);
  }, [entities]);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!from.trim() || !to.trim()) {
      setErr("Both From and To are required.");
      return;
    }
    if (from.trim() === to.trim()) {
      setErr("From and To must be different.");
      return;
    }
    setErr(null);
    onSubmit(from.trim(), to.trim());
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="absolute inset-0 z-50 flex items-center justify-center"
      style={{ background: "rgba(0, 0, 0, 0.55)", backdropFilter: "blur(2px)" }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <form
        onSubmit={handleSubmit}
        className="w-[480px] max-w-[90vw] rounded-lg"
        style={{
          background:   "rgba(8, 11, 17, 0.97)",
          border:       "1px solid rgba(155, 159, 238, 0.30)",
          boxShadow:    "0 12px 48px rgba(0,0,0,0.7)",
          padding:      20,
          color:        "#fff",
          fontFamily:   "'IBM Plex Mono', monospace",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <span style={{ fontSize: 12, letterSpacing: "0.15em", textTransform: "uppercase", color: "#9B9FEE", fontWeight: 700 }}>
            Find Shortest Path
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "transparent",
              border: "none",
              color: "rgba(255,255,255,0.5)",
              cursor: "pointer",
              fontSize: 18,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        <label style={{ display: "block", fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", color: "rgba(200,220,240,0.7)", marginBottom: 6 }}>
          From entity
        </label>
        <input
          autoFocus
          list="path-from-suggestions"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
          placeholder="e.g. LockBit"
          disabled={querying}
          style={inputStyle}
        />
        <datalist id="path-from-suggestions">
          {suggestions.map((s) => (
            <option key={`f-${s.id}`} value={s.label}>
              {s.type ? ` — ${s.type}` : ""}
            </option>
          ))}
        </datalist>

        <label style={{ display: "block", fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", color: "rgba(200,220,240,0.7)", margin: "14px 0 6px" }}>
          To entity
        </label>
        <input
          list="path-to-suggestions"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="e.g. 185.220.101.45"
          disabled={querying}
          style={inputStyle}
        />
        <datalist id="path-to-suggestions">
          {suggestions.map((s) => (
            <option key={`t-${s.id}`} value={s.label}>
              {s.type ? ` — ${s.type}` : ""}
            </option>
          ))}
        </datalist>

        {err && (
          <div style={{ color: "#ef4444", fontSize: 11, marginTop: 10 }}>
            {err}
          </div>
        )}

        {result && !result.found && result.message && (
          <div style={{ color: "#facc15", fontSize: 11, marginTop: 10 }}>
            {result.message}
          </div>
        )}

        <div style={{ display: "flex", gap: 8, marginTop: 18, justifyContent: "flex-end" }}>
          <button
            type="button"
            onClick={onClose}
            disabled={querying}
            style={{
              background: "transparent",
              border: "1px solid rgba(255,255,255,0.15)",
              color: "rgba(255,255,255,0.7)",
              padding: "6px 14px",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 11,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
            }}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={querying}
            style={{
              background: "rgba(250, 204, 21, 0.18)",
              border: "1px solid rgba(250, 204, 21, 0.45)",
              color: "#FACC15",
              padding: "6px 14px",
              borderRadius: 4,
              cursor: querying ? "wait" : "pointer",
              fontSize: 11,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              fontWeight: 700,
              opacity: querying ? 0.6 : 1,
            }}
          >
            {querying ? "Searching…" : "Find Path"}
          </button>
        </div>
      </form>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width:        "100%",
  background:   "rgba(0, 0, 0, 0.55)",
  border:       "1px solid rgba(155, 159, 238, 0.25)",
  borderRadius: 4,
  color:        "#fff",
  fontFamily:   "'IBM Plex Mono', monospace",
  fontSize:     12,
  padding:      "8px 10px",
  outline:      "none",
};

// ─── Path result panel ───────────────────────────────────────────────────────

function PathResultPanel({ result, onClear }: { result: PathResponse; onClear: () => void }) {
  if (!result.found) {
    return (
      <div
        className="absolute left-4 right-4 bottom-32 z-30 mx-auto"
        style={{
          maxWidth:    640,
          background:  "rgba(8, 11, 17, 0.94)",
          border:      "1px solid rgba(250, 204, 21, 0.35)",
          borderRadius: 8,
          padding:     "10px 14px",
          color:       "#fff",
          fontFamily:  "'IBM Plex Mono', monospace",
          display:     "flex",
          alignItems:  "center",
          justifyContent: "space-between",
          boxShadow:   "0 6px 24px rgba(0,0,0,0.55)",
        }}
      >
        <span style={{ fontSize: 11, color: "#FACC15" }}>
          ⚠ {result.message || "No path found"}
        </span>
        <button
          onClick={onClear}
          style={{
            background:  "transparent",
            border:      "1px solid rgba(255,255,255,0.18)",
            color:       "rgba(255,255,255,0.75)",
            padding:     "4px 10px",
            borderRadius: 4,
            cursor:      "pointer",
            fontSize:    10,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          Dismiss
        </button>
      </div>
    );
  }

  return (
    <div
      className="absolute left-4 right-4 bottom-32 z-30 mx-auto"
      style={{
        maxWidth:    720,
        background:  "rgba(8, 11, 17, 0.96)",
        border:      "1px solid rgba(250, 204, 21, 0.45)",
        borderRadius: 10,
        padding:     "12px 16px",
        color:       "#fff",
        fontFamily:  "'IBM Plex Mono', monospace",
        boxShadow:   "0 10px 40px rgba(0,0,0,0.7)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ fontSize: 11, letterSpacing: "0.15em", textTransform: "uppercase", color: "#FACC15", fontWeight: 700 }}>
          Shortest Path · {result.path_length ?? 0} hop{(result.path_length ?? 0) === 1 ? "" : "s"}
          {result.directed === false ? " · undirected fallback" : ""}
        </span>
        <button
          onClick={onClear}
          style={{
            background:  "transparent",
            border:      "1px solid rgba(255,255,255,0.18)",
            color:       "rgba(255,255,255,0.75)",
            padding:     "4px 10px",
            borderRadius: 4,
            cursor:      "pointer",
            fontSize:    10,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          Clear
        </button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {result.hops.map((hop, idx) => (
          <div key={`${hop.node_id}-${idx}`} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{
              display: "inline-block",
              width: 22, height: 22, lineHeight: "22px",
              borderRadius: "50%",
              background: "rgba(250, 204, 21, 0.22)",
              color: "#FACC15",
              textAlign: "center",
              fontSize: 10, fontWeight: 700,
              border: "1px solid rgba(250, 204, 21, 0.55)",
              flexShrink: 0,
            }}>
              {idx + 1}
            </span>
            <span style={{ color: "#fff", fontSize: 12 }}>
              {hop.canonical_value}
            </span>
            <span style={{ color: "rgba(200,220,240,0.5)", fontSize: 10 }}>
              [{hop.entity_type || "?"}] conf {hop.confidence.toFixed(2)}
            </span>
            {idx < result.hops.length - 1 && hop.relationship_to_previous && (
              <span style={{ color: "rgba(200,220,240,0.85)", fontSize: 11, marginLeft: 8 }}>
                ↓ {hop.relationship_to_previous.type || "RELATED"} ({hop.relationship_to_previous.confidence.toFixed(2)})
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
