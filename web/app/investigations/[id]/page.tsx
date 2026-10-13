"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState, useRef } from "react";
import dynamic from "next/dynamic";
import { EntityDetailsPanel } from "@/components/EntityDetailsPanel";
import { EntitySidebar } from "@/components/EntitySidebar";
import { InvestigationSummary } from "@/components/InvestigationSummary";
import { InfrastructureClusters } from "@/components/InfrastructureClusters";
import { SourcesPanel } from "@/components/SourcesPanel";
import { TemporalAnalysisPanel } from "@/components/TemporalAnalysisPanel";
import { OpsecPanel } from "@/components/OpsecPanel";
import { StylometryPanel } from "@/components/StylometryPanel";
import { useGraphData } from "@/lib/hooks/useGraphData";
import { useInvestigationPolling } from "@/lib/hooks/useInvestigationPolling";
import { InvestigationLoadingScreen } from "@/components/InvestigationLoadingScreen";
import type {
  EntityCategoryKey,
  GraphNodeJSON,
  InvestigationEntity,
  InvestigationSummary as Inv,
} from "@/lib/types/investigation";

const GraphVisualization = dynamic(
  () => import("@/components/GraphVisualization").then(m => m.GraphVisualization),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent" />
      </div>
    ),
  }
);

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 45) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

export default function InvestigationPage() {
  const params = useParams();
  const investigationParamId = typeof params.id === "string" ? params.id : "";

  const [investigation, setInvestigation] = useState<Inv | null>(null);
  const [entities, setEntities] = useState<InvestigationEntity[]>([]);
  const [entitiesLoading, setEntitiesLoading] = useState(true);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailsEntity, setDetailsEntity] = useState<InvestigationEntity | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string | null>(null);
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [hiddenCategories, setHiddenCategories] = useState<Set<EntityCategoryKey>>(() => new Set());
  const [strongEdgesOnly, setStrongEdgesOnly] = useState(true);
  const [expandedPanel, setExpandedPanel] = useState<string | null>(null);
  const [minConfidence, setMinConfidence] = useState(0.75);
  const [debouncedMinConfidence, setDebouncedMinConfidence] = useState(0.75);
  const [entityMinConfidence, setEntityMinConfidence] = useState(0.75);
  const [defangEnabled, setDefangEnabled] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  const handleMinConfidenceChange = useCallback((value: number) => {
    setMinConfidence(value);
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }
    debounceTimerRef.current = setTimeout(() => {
      setDebouncedMinConfidence(value);
    }, 500);
  }, []);

  const handleEntityMinConfidenceChange = useCallback((value: number) => {
    setEntityMinConfidence(value);
    void fetchEntities(value);
  }, []);

  const {
    status: graphStatus,
    data: graphData,
    error: graphError,
    refetch: refetchGraph,
  } = useGraphData(investigationParamId, debouncedMinConfidence);

  const processing =
    investigation &&
    (investigation.status === "pending" || investigation.status === "processing");

  const handleCancelRequest = useCallback(() => {
    if (!window.confirm("Cancel this investigation? Partial results collected so far will be kept.")) return;
    setCancelling(true);

    fetch(`/api/investigations/${encodeURIComponent(investigationParamId)}/cancel`, {
      method: "POST",
      headers: {  },
    })
      .then(async (res) => {
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          const msg = (data as { detail?: string }).detail ?? `Error ${res.status}`;
          alert(msg);
          setCancelling(false);
        }
      })
      .catch((err) => {
        alert(err instanceof Error ? err.message : "Failed to cancel");
        setCancelling(false);
      });
  }, [investigationParamId]);

  const fetchInvestigation = useCallback(async () => {
    if (!investigationParamId) return;

    const res = await fetch(`/api/investigations/${encodeURIComponent(investigationParamId)}`, {
      cache: "no-store",
      headers: {  },
    });
    if (res.ok) {
      const data = (await res.json()) as Inv;
      setInvestigation(data);
    }
  }, [investigationParamId]);

  const fetchEntities = useCallback(async (minConf?: number, freshness?: string) => {
    if (!investigationParamId) return;
    setEntitiesLoading(true);
    try {

      const conf = minConf !== undefined ? minConf : entityMinConfidence;
      // Keep the client within the API's paginated maximum.  The previous
      // 1000 request was rejected with HTTP 422 before the sidebar could
      // render any entities or their priority scores.
      const qs = new URLSearchParams({ limit: "100", min_confidence: conf.toString(), defang: defangEnabled.toString() });
      if (freshness && freshness !== "expired") {
        qs.set("freshness_exclude", freshness);
      } else if (freshness === "expired") {
        qs.set("freshness_exclude", "expired");
      }
      const res = await fetch(
        `/api/investigations/${encodeURIComponent(investigationParamId)}/entities?${qs}`,
        { cache: "no-store", headers: {  } }
      );
      if (res.ok) {
        const json = await res.json();
        const items = (Array.isArray(json) ? json : (json.items ?? [])) as InvestigationEntity[];
        setEntities(items);
      }
    } finally {
      setEntitiesLoading(false);
    }
  }, [investigationParamId, entityMinConfidence, defangEnabled]);

  useEffect(() => {
    void fetchInvestigation();
    void fetchEntities();
  }, [fetchInvestigation, fetchEntities]);

  useInvestigationPolling({
    investigationId: investigationParamId,
    enabled: Boolean(processing) || cancelling,
    onUpdate: (inv) => {
      setInvestigation(inv);
      if (inv.status === "completed" || inv.status === "failed" || inv.status === "cancelled") {
        setCancelling(false);
        void fetchEntities();
        void refetchGraph();
      }
    },
  });

  const handleNodeClick = useCallback(
    (nodeId: string, _raw: GraphNodeJSON | null) => {
      setSelectedGraphNodeId(nodeId);
      const ent = entities.find(e => e.graph_node_id === nodeId || e.value === nodeId);
      if (ent) {
        setDetailsEntity(ent);
        setDetailsOpen(true);
      }
    },
    [entities]
  );

  const handleEntityActivate = useCallback((e: InvestigationEntity) => {
    setSelectedGraphNodeId(e.graph_node_id);
    setDetailsEntity(e);
    setDetailsOpen(true);
    setFocusNodeId(e.graph_node_id);
  }, []);

  const toggleCategoryHidden = useCallback((c: EntityCategoryKey) => {
    setHiddenCategories((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  }, []);

  const isOverflow = graphData?.graph_status === "skipped_overflow";
  const isNoData = graphData?.graph_status === "no_data";

  const handleDownloadCsv = useCallback(() => {

    const url = `/api/investigations/${encodeURIComponent(investigationParamId)}/entities/export/csv`;
    fetch(url, {
      headers: {  },
    })
      .then(res => res.blob())
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `voidaccess_${investigationParamId}_entities.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      });
  }, [investigationParamId]);

  if (!investigationParamId || !investigation) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg-void)]">
        <div className="flex flex-col items-center gap-6">
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent shadow-[0_0_15px_var(--accent-dim)]" />
          <div className="space-y-1 text-center">
            <p className="font-heading text-lg font-bold tracking-tight text-[var(--text-primary)]">Initializing Intelligence Workspace</p>
            <p className="font-mono text-[10px] uppercase tracking-widest text-[var(--text-muted)]">Verifying node authorization...</p>
          </div>
        </div>
      </div>
    );
  }

  if (investigation.status === "completed_no_results") {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[var(--bg-void)] px-4">
        <div className="flex flex-col items-center gap-6 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] p-8 shadow-xl max-w-md text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--bg-raised)]">
            <svg className="h-8 w-8 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="space-y-3">
            <h3 className="text-xl font-bold text-[var(--text-primary)]">No intelligence results found</h3>
            <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
              This query returned only directory or index pages. Try a more specific query such as a threat actor name, malware family, or CVE identifier.
            </p>
            {investigation.refined_query && investigation.refined_query !== investigation.query && (
              <p className="font-mono text-[11px] text-[var(--text-muted)]">
                Your query was interpreted as: <span className="text-[var(--accent)]">{investigation.refined_query}</span>
              </p>
            )}
          </div>
          <button
            onClick={() => window.location.href = "/"}
            className="mt-2 px-6 py-2.5 rounded-md bg-[var(--accent)] text-[var(--text-inverse)] text-sm font-bold hover:bg-[var(--accent-hover)] transition-colors"
          >
            New investigation
          </button>
        </div>
      </div>
    );
  }

  if (processing) {
    return (
      <InvestigationLoadingScreen
        query={investigation.query}
        currentStep={investigation.current_step}
        createdAt={investigation.created_at}
        onCancelRequest={handleCancelRequest}
        cancelling={cancelling}
      />
    );
  }

  return (
    <div className="flex h-screen flex-col bg-[var(--bg-void)] overflow-hidden font-sans">
      {/* Header Bar */}
      <InvestigationSummary
        investigation={investigation}
        investigationParamId={investigationParamId}
        entityCount={investigation.entity_count ?? entities.length}
        relationshipCount={graphData?.edges?.length ?? 0}
        pagesCrawled={investigation.page_count ?? 0}
        lastUpdatedLabel={formatRelative(investigation.created_at)}
      />

      {investigation.status === "cancelled" && (
        <div className="flex items-center gap-3 border-b border-amber-500/20 bg-amber-500/10 px-6 py-2.5">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400 shrink-0" />
          <span className="text-[12px] font-semibold text-amber-400">
            Investigation cancelled — showing partial results
          </span>
        </div>
      )}

      {investigation.refined_query && investigation.refined_query !== investigation.query && (
        <div className="flex items-center gap-2 border-b border-[var(--border-dim)] bg-[var(--bg-surface)] px-6 py-2">
          <span className="font-mono text-[10px] text-[var(--text-muted)]">Refined to:</span>
          <span className="font-mono text-[11px] text-[var(--accent)]">{investigation.refined_query}</span>
        </div>
      )}

      {/* Graph Controls Sub-header */}
      <div className="flex h-10 shrink-0 items-center justify-between border-b border-[var(--border-dim)] bg-[var(--bg-surface)] px-6">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Visibility:</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setHiddenCategories(new Set())}
                className={`text-[11px] font-bold transition-all ${hiddenCategories.size === 0 ? "text-[var(--accent)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}
              >
                Clear Filters
              </button>
              <div className="h-3 w-px bg-[var(--border-dim)] mx-1" />
              {(["THREAT_ACTOR", "WALLET", "MALWARE", "ONION_URL"] as EntityCategoryKey[]).map(cat => (
                <button
                  key={cat}
                  onClick={() => toggleCategoryHidden(cat)}
                  className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-all border ${!hiddenCategories.has(cat) ? "border-[var(--accent-dim)] bg-[var(--accent-dim)] text-[var(--accent)]" : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}
                >
                  <span className="text-[10px] font-bold uppercase tracking-tight">{cat.replace(/_/g, " ")}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Min confidence:</span>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={minConfidence}
              onChange={(e) => handleMinConfidenceChange(parseFloat(e.target.value))}
              className="h-1 w-24 cursor-pointer appearance-none rounded-full bg-[var(--border-dim)] accent-[var(--accent)]"
            />
            <span className="w-12 text-[10px] font-mono text-[var(--text-secondary)]">{minConfidence.toFixed(2)}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Defanged:</span>
            <button
              onClick={() => setDefangEnabled(!defangEnabled)}
              className={`px-3 py-1 text-[10px] font-bold uppercase tracking-widest transition-all rounded ${defangEnabled ? "bg-green-600 text-white shadow-lg" : "bg-[var(--border-dim)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
              title="Defanged mode replaces http:// with hxxp:// and dots in IPs with [.] for safe sharing. Disable for programmatic use."
            >
              {defangEnabled ? "ON" : "OFF"}
            </button>
          </div>
          {graphData?.total_entities !== undefined && (
            <span className="text-[10px] font-mono text-[var(--text-muted)]">
              Showing {graphData.filtered_entities} of {graphData.total_entities}
            </span>
          )}
          <div className="flex items-center bg-[var(--bg-void)] rounded-md border border-[var(--border-dim)] p-0.5">
            <button
              onClick={() => setStrongEdgesOnly(true)}
              className={`px-3 py-1 text-[10px] font-bold uppercase tracking-widest transition-all rounded ${strongEdgesOnly ? "bg-[var(--accent)] text-[var(--text-inverse)] shadow-lg" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
            >
              Strong
            </button>
            <button
              onClick={() => setStrongEdgesOnly(false)}
              className={`px-3 py-1 text-[10px] font-bold uppercase tracking-widest transition-all rounded ${!strongEdgesOnly ? "bg-[var(--accent)] text-[var(--text-inverse)] shadow-lg" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
            >
              Weak
            </button>
          </div>
          <button
            className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] hover:text-[var(--accent)] hover:underline transition-colors"
            onClick={() => {
              setHiddenCategories(new Set());
              setStrongEdgesOnly(true);
            }}
          >
            Reset
          </button>
        </div>
      </div>

      {/* Main Three-Panel View */}
      <div className="flex flex-1 min-h-0 relative overflow-hidden">
        {/* LEFT PANEL: Entities */}
        <aside className="w-[320px] shrink-0 border-r border-[var(--border-dim)] bg-[var(--bg-surface)] backdrop-blur-md" id="entities">
          <EntitySidebar
            entities={entities}
            selectedIds={selectedIds}
            onToggle={(id, next) => {
              setSelectedIds(prev => {
                const n = new Set(prev);
                if (next) n.add(id); else n.delete(id);
                return n;
              });
            }}
            onEntityActivate={handleEntityActivate}
            loading={entitiesLoading}
            investigationParamId={investigationParamId}
            minConfidence={entityMinConfidence}
            onMinConfidenceChange={handleEntityMinConfidenceChange}
          />
        </aside>

        {/* CENTER PANEL: Graph */}
        <main className="flex-1 relative bg-[var(--bg-void)] transition-all duration-300">
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_center,_transparent_0%,_var(--bg-void)_85%)] z-10 opacity-40" />
          {isNoData ? (
            <div className="flex h-full flex-col items-center justify-center">
              <div className="flex flex-col items-center gap-6 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] p-8 shadow-xl max-w-md text-center">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--bg-raised)]">
                  <svg className="h-8 w-8 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-lg font-bold text-[var(--text-primary)]">No intelligence data available</h3>
                  <p className="mt-2 text-sm text-[var(--text-muted)]">
                    The query returned no scrapeable pages.
                  </p>
                </div>
              </div>
            </div>
          ) : isOverflow ? (
            <div className="flex h-full flex-col items-center justify-center">
              <div className="flex flex-col items-center gap-6 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] p-8 shadow-xl max-w-md text-center">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--accent-dim)]">
                  <svg className="h-8 w-8 text-[var(--accent)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-lg font-bold text-[var(--text-primary)]">Graph too large to render</h3>
                  <p className="mt-2 text-sm text-[var(--text-muted)]">
                    This investigation has too many entity relationships to display visually. You can still browse entities in the list view or download the full dataset.
                  </p>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => window.location.hash = "#entities"}
                    className="px-4 py-2 rounded-md bg-[var(--accent)] text-[var(--text-inverse)] text-sm font-bold hover:bg-[var(--accent-hover)] transition-colors"
                  >
                    View entity list
                  </button>
                  <button
                    onClick={handleDownloadCsv}
                    className="px-4 py-2 rounded-md border border-[var(--border-dim)] text-[var(--text-secondary)] text-sm font-bold hover:bg-[var(--bg-raised)] transition-colors"
                  >
                    Download CSV
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <GraphVisualization
              data={graphData}
              loading={graphStatus === "loading"}
              error={graphError}
              selectedNodeId={selectedGraphNodeId}
              hiddenCategories={hiddenCategories}
              strongEdgesOnly={strongEdgesOnly}
              onNodeClick={handleNodeClick}
              focusNodeId={focusNodeId}
              onFocusHandled={() => setFocusNodeId(null)}
              investigationId={investigationParamId}
            />
          )}
        </main>

        {/* RIGHT PANEL: Details */}
        <EntityDetailsPanel
          entity={detailsEntity}
          investigationId={investigationParamId}
          open={detailsOpen}
          onClose={() => setDetailsOpen(false)}
          onViewInGraph={() => setFocusNodeId(detailsEntity?.graph_node_id || null)}
          onExportThisEntity={() => {}}
          onBackdropClick={() => setDetailsOpen(false)}
        />
      </div>

      {/* Analysis Panels Section */}
      <div className="shrink-0 border-t border-[var(--border-dim)] bg-[var(--bg-surface)]">
        <div className="flex h-10 items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)] mr-2">Analysis:</span>
            {[
              { id: "temporal", label: "Timeline" },
              { id: "opsec", label: "OPSEC" },
              { id: "stylometry", label: "Linguistics" },
              ...(investigation.infrastructure_clusters && investigation.infrastructure_clusters.length > 0
                ? [{ id: "infrastructure", label: `Infrastructure (${investigation.infrastructure_clusters.length})` }]
                : []),
              ...(investigation.sources_used && Object.keys(investigation.sources_used).length > 0
                ? [{ id: "sources", label: "Sources" }]
                : []),
            ].map(panel => (
              <button
                key={panel.id}
                onClick={() => setExpandedPanel(expandedPanel === panel.id ? null : panel.id)}
                className={`flex items-center gap-2 px-3 h-7 rounded-md text-[10px] font-bold uppercase tracking-widest transition-all ${expandedPanel === panel.id ? "bg-[var(--accent-dim)] text-[var(--accent)] border border-[var(--accent-border)]" : "border border-transparent text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)] hover:border-[var(--border-dim)]"}`}
              >
                <span className={`transition-transform duration-300 inline-block ${expandedPanel === panel.id ? "rotate-90" : ""}`}>▶</span>
                {panel.label}
              </button>
            ))}
          </div>
          {expandedPanel && (
            <button
              onClick={() => setExpandedPanel(null)}
              className="flex items-center gap-1.5 px-3 h-7 rounded-md text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-raised)] transition-all"
            >
              <span className="text-[12px] leading-none">✕</span>
              Close
            </button>
          )}
        </div>

        {expandedPanel && (
          <div className="h-[320px] overflow-y-auto bg-[var(--bg-void)] px-6 py-6 border-t border-[var(--border-dim)] animate-in slide-in-from-bottom-2 duration-300 custom-scrollbar">
            {expandedPanel === "temporal" && <TemporalAnalysisPanel investigationId={investigationParamId} />}
            {expandedPanel === "opsec" && <OpsecPanel entityId={detailsEntity?.id || ""} data={null} loading={false} error={null} onExpand={() => {}} />}
            {expandedPanel === "stylometry" && <StylometryPanel entityId={detailsEntity?.id || ""} data={null} loading={false} error={null} onExpand={() => {}} />}
            {expandedPanel === "infrastructure" && (
              <InfrastructureClusters
                clusters={investigation.infrastructure_clusters ?? []}
                onHighlightDomains={(domains) => {
                  const match = entities.find(e =>
                    domains.some(d => e.value?.includes(d))
                  );
                  if (match) {
                    setSelectedGraphNodeId(match.graph_node_id);
                    setFocusNodeId(match.graph_node_id);
                  }
                }}
              />
            )}
            {expandedPanel === "sources" && (
              <SourcesPanel sourcesUsed={investigation.sources_used ?? {}} />
            )}
          </div>
        )}
      </div>
    </div>
  );
}
