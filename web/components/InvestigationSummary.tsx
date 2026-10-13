"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { InvestigationSummary as Inv } from "@/lib/types/investigation";

interface Props {
  investigation: Inv;
  investigationParamId: string;
  entityCount: number;
  relationshipCount: number;
  pagesCrawled: number;
  lastUpdatedLabel: string;
}

function parseModelDisplayName(modelId: string): string {
  let name = modelId.replace(/^openrouter\//, "");
  const lastSlash = name.lastIndexOf("/");
  if (lastSlash !== -1) name = name.slice(lastSlash + 1);
  name = name.replace(/-openrouter$/, "");
  return name.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function StatusBadge({ status }: { status: string }) {
  const isProcessing = status === "processing" || status === "pending";
  const isFailed = status === "failed";
  const isNoResults = status === "completed_no_results";
  const isCancelled = status === "cancelled";

  const baseDot = "h-1.5 w-1.5 rounded-full";
  const baseLabel = "font-mono text-[10px] font-bold uppercase tracking-wider";

  if (isProcessing) {
    return (
      <div className="flex items-center gap-2.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1">
        <span className={`${baseDot} bg-[var(--warning)] animate-pulse`} />
        <span className={`${baseLabel} text-[var(--text-secondary)]`}>Running</span>
      </div>
    );
  }

  if (isCancelled) {
    return (
      <div className="flex items-center gap-2.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1">
        <span className={`${baseDot} bg-amber-400`} />
        <span className={`${baseLabel} text-amber-400`}>Cancelled</span>
      </div>
    );
  }

  if (isFailed) {
    return (
      <div className="flex items-center gap-2.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1">
        <span className={`${baseDot} bg-[var(--danger)]`} />
        <span className={`${baseLabel} text-[var(--danger)]`}>Failed</span>
      </div>
    );
  }

  if (isNoResults) {
    return (
      <div className="flex items-center gap-2.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1">
        <span className={`${baseDot} bg-[var(--neutral)]`} />
        <span className={`${baseLabel} text-[var(--text-muted)]`}>No results</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1">
      <span className={`${baseDot} bg-[var(--success)] shadow-[0_0_8px_var(--success)]`} />
      <span className={`${baseLabel} text-[var(--text-secondary)]`}>Complete</span>
    </div>
  );
}

const EXPORT_FORMATS = [
  { key: "stix",  label: "STIX 2.1",     ext: "json", desc: "Structured threat intel" },
  { key: "misp",  label: "MISP",          ext: "json", desc: "Event sharing format"    },
  { key: "sigma", label: "Sigma Rules",   ext: "zip",  desc: "Detection rule archive"  },
] as const;

export function InvestigationSummary({
  investigation,
  investigationParamId,
  entityCount,
  relationshipCount,
  pagesCrawled,
}: Props) {
  const [exportOpen, setExportOpen]   = useState(false);
  const [exporting,  setExporting]    = useState<string | null>(null);
  const dropdownRef                   = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    const handle = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setExportOpen(false);
      }
    };
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, []);

  async function handleExport(format: "stix" | "misp" | "sigma") {
    setExporting(format);
    setExportOpen(false);
    try {

      const res = await fetch(
        `/api/export/${encodeURIComponent(investigationParamId)}/${format}`,
        { headers: {} }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const ext  = format === "sigma" ? "zip" : "json";
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `voidaccess_${investigationParamId}_${format}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      setExporting(null);
    }
  }

  return (
    <header className="flex h-[56px] shrink-0 items-center justify-between border-b border-[var(--border-dim)] bg-[var(--bg-void)]/60 px-6 backdrop-blur-xl">
      <div className="flex items-center gap-6">
        <Link href="/" className="flex items-center gap-2 font-heading transition-opacity hover:opacity-80">
          <span className="text-[var(--accent)]" aria-hidden>●</span>
          <span className="text-[15px] font-bold tracking-tight text-[var(--text-primary)]">voidaccess</span>
        </Link>

        <div className="h-4 w-px bg-[var(--border-dim)]" />

        <div className="flex items-center gap-5 font-mono text-[11px] font-medium tracking-tight">
          <div className="flex items-center gap-1.5 text-ellipsis overflow-hidden max-w-[200px]">
            <span className="text-[var(--text-muted)]">ID:</span>
            <span className="text-[var(--text-secondary)] uppercase">{String(investigation.id).slice(0, 8)}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[var(--text-primary)]">{entityCount}</span>
            <span className="text-[var(--text-muted)] uppercase">Entities</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[var(--text-primary)]">{relationshipCount}</span>
            <span className="text-[var(--text-muted)] uppercase">Edges</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[var(--text-primary)]">{pagesCrawled}</span>
            <span className="text-[var(--text-muted)] uppercase">Pages</span>
          </div>
          {investigation.model_used && (
            <div className="hidden md:flex items-center gap-1.5 rounded border border-[var(--border-dim)] bg-[var(--bg-overlay)] px-2 py-0.5">
              <span className="text-[var(--text-muted)] uppercase">Model:</span>
              <span className="text-[var(--text-secondary)]" title={investigation.model_used}>
                {parseModelDisplayName(investigation.model_used)}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4">
        <StatusBadge status={investigation.status} />

        <div className="h-4 w-px bg-[var(--border-dim)]" />

        {/* Export dropdown */}
        <div ref={dropdownRef} className="relative">
          <button
            onClick={() => setExportOpen((v) => !v)}
            disabled={!!exporting}
            className="flex h-8 items-center gap-2 rounded border border-[var(--border-dim)] bg-[var(--bg-raised)] px-3 text-[11px] font-semibold text-[var(--text-secondary)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-overlay)] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {exporting ? (
              <>
                <span
                  style={{
                    display: "inline-block",
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    border: "2px solid rgba(88,166,255,0.3)",
                    borderTopColor: "#9B9FEE",
                    animation: "spin 0.8s linear infinite",
                    flexShrink: 0,
                  }}
                />
                Exporting…
              </>
            ) : (
              <>
                Export Archive
                <svg
                  width="10" height="10" viewBox="0 0 16 16" fill="none"
                  className="opacity-50"
                  style={{ transform: exportOpen ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.15s" }}
                >
                  <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </>
            )}
          </button>

          {exportOpen && (
            <div
              className="absolute right-0 top-[calc(100%+6px)] z-50 min-w-[180px] overflow-hidden rounded border border-[var(--border-subtle)] bg-[var(--bg-surface)] shadow-xl"
              style={{ backdropFilter: "blur(12px)" }}
            >
              {EXPORT_FORMATS.map(({ key, label, ext, desc }) => (
                <button
                  key={key}
                  onClick={() => void handleExport(key)}
                  className="flex w-full flex-col items-start gap-0.5 px-4 py-2.5 text-left transition-colors hover:bg-[var(--bg-overlay)]"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[12px] font-semibold text-[var(--text-primary)]">{label}</span>
                    <span className="rounded bg-[var(--bg-raised)] px-1.5 py-px font-mono text-[9px] uppercase text-[var(--text-muted)]">.{ext}</span>
                  </div>
                  <span className="text-[10px] text-[var(--text-muted)]">{desc}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </header>
  );
}
