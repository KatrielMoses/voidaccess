"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ModelInfo {
  id: string;
  name: string;
  provider: string;
  free_tier: boolean;
  recommended: boolean;
  default?: boolean;
  context_window?: number | null;
}

interface ProviderInfo {
  name: string;
  key_name: string;
  configured: boolean;
  models: ModelInfo[];
}

interface ModelListResponse {
  providers: ProviderInfo[];
  custom_model_allowed: boolean;
}

interface ValidateResult {
  valid: boolean;
  model_id: string;
  provider?: string;
  message: string;
  error?: string;
  suggestion?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseModelDisplayName(modelId: string): string {
  // Strip "openrouter/" prefix
  let name = modelId.replace(/^openrouter\//, "");
  // Strip provider prefix before last "/"
  const lastSlash = name.lastIndexOf("/");
  if (lastSlash !== -1) name = name.slice(lastSlash + 1);
  // Strip trailing "-openrouter"
  name = name.replace(/-openrouter$/, "");
  // Replace dashes/underscores with spaces and title-case
  return name.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatContextWindow(ctx?: number | null): string {
  if (!ctx) return "";
  if (ctx >= 1_000_000) return `${(ctx / 1_000_000).toFixed(1)}M ctx`;
  if (ctx >= 1_000) return `${Math.round(ctx / 1000)}K ctx`;
  return `${ctx} ctx`;
}

// ---------------------------------------------------------------------------
// Component props
// ---------------------------------------------------------------------------

interface ModelSelectorProps {
  value: string;
  onChange: (modelId: string) => void;
}

// ---------------------------------------------------------------------------
// ModelSelector component
// ---------------------------------------------------------------------------

export function ModelSelector({ value, onChange }: ModelSelectorProps) {
  const [modelList, setModelList] = useState<ModelListResponse | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  const [isOpen, setIsOpen] = useState(false);
  const [mode, setMode] = useState<"browse" | "custom">("browse");
  const [search, setSearch] = useState("");

  const [customInput, setCustomInput] = useState("");
  const [validating, setValidating] = useState(false);
  const [validateResult, setValidateResult] = useState<ValidateResult | null>(null);
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [focusedIndex, setFocusedIndex] = useState(-1);

  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => {
    if (value || !modelList) return;
    const available = modelList.providers
      .filter((provider) => provider.configured)
      .flatMap((provider) => provider.models);
    const initial = available.find((model) => model.default)
      ?? available.find((model) => model.recommended)
      ?? available[0];
    if (initial) onChangeRef.current(initial.id);
  }, [value, modelList]);

  // ── Fetch model list ──────────────────────────────────────────────────────

  // The server cache is scoped to the authenticated user; localStorage is not.
  const fetchModelList = useCallback(async () => {
    setLoadingList(true);
    setListError(null);
    try {

      const res = await fetch("/api/settings/models", {
        headers: {  },
      });
      if (!res.ok) throw new Error(`Failed to load models (${res.status})`);
      const data: ModelListResponse = await res.json();
      setModelList(data);
    } catch (e) {
      setListError(e instanceof Error ? e.message : "Failed to load models");
    } finally {
      setLoadingList(false);
    }
  }, []);

  useEffect(() => { void fetchModelList(); }, [fetchModelList]);

  // ── Close on outside click ────────────────────────────────────────────────

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // ── Focus search on open ──────────────────────────────────────────────────

  useEffect(() => {
    if (isOpen && mode === "browse") {
      setTimeout(() => searchRef.current?.focus(), 50);
    }
  }, [isOpen, mode]);

  // ── Debounced validation ──────────────────────────────────────────────────

  const triggerValidation = useCallback((id: string) => {
    if (validateTimer.current) clearTimeout(validateTimer.current);
    if (!id.trim()) { setValidateResult(null); return; }
    validateTimer.current = setTimeout(async () => {
      setValidating(true);
      setValidateResult(null);
      try {

        const res = await fetch("/api/settings/models/validate", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",

          },
          body: JSON.stringify({ model_id: id.trim() }),
        });
        const data: ValidateResult = await res.json();
        setValidateResult(data);
      } catch {
        setValidateResult({ valid: false, model_id: id, message: "Validation request failed" });
      } finally {
        setValidating(false);
      }
    }, 800);
  }, []);

  const handleCustomInput = (v: string) => {
    setCustomInput(v);
    triggerValidation(v);
  };

  // ── Flat filterable model list for browse mode ────────────────────────────

  const allModels: (ModelInfo & { providerName: string })[] = [];
  if (modelList) {
    for (const p of modelList.providers) {
      if (!p.configured || p.models.length === 0) continue;
      for (const m of p.models) {
        allModels.push({ ...m, providerName: p.name });
      }
    }
  }

  const filtered = search.trim()
    ? allModels.filter((m) =>
        m.name.toLowerCase().includes(search.toLowerCase()) ||
        m.id.toLowerCase().includes(search.toLowerCase()) ||
        m.provider.toLowerCase().includes(search.toLowerCase())
      )
    : allModels;

  // Group by provider (preserve order)
  const grouped: { provider: string; models: typeof filtered }[] = [];
  for (const m of filtered) {
    const last = grouped[grouped.length - 1];
    if (last && last.provider === m.providerName) {
      last.models.push(m);
    } else {
      grouped.push({ provider: m.providerName, models: [m] });
    }
  }

  // ── Keyboard navigation ───────────────────────────────────────────────────

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!isOpen) return;
    if (e.key === "Escape") { setIsOpen(false); return; }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((i) => Math.min(i + 1, filtered.length - 1));
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((i) => Math.max(i - 1, 0));
    }
    if (e.key === "Enter" && focusedIndex >= 0 && filtered[focusedIndex]) {
      onChange(filtered[focusedIndex].id);
      setIsOpen(false);
    }
  };

  // ── Derived display name ──────────────────────────────────────────────────

  const displayModelId = value;

  const displayName = (() => {
    if (!displayModelId) return loadingList ? "Loading models…" : "Select a model";
    const found = allModels.find((m) => m.id === displayModelId);
    return found ? found.name : parseModelDisplayName(displayModelId);
  })();

  // ── Check if no keys configured at all ───────────────────────────────────

  const noKeysConfigured =
    modelList !== null && modelList.providers.every((p) => !p.configured);

  // ── Mode C: No key banner ─────────────────────────────────────────────────

  if (noKeysConfigured && !loadingList) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-[var(--warning)]/40 bg-[var(--warning)]/10 px-3 py-2 text-[11px]">
        <span className="text-[var(--warning)]">⚠</span>
        <span className="text-[var(--text-secondary)]">
          No LLM provider configured.{" "}
          <Link href="/settings" className="text-[var(--accent)] hover:underline">
            Add an API key in Settings →
          </Link>
        </span>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div ref={containerRef} className="relative" onKeyDown={handleKeyDown}>
      {/* Trigger button */}
      <button
        id="model-selector-trigger"
        type="button"
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        onClick={() => setIsOpen((v) => !v)}
        className="flex items-center gap-2 rounded-md border border-[var(--border-dim)] bg-[var(--bg-overlay)] px-2.5 py-1 font-mono text-[11px] text-[var(--text-secondary)] outline-none transition-colors hover:border-[var(--border-subtle)] hover:text-[var(--text-primary)] focus:border-[var(--accent-border)]"
      >
        <span className="max-w-[130px] truncate">{displayName}</span>
        <svg
          width="10"
          height="10"
          viewBox="0 0 16 16"
          fill="none"
          className={`shrink-0 opacity-50 transition-transform ${isOpen ? "rotate-180" : ""}`}
        >
          <path
            d="M4 6l4 4 4-4"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>

      {/* Dropdown panel */}
      {isOpen && (
        <div
          className="absolute bottom-full left-0 z-50 mb-2 w-[380px] overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] shadow-2xl"
          style={{ maxHeight: "min(480px, 80vh)" }}
          role="dialog"
          aria-label="Model picker"
        >
          {/* Tabs */}
          <div className="flex border-b border-[var(--border-dim)] bg-[var(--bg-void)]/60">
            <button
              type="button"
              onClick={() => setMode("browse")}
              className={`flex-1 px-4 py-2.5 font-mono text-[11px] font-semibold transition-colors ${
                mode === "browse"
                  ? "text-[var(--accent)] border-b border-[var(--accent)]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              Browse Models
            </button>
            <button
              type="button"
              onClick={() => setMode("custom")}
              className={`flex-1 px-4 py-2.5 font-mono text-[11px] font-semibold transition-colors ${
                mode === "custom"
                  ? "text-[var(--accent)] border-b border-[var(--accent)]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              Enter Model ID
            </button>
          </div>

          {/* ── Mode A: Browse ── */}
          {mode === "browse" && (
            <>
              {/* Search */}
              <div className="border-b border-[var(--border-dim)] px-3 py-2">
                <div className="flex items-center gap-2">
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" className="shrink-0 text-[var(--text-muted)]">
                    <circle cx="6.5" cy="6.5" r="5" stroke="currentColor" strokeWidth="1.5" />
                    <path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <input
                    ref={searchRef}
                    type="text"
                    aria-label="Search models"
                    value={search}
                    onChange={(e) => { setSearch(e.target.value); setFocusedIndex(-1); }}
                    placeholder="Search models..."
                    className="w-full bg-transparent font-mono text-[11px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)]"
                  />
                  {search && (
                    <button
                      type="button"
                      aria-label="Clear model search"
                      onClick={() => setSearch("")}
                      className="shrink-0 text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                    >
                      ×
                    </button>
                  )}
                </div>
              </div>

              {/* Model list */}
              <div ref={listRef} className="overflow-y-auto" style={{ maxHeight: "340px" }}>
                {loadingList && (
                  <div className="py-8 text-center font-mono text-[11px] text-[var(--text-muted)]">
                    Loading models…
                  </div>
                )}
                {listError && (
                  <div className="py-4 px-3 font-mono text-[11px] text-[var(--error)]">
                    {listError}
                  </div>
                )}
                {!loadingList && !listError && grouped.length === 0 && (
                  <div className="py-8 text-center font-mono text-[11px] text-[var(--text-muted)]">
                    {search ? "No models match your search." : "No providers configured."}
                  </div>
                )}
                {grouped.map(({ provider, models }) => (
                  <div key={provider} role="listbox" aria-label={`${provider} models`}>
                    <div className="sticky top-0 z-10 bg-[var(--bg-surface)] px-3 py-1.5 font-mono text-[9px] font-semibold uppercase tracking-widest text-[var(--text-muted)]">
                      {provider}
                    </div>
                    {models.map((m) => {
                      const globalIdx = filtered.findIndex((am) => am.id === m.id);
                      return (
                        <button
                          key={m.id}
                          type="button"
                          role="option"
aria-selected={displayModelId === m.id}
                          onClick={() => { onChange(m.id); setIsOpen(false); }}
                          className={`flex w-full items-start gap-2.5 px-3 py-2 text-left transition-colors ${
                              displayModelId === m.id
                              ? "bg-[var(--accent)]/10 text-[var(--accent)]"
                              : focusedIndex === globalIdx
                              ? "bg-[var(--bg-overlay)] text-[var(--text-primary)]"
                              : "text-[var(--text-secondary)] hover:bg-[var(--bg-overlay)] hover:text-[var(--text-primary)]"
                          }`}
                        >
                          <span className="mt-0.5 font-mono text-[10px] leading-tight">{m.name}</span>
                          <span className="ml-auto flex shrink-0 items-center gap-1.5 font-mono text-[9px]">
                            {m.free_tier && (
                              <span className="rounded bg-[var(--success)]/15 px-1 py-0.5 text-[var(--success)]">
                                free
                              </span>
                            )}
                            {m.recommended && (
                              <span className="rounded bg-[var(--accent)]/15 px-1 py-0.5 text-[var(--accent)]">
                                rec
                              </span>
                            )}
                            {formatContextWindow(m.context_window) && (
                              <span className="text-[var(--text-muted)]">{formatContextWindow(m.context_window)}</span>
                            )}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                ))}
              </div>
            </>
          )}

          {/* ── Mode B: Custom ── */}
          {mode === "custom" && (
            <div className="p-3">
              <p className="mb-2 font-mono text-[10px] text-[var(--text-muted)]">
                Enter any model ID supported by your configured providers.
                Validation sends a short prompt to the selected provider and may incur charges.
              </p>
              <input
                type="text"
                aria-label="Custom model ID"
                value={customInput}
                onChange={(e) => handleCustomInput(e.target.value)}
                placeholder="e.g. gpt-6-luna or openrouter/deepseek/deepseek-v4.1-flash"
                className="w-full rounded-md border border-[var(--border-dim)] bg-[var(--bg-overlay)] px-3 py-1.5 font-mono text-[11px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-border)]"
              />
              {validating && (
                <p className="mt-1.5 font-mono text-[10px] text-[var(--text-muted)]">Validating…</p>
              )}
              {validateResult && (
                <p className={`mt-1.5 font-mono text-[10px] ${validateResult.valid ? "text-[var(--success)]" : "text-[var(--error)]"}`}>
                  {validateResult.valid ? `✓ ${validateResult.message}` : `✗ ${validateResult.message}`}
                  {validateResult.suggestion && (
                    <span className="block text-[var(--text-muted)]">Suggestion: {validateResult.suggestion}</span>
                  )}
                </p>
              )}
              <p className="mt-1 font-mono text-[9px] text-[var(--text-muted)]">
                Select a model from a provider you have configured.
              </p>
              <button
                type="button"
                disabled={!customInput.trim() || (validateResult !== null && !validateResult.valid)}
                onClick={() => {
                  if (customInput.trim()) {
                    onChange(customInput.trim());
                    setIsOpen(false);
                  }
                }}
                className="mt-3 w-full rounded-md bg-[var(--accent)] px-3 py-1.5 font-mono text-[11px] font-semibold text-[var(--text-inverse)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
              >
                Use This Model
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
