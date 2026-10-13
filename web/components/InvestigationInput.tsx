"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ModelSelector } from "@/components/ModelSelector";


const PRESETS = [
  {
    label: "Ransomware Lookup",
    text: "Investigate ransomware group activity, leak sites, and recent victim announcements related to LockBit affiliates.",
  },
  {
    label: "Crypto Trace",
    text: "Trace Bitcoin wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for dark web mentions and mixer interactions.",
  },
  {
    label: "Threat Actor",
    text: "Build an OSINT profile for threat actor handle 'void_runner' across forums and paste sites.",
  },
  {
    label: "Dark Web Search",
    text: "Search dark web forums and marketplaces for discussions about critical infrastructure attacks in the last 30 days.",
  },
  {
    label: "Entity Map",
    text: "Map all entities, connections, and relationships associated with the Scattered Spider threat group.",
  },
];

const MIN_HEIGHT = 56;
const MAX_HEIGHT = 120;

export function InvestigationInput() {
  const router = useRouter();
  const taRef = useRef<HTMLTextAreaElement>(null);
  const [value, setValue] = useState("");
  const [model, setModel] = useState<string>("");
  const [fullIntel, setFullIntel] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const adjustHeight = useCallback((reset?: boolean) => {
    const el = taRef.current;
    if (!el) return;
    if (reset) {
      el.style.height = `${MIN_HEIGHT}px`;
      return;
    }
    el.style.height = `${MIN_HEIGHT}px`;
    const next = Math.max(MIN_HEIGHT, Math.min(el.scrollHeight, MAX_HEIGHT));
    el.style.height = `${next}px`;
  }, []);

  useEffect(() => {
    if (taRef.current) taRef.current.style.height = `${MIN_HEIGHT}px`;
  }, []);

  useEffect(() => {
    const handleResize = () => adjustHeight();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [adjustHeight]);

  const handleSubmit = async () => {
    const q = value.trim();
    if (!q || loading) return;
    setError(null);
    setLoading(true);
    try {

      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",

        },
        body: JSON.stringify({ query: q, model, full_intelligence: fullIntel }),
      });
      const data = (await res.json()) as {
        run_id?: string;
        error?: string;
        detail?: string | { error?: string; message?: string; code?: string };
      };
      if (!res.ok) {
        if (res.status === 401) { router.push("/login"); return; }
        const detail = data.detail;
        if (typeof detail === "object" && detail?.code === "CONTENT_BLOCKED") {
          setError(
            "This search query cannot be processed. " +
            "VoidAccess is designed for legitimate security research only."
          );
          return;
        }
        setError(
          (typeof detail === "string" ? detail : null) ??
          data.error ??
          `Request failed (${res.status})`
        );
        return;
      }
      if (data.run_id) {
        router.push(`/investigations/${data.run_id}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (text: string) => {
    setValue(text);
    setError(null);
    requestAnimationFrame(() => {
      adjustHeight();
      taRef.current?.focus();
    });
  };

  const hasValue = value.trim().length > 0;

  return (
    <div className="flex w-full flex-col items-center gap-6">
      {/* Investigation Container */}
      <div className="group relative w-full rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-raised)] transition-all duration-300 focus-within:border-[var(--accent-border)] focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.5)]">
        <div className="p-4">
          <textarea
            ref={taRef}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              adjustHeight();
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                if (hasValue) void handleSubmit();
              }
            }}
            placeholder="Search for a threat actor, wallet address, malware family, or onion URL..."
            spellCheck={false}
            className="w-full resize-none border-none bg-transparent p-0 text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:ring-0"
            style={{ minHeight: MIN_HEIGHT }}
          />
        </div>

        {/* Toolbar */}
        <div className="flex items-center justify-between border-t border-[var(--border-dim)] bg-[var(--bg-void)]/30 px-3 py-2.5">
          <div className="flex items-center gap-2">
            <ModelSelector value={model} onChange={setModel} />

            <button
              type="button"
              onClick={() => setFullIntel((v) => !v)}
              className={`px-2.5 py-1 text-[11px] font-medium transition-colors border rounded-md ${
                fullIntel
                  ? "border-[var(--accent-border)] bg-[var(--accent-dim)] text-[var(--accent)]"
                  : "border-[var(--border-dim)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-subtle)]"
              }`}
            >
              {fullIntel ? "● Full Intel" : "+ Full Intel"}
            </button>
          </div>

          <button
            type="button"
            onClick={() => void handleSubmit()}
            disabled={loading || !hasValue}
            className="flex h-9 items-center gap-2 rounded-lg bg-[var(--accent)] px-4 text-[13px] font-semibold text-[var(--text-inverse)] transition-all hover:opacity-90 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-30"
          >
            {loading ? (
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-[var(--text-inverse)] border-t-transparent" />
            ) : (
              <>Hunt <ArrowRightIcon /></>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 font-mono text-[13px] text-[var(--warning)]">
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}

      {/* Preset shortcuts */}
      <div className="flex flex-wrap items-center justify-center gap-x-5 gap-y-3 px-4">
        {PRESETS.map((p, i) => (
          <div key={p.label} className="flex items-center gap-5">
            <button
              type="button"
              onClick={() => applyPreset(p.text)}
              className="font-mono text-[13px] text-[var(--text-muted)] transition-colors hover:text-[var(--text-secondary)]"
            >
              {p.label}
            </button>
            {i < PRESETS.length - 1 && (
              <span className="text-[var(--text-muted)] opacity-30 cursor-default">·</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function ArrowRightIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <path
        d="M3.5 8h9M9 4.5l4.5 3.5-4.5 3.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
