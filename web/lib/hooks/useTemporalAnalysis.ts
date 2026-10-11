"use client";

import { useState, useCallback } from "react";
import { getToken } from "@/lib/auth";

// ── Types ───────────────────────────────────────────────────────────────────

export interface TemporalAnomaly {
  date: string;
  count: number;
  // Poisson event-count model (replaced the old z_score signal).
  poisson_p_value: number;
  expected_rate: number;
  type: "spike" | "drop";
  description: string;
}

export interface TemporalSilenceBreak {
  before: string;
  after: string;
  gap_days: number;
  significance: "medium" | "high";
}

export interface TemporalAnalysisData {
  investigation_id: string;
  activity_by_hour: Record<string, number>;
  activity_by_day: Record<string, number>;
  anomalies: TemporalAnomaly[];
  silence_breaks: TemporalSilenceBreak[];
  peak_hour: number | null;
  peak_day: string | null;
  total_timespan_days: number;
  data_points: number;
  // Graceful degradation fields
  error?: string;
  message?: string;
}

// ── Hook ───────────────────────────────────────────────────────────────────

type State = {
  data: TemporalAnalysisData | null;
  loading: boolean;
  error: string | null;
  fetched: boolean;
};

/**
 * Lazy fetch — only calls the temporal analysis endpoint when trigger() is
 * invoked (i.e., when the analyst expands the panel). No polling.
 */
export function useTemporalAnalysis(investigationId: string | null) {
  const [state, setState] = useState<State>({
    data: null,
    loading: false,
    error: null,
    fetched: false,
  });

  const trigger = useCallback(async () => {
    if (!investigationId || state.fetched || state.loading) return;
    setState((prev) => ({ ...prev, loading: true, error: null }));

    try {
      const token = getToken();
      const res = await fetch(
        `/api/investigations/${encodeURIComponent(investigationId)}/analysis/temporal`,
        { cache: "no-store", headers: { ...(token ? { "Authorization": `Bearer ${token}` } : {}) } }
      );
      const json = (await res.json()) as TemporalAnalysisData & { detail?: unknown };

      if (!res.ok) {
        const msg =
          typeof json?.detail === "string" ? json.detail : `Error ${res.status}`;
        setState({ data: null, loading: false, error: msg, fetched: true });
        return;
      }

      // Backend returned a structured error (insufficient_data / analysis_failed)
      if (json.error) {
        setState({
          data: json,
          loading: false,
          error: json.message ?? json.error,
          fetched: true,
        });
        return;
      }

      setState({ data: json, loading: false, error: null, fetched: true });
    } catch (err) {
      setState({
        data: null,
        loading: false,
        error: err instanceof Error ? err.message : "Request failed",
        fetched: true,
      });
    }
  }, [investigationId, state.fetched, state.loading]);

  return { ...state, trigger };
}
