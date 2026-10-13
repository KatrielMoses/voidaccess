"use client";

import { useState, useCallback } from "react";

// ── Stylometry types ────────────────────────────────────────────────────────

export interface StylometryData {
  entity_id: string;
  text_samples: number;
  total_chars: number;
  profile: Record<string, number>;
  confidence: "low" | "medium" | "high";
  notable_traits: string[];
  similar_actors: Array<{
    canonical_value: string;
    entity_type: string;
    similarity_score: number;
    confidence: "low" | "medium" | "high";
    matching_features: string[];
    profile_sample_count: number;
    calibration_status?: "calibrated";
  }>;
  similarity_method?: string;
  calibration?: {
    status: "calibrated" | "uncalibrated";
    threshold?: number;
    false_match_rate?: number;
    validation_pairs?: number;
    dataset?: string;
    message?: string;
  };
  reliability?: {
    text_samples: number;
    total_chars: number;
    minimum_recommended_chars: number;
    warning: string | null;
  };
  // Graceful degradation
  error?: string;
  message?: string;
}

// ── OPSEC types ─────────────────────────────────────────────────────────────

export interface OpsecFinding {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  evidence: string;
  first_detected: string | null;
}

export interface OpsecData {
  entity_id: string;
  opsec_score: number | null;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null;
  findings: OpsecFinding[];
  pages_analyzed: number;
  // Graceful degradation
  error?: string;
  message?: string;
}

// ── Hook ───────────────────────────────────────────────────────────────────

type SingleState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
  fetched: boolean;
};

/**
 * Lazy fetch for entity-level analysis (stylometry + OPSEC).
 * Each panel triggers its own fetch independently when expanded.
 * No polling — entity analysis is a static snapshot.
 */
export function useEntityAnalysis(entityId: string | null) {
  const [stylometry, setStylometry] = useState<SingleState<StylometryData>>({
    data: null,
    loading: false,
    error: null,
    fetched: false,
  });

  const [opsec, setOpsec] = useState<SingleState<OpsecData>>({
    data: null,
    loading: false,
    error: null,
    fetched: false,
  });

  const fetchStylometry = useCallback(async () => {
    if (!entityId || stylometry.fetched || stylometry.loading) return;
    setStylometry((prev) => ({ ...prev, loading: true, error: null }));

    try {

      const res = await fetch(
        `/api/entities/${encodeURIComponent(entityId)}/analysis/stylometry`,
        { cache: "no-store", headers: {  } }
      );
      const json = (await res.json()) as StylometryData & { detail?: unknown };

      if (!res.ok) {
        const msg =
          typeof json?.detail === "string" ? json.detail : `Error ${res.status}`;
        setStylometry({ data: null, loading: false, error: msg, fetched: true });
        return;
      }
      if (json.error) {
        setStylometry({
          data: json,
          loading: false,
          error: json.message ?? json.error,
          fetched: true,
        });
        return;
      }
      setStylometry({ data: json, loading: false, error: null, fetched: true });
    } catch (err) {
      setStylometry({
        data: null,
        loading: false,
        error: err instanceof Error ? err.message : "Request failed",
        fetched: true,
      });
    }
  }, [entityId, stylometry.fetched, stylometry.loading]);

  const fetchOpsec = useCallback(async () => {
    if (!entityId || opsec.fetched || opsec.loading) return;
    setOpsec((prev) => ({ ...prev, loading: true, error: null }));

    try {

      const res = await fetch(
        `/api/entities/${encodeURIComponent(entityId)}/analysis/opsec`,
        { cache: "no-store", headers: {  } }
      );
      const json = (await res.json()) as OpsecData & { detail?: unknown };

      if (!res.ok) {
        const msg =
          typeof json?.detail === "string" ? json.detail : `Error ${res.status}`;
        setOpsec({ data: null, loading: false, error: msg, fetched: true });
        return;
      }
      if (json.error) {
        setOpsec({
          data: json,
          loading: false,
          error: json.message ?? json.error,
          fetched: true,
        });
        return;
      }
      setOpsec({ data: json, loading: false, error: null, fetched: true });
    } catch (err) {
      setOpsec({
        data: null,
        loading: false,
        error: err instanceof Error ? err.message : "Request failed",
        fetched: true,
      });
    }
  }, [entityId, opsec.fetched, opsec.loading]);

  return { stylometry, opsec, fetchStylometry, fetchOpsec };
}
