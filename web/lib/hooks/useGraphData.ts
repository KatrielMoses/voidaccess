"use client";

import { useCallback, useEffect, useState } from "react";
import type { GraphApiResponse } from "@/lib/types/investigation";

type State =
  | { status: "idle" | "loading"; data: null; error: null }
  | { status: "ready"; data: GraphApiResponse; error: null }
  | { status: "error"; data: null; error: string };

export function useGraphData(investigationId: string, minConfidence?: number) {
  const [state, setState] = useState<State>({
    status: "idle",
    data: null,
    error: null,
  });

  const refetch = useCallback(async () => {
    setState({ status: "loading", data: null, error: null });
    try {

      const qs = minConfidence !== undefined ? `?min_confidence=${minConfidence}` : "";
      const res = await fetch(`/api/investigations/${encodeURIComponent(investigationId)}/graph${qs}`, {
        cache: "no-store",
        headers: {  },
      });
      if (!res.ok) {
        const errBody = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(errBody.error ?? `Graph request failed (${res.status})`);
      }
      const data = (await res.json()) as GraphApiResponse;
      setState({ status: "ready", data, error: null });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load graph";
      setState({ status: "error", data: null, error: msg });
    }
  }, [investigationId, minConfidence]);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  return { ...state, refetch };
}
