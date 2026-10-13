"use client";

import { useCallback, useEffect, useRef } from "react";
import type { InvestigationSummary } from "@/lib/types/investigation";

const POLL_MS = 2000;

type Options = {
  investigationId: string;
  enabled: boolean;
  onUpdate: (inv: InvestigationSummary) => void;
};

export function useInvestigationPolling({ investigationId, enabled, onUpdate }: Options) {
  const onUpdateRef = useRef(onUpdate);
  onUpdateRef.current = onUpdate;

  const fetchOne = useCallback(async () => {

    const res = await fetch(`/api/investigations/${encodeURIComponent(investigationId)}`, {
      cache: "no-store",
      headers: {  },
    });
    if (!res.ok) return;
    const data = (await res.json()) as InvestigationSummary;
    onUpdateRef.current(data);
    // Return the status so callers can stop polling on terminal states
    return data.status;
  }, [investigationId]);

  useEffect(() => {
    if (!enabled) return;
    const id = window.setInterval(() => {
      void fetchOne();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [enabled, fetchOne]);
}
