"use client";

import { useCallback, useEffect, useState } from "react";
import type { MonitorAlert } from "@/types/monitor";

type AlertsPayload = {
  alerts?: MonitorAlert[];
};

export function useMonitorAlerts(monitorName: string | null) {
  const [alerts, setAlerts] = useState<MonitorAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    if (!monitorName) {
      setAlerts([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {

      const res = await fetch(
        `/api/monitors/${encodeURIComponent(monitorName)}/alerts?include_acknowledged=true&limit=50`,
        { cache: "no-store", headers: {  } }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(
          (body as { detail?: string; error?: string }).detail ??
            (body as { error?: string }).error ??
            `HTTP ${res.status}`
        );
      }
      const data = (await res.json()) as AlertsPayload;
      setAlerts(Array.isArray(data.alerts) ? data.alerts : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, [monitorName]);

  useEffect(() => {
    void fetchAlerts();
  }, [fetchAlerts]);

  const acknowledgeAll = useCallback(async (): Promise<boolean> => {
    if (!monitorName) return false;
    try {

      const res = await fetch(
        `/api/monitors/${encodeURIComponent(monitorName)}/alerts/acknowledge`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",

          },
          body: JSON.stringify({}),
        }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(
          (body as { detail?: string }).detail ?? `HTTP ${res.status}`
        );
      }
      await fetchAlerts();
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Acknowledge failed");
      return false;
    }
  }, [monitorName, fetchAlerts]);

  return {
    alerts,
    loading,
    error,
    refresh: fetchAlerts,
    acknowledgeAll,
  };
}
