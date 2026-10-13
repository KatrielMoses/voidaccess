"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  Monitor,
  RawWatch,
  RawWatchStatus,
  CreateMonitorInput,
  AlertCountResponse,
} from "@/types/monitor";

const POLL_INTERVAL_MS = 60_000;


function toChannels(w: RawWatch): string[] {
  const ch: string[] = [];
  if (w.webhook_url) ch.push("webhook");
  if (w.telegram_chat_id) ch.push("telegram");
  if (w.email) ch.push("email");
  return ch;
}

function mergeMonitors(
  watches: RawWatch[],
  statuses: RawWatchStatus[],
  byMonitor: Record<string, number>
): Monitor[] {
  const statusMap = new Map<string, RawWatchStatus>();
  for (const s of statuses) {
    statusMap.set(s.name, s);
  }

  return watches.map((w) => {
    const st = statusMap.get(w.name);
    return {
      id: w.name,
      type: w.type,
      query: w.type === "keyword" ? (w.query ?? "") : (w.url ?? ""),
      status: w.enabled ? "active" : "paused",
      check_interval_hours: w.interval_hours,
      last_checked_at: st?.last_run_time ?? null,
      next_check_at: st?.next_run_time ?? null,
      alert_count: byMonitor[w.name] ?? 0,
      alert_channels: toChannels(w),
      alert_on: w.alert_on,
    };
  });
}

export function useMonitors() {
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [totalUnacknowledged, setTotalUnacknowledged] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const fetchMonitors = useCallback(async () => {


    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const headers = {

    };

    try {
      const [watchesRes, statusRes, countRes] = await Promise.all([
        fetch("/api/monitors", {
            signal: ctrl.signal,
            cache: "no-store",
            headers
        }),
        fetch("/api/monitors/status", {
          signal: ctrl.signal,
          cache: "no-store",
          headers
        }),
        fetch("/api/monitors/alerts/count", {
          signal: ctrl.signal,
          cache: "no-store",
          headers
        }),
      ]);

      if (!watchesRes.ok) {
        throw new Error(`GET /monitors returned ${watchesRes.status}`);
      }

      const watches = (await watchesRes.json()) as RawWatch[];
      const statuses = statusRes.ok
        ? ((await statusRes.json()) as RawWatchStatus[])
        : [];

      let byMonitor: Record<string, number> = {};
      let total = 0;
      if (countRes.ok) {
        const countData = (await countRes.json()) as AlertCountResponse;
        byMonitor = countData.by_monitor ?? {};
        total = countData.total_unacknowledged ?? 0;
      }
      setTotalUnacknowledged(total);

      setMonitors(mergeMonitors(watches, statuses, byMonitor));
      setError(null);
    } catch (err) {
      if ((err as Error).name === "AbortError") return;
      setError(err instanceof Error ? err.message : "Failed to load monitors");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchMonitors();
    const id = window.setInterval(() => void fetchMonitors(), POLL_INTERVAL_MS);
    return () => {
      window.clearInterval(id);
      abortRef.current?.abort();
    };
  }, [fetchMonitors]);

  const createMonitor = useCallback(
    async (input: CreateMonitorInput): Promise<{ error?: string }> => {

      try {
        const res = await fetch("/api/monitors", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",

          },
          body: JSON.stringify(input),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          return {
            error: (body as { detail?: string }).detail ?? `HTTP ${res.status}`,
          };
        }
        await fetchMonitors();
        return {};
      } catch (err) {
        return { error: err instanceof Error ? err.message : "Unknown error" };
      }
    },
    [fetchMonitors]
  );

  const deleteMonitor = useCallback(
    async (id: string): Promise<{ error?: string }> => {

      try {
        const res = await fetch(
          `/api/monitors/${encodeURIComponent(id)}`,
          {
            method: "DELETE",
            headers: {

            }
          }
        );
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          return {
            error: (body as { detail?: string }).detail ?? `HTTP ${res.status}`,
          };
        }
        setMonitors((prev) => prev.filter((m) => m.id !== id));
        return {};
      } catch (err) {
        return { error: err instanceof Error ? err.message : "Unknown error" };
      }
    },
    []
  );

  const triggerMonitor = useCallback(
    async (id: string): Promise<{ error?: string }> => {

      try {
        const res = await fetch(
          `/api/monitors/${encodeURIComponent(id)}/trigger`,
          {
            method: "POST",
            headers: {

            }
          }
        );
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          return {
            error: (body as { detail?: string }).detail ?? `HTTP ${res.status}`,
          };
        }
        return {};
      } catch (err) {
        return { error: err instanceof Error ? err.message : "Unknown error" };
      }
    },
    []
  );

  return {
    monitors,
    total_unacknowledged: totalUnacknowledged,
    loading,
    error,
    refresh: fetchMonitors,
    createMonitor,
    deleteMonitor,
    triggerMonitor,
  };
}
