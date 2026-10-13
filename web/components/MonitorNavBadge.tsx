"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const POLL_MS = 60_000;

/**
 * Navigation link for Monitor with unacknowledged alert count.
 * Polls GET /api/monitors/alerts/count every 60s (Next.js proxy → backend).
 */
export function MonitorNavBadge() {
  const [count, setCount] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;

    const load = () => {

      fetch("/api/monitors/alerts/count", {
        cache: "no-store",
        headers: {

        }
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((data: { total_unacknowledged?: number } | null) => {
          if (cancelled || !data) return;
          setCount(Number(data.total_unacknowledged ?? 0));
        })
        .catch(() => {});
    };

    load();
    const id = window.setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return (
    <Link
      href="/monitor"
      className="flex items-center gap-1 text-neutral-500 transition-colors hover:text-neutral-300"
    >
      Monitor
      {count > 0 && (
        <span className="ml-1 animate-pulse rounded border border-red-500/50 bg-red-900/50 px-1.5 py-0.5 font-mono text-xs text-red-400">
          {count}
        </span>
      )}
    </Link>
  );
}
