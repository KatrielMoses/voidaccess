"use client";

import type { SourceEntry, SourceResult } from "@/lib/types/investigation";

const SOURCE_LABELS: Record<string, string> = {
  tor_search: "Tor Search",
  otx: "AlienVault OTX",
  malwarebazaar: "MalwareBazaar",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
  ransomware_live: "ransomware.live",
  ransomlook: "ransomlook.io",
  cisa: "CISA KEV",
  cisa_kev: "CISA KEV",
  nvd: "NVD 2.0",
  shodan: "Shodan InternetDB",
  shodan_internetdb: "Shodan InternetDB",
  virustotal: "VirusTotal",
  securitytrails: "SecurityTrails",
  github: "GitHub",
  gitlab: "GitLab",
  paste_sites: "Paste Sites",
  rss_feeds: "RSS Feeds",
  rss: "RSS Feeds",
  circl_pdns: "CIRCL pDNS",
  email_reputation: "Email Reputation",
  xposedornot: "XposedOrNot",
  leakcheck: "LeakCheck",
  hudsonrock: "Hudson Rock",
  domain_reputation: "Domain Reputation",
  hash_reputation: "Hash Reputation",
};

// Canonical display order
const SOURCE_ORDER = [
  "tor_search",
  "otx",
  "malwarebazaar",
  "threatfox",
  "urlhaus",
  "ransomware_live",
  "ransomlook",
  "cisa",
  "nvd",
  "shodan",
  "virustotal",
  "securitytrails",
  "circl_pdns",
  "email_reputation",
  "xposedornot",
  "leakcheck",
  "hudsonrock",
  "domain_reputation",
  "hash_reputation",
  "github",
  "gitlab",
  "paste_sites",
  "rss_feeds",
];

// Where to get the free API key for sources that are skipped when unconfigured.
const SOURCE_KEY_HINTS: Record<string, string> = {
  malwarebazaar: "free key at https://auth.abuse.ch",
  threatfox: "free key at https://auth.abuse.ch",
  urlhaus: "free key at https://auth.abuse.ch",
  otx: "free key at https://otx.alienvault.com",
};

type DotColor = "green" | "gray" | "yellow" | "red" | "orange";

function sourceEntry(raw: SourceResult): SourceEntry {
  if (typeof raw !== "string") return raw;
  const count = raw.match(/^ok_(\d+)_/);
  return { status: count ? "ok" : raw, ...(count ? { count: Number(count[1]) } : {}) };
}

function getDotColor({ status, count, requests }: SourceEntry): DotColor {
  if (status === "timed_out" || status === "partial") return "orange";
  if (status === "error" || status.startsWith("error_") || status.startsWith("http_")) return "red";
  if (status === "ok") return count === 0 ? (requests === 0 ? "gray" : "yellow") : "green";
  return "gray";
}

function describeSource(key: string, entry: SourceEntry): string {
  const { status, count, requests } = entry;
  if (status === "no_key" || status === "skipped_no_key") {
    const hint = SOURCE_KEY_HINTS[key];
    return `No API key${hint ? ` (${hint})` : ""}`;
  }
  if (status === "disabled" || status === "skipped_disabled") return "Disabled";
  if (status === "skipped_by_allowlist") return "Excluded by source selection";
  if (status === "skipped_not_implemented") return "Integration unavailable";
  if (status === "skipped") return key === "paste_sites" || ["pastebin", "paste_ee", "dpaste", "rentry"].includes(key)
    ? "No supported anonymous search" : "Not run";
  if (status.startsWith("skipped")) return status.replaceAll("_", " ");
  if (status === "timed_out") return "Timed out";
  if (status === "partial") return `Partial results (${count ?? 0}); some requests failed`;
  if (status === "error" || status.startsWith("error_") || status.startsWith("http_")) return "Failed";
  if (status === "ok" && count === 0 && requests === 0) return "No results; no external requests recorded";
  if (status === "ok") return count === undefined ? "Completed" : count === 0 ? "No results" : `${count} results`;
  return status === "pending" ? "Pending" : status.replaceAll("_", " ");
}

const DOT_CLASSES: Record<DotColor, string> = {
  green: "bg-green-500 shadow-[0_0_6px_rgba(74,222,128,0.6)]",
  gray: "bg-[var(--text-muted)] opacity-50",
  yellow: "bg-yellow-400",
  red: "bg-red-500",
  orange: "bg-orange-500",
};

const LEGEND = [
  { color: "green" as DotColor, label: "Results" },
  { color: "yellow" as DotColor, label: "No results" },
  { color: "gray" as DotColor, label: "Skipped" },
  { color: "orange" as DotColor, label: "Partial / timed out" },
  { color: "red" as DotColor, label: "Error" },
];

interface Props {
  sourcesUsed: Record<string, SourceResult>;
}

export function SourcesPanel({ sourcesUsed }: Props) {
  if (!sourcesUsed || Object.keys(sourcesUsed).length === 0) {
    return (
      <p className="text-[12px] text-[var(--text-muted)]">
        Source data not available for this investigation.
      </p>
    );
  }

  // All known keys in order, then any extras not in SOURCE_ORDER
  const allKeys = [
    ...SOURCE_ORDER.filter(k => k in sourcesUsed),
    ...Object.keys(sourcesUsed).filter(k => !SOURCE_ORDER.includes(k)),
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-6">
        <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">
          Intelligence Sources
        </h3>
        <div className="flex items-center gap-4">
          {LEGEND.map(({ color, label }) => (
            <span key={color} className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full shrink-0 ${DOT_CLASSES[color]}`} />
              <span className="text-[10px] text-[var(--text-muted)]">{label}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-3">
        {allKeys.map(key => {
          const entry = sourceEntry(sourcesUsed[key]);
          const color = getDotColor(entry);
          const label = SOURCE_LABELS[key] ?? key;
          const description = describeSource(key, entry);
          const requestDetail = entry.requests === undefined ? "" : ` · ${entry.requests} requests`;
          const tip = `${label}: ${description}${requestDetail}`;

          return (
            <div
              key={key}
              title={tip}
              className="flex items-center gap-2 cursor-default select-none"
            >
              <span className={`h-2 w-2 rounded-full shrink-0 ${DOT_CLASSES[color]}`} />
              <span className="text-[12px] text-[var(--text-primary)]">{label}</span>
              <span className="text-[10px] text-[var(--text-muted)]">{description}{requestDetail}</span>
            </div>
          );
        })}
      </div>
      <p className="text-xs text-[var(--text-muted)]">Completion describes the investigation run. Skipped or failed sources leave gaps in coverage.</p>
    </div>
  );
}
