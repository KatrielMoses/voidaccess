import { LogoutButton } from "@/components/LogoutButton";
import Link from "next/link";
import { Settings } from "lucide-react";
import { InvestigationInput } from "@/components/InvestigationInput";
import { StatusBar } from "@/components/StatusBar";
import { MonitorNavBadge } from "@/components/MonitorNavBadge";
import { WebNetworkBg } from "@/components/WebNetworkBg";

export default function HomePage() {
  return (
    <div
      className="relative min-h-screen overflow-hidden selection:bg-[var(--accent-dim)] selection:text-[var(--accent)]"
    >
      {/* Asymmetric node-web background */}
      <WebNetworkBg />

      {/* Radial vignette — softens edges */}
      <div
        className="pointer-events-none fixed inset-0 z-0"
        style={{
          background:
            "radial-gradient(ellipse at center, rgba(8, 11, 17, 0) 0%, rgba(8, 11, 17, 0.75) 100%)",
        }}
        aria-hidden
      />

      {/* Navigation */}
      <header className="fixed left-0 right-0 top-0 z-30 flex h-[64px] items-center justify-between px-6 md:px-10 border-b border-[var(--border-dim)] backdrop-blur-md bg-[#080B11]/50">
        <Link
          href="/"
          className="flex items-center gap-2 text-[1.1rem] font-semibold tracking-tight text-[var(--text-primary)]"
          style={{ fontFamily: "var(--font-display)" }}
        >
          <span className="text-[var(--accent)]" aria-hidden>
            ●
          </span>
          voidaccess
        </Link>
        <nav className="flex items-center gap-8 text-[13px] font-medium text-[var(--text-secondary)]">
          <Link
            href="/investigations"
            className="transition-colors hover:text-[var(--text-primary)]"
          >
            Investigations
          </Link>
          <MonitorNavBadge />
          <Link
            href="/settings"
            className="transition-colors hover:text-[var(--text-primary)]"
          >
            <Settings className="h-4 w-4" />
          </Link>
          <Link
            href="/docs"
            className="transition-colors hover:text-[var(--text-primary)]"
          >
            Documentation
          </Link>
          <div className="h-4 w-px bg-[var(--border-subtle)]" />
          <StatusBar />
          <LogoutButton />
        </nav>
      </header>

      {/* Main content — vertically centered focus */}
      <main className="relative z-10 flex min-h-screen flex-col items-center justify-center px-4">
        <div className="flex w-full max-w-4xl flex-col items-center gap-12 text-center">
          <div className="flex flex-col items-center gap-4 animate-in fade-in slide-in-from-bottom-4 duration-1000">
            <h1
              className="text-[3.5rem] font-bold leading-[1.1] tracking-tight text-[var(--text-primary)] md:text-[4.5rem]"
              style={{
                fontFamily: "var(--font-display)",
                fontWeight: 700,
                letterSpacing: "-0.02em",
              }}
            >
              What will you <br />
              <span className="text-[var(--accent)]">hunt</span> today?
            </h1>
            <p
              className="max-w-xl text-[15px] leading-relaxed text-[var(--text-secondary)]"
              style={{ fontFamily: "var(--font-body)", fontWeight: 400 }}
            >
              Professional dark web intelligence platform for serious threat analysts.{" "}
              Search, map, and attribute with precision.
            </p>
          </div>

          <div className="w-full max-w-2xl animate-in fade-in slide-in-from-bottom-8 delay-300 duration-1000 fill-mode-both">
            <InvestigationInput />
          </div>

          <div
            className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-[13px] text-[var(--text-muted)] animate-in fade-in delay-500 duration-1000 fill-mode-both"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            <span className="cursor-default">Ransomware Lookup</span>
            <span className="text-[var(--border-strong)]">·</span>
            <span className="cursor-default">Crypto Trace</span>
            <span className="text-[var(--border-strong)]">·</span>
            <span className="cursor-default">Threat Actor</span>
            <span className="text-[var(--border-strong)]">·</span>
            <span className="cursor-default">Dark Web Search</span>
            <span className="text-[var(--border-strong)]">·</span>
            <span className="cursor-default">Entity Map</span>
          </div>
        </div>
      </main>

      {/* Footer / Legal minimal */}
      <footer className="absolute bottom-6 left-0 right-0 z-10 hidden md:block">
        <div
          className="flex items-center justify-center gap-4 text-[11px] font-medium uppercase tracking-[0.2em] text-[var(--text-muted)]"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          <span>Encrypted Architecture</span>
          <span className="h-1 w-1 rounded-full bg-[var(--text-muted)]" />
          <span>Distributed OSINT Nodes</span>
          <span className="h-1 w-1 rounded-full bg-[var(--text-muted)]" />
          <span>AI Enrichment [m2.1]</span>
        </div>
      </footer>
    </div>
  );
}
