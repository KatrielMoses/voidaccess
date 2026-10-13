"use client";

import { useState } from "react";
import Link from "next/link";

interface ApiKeyDef {
  key_name: string;
  label: string;
  description: string;
}

interface ApiKeyStatus {
  key_name: string;
  is_set: boolean;
  server_configured: boolean;
  label: string;
  description: string;
}

async function fetchApiKeys(): Promise<ApiKeyStatus[]> {
  const res = await fetch("/api/settings/api-keys", {

  });
  if (!res.ok) throw new Error("Failed to load keys");
  const data = await res.json();
  return data.keys;
}

async function saveKey(keyName: string, value: string): Promise<void> {
  const res = await fetch("/api/settings/api-keys", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_name: keyName, value }),
  });
  if (!res.ok) throw new Error("Failed to save key");
}

async function deleteKey(keyName: string): Promise<void> {
  const res = await fetch(`/api/settings/api-keys/${keyName}`, {
    method: "DELETE",

  });
  if (!res.ok) throw new Error("Failed to delete key");
}

async function testKey(keyName: string, value: string): Promise<{ valid: boolean; message: string }> {
  const res = await fetch("/api/settings/api-keys/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_name: keyName, value }),
  });
  if (!res.ok) throw new Error("Failed to test key");
  return res.json();
}

const API_KEY_DEFS: ApiKeyDef[] = [
  {
    key_name: "OPENAI_API_KEY",
    label: "OpenAI",
    description: "Enables GPT-4o and GPT-4 models",
  },
  {
    key_name: "ANTHROPIC_API_KEY",
    label: "Anthropic",
    description: "Enables Claude models",
  },
  {
    key_name: "GOOGLE_API_KEY",
    label: "Google Gemini",
    description: "Enables Gemini models (free tier available)",
  },
  {
    key_name: "OPENROUTER_API_KEY",
    label: "OpenRouter",
    description: "Access 100+ models including free tier options",
  },
  {
    key_name: "GROQ_API_KEY",
    label: "Groq (Free tier)",
    description: "Fast inference — Llama 3.3 70B free. Sign up at console.groq.com",
  },
  {
    key_name: "OTX_API_KEY",
    label: "AlienVault OTX",
    description: "Threat intelligence enrichment",
  },
  {
    key_name: "VT_API_KEY",
    label: "VirusTotal",
    description: "File hash enrichment (optional)",
  },
];

export default function SettingsPage() {


  const [keys, setKeys] = useState<ApiKeyStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inputValues, setInputValues] = useState<Record<string, string>>({});
  const [testingKey, setTestingKey] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ keyName: string; valid: boolean; message: string } | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  const loadKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchApiKeys();
      setKeys(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (keyName: string) => {
    const value = inputValues[keyName] || "";
    if (!value) return;
    setSaving(keyName);
    try {
      await saveKey(keyName, value);
      setInputValues((prev) => ({ ...prev, [keyName]: "" }));
      await loadKeys();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(null);
    }
  };

  const handleDelete = async (keyName: string) => {
    try {
      await deleteKey(keyName);
      await loadKeys();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete");
    }
  };

  const handleTest = async (keyName: string) => {
    const value = inputValues[keyName];
    if (!value) return;
    setTestingKey(keyName);
    setTestResult(null);
    try {
      const result = await testKey(keyName, value);
      setTestResult({ keyName, valid: result.valid, message: result.message });
    } catch (e) {
      setTestResult({ keyName, valid: false, message: e instanceof Error ? e.message : "Test failed" });
    } finally {
      setTestingKey(null);
    }
  };

  const getStatus = (keyName: string) => {
    const k = keys.find((k) => k.key_name === keyName);
    if (!k) return "loading";
    if (k.is_set) return "user";
    if (k.server_configured) return "server";
    return "none";
  };

  return (
    <div className="min-h-screen bg-[var(--bg-void)]">
      <header className="sticky top-0 z-10 flex h-[56px] shrink-0 items-center justify-between border-b border-[var(--border-dim)] bg-[var(--bg-void)]/80 px-6 backdrop-blur-md">
        <Link href="/" className="flex items-center gap-2 text-sm text-[var(--text-secondary)] transition-colors hover:text-[var(--text-primary)]">
          ← Back
        </Link>
        <h1 className="text-[15px] font-semibold">Settings</h1>
        <div className="w-16" />
      </header>

      <main className="mx-auto max-w-2xl px-6 py-10">
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">API Keys</h2>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Configure your personal API keys. These override server defaults and are encrypted before storage.
          </p>
        </div>

        <div className="mb-6 rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-4 text-sm text-yellow-400">
          💡 Free options: Groq offers fast Llama 3 inference with no credit card required (console.groq.com). OpenRouter has free model access. Google Gemini has a free tier via AI Studio. You can also run models locally with Ollama (no API key needed).
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <button
          onClick={loadKeys}
          className="mb-6 text-sm text-[var(--accent)] transition-opacity hover:underline"
        >
          {loading ? "Loading..." : "Load API key status"}
        </button>

        <div className="space-y-4">
          {API_KEY_DEFS.map((def) => {
            const status = getStatus(def.key_name);
            return (
              <div key={def.key_name} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-medium text-[var(--text-primary)]">{def.label}</h3>
                    <p className="mt-1 text-sm text-[var(--text-secondary)]">{def.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {status === "user" && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-green-500/20 px-2.5 py-0.5 text-xs font-medium text-green-400">
                        <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
                        Configured
                      </span>
                    )}
                    {status === "server" && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--bg-surface)] px-2.5 py-0.5 text-xs font-medium text-[var(--text-muted)]">
                        <span className="h-1.5 w-1.5 rounded-full bg-[var(--text-muted)]" />
                        Server default
                      </span>
                    )}
                    {status === "none" && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-red-500/20 px-2.5 py-0.5 text-xs font-medium text-red-400">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                        Not configured
                      </span>
                    )}
                  </div>
                </div>

                {status === "none" && (
                  <div className="mt-3 rounded bg-yellow-500/10 p-2 text-xs text-yellow-400">
                    No key configured — this provider will be unavailable
                  </div>
                )}

                <div className="mt-4 flex items-center gap-2">
                  <input
                    type="password"
                    placeholder="Enter new key to update"
                    value={inputValues[def.key_name] || ""}
                    onChange={(e) => setInputValues((prev) => ({ ...prev, [def.key_name]: e.target.value }))}
                    className="flex-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-void)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none"
                  />
                  <button
                    onClick={() => handleTest(def.key_name)}
                    disabled={!inputValues[def.key_name] || testingKey === def.key_name}
                    className="rounded-lg border border-[var(--border-subtle)] px-3 py-2 text-sm text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text-primary)] disabled:opacity-40"
                  >
                    {testingKey === def.key_name ? "Testing..." : "Test"}
                  </button>
                  <button
                    onClick={() => handleSave(def.key_name)}
                    disabled={!inputValues[def.key_name] || saving === def.key_name}
                    className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-fg)] transition-opacity hover:opacity-90 disabled:opacity-40"
                  >
                    {saving === def.key_name ? "Saving..." : "Save"}
                  </button>
                  {status === "user" && (
                    <button
                      onClick={() => handleDelete(def.key_name)}
                      className="rounded-lg border border-red-500/30 px-3 py-2 text-sm text-red-400 transition-colors hover:border-red-500 hover:bg-red-500/10"
                    >
                      Remove
                    </button>
                  )}
                </div>

                {testResult?.keyName === def.key_name && (
                  <div className={`mt-3 rounded p-2 text-sm ${testResult.valid ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}`}>
                    {testResult.message}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </main>
    </div>
  );
}
