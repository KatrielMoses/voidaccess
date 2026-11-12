import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

/** Proxy POST /api/monitors/{name}/alerts/acknowledge → backend */
export async function POST(request: Request, { params }: { params: Promise<{ name: string }> }) {
  const token = await getSessionAuthorization();
    const { name } = await params;
  let body: unknown = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    body = {};
  }
  try {
    const res = await fetch(
      `${getBackendUrl()}/monitors/${encodeURIComponent(name)}/alerts/acknowledge`, {
        method: "POST",
        headers: { "Content-Type": "application/json",
          ...(token ? { "Authorization": token } : {}) },
        body: JSON.stringify(body),
      });
    const text = await res.text();
    let data: unknown;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      return NextResponse.json(data ?? { detail: `Error ${res.status}` }, { status: res.status });
    }
    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Request failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
