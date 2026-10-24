import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request) {
  const token = await getSessionAuthorization();
  try {
    const res = await fetch(`${getBackendUrl()}/settings/api-keys`, {
      headers: { ...(token ? { Authorization: token } : {}) },
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "Request failed" }, { status: 502 });
  }
}

export async function POST(request: Request) {
  const token = await getSessionAuthorization();
  const body = await request.json();
  try {
    const res = await fetch(`${getBackendUrl()}/settings/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: token } : {}) },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "Request failed" }, { status: 502 });
  }
}
