import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request) {
  const token = getSessionAuthorization();
  const { searchParams } = new URL(request.url);
  const skip = searchParams.get("skip");
  const limit = searchParams.get("limit");

  const q = new URLSearchParams();
  if (skip) q.set("offset", skip);
  if (limit) q.set("limit", limit);
  const qs = q.toString();

  try {
    const res = await fetch(`${getBackendUrl()}/investigations${qs ? `?${qs}` : ""}`, {
      cache: "no-store",
      headers: {
        ...(token ? { "Authorization": token } : {})
      }
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
