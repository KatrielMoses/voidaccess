import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

/** Proxy GET /api/monitors/{name}/alerts → backend GET /monitors/{name}/alerts */
export async function GET(request: Request, { params }: { params: { name: string } }) {
  const token = getSessionAuthorization();
    const { name } = params;
  const url = new URL(request.url);
  const qs = url.searchParams.toString();
  const suffix = qs ? `?${qs}` : "";
  try {
    const res = await fetch(
      `${getBackendUrl()}/monitors/${encodeURIComponent(name)}/alerts${suffix}`, {cache: "no-store",
      headers: {
        ...(token ? { "Authorization": token } : {})
      }});
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
