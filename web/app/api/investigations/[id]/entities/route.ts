import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const token = getSessionAuthorization();
    const { id } = params;
  const { searchParams } = new URL(request.url);
  const q = new URLSearchParams();
  const limit = searchParams.get("limit");
  const offset = searchParams.get("offset");
  const entityType = searchParams.get("entity_type");
  const minConfidence = searchParams.get("min_confidence");
  if (limit) q.set("limit", limit);
  if (offset) q.set("offset", offset);
  if (entityType) q.set("entity_type", entityType);
  if (minConfidence) q.set("min_confidence", minConfidence);
  const qs = q.toString();
  const url = `${getBackendUrl()}/investigations/${encodeURIComponent(id)}/entities${qs ? `?${qs}` : ""}`;

  try {
    const res = await fetch(url, {cache: "no-store",
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
