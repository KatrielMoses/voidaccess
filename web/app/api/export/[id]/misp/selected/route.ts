import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = await getSessionAuthorization();
    const { id } = await params;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const entity_ids =
    body &&
    typeof body === "object" &&
    "entity_ids" in body &&
    Array.isArray((body as { entity_ids: unknown }).entity_ids)
      ? (body as { entity_ids: string[] }).entity_ids
      : [];

  try {
    const res = await fetch(`${getBackendUrl()}/export/${encodeURIComponent(id)}/misp/selected`, {
      method: "POST",
      headers: { "Content-Type": "application/json",
          ...(token ? { "Authorization": token } : {}) },
      body: JSON.stringify({ entity_ids }),
      cache: "no-store",
    });
    if (!res.ok) {
      const detail = await res.text();
      return NextResponse.json({ error: "Export failed", detail }, { status: res.status });
    }
    const buf = await res.arrayBuffer();
    const cd =
      res.headers.get("content-disposition") ?? `attachment; filename="voidaccess_${id}_misp.json"`;
    return new NextResponse(buf, {
      status: 200,
      headers: {
        "Content-Type": res.headers.get("content-type") ?? "application/json",
        "Content-Disposition": cd,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Request failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
