import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = await getSessionAuthorization();
    const { id } = await params;
  const { searchParams } = new URL(request.url);
  const format = searchParams.get("format") ?? "json";
  const backendPath =
    format === "stix"
      ? `/entities/${encodeURIComponent(id)}/export/stix`
      : `/entities/${encodeURIComponent(id)}/export/json`;

  try {
    const res = await fetch(`${getBackendUrl()}${backendPath}`, {cache: "no-store",
      headers: {
        ...(token ? { "Authorization": token } : {})
      }});
    if (!res.ok) {
      const text = await res.text();
      return NextResponse.json(
        { error: "Backend error", detail: text },
        { status: res.status }
      );
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") ?? "";
    return new NextResponse(blob, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": disposition || `attachment; filename="entity_${id}.json"`,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Request failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
