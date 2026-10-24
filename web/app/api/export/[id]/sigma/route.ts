import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = await getSessionAuthorization();
    const { id } = await params;
  try {
    const res = await fetch(`${getBackendUrl()}/export/${encodeURIComponent(id)}/sigma`, {cache: "no-store",
      headers: {
        ...(token ? { "Authorization": token } : {})
      }});
    if (!res.ok) {
      const detail = await res.text();
      return NextResponse.json({ error: "Export failed", detail }, { status: res.status });
    }
    const body = await res.arrayBuffer();
    const cd = res.headers.get("content-disposition") ?? `attachment; filename="voidaccess_${id}_sigma.zip"`;
    return new NextResponse(body, {
      status: 200,
      headers: {
        "Content-Type": res.headers.get("content-type") ?? "application/zip",
        "Content-Disposition": cd,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Request failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
