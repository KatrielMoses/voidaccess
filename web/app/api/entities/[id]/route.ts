import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const token = getSessionAuthorization();
    const { id } = params;
  try {
    const res = await fetch(
      `${getBackendUrl()}/entities/${encodeURIComponent(id)}`,
      {
        cache: "no-store",
        headers: {
          ...(token ? { "Authorization": token } : {})
        }
      }
    );

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
