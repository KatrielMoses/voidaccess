import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ key_name: string }> }
) {
  const token = await getSessionAuthorization();
  const { key_name } = await params;
  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/settings/api-keys/${key_name}`,
      {
        method: "DELETE",
        headers: { ...(token ? { Authorization: token } : {}) },
      }
    );
    return new NextResponse(null, { status: res.status });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "Request failed" }, { status: 502 });
  }
}
