import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET(request: Request) {
  const token = await getSessionAuthorization();
  const backendUrl = getBackendUrl();

  try {
    const res = await fetch(`${backendUrl}/monitors`, {
      method: "GET",
      headers: {
        ...(token ? { "Authorization": token } : {})
      },
      cache: "no-store",
    });

    if (!res.ok) {
      const text = await res.text();
      return NextResponse.json({ detail: text }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Backend unavailable" },
      { status: 502 }
    );
  }
}

export async function POST(request: Request) {
  const token = await getSessionAuthorization();
  const backendUrl = getBackendUrl();
  const body = await request.json();

  try {
    const res = await fetch(`${backendUrl}/monitors`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "Authorization": token } : {})
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Backend unavailable" },
      { status: 502 }
    );
  }
}
