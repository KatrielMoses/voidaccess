import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server"
import { getBackendUrl } from "@/lib/backend"

export async function POST(request: Request) {
  const token = await getSessionAuthorization();
    const body = await request.json()
    const BACKEND_URL = getBackendUrl()

  try {
    const res = await fetch(`${BACKEND_URL}/auth/reset-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "Authorization": token } : {})
      },
      body: JSON.stringify(body),
    })

    const text = await res.text()
    let data: any
    try {
      data = text ? JSON.parse(text) : {}
    } catch {
      data = { detail: text || "Backend returned invalid response" }
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    return NextResponse.json(data)
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Backend unavailable" },
      { status: 502 }
    )
  }
}
