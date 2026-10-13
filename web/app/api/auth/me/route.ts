import { getSessionAuthorization } from "@/lib/session"
import { NextResponse } from "next/server"
import { getBackendUrl } from "@/lib/backend"

export async function GET(request: Request) {
  const token = getSessionAuthorization();
      const BACKEND_URL = getBackendUrl()

  try {
    const res = await fetch(`${BACKEND_URL}/auth/me`, {
      method: "GET",
      headers: {
        ...(token ? { "Authorization": token.startsWith("Bearer ") ? token : `Bearer ${token}` } : {})
      },
    })

    const data = await res.json()

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
