import { sessionCookieOptions } from "@/lib/session"
import { NextResponse } from "next/server"
import { getBackendUrl } from "@/lib/backend"

export async function POST(request: Request) {
    const body = await request.json()
  const BACKEND_URL = getBackendUrl()

  try {
    const res = await fetch(`${BACKEND_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })

    let data
    const text = await res.text()
    try {
      data = text ? JSON.parse(text) : {}
    } catch {
      // If parsing fails, backend likely returned an HTML error page
      return NextResponse.json(
        { detail: `Backend error (${res.status}): ${text.slice(0, 100)}...` },
        { status: 502 }
      )
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    const response = NextResponse.json({ must_reset_password: data.must_reset_password })
    response.cookies.set("va_token", data.access_token, sessionCookieOptions)

    return response
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Backend unavailable" },
      { status: 502 }
    )
  }
}
