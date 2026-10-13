import { NextResponse } from "next/server"
import { getBackendUrl } from "@/lib/backend"
import { getSessionAuthorization, sessionCookieOptions } from "@/lib/session"

export async function POST() {
  const authorization = getSessionAuthorization()
  if (authorization) {
    try {
      const res = await fetch(`${getBackendUrl()}/auth/logout`, {
        method: "POST", headers: { Authorization: authorization },
      })
      if (!res.ok && res.status !== 401) {
        return NextResponse.json({ detail: "Logout failed; please retry" }, { status: 503 })
      }
    } catch {
      return NextResponse.json({ detail: "Logout failed; please retry" }, { status: 503 })
    }
  }
  const response = NextResponse.json({ message: "Logged out" })
  response.cookies.set("va_token", "", { ...sessionCookieOptions, maxAge: 0 })
  return response
}
