import { cookies } from "next/headers"

export function getSessionAuthorization(): string | null {
  const token = cookies().get("va_token")?.value
  return token ? `Bearer ${token}` : null
}

export const sessionCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: 8 * 60 * 60,
}
