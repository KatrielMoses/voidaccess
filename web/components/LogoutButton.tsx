"use client"
import { useState } from "react"
import { logout } from "@/lib/auth"
export function LogoutButton() {
  const [error, setError] = useState("")
  return <span><button onClick={() => logout().catch(() => setError("Logout failed; please retry"))}>Log out</button>{error && <span role="alert">{error}</span>}</span>
}
