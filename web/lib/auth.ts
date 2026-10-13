export interface AuthUser {
  email: string
  mustResetPassword: boolean
}

export async function login(
  email: string,
  password: string
): Promise<{ must_reset_password: boolean }> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Login failed")
  }
  return res.json()
}

export async function resetPassword(
  currentPassword: string,
  newPassword: string,
  confirmPassword: string
): Promise<void> {
  const res = await fetch("/api/auth/reset-password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      confirm_password: confirmPassword,
    }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Password reset failed")
  }
}

// Authentication travels in the server-set httpOnly cookie.
export async function logout(): Promise<void> {
  const res = await fetch("/api/auth/logout", { method: "POST" })
  if (!res.ok) throw new Error("Logout failed; please retry")
  window.location.assign("/login")
}
