import { POST as login } from "@/app/api/auth/login/route"
import { POST as logout } from "@/app/api/auth/logout/route"
import { getSessionAuthorization } from "@/lib/session"
import { cookies } from "next/headers"
import fs from "fs"
import path from "path"

jest.mock("next/headers", () => ({ cookies: jest.fn() }))
const mockedCookies = cookies as jest.Mock

beforeEach(() => {
  mockedCookies.mockReturnValue({ get: () => ({ value: "private-token" }) })
  global.fetch = jest.fn()
})

test("login returns only reset status and sets httpOnly SameSite session cookie", async () => {
  ;(fetch as jest.Mock).mockResolvedValue(new Response(JSON.stringify({ access_token: "private-token", must_reset_password: false })))
  const response = await login(new Request("http://localhost/api/auth/login", { method: "POST", body: JSON.stringify({ email: "a@test", password: "test" }) }))
  expect(await response.json()).toEqual({ must_reset_password: false })
  expect(response.headers.get("set-cookie")).toMatch(/HttpOnly/i)
  expect(response.headers.get("set-cookie")).toMatch(/SameSite=lax/i)
})

test("server reads authentication from the cookie", () => {
  expect(getSessionAuthorization()).toBe("Bearer private-token")
})

test("logout revokes the backend token before clearing the session", async () => {
  ;(fetch as jest.Mock).mockResolvedValue(new Response('{}'))
  const response = await logout()
  expect(fetch).toHaveBeenCalledWith(expect.stringMatching(/\/auth\/logout$/), expect.objectContaining({ method: "POST", headers: { Authorization: "Bearer private-token" } }))
  expect(response.headers.get("set-cookie")).toMatch(/Max-Age=0/i)
})

test("failed revocation keeps the cookie so logout can be retried", async () => {
  ;(fetch as jest.Mock).mockResolvedValue(new Response('{}', { status: 503 }))
  const response = await logout()
  expect(response.status).toBe(503)
  expect(response.headers.get("set-cookie")).toBeNull()
})

test("client source never reads or stores the token", () => {
  const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : /\.(ts|tsx)$/.test(e.name) ? [path.join(dir, e.name)] : [])
  for (const file of [...walk('app'), ...walk('components'), ...walk('hooks'), ...walk('lib')]) {
    if (file.startsWith('app/api') || file === 'lib/session.ts') continue
    const source = fs.readFileSync(file, 'utf8')
    expect(source).not.toMatch(/sessionStorage|document\.cookie|getToken|setToken/)
  }
  expect(fs.readFileSync('lib/session.ts', 'utf8')).toContain('secure: process.env.NODE_ENV === "production"')
})
