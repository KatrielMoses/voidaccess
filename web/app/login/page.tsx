"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { login } from "@/lib/auth"
import DarkWebSVG from "@/components/DarkWebSVG"
import { Eye, EyeOff, Shield } from "lucide-react"
import { motion } from "framer-motion"

export default function LoginPage() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [mounted, setMounted] = useState(false)
  const router = useRouter()

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true)
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    try {
      const { must_reset_password } = await login(email, password)

      if (must_reset_password) {
        router.push("/reset-password")
      } else {
        router.push("/")
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid credentials")
    } finally {
      setIsLoading(false)
    }
  }

  if (!mounted) return null;

  return (
    <div className="h-screen w-full flex bg-[#0c0c0e] overflow-hidden font-body">

      {/* LEFT SIDE - LOGIN FORM */}
      <div className="w-full lg:w-1/2 flex flex-col justify-center relative z-20 px-4 sm:px-16 md:px-24 xl:px-32">
        {/* Top-level branding */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="absolute top-8 left-8 sm:top-12 sm:left-12 flex items-center gap-3"
        >
          <div className="w-8 h-8 rounded-lg bg-[var(--accent)]/10 border border-[var(--accent)]/30 flex items-center justify-center">
            <Shield className="w-4 h-4 text-[var(--accent)]" />
          </div>
          <span className="text-xl font-bold tracking-tight text-[#e6edf3] font-heading">
            voidaccess
          </span>
        </motion.div>

        <div className="max-w-[420px] w-full mx-auto">
          {/* 3D Card Container matching HexaUI reference */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="w-full bg-[#18181b] rounded-[2rem] p-8 sm:p-10 shadow-2xl relative border border-white/5"
            style={{
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.05)"
            }}
          >
            <div className="flex flex-col items-center justify-center mb-10 space-y-4">
              <div className="w-12 h-12 rounded-full bg-white/5 border border-white/10 flex items-center justify-center shadow-inner">
                 <Shield className="w-6 h-6 text-[#8b949e]" />
              </div>
              <h1 className="text-2xl font-semibold tracking-tight text-white font-heading">
                Sign in to your account
              </h1>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-2 group">
                <div className="relative">
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                    className="w-full bg-[#27272a] border border-transparent rounded-xl px-4 py-3.5 text-[15px] text-white placeholder:text-[#a1a1aa] focus:outline-none focus:ring-1 focus:ring-[var(--accent)] transition-all font-body font-medium"
                    placeholder="your@email.com"
                    style={{
                       boxShadow: "inset 0 2px 4px rgba(0,0,0,0.2)"
                    }}
                  />
                </div>
              </div>

              <div className="space-y-2 group">
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                    className="w-full bg-[#27272a] border border-transparent rounded-xl pl-4 pr-12 py-3.5 text-[15px] text-white placeholder:text-[#a1a1aa] focus:outline-none focus:ring-1 focus:ring-[var(--accent)] transition-all font-body font-medium"
                    placeholder="Password"
                    style={{
                       boxShadow: "inset 0 2px 4px rgba(0,0,0,0.2)"
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 text-[#a1a1aa] hover:text-white transition-colors focus:outline-none rounded-md"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="text-[13px] text-red-400 bg-red-400/10 border border-red-400/20 rounded-lg p-3 flex items-start gap-2"
                >
                  <span className="shrink-0 mt-0.5">⚠</span>
                  <span>{error}</span>
                </motion.div>
              )}

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full relative group overflow-hidden bg-[#3f3f46] text-white font-semibold rounded-xl px-4 py-3.5 flex items-center justify-center gap-2 hover:bg-[#52525b] active:scale-[0.98] transition-all disabled:opacity-50 disabled:pointer-events-none shadow-sm"
                  style={{
                     boxShadow: "inset 0 1px 0 rgba(255,255,255,0.1), 0 1px 2px rgba(0,0,0,0.2)"
                  }}
                >
                  <span className="relative z-10 flex items-center gap-2">
                    {isLoading ? (
                      <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    ) : (
                      <>
                        Sign In
                      </>
                    )}
                  </span>
                </button>
              </div>


            </form>
          </motion.div>

          {/* Footer stats below the card like HexaUI reference */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1, delay: 0.8 }}
            className="mt-8 text-center px-4"
          >
             <p className="text-[#a1a1aa] text-[13px] font-medium font-body">
               Join <span className="text-white font-semibold">thousands</span> of authorized
               personnel on the intelligence network.
             </p>
          </motion.div>
        </div>
      </div>

      {/* RIGHT SIDE - DARK GRAY BG WITH SVG ANIMATION */}
      <div className="hidden lg:flex lg:w-1/2 relative bg-[#1c1c21] items-center justify-center border-l border-white/[0.02]">
        <DarkWebSVG />

        {/* Overlay quote or branding on the SVG */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 1, delay: 0.5 }}
          className="absolute bottom-16 right-16 z-20 max-w-[340px] text-right pointer-events-none"
        >
          <h3 className="text-2xl font-bold text-white mb-2 font-heading tracking-tight">
            Into the abyss.
          </h3>
          <p className="text-[#8b949e] text-sm leading-relaxed font-body">
            Advanced intelligence platform for monitoring, analyzing, and mitigating emerging threats on the dark web.
          </p>
        </motion.div>
      </div>

    </div>
  )
}
