"use client"

import { useState, useEffect, useCallback } from "react"
import { usePathname, useRouter } from "next/navigation"

export function useInstagramSession() {
  const [username, setUsername] = useState<string | null>(null)
  const [userId, setUserId] = useState<string | null>(null)
  const [profilePic, setProfilePic] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const router = useRouter()
  const pathname = usePathname()

  const syncSession = useCallback(async () => {
    try {
      // Authoritative server-side verification of HttpOnly session cookie
      const res = await fetch("/api/auth/me", {
        method: "GET",
        headers: { "Cache-Control": "no-cache" },
      })

      if (res.ok) {
        const data = await res.json()
        if (data.authenticated && data.user) {
          setUserId(data.user.userId)
          setUsername(data.user.username)
          // Maintain non-authoritative display cache
          localStorage.setItem("ig_username", data.user.username)
          localStorage.setItem("ig_user_id", data.user.userId)
          setIsLoading(false)
          return
        }
      }

      // If unauthenticated, clear local display cache
      setUserId(null)
      setUsername(null)
      setProfilePic(null)
      localStorage.removeItem("ig_user_id")
      localStorage.removeItem("ig_username")
      localStorage.removeItem("ig_profile_pic")

      // Redirect if attempting to access protected dashboard routes
      if (pathname && pathname.startsWith("/dashboard")) {
        router.replace("/")
      }
    } catch (err) {
      console.error("[useInstagramSession] Session verification error:", err)
      setUserId(null)
      setUsername(null)
    } finally {
      setIsLoading(false)
    }
  }, [pathname, router])

  useEffect(() => {
    syncSession()
  }, [syncSession])

  const logout = async () => {
    try {
      // Server-side cookie clearance
      await fetch("/api/auth/logout", { method: "POST" })
    } catch (err) {
      console.error("[useInstagramSession] Logout error:", err)
    } finally {
      localStorage.removeItem("ig_user_id")
      localStorage.removeItem("ig_username")
      localStorage.removeItem("ig_profile_pic")
      setUsername(null)
      setUserId(null)
      setProfilePic(null)
      router.push("/")
    }
  }

  return { userId, username, profilePic, isLoading, logout, refreshSession: syncSession }
}
