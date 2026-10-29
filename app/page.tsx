"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { LandingPage } from "@/components/layout/landing-page"

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    // Check if we have a non-authoritative display session to optimistically redirect
    const savedId = localStorage.getItem("ig_user_id")
    if (savedId) {
      router.replace("/dashboard")
    }
  }, [router])

  return <LandingPage />
}
