import { type NextRequest, NextResponse } from "next/server"
import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@/lib/session"

export async function POST(_request: NextRequest) {
  const response = NextResponse.json({ success: true, message: "Logged out" })

  // Delete session cookie symmetrically across environments
  response.cookies.set(SESSION_COOKIE_NAME, "", {
    ...getSessionCookieOptions(),
    maxAge: 0,
  })

  // Clear any residual oauth_state cookie
  const isProd = process.env.NODE_ENV === "production"
  response.cookies.set("oauth_state", "", {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  })

  return response
}

