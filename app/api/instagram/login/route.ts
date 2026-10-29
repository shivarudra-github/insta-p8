import crypto from "crypto"
import { type NextRequest, NextResponse } from "next/server"

export async function GET(_request: NextRequest) {
  const clientId = process.env.NEXT_PUBLIC_INSTAGRAM_APP_ID || process.env.INSTAGRAM_APP_ID
  const redirectUri = process.env.NEXT_PUBLIC_INSTAGRAM_REDIRECT_URI

  if (!clientId || !redirectUri) {
    console.error("[oauth/login] Missing INSTAGRAM_APP_ID or NEXT_PUBLIC_INSTAGRAM_REDIRECT_URI")
    return NextResponse.json(
      { error: "OAuth configuration error: missing client ID or redirect URI" },
      { status: 500 }
    )
  }

  // Generate 32-byte cryptographically secure random state nonce
  const state = crypto.randomBytes(32).toString("hex")

  // Construct Instagram OAuth authorization URL with state parameter
  const authUrl = new URL("https://www.instagram.com/oauth/authorize")
  authUrl.searchParams.set("enable_fb_login", "0")
  authUrl.searchParams.set("force_authentication", "1")
  authUrl.searchParams.set("client_id", clientId)
  authUrl.searchParams.set("redirect_uri", redirectUri)
  authUrl.searchParams.set("response_type", "code")
  authUrl.searchParams.set("scope", "instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments")
  authUrl.searchParams.set("state", state)

  const isProd = process.env.NODE_ENV === "production"
  const response = NextResponse.redirect(authUrl.toString(), {
    status: 302,
    headers: {
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      Pragma: "no-cache",
      Expires: "0",
      "Referrer-Policy": "no-referrer",
    },
  })

  // Store state nonce in an HttpOnly, SameSite=Lax cookie with 5-minute TTL
  response.cookies.set("oauth_state", state, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 300, // 5 minutes
  })

  return response
}

