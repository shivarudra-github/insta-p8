import crypto from "crypto"
import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { SESSION_COOKIE_NAME, createSessionToken, getSessionCookieOptions } from "@/lib/session"

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const code = searchParams.get("code")
  const state = searchParams.get("state")
  const error = searchParams.get("error")
  const errorDescription = searchParams.get("error_description")

  const isProd = process.env.NODE_ENV === "production"

  // 1. Derive the public application origin from NEXT_PUBLIC_INSTAGRAM_REDIRECT_URI.
  // This ensures all redirects go to the public host (e.g. Cloudflare tunnel) rather than
  // resolving to an internal localhost socket/port.
  const configuredRedirectUri = process.env.NEXT_PUBLIC_INSTAGRAM_REDIRECT_URI
  let appOrigin: string
  try {
    appOrigin = configuredRedirectUri ? new URL(configuredRedirectUri).origin : new URL(request.url).origin
  } catch {
    appOrigin = new URL(request.url).origin
  }

  // Helper to clear oauth_state cookie on error redirects
  const clearStateCookie = (res: NextResponse) => {
    res.cookies.set("oauth_state", "", {
      path: "/",
      maxAge: 0,
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
    })
  }

  // 1. Handle Meta OAuth Error Responses
  if (error) {
    console.warn("[oauth/callback] Meta returned error:", error, errorDescription)
    const redirectUrl = new URL("/", appOrigin)
    redirectUrl.searchParams.set("error", errorDescription || error)
    const res = NextResponse.redirect(redirectUrl, {
      status: 302,
      headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
    })
    clearStateCookie(res)
    return res
  }

  // 2. Validate OAuth CSRF State Nonce Defensively
  const storedState = request.cookies.get("oauth_state")?.value
  const incomingBuf = Buffer.from(state || "", "utf8")
  const storedBuf = Buffer.from(storedState || "", "utf8")

  const isStateValid =
    incomingBuf.length > 0 &&
    incomingBuf.length === storedBuf.length &&
    crypto.timingSafeEqual(incomingBuf, storedBuf)

  if (!isStateValid) {
    console.warn("[oauth/callback] Potential CSRF or expired state nonce. Verification failed.")
    const redirectUrl = new URL("/", appOrigin)
    redirectUrl.searchParams.set("error", "invalid_oauth_state")
    const res = NextResponse.redirect(redirectUrl, {
      status: 302,
      headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
    })
    clearStateCookie(res)
    return res
  }

  // 3. Ensure Authorization Code is Present
  if (!code) {
    console.warn("[oauth/callback] Missing authorization code")
    const redirectUrl = new URL("/", appOrigin)
    redirectUrl.searchParams.set("error", "missing_code")
    const res = NextResponse.redirect(redirectUrl, {
      status: 302,
      headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
    })
    clearStateCookie(res)
    return res
  }

  try {
    // 4. Validate Server Environment Configuration
    const clientId = process.env.INSTAGRAM_APP_ID || process.env.NEXT_PUBLIC_INSTAGRAM_APP_ID
    const clientSecret = process.env.INSTAGRAM_APP_SECRET
    const redirectUri = process.env.NEXT_PUBLIC_INSTAGRAM_REDIRECT_URI

    if (!clientId || !clientSecret || !redirectUri) {
      throw new Error("Missing required OAuth environment variables")
    }

    // 5. Exchange Authorization Code for Short-Lived Access Token
    const tokenParams = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
      code,
    })

    const tokenRes = await fetch("https://api.instagram.com/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenParams.toString(),
    })

    // Safe response parsing: read as text, parse JSON safely
    const rawTokenBody = await tokenRes.text()
    let tokenData: any = null
    try {
      tokenData = JSON.parse(rawTokenBody)
    } catch {
      const sanitizedBodyPreview = rawTokenBody
        .replace(/[\r\n\t]+/g, " ")
        .replace(/[^a-zA-Z0-9\s.,:;_\-/<>=]/g, "")
        .trim()
        .slice(0, 150)
      console.error(
        `[oauth/callback] Token exchange returned non-JSON response. HTTP status: ${tokenRes.status}. Body preview: ${sanitizedBodyPreview}`
      )
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    if (!tokenRes.ok) {
      const sanitizedError =
        typeof tokenData?.error_message === "string"
          ? tokenData.error_message.slice(0, 200)
          : typeof tokenData?.error?.message === "string"
          ? tokenData.error.message.slice(0, 200)
          : "token_exchange_failed"
      console.error(
        `[oauth/callback] Token exchange failed. HTTP status: ${tokenRes.status}: ${sanitizedError}`
      )
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    if (!tokenData?.access_token || !tokenData?.user_id) {
      console.error(
        `[oauth/callback] Token exchange response missing required tokens. HTTP status: ${tokenRes.status}`
      )
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    const shortToken = tokenData.access_token
    const loginUserId = tokenData.user_id.toString()

    // 6. Exchange for Long-Lived Token (60 Days)
    const longLivedUrl = `https://graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret=${clientSecret}&access_token=${shortToken}`
    const longRes = await fetch(longLivedUrl)
    let longData: any = {}
    try {
      longData = await longRes.json()
    } catch {
      console.warn("[oauth/callback] Long-lived token response was not JSON, falling back to short-lived token")
    }
    const accessToken = longData.access_token || shortToken
    const expiresIn = longData.expires_in || 5184000

    // 7. Retrieve Username & IG Professional Account ID
    let username = `user_${loginUserId}`
    let businessAccountId = loginUserId

    try {
      const meRes = await fetch(
        `https://graph.instagram.com/v24.0/me?fields=user_id,username,profile_picture_url&access_token=${accessToken}`
      )
      const meData = await meRes.json()
      if (meData.username) username = meData.username
      if (meData.user_id) businessAccountId = meData.user_id.toString()
    } catch (e) {
      console.error("[oauth/callback] /me profile fetch error:", e)
    }

    // 8. Upsert User in Supabase
    const supabase = await getSupabaseServerClient()
    const updates = {
      username,
      access_token: accessToken,
      token_expires_at: new Date(Date.now() + expiresIn * 1000).toISOString(),
      updated_at: new Date().toISOString(),
      business_account_id: businessAccountId,
      page_id: businessAccountId,
    }

    const { error: upsertError } = await supabase
      .from("users")
      .upsert({ id: loginUserId, ...updates }, { onConflict: "id" })

    if (upsertError) {
      console.error("[oauth/callback] User persistence error:", upsertError)
      throw upsertError
    }

    // 9. Issue Cryptographically Signed Session Token
    const sessionToken = createSessionToken({ userId: loginUserId, username }, expiresIn * 1000)

    // 10. Redirect directly to clean /dashboard URL with defensive headers
    const dashboardUrl = new URL("/dashboard", appOrigin)
    const response = NextResponse.redirect(dashboardUrl, {
      status: 302,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        Pragma: "no-cache",
        Expires: "0",
        "Referrer-Policy": "no-referrer",
      },
    })

    // Set signed, HttpOnly session cookie
    response.cookies.set(SESSION_COOKIE_NAME, sessionToken, {
      ...getSessionCookieOptions(),
      maxAge: expiresIn,
    })

    // Clear single-use oauth_state cookie on success
    clearStateCookie(response)

    return response
  } catch (err: any) {
    console.error("[oauth/callback] Critical OAuth error:", err?.message || err)
    const redirectUrl = new URL("/", appOrigin)
    redirectUrl.searchParams.set("error", "authentication_failed")
    const res = NextResponse.redirect(redirectUrl, {
      status: 302,
      headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
    })
    clearStateCookie(res)
    return res
  }
}

/**
 * Direct POST code exchange is disabled.
 * All token exchange and session issuance occur strictly within the verified GET callback flow.
 */
export async function POST(_request: NextRequest) {
  return NextResponse.json(
    { error: "Method not allowed. OAuth token exchange must occur via the secure GET callback flow." },
    {
      status: 405,
      headers: {
        Allow: "GET",
        "Cache-Control": "no-store",
      },
    }
  )
}
