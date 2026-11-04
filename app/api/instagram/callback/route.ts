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
      signal: AbortSignal.timeout(10000),
    })

    // Safe response parsing: read as text, parse JSON safely
    const rawTokenBody = await tokenRes.text()
    let tokenData: any = null
    try {
      tokenData = JSON.parse(rawTokenBody)
    } catch {
      console.error(
        `[oauth/callback] Token exchange returned non-JSON response. HTTP status: ${tokenRes.status}. category=PARSE_ERROR`
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
      console.error(
        `[oauth/callback] Token exchange failed. HTTP status: ${tokenRes.status}. category=HTTP_ERROR`
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
        `[oauth/callback] Token exchange response missing required tokens. HTTP status: ${tokenRes.status}. category=MISSING_TOKENS`
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

    // 6. Exchange for Long-Lived Token (Strictly Required, Up to 60 Days)
    const longLivedUrl = `https://graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret=${encodeURIComponent(clientSecret)}&access_token=${encodeURIComponent(shortToken)}`

    let longRes: Response
    try {
      longRes = await fetch(longLivedUrl, {
        signal: AbortSignal.timeout(10000),
      })
    } catch (fetchErr: any) {
      const isTimeout = fetchErr?.name === "AbortError" || fetchErr?.name === "TimeoutError"
      const category = isTimeout ? "TIMEOUT" : "FETCH_ERROR"
      console.error(`[oauth/callback] Long-lived token exchange request failed: category=${category}`)
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    if (!longRes.ok) {
      console.error(`[oauth/callback] Long-lived token exchange HTTP failure. Status: ${longRes.status}`)
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    let longData: any = null
    try {
      const rawLongBody = await longRes.text()
      longData = JSON.parse(rawLongBody)
    } catch {
      console.error("[oauth/callback] Long-lived token response was not valid JSON")
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    if (
      !longData ||
      typeof longData !== "object" ||
      Array.isArray(longData) ||
      typeof longData.access_token !== "string" ||
      longData.access_token.trim().length === 0
    ) {
      console.error("[oauth/callback] Long-lived token exchange missing or invalid access_token")
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    const MAX_EXPIRES_IN_SECONDS = 60 * 24 * 60 * 60 // 5,184,000 seconds (60 days)
    const rawExpiresIn = longData.expires_in
    if (
      typeof rawExpiresIn !== "number" ||
      !Number.isInteger(rawExpiresIn) ||
      rawExpiresIn <= 0 ||
      rawExpiresIn > MAX_EXPIRES_IN_SECONDS
    ) {
      console.error("[oauth/callback] Long-lived token exchange invalid expires_in:", typeof rawExpiresIn)
      const redirectUrl = new URL("/", appOrigin)
      redirectUrl.searchParams.set("error", "token_exchange_failed")
      const res = NextResponse.redirect(redirectUrl, {
        status: 302,
        headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
      })
      clearStateCookie(res)
      return res
    }

    const accessToken = longData.access_token.trim()
    const expiresIn = rawExpiresIn

    // 7. Retrieve Username & IG Professional Account ID
    let username = `user_${loginUserId}`
    let businessAccountId = loginUserId

    try {
      const meRes = await fetch(
        `https://graph.instagram.com/v24.0/me?fields=user_id,username,profile_picture_url&access_token=${encodeURIComponent(accessToken)}`,
        { signal: AbortSignal.timeout(10000) }
      )
      if (meRes.ok) {
        const meData = await meRes.json()
        if (typeof meData?.username === "string" && meData.username.trim()) {
          username = meData.username.trim()
        }
        if (typeof meData?.user_id === "string" || typeof meData?.user_id === "number") {
          businessAccountId = meData.user_id.toString()
        }
      }
    } catch (e: any) {
      const isTimeout = e?.name === "AbortError" || e?.name === "TimeoutError"
      const category = isTimeout ? "TIMEOUT" : "FETCH_ERROR"
      console.error(`[oauth/callback] Profile fetch failed: category=${category}`)
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
      console.error("[oauth/callback] User persistence error code:", (upsertError as any)?.code || "unknown")
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
    const isTimeout = err?.name === "AbortError" || err?.name === "TimeoutError"
    const category = isTimeout ? "TIMEOUT" : "UNHANDLED_EXCEPTION"
    console.error(`[oauth/callback] Critical OAuth error: category=${category}`)
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
