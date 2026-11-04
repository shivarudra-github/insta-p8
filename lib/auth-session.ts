import { type NextRequest, NextResponse } from "next/server"
import {
  SESSION_COOKIE_NAME,
  verifySessionToken,
  type SessionPayload,
  verifySessionSecretConfigured,
  getSessionCookieOptions,
} from "@/lib/session"
import { getSupabaseServerClient } from "@/lib/supabase-server"

export interface AuthSuccess {
  session: SessionPayload
  errorResponse?: undefined
}

export interface AuthFailure {
  session?: undefined
  errorResponse: NextResponse
}

export type AuthResult = AuthSuccess | AuthFailure

/**
 * Central server-side authentication guard for Next.js API route handlers.
 * Extracts the signed session cookie, validates HMAC signature, expiration, and types,
 * and verifies that the referenced user account still exists in the database.
 *
 * Fails closed:
 * - 500: Server SESSION_SECRET is misconfigured.
 * - 401: Missing cookie, invalid/tampered HMAC, or user deleted/revoked (expires cookie).
 * - 503: Database error or network failure during user verification.
 */
export async function authenticateRequest(request: NextRequest): Promise<AuthResult> {
  const { configured, adequateLength } = verifySessionSecretConfigured()
  if (!configured || !adequateLength) {
    console.error("[auth] FATAL: Server SESSION_SECRET is missing or invalid. Failing closed.")
    return {
      errorResponse: NextResponse.json(
        { error: "Authentication system configuration error" },
        { status: 500 }
      ),
    }
  }

  const token = request.cookies.get(SESSION_COOKIE_NAME)?.value

  if (!token) {
    return {
      errorResponse: NextResponse.json(
        { error: "Unauthorized: Missing session cookie" },
        { status: 401 }
      ),
    }
  }

  const session = verifySessionToken(token)
  if (!session) {
    return {
      errorResponse: NextResponse.json(
        { error: "Unauthorized: Invalid, tampered, or expired session" },
        { status: 401 }
      ),
    }
  }

  // Session token signature and payload are cryptographically valid.
  // Query users table to verify the user account has not been deleted or revoked.
  let user: { id: string } | null = null
  let userError: any = null

  try {
    const supabase = await getSupabaseServerClient()
    const { data, error } = await supabase
      .from("users")
      .select("id")
      .eq("id", session.userId)
      .maybeSingle()

    user = data
    userError = error
  } catch (thrown: any) {
    console.error(
      "[auth] Database exception during user existence check:",
      thrown?.message ? "connection_error" : "unknown_error"
    )
    return {
      errorResponse: NextResponse.json(
        { error: "Service Unavailable: Authentication service temporarily unavailable" },
        { status: 503 }
      ),
    }
  }

  if (userError) {
    console.error("[auth] Database error during user existence check: code=" + (userError?.code || "unknown"))
    return {
      errorResponse: NextResponse.json(
        { error: "Service Unavailable: Authentication verification failed" },
        { status: 503 }
      ),
    }
  }

  if (!user) {
    console.warn("[auth] Session referenced nonexistent or deleted user. Expiring session cookie.")
    const errorResponse = NextResponse.json(
      { error: "Unauthorized: User session revoked or not found" },
      { status: 401 }
    )
    errorResponse.cookies.set(SESSION_COOKIE_NAME, "", {
      ...getSessionCookieOptions(),
      maxAge: 0,
    })
    return { errorResponse }
  }

  return { session }
}
