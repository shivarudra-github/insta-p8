import { type NextRequest, NextResponse } from "next/server"
import { SESSION_COOKIE_NAME, verifySessionToken, type SessionPayload, verifySessionSecretConfigured } from "@/lib/session"

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
 * Extracts the signed session cookie, validates HMAC signature, expiration, and types.
 * Fails closed with 500 if SESSION_SECRET is misconfigured, or 401 if unauthenticated.
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

  return { session }
}

