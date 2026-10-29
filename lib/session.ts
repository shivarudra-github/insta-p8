import crypto from "crypto"

export const SESSION_COOKIE_NAME = "insta_session"
export const DEFAULT_SESSION_DURATION_MS = 60 * 24 * 60 * 60 * 1000 // 60 days
const MAX_CLOCK_SKEW_MS = 60 * 1000 // 60 seconds tolerance

export interface SessionPayload {
  userId: string
  username: string
  issuedAt: number
  expiresAt: number
}

/**
 * Non-disclosing check of SESSION_SECRET presence and minimum length.
 * Does not expose or log the secret value.
 */
export function verifySessionSecretConfigured(): { configured: boolean; adequateLength: boolean } {
  const secret = process.env.SESSION_SECRET
  const len = secret ? secret.trim().length : 0
  return {
    configured: Boolean(secret),
    adequateLength: len >= 32, // Minimum 256 bits of entropy
  }
}

/**
 * Returns the dedicated server-side SESSION_SECRET.
 * Fails closed if missing or insufficiently random (< 32 characters).
 * Strictly zero fallback to any other environment variable or default.
 */
export function getSessionSecret(): string {
  const { configured, adequateLength } = verifySessionSecretConfigured()
  if (!configured || !adequateLength) {
    console.error("[auth] FATAL: SESSION_SECRET is missing or under 32 characters. Failing closed.")
    throw new Error("Authentication configuration error: SESSION_SECRET missing or invalid")
  }
  return process.env.SESSION_SECRET!.trim()
}

/**
 * Defensive parsing and strict validation of session payload.
 * Rejects non-string types, empty fields, malformed JSON, and temporal violations.
 */
export function parseAndValidatePayload(jsonStr: string): SessionPayload | null {
  try {
    const data = JSON.parse(jsonStr)
    if (!data || typeof data !== "object") return null

    // 1. Strict Type Validation
    if (typeof data.userId !== "string" || data.userId.trim().length === 0) return null
    if (typeof data.username !== "string" || data.username.trim().length === 0) return null
    if (typeof data.issuedAt !== "number" || !Number.isFinite(data.issuedAt)) return null
    if (typeof data.expiresAt !== "number" || !Number.isFinite(data.expiresAt)) return null

    // 2. Temporal & Clock-Skew Invariants
    const now = Date.now()

    // Reject tokens claiming to be issued in the future (beyond clock skew)
    if (data.issuedAt > now + MAX_CLOCK_SKEW_MS) return null

    // Reject expired tokens
    if (now > data.expiresAt) return null

    // Reject artificially extended expiration windows
    if (data.expiresAt > data.issuedAt + DEFAULT_SESSION_DURATION_MS + MAX_CLOCK_SKEW_MS) return null

    return {
      userId: data.userId.trim(),
      username: data.username.trim(),
      issuedAt: data.issuedAt,
      expiresAt: data.expiresAt,
    }
  } catch {
    return null
  }
}

/**
 * Signs and packages a session into format: [base64url(payload)].[base64url(hmac)]
 */
export function createSessionToken(
  user: { userId: string; username: string },
  durationMs = DEFAULT_SESSION_DURATION_MS,
  secretOverride?: string
): string {
  const secret = secretOverride || getSessionSecret()
  const now = Date.now()
  const payload: SessionPayload = {
    userId: user.userId.trim(),
    username: user.username.trim(),
    issuedAt: now,
    expiresAt: now + durationMs,
  }

  const payloadBase64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")
  const signature = crypto.createHmac("sha256", secret).update(payloadBase64).digest("base64url")

  return `${payloadBase64}.${signature}`
}

/**
 * Verifies an HMAC-signed session token.
 * Performs constant-time comparison to guard against timing attacks.
 * Returns verified SessionPayload or null if invalid, tampered, or expired.
 */
export function verifySessionToken(
  token: string | null | undefined,
  secretOverride?: string
): SessionPayload | null {
  if (!token || typeof token !== "string") return null

  const parts = token.split(".")
  if (parts.length !== 2) return null

  const [payloadBase64, receivedSig] = parts
  if (!payloadBase64 || !receivedSig) return null

  let secret: string
  try {
    secret = secretOverride || getSessionSecret()
  } catch {
    return null
  }

  const expectedSig = crypto.createHmac("sha256", secret).update(payloadBase64).digest("base64url")

  const receivedBuf = Buffer.from(receivedSig, "utf8")
  const expectedBuf = Buffer.from(expectedSig, "utf8")

  // Length check prevents RangeError in timingSafeEqual and blocks unequal signatures
  if (receivedBuf.length === 0 || receivedBuf.length !== expectedBuf.length) {
    return null
  }

  if (!crypto.timingSafeEqual(receivedBuf, expectedBuf)) {
    return null
  }

  try {
    const jsonStr = Buffer.from(payloadBase64, "base64url").toString("utf8")
    return parseAndValidatePayload(jsonStr)
  } catch {
    return null
  }
}

/**
 * Cookie configuration options ensuring symmetric issuance and deletion across environments.
 */
export function getSessionCookieOptions() {
  const isProd = process.env.NODE_ENV === "production"
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax" as const,
    path: "/",
  }
}

