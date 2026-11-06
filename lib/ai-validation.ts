export const ALLOWED_AI_HOSTNAMES = new Set([
  "api.groq.com",
  "api.openai.com",
  "openrouter.ai",
])

export interface AiUrlValidationResult {
  valid: boolean
  normalized?: string
  error?: string
}

/**
 * Validates an AI provider base URL against strict security criteria:
 * 1. Must parse as a valid URL.
 * 2. Protocol must be strictly HTTPS.
 * 3. Hostname must be in the approved allowlist (api.groq.com, api.openai.com, openrouter.ai).
 * 4. Embedded credentials (user:pass) are forbidden.
 * 5. Non-standard ports are forbidden.
 */
export function validateAiBaseUrl(urlStr: unknown): AiUrlValidationResult {
  if (!urlStr || typeof urlStr !== "string") {
    return { valid: false, error: "AI base URL must be a non-empty string" }
  }

  const trimmed = urlStr.trim()
  if (trimmed.length === 0) {
    return { valid: false, error: "AI base URL cannot be blank" }
  }

  try {
    const parsed = new URL(trimmed)

    if (parsed.protocol !== "https:") {
      return { valid: false, error: "AI base URL must use HTTPS" }
    }

    if (parsed.username || parsed.password) {
      return { valid: false, error: "AI base URL must not contain embedded user credentials" }
    }

    if (parsed.port && parsed.port !== "443") {
      return { valid: false, error: "AI base URL must not use non-standard ports" }
    }

    const hostname = parsed.hostname.toLowerCase()
    if (!ALLOWED_AI_HOSTNAMES.has(hostname)) {
      return {
        valid: false,
        error: `Hostname '${hostname}' is not approved. Allowed providers: ${Array.from(ALLOWED_AI_HOSTNAMES).join(", ")}`,
      }
    }

    // Strip trailing slashes for clean normalization
    const cleanPath = parsed.pathname.replace(/\/+$/, "")
    const normalized = `${parsed.origin}${cleanPath}`

    return { valid: true, normalized }
  } catch {
    return { valid: false, error: "Malformed URL" }
  }
}

