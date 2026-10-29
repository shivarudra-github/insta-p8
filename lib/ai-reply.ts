import { validateAiBaseUrl } from "@/lib/ai-validation"

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
const OPENAI_URL = "https://api.openai.com/v1/chat/completions"

interface ResolvedEndpoint {
  endpoint: string
  apiKey: string
  model: string
}

/**
 * Resolves the AI endpoint with strict security safeguards:
 * 1. Validates user-supplied base URL against the approved HTTPS hostname allowlist.
 * 2. If user URL is unapproved, falls back to default provider only if a safe fallback key is configured.
 * 3. If no approved endpoint or API key exists, fails closed (returns null) to prevent credential exfiltration.
 */
function resolveSafeEndpoint(
  userBaseUrl?: string | null,
  userApiKey?: string | null,
  userModel?: string | null
): ResolvedEndpoint | null {
  // 1. If custom user URL is provided, strictly validate against allowlist
  if (userBaseUrl && typeof userBaseUrl === "string" && userBaseUrl.trim().length > 0) {
    const validation = validateAiBaseUrl(userBaseUrl)
    if (validation.valid && validation.normalized) {
      const base = validation.normalized
      const endpoint = base.endsWith("/chat/completions") ? base : `${base}/chat/completions`
      const apiKey = userApiKey || process.env.GROQ_API_KEY || process.env.OPENAI_API_KEY

      if (!apiKey) {
        console.warn("[ai-reply] Safe abort: Approved custom endpoint specified but no API key configured.")
        return null
      }

      const model = userModel || process.env.AI_MODEL || (process.env.GROQ_API_KEY ? "llama-3.1-8b-instant" : "gpt-4o-mini")
      return { endpoint, apiKey, model }
    }

    console.warn(`[ai-reply] SECURITY ALERT: Blocked unapproved AI base URL '${userBaseUrl}'. Attempting safe fallback.`)
  }

  // 2. Safe Fallback Provider: Verify fallback key and URL before dispatching
  if (process.env.GROQ_API_KEY) {
    return {
      endpoint: GROQ_URL,
      apiKey: process.env.GROQ_API_KEY,
      model: userModel || process.env.AI_MODEL || "llama-3.1-8b-instant",
    }
  }

  if (process.env.OPENAI_API_KEY) {
    return {
      endpoint: OPENAI_URL,
      apiKey: process.env.OPENAI_API_KEY,
      model: userModel || process.env.AI_MODEL || "gpt-4o-mini",
    }
  }

  console.warn("[ai-reply] Safe abort: No approved AI endpoint with valid API key configured. Refusing to dispatch request.")
  return null
}

export async function generateAIReply(
  userMessage: string,
  aiContext: string,
  conversationHistory: Array<{ role: "user" | "assistant"; content: string }> = [],
  userApiKey?: string | null,
  userBaseUrl?: string | null,
  userModel?: string | null,
): Promise<string | null> {
  const resolved = resolveSafeEndpoint(userBaseUrl, userApiKey, userModel)
  if (!resolved) {
    return null
  }

  const { endpoint, apiKey, model } = resolved

  const systemPrompt = aiContext?.trim()
    ? `You are replying to Instagram DMs on behalf of this account: ${aiContext.trim()}\n\nRules: max 1 sentence, casual Instagram tone, no hashtags, no emojis unless natural, never reveal you are AI. If you don't know something specific, say you'll get back to them.`
    : "You are replying to Instagram DMs. Keep replies to 1 short sentence. Casual tone. No hashtags. Never reveal you are AI."

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      signal: AbortSignal.timeout(15000),
      // redirect: "error" blocks redirect-based SSRF into internal networks or cloud metadata (169.254.169.254)
      redirect: "error",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          ...conversationHistory.slice(-10),
          { role: "user", content: userMessage },
        ],
        max_tokens: 150,
        temperature: 0.7,
      }),
    })

    if (!res.ok) {
      const errText = await res.text()
      console.error("[ai-reply] API error", res.status, errText.slice(0, 200))
      return null
    }

    const data = await res.json()
    return data.choices?.[0]?.message?.content?.trim() || null
  } catch (e) {
    console.error("[ai-reply] fetch error", e)
    return null
  }
}
