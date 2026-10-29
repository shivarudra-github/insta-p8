import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"
import { validateAiBaseUrl } from "@/lib/ai-validation"

export async function GET(request: NextRequest) {
  const auth = await authenticateRequest(request)
  if (auth.errorResponse) return auth.errorResponse

  const requestedUserId = request.nextUrl.searchParams.get("userId")
  if (requestedUserId && requestedUserId !== auth.session.userId) {
    return NextResponse.json({ error: "Forbidden: Cannot access another user's AI settings" }, { status: 403 })
  }

  const supabase = await getSupabaseServerClient()
  const { data, error } = await supabase
    .from("users")
    .select("groq_auto_reply_enabled, ai_context, groq_api_key, ai_base_url, ai_model")
    .eq("id", auth.session.userId)
    .single()

  if (error || !data) {
    return NextResponse.json({
      enabled: false,
      ai_context: "",
      has_api_key: false,
      ai_base_url: "",
      ai_model: "",
    })
  }

  return NextResponse.json({
    enabled: data.groq_auto_reply_enabled ?? false,
    ai_context: data.ai_context ?? "",
    has_api_key: Boolean(data.groq_api_key),
    ai_base_url: data.ai_base_url ?? "",
    ai_model: data.ai_model ?? "",
  })
}

export async function PUT(request: NextRequest) {
  const auth = await authenticateRequest(request)
  if (auth.errorResponse) return auth.errorResponse

  const body = await request.json()
  const { userId, enabled, ai_context, groq_api_key, ai_base_url, ai_model } = body

  if (userId && userId !== auth.session.userId) {
    return NextResponse.json({ error: "Forbidden: Cannot update another user's AI settings" }, { status: 403 })
  }

  const update: Record<string, unknown> = {}
  if (typeof enabled === "boolean") update.groq_auto_reply_enabled = enabled
  if (typeof ai_context === "string") update.ai_context = ai_context
  if (typeof groq_api_key === "string") update.groq_api_key = groq_api_key.trim() || null
  if (typeof ai_model === "string") update.ai_model = ai_model.trim() || null

  // Layer 1: Ingestion validation of custom AI base URL against strict HTTPS allowlist
  if (typeof ai_base_url === "string" && ai_base_url.trim().length > 0) {
    const validation = validateAiBaseUrl(ai_base_url)
    if (!validation.valid) {
      return NextResponse.json(
        { error: validation.error || "Invalid ai_base_url" },
        { status: 400 }
      )
    }
    update.ai_base_url = validation.normalized
  } else if (ai_base_url === "" || ai_base_url === null) {
    update.ai_base_url = null
  }

  const supabase = await getSupabaseServerClient()
  const { error } = await supabase
    .from("users")
    .update(update)
    .eq("id", auth.session.userId)

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 })
  }

  return NextResponse.json({ ok: true })
}
