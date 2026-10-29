import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

type Knowledge = Record<string, string>

export async function GET(request: NextRequest) {
  const auth = await authenticateRequest(request)
  if (auth.errorResponse) return auth.errorResponse

  const requestedUserId = request.nextUrl.searchParams.get("userId")
  if (requestedUserId && requestedUserId !== auth.session.userId) {
    return NextResponse.json({ error: "Forbidden: Cannot access another user's profile" }, { status: 403 })
  }

  const supabase = await getSupabaseServerClient()
  const { data, error } = await supabase
    .from("users")
    .select("ai_context")
    .eq("id", auth.session.userId)
    .single()

  if (error) {
    return NextResponse.json({ error: "Failed to load business profile" }, { status: 500 })
  }

  let knowledge: Knowledge = {}
  try {
    knowledge = data?.ai_context ? JSON.parse(data.ai_context) : {}
  } catch {
    knowledge = { business_description: data?.ai_context ?? "" }
  }

  return NextResponse.json({ knowledge })
}

export async function PUT(request: NextRequest) {
  const auth = await authenticateRequest(request)
  if (auth.errorResponse) return auth.errorResponse

  const body = await request.json()
  const { userId, knowledge } = body as { userId?: string; knowledge?: Knowledge }

  if (userId && userId !== auth.session.userId) {
    return NextResponse.json({ error: "Forbidden: Cannot update another user's profile" }, { status: 403 })
  }

  if (!knowledge || typeof knowledge !== "object" || Array.isArray(knowledge)) {
    return NextResponse.json({ error: "Invalid payload: knowledge must be an object" }, { status: 400 })
  }

  const sanitizedKnowledge = Object.fromEntries(
    Object.entries(knowledge)
      .filter(([key, value]) => typeof key === "string" && typeof value === "string")
      .map(([key, value]) => [key, value.trim().slice(0, 5000)])
  )

  const supabase = await getSupabaseServerClient()
  const { error } = await supabase
    .from("users")
    .update({ ai_context: JSON.stringify(sanitizedKnowledge) })
    .eq("id", auth.session.userId)

  if (error) {
    return NextResponse.json({ error: "Failed to save business profile" }, { status: 500 })
  }

  return NextResponse.json({ ok: true })
}
