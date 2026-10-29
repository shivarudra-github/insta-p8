import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const requestedUserId = request.nextUrl.searchParams.get("userId")
    if (requestedUserId && requestedUserId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot access another user's conversations" }, { status: 403 })
    }

    const supabase = await getSupabaseServerClient()

    // Fetch conversations strictly scoped to authenticated user
    const { data: conversations, error } = await supabase
      .from("conversations")
      .select("*")
      .eq("user_id", auth.session.userId)
      .order("last_message_at", { ascending: false })

    if (error) throw error

    return NextResponse.json(conversations || [])
  } catch (error) {
    console.error("[Inbox] Conversations GET error:", error)
    return NextResponse.json({ error: "Failed to fetch conversations" }, { status: 500 })
  }
}
