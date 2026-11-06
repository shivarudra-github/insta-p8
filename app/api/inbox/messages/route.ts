import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const conversationId = request.nextUrl.searchParams.get("conversationId")
    if (!conversationId) {
      return NextResponse.json({ error: "Missing conversationId" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    // 1. Verify conversation ownership before returning messages
    const { data: conv, error: convError } = await supabase
      .from("conversations")
      .select("id")
      .eq("id", conversationId)
      .eq("user_id", auth.session.userId)
      .single()

    if (convError || !conv) {
      return NextResponse.json(
        { error: "Conversation not found or not owned by user" },
        { status: 404 }
      )
    }

    // 2. Fetch messages strictly scoped to conversation and authenticated user
    const { data: messages, error } = await supabase
      .from("messages")
      .select("*")
      .eq("conversation_id", conversationId)
      .eq("user_id", auth.session.userId)
      .order("created_at", { ascending: true })

    if (error) throw error

    return NextResponse.json(messages || [])
  } catch (error) {
    console.error("[Inbox] Messages GET error:", error)
    return NextResponse.json({ error: "Failed to fetch messages" }, { status: 500 })
  }
}
