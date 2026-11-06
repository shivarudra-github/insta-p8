import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const requestedUserId = request.nextUrl.searchParams.get("userId")
    if (requestedUserId && requestedUserId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot access another user's stats" }, { status: 403 })
    }

    const supabase = await getSupabaseServerClient()
    const userId = auth.session.userId

    // 1. Total Automations
    const automationsQuery = supabase
      .from("automations")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId)

    // 2. Active Triggers
    const activeQuery = supabase
      .from("automations")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("is_active", true)

    // 3. Audience Reached (Total Conversations)
    const audienceQuery = supabase
      .from("conversations")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId)

    // 4. Messages Sent (where is_from_instagram is false, bot/system sent it)
    const sentQuery = supabase
      .from("messages")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("is_from_instagram", false)

    // 5. Recent Activity (Last 5 messages sent by bot)
    const recentQuery = supabase
      .from("messages")
      .select("id, content, created_at, sender_username, conversation_id, recipient:conversations(recipient_username)")
      .eq("user_id", userId)
      .eq("is_from_instagram", false)
      .order("created_at", { ascending: false })
      .limit(5)

    const results = await Promise.all([automationsQuery, activeQuery, audienceQuery, sentQuery, recentQuery])
    const failed = results.find(result => result.error)
    if (failed?.error) throw failed.error

    const [
      { count: automationsCount },
      { count: activeTriggersCount },
      { count: audienceCount },
      { count: messagesSentCount },
      { data: recentMessages },
    ] = results

    return NextResponse.json({
      metrics: {
        totalAutomations: automationsCount || 0,
        activeTriggers: activeTriggersCount || 0,
        audienceReached: audienceCount || 0,
        messagesSent: messagesSentCount || 0,
      },
      recentActivity: recentMessages || [],
    })
  } catch (error) {
    console.error("[Dashboard Stats] GET error:", error)
    return NextResponse.json({ error: "Failed to fetch stats" }, { status: 500 })
  }
}
