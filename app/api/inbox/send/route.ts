import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const body = await request.json()
    const { userId, recipientId, message, attachment } = body

    if (userId && userId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot send messages from another user's account" }, { status: 403 })
    }

    if (!recipientId || (!message && !attachment)) {
      return NextResponse.json({ error: "Missing required fields: recipientId and message or attachment" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    // 1. Get authenticated user's access token
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("access_token, username, business_account_id")
      .eq("id", auth.session.userId)
      .single()

    if (userError || !user?.access_token) {
      return NextResponse.json({ error: "User not found or Instagram not connected" }, { status: 404 })
    }

    // 2. Prepare Payload for Instagram Graph API
    const apiBody: any = { recipient: { id: recipientId } }
    if (message) {
      apiBody.message = { text: message }
    } else if (attachment) {
      apiBody.message = { attachment }
    }

    // 3. Send message via Instagram Graph API
    const res = await fetch(
      `https://graph.instagram.com/v24.0/me/messages?access_token=${encodeURIComponent(user.access_token)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(apiBody),
      }
    )

    const data = await res.json()

    if (data.error) {
      console.error("[Inbox Send] Instagram API Error:", data.error)
      return NextResponse.json({ error: data.error.message }, { status: 500 })
    }

    // 4. Log to Database under authenticated user identity
    const { data: conv } = await supabase
      .from("conversations")
      .select("id")
      .eq("user_id", auth.session.userId)
      .eq("recipient_id", recipientId)
      .single()

    if (conv) {
      await supabase.from("messages").insert({
        id: `mid_out_${Date.now()}_${Math.random().toString(36).substring(7)}`,
        conversation_id: conv.id,
        user_id: auth.session.userId,
        sender_id: user.business_account_id,
        sender_username: user.username,
        content: message || "[Attachment]",
        is_from_instagram: false,
      })

      // Update conversation timestamp
      await supabase
        .from("conversations")
        .update({ last_message_at: new Date().toISOString() })
        .eq("id", conv.id)
    }

    return NextResponse.json({ success: true, data })
  } catch (error) {
    console.error("[Inbox Send] Internal Error:", error)
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}
