import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const body = await request.json()
    const { user_id, recipient_id, message } = body

    if (user_id && user_id.toString() !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot send messages from another user's account" }, { status: 403 })
    }

    if (!recipient_id || !message) {
      return NextResponse.json({ error: "Missing required fields: recipient_id, message" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    // Get authenticated user's access token
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("access_token, username")
      .eq("id", auth.session.userId)
      .single()

    if (userError || !user?.access_token) {
      return NextResponse.json({ error: "User not found or Instagram not connected" }, { status: 404 })
    }

    // Send message via Instagram Graph API
    const sendUrl = `https://graph.instagram.com/v24.0/me/messages?access_token=${encodeURIComponent(user.access_token)}`

    const response = await fetch(sendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        recipient: {
          id: recipient_id.toString(),
        },
        message: {
          text: message,
        },
      }),
    })

    const data = await response.json()

    if (!response.ok) {
      console.error("[Instagram Send Message] API Error:", data)
      return NextResponse.json({ error: data.error?.message || "Failed to send message" }, { status: 400 })
    }

    // Store the sent message in database under authenticated user identity
    const { data: conversation } = await supabase
      .from("conversations")
      .select("id")
      .eq("user_id", auth.session.userId)
      .eq("recipient_id", recipient_id.toString())
      .single()

    if (conversation) {
      await supabase.from("messages").insert({
        id: data.message_id,
        conversation_id: conversation.id,
        user_id: auth.session.userId,
        sender_id: auth.session.userId,
        sender_username: user.username,
        content: message,
        is_from_instagram: false,
      })
    }

    return NextResponse.json({
      success: true,
      message_id: data.message_id,
    })
  } catch (error) {
    console.error("[Instagram Send Message] Server error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
