import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const requestedUserId = request.nextUrl.searchParams.get("userId")
    if (requestedUserId && requestedUserId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot access another user's ice breakers" }, { status: 403 })
    }

    const supabase = await getSupabaseServerClient()
    const { data, error } = await supabase
      .from("ice_breakers")
      .select("*")
      .eq("user_id", auth.session.userId)
      .order("created_at", { ascending: true })

    if (error) throw error

    return NextResponse.json(data)
  } catch (error) {
    console.error("[IceBreakers] GET Error:", error)
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const body = await request.json()
    const { userId, iceBreakers } = body

    if (userId && userId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot update ice breakers for another user" }, { status: 403 })
    }

    if (!Array.isArray(iceBreakers)) {
      return NextResponse.json({ error: "Invalid payload: iceBreakers must be an array" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    // 1. Delete existing ice breakers for this authenticated user only
    const { error: deleteError } = await supabase
      .from("ice_breakers")
      .delete()
      .eq("user_id", auth.session.userId)

    if (deleteError) throw deleteError

    // 2. Insert new ice breakers bound to authenticated user
    const { data: inserted, error: insertError } = await supabase
      .from("ice_breakers")
      .insert(
        iceBreakers.map((ib: any) => ({
          user_id: auth.session.userId,
          question: String(ib.question || "").slice(0, 500),
          response: String(ib.response || "").slice(0, 2000),
          is_active: true,
        }))
      )
      .select()

    if (insertError) throw insertError

    // 3. Sync to Instagram using authenticated user's access token
    const { data: user } = await supabase
      .from("users")
      .select("access_token, page_id")
      .eq("id", auth.session.userId)
      .single()

    if (user?.access_token && user?.page_id) {
      const igPayload = inserted.map((ib: any) => ({
        question: ib.question,
        payload: `ICE_BREAKER_${ib.id}`,
      }))

      const response = await fetch(
        `https://graph.instagram.com/v21.0/me/messenger_profile?access_token=${encodeURIComponent(user.access_token)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ice_breakers: igPayload,
            platform: "instagram",
          }),
        }
      )
      const igResult = await response.json()
      if (igResult.error) {
        console.error("[IceBreakers] IG Sync Error:", igResult.error)
        return NextResponse.json(
          { success: true, warning: "Saved to DB but IG Sync failed", error: igResult.error },
          { status: 200 }
        )
      }
    }

    return NextResponse.json({ success: true, data: inserted })
  } catch (error) {
    console.error("[IceBreakers] POST Error:", error)
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}
