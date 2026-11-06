import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const requestedUserId = request.nextUrl.searchParams.get("userId")
    if (requestedUserId && requestedUserId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot access another user's media" }, { status: 403 })
    }

    const supabase = await getSupabaseServerClient()

    // 1. Get Access Token strictly for authenticated user
    const { data: user } = await supabase
      .from("users")
      .select("access_token")
      .eq("id", auth.session.userId)
      .single()

    if (!user?.access_token) {
      return NextResponse.json({ error: "Instagram not connected" }, { status: 401 })
    }

    // 2. Fetch Media via Instagram Graph API
    const url = `https://graph.instagram.com/me/media?fields=id,caption,media_type,media_url,thumbnail_url,permalink,timestamp&limit=24&access_token=${encodeURIComponent(user.access_token)}`

    const res = await fetch(url, { cache: "no-store" })
    const data = await res.json()

    if (data.error) {
      console.error("[Instagram Media] Graph API Error:", data.error)
      if (data.error.code === 190) {
        return NextResponse.json({ error: "Instagram session expired. Please reconnect." }, { status: 401 })
      }
      return NextResponse.json({ error: data.error.message }, { status: 500 })
    }

    // Normalize: pick thumbnail_url for videos, media_url for images
    const normalized = (data.data || [])
      .map((m: any) => ({
        ...m,
        image_url: m.thumbnail_url || m.media_url || null,
      }))
      .filter((m: any) => typeof m.image_url === "string" && m.image_url.length > 0)

    return NextResponse.json({ data: normalized })
  } catch (error) {
    console.error("[Instagram Media] Server Error:", error)
    return NextResponse.json({ error: "Server Error" }, { status: 500 })
  }
}
