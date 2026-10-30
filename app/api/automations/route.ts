import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const requestedUserId = request.nextUrl.searchParams.get("userId")
    if (requestedUserId && requestedUserId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot access another user's automations" }, { status: 403 })
    }

    const supabase = await getSupabaseServerClient()

    const { data, error } = await supabase
      .from("automations")
      .select("*")
      .eq("user_id", auth.session.userId)
      .order("created_at", { ascending: false })

    if (error) throw error
    return NextResponse.json(data)
  } catch (error) {
    console.error("[Automations] GET error:", error)
    return NextResponse.json({ error: "Failed to fetch automations" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const body = await request.json()
    const { userId, name, trigger_source, trigger_type, trigger_value, content, specific_media_id } = body

    if (userId && userId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot create automations for another user" }, { status: 403 })
    }

    if (!name || !trigger_value || !content || !trigger_source) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    // Validate trigger_source
    if (!["comment", "dm", "story"].includes(trigger_source)) {
      return NextResponse.json({ error: "Invalid trigger source" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    const finalTriggerValue =
      trigger_type === "postback"
        ? `PAYLOAD_${Date.now()}_${Math.random().toString(36).substring(7)}`
        : trigger_value.toLowerCase()

    const { data, error } = await supabase
      .from("automations")
      .insert({
        user_id: auth.session.userId,
        name,
        trigger_source,
        trigger_type: trigger_type || "keyword",
        trigger_value: finalTriggerValue,
        response_type: "pro",
        response_content: content,
        is_active: false,
        specific_media_id: specific_media_id || null,
      })
      .select()
      .single()

    if (error) throw error
    return NextResponse.json(data)
  } catch (error) {
    console.error("[Automations] POST error:", error)
    return NextResponse.json({ error: "Failed to create automation" }, { status: 500 })
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const id = request.nextUrl.searchParams.get("id")
    if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 })

    const supabase = await getSupabaseServerClient()

    // Strictly enforce ownership on delete
    const { error, count } = await supabase
      .from("automations")
      .delete({ count: "exact" })
      .eq("id", id)
      .eq("user_id", auth.session.userId)

    if (error) throw error
    if (count === 0) {
      return NextResponse.json({ error: "Automation not found or not owned by user" }, { status: 404 })
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("[Automations] DELETE error:", error)
    return NextResponse.json({ error: "Failed to delete automation" }, { status: 500 })
  }
}

export async function PUT(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const body = await request.json()
    const { id, name, trigger_source, trigger_type, trigger_value, content, specific_media_id, userId } = body

    if (userId && userId !== auth.session.userId) {
      return NextResponse.json({ error: "Forbidden: Cannot update automations for another user" }, { status: 403 })
    }

    if (!id || !name || !trigger_value || !content) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    if (trigger_source && !["comment", "dm", "story"].includes(trigger_source)) {
      return NextResponse.json({ error: "Invalid trigger source" }, { status: 400 })
    }

    const supabase = await getSupabaseServerClient()

    const updateData: Record<string, unknown> = {
      name,
      trigger_type: trigger_type || "keyword",
      trigger_value: trigger_value.toLowerCase(),
      response_content: content,
      specific_media_id: specific_media_id || null,
    }

    if (trigger_source) {
      updateData.trigger_source = trigger_source
    }

    // Strictly enforce ownership on update
    const { data, error } = await supabase
      .from("automations")
      .update(updateData)
      .eq("id", id)
      .eq("user_id", auth.session.userId)
      .select()
      .single()

    if (error) throw error
    if (!data) {
      return NextResponse.json({ error: "Automation not found or not owned by user" }, { status: 404 })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error("[Automations] PUT error:", error)
    return NextResponse.json({ error: "Failed to update automation" }, { status: 500 })
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    const { id, is_active, action } = await request.json()
    if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 })

    const supabase = await getSupabaseServerClient()

    if (action === "duplicate") {
      const { data: original, error: fetchError } = await supabase
        .from("automations")
        .select("*")
        .eq("id", id)
        .eq("user_id", auth.session.userId)
        .single()

      if (fetchError || !original) {
        return NextResponse.json({ error: "Automation not found or not owned by user" }, { status: 404 })
      }

      const { id: _id, created_at, updated_at, ...rest } = original
      const { data, error } = await supabase
        .from("automations")
        .insert({
          ...rest,
          user_id: auth.session.userId,
          name: `${original.name} (copy)`,
          is_active: false,
        })
        .select()
        .single()

      if (error) throw error
      return NextResponse.json(data)
    }

    if (typeof is_active !== "boolean") {
      return NextResponse.json({ error: "Missing is_active" }, { status: 400 })
    }

    const { data, error } = await supabase
      .from("automations")
      .update({ is_active })
      .eq("id", id)
      .eq("user_id", auth.session.userId)
      .select()
      .single()

    if (error) throw error
    if (!data) {
      return NextResponse.json({ error: "Automation not found or not owned by user" }, { status: 404 })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error("[Automations] PATCH error:", error)
    return NextResponse.json({ error: "Failed to update automation status" }, { status: 500 })
  }
}
