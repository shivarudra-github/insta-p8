import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import { authenticateRequest } from "@/lib/auth-session"

function sanitizeDbErrorCode(code: unknown): string {
  if (typeof code === "string" && /^[A-Za-z0-9]{1,10}$/.test(code)) {
    return code
  }
  return "UNKNOWN_DB_ERR"
}

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

    if (error) {
      console.error(`[IceBreakers] Database query error: code=${sanitizeDbErrorCode((error as any)?.code)}`)
      return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
    }

    return NextResponse.json(data)
  } catch {
    console.error("[IceBreakers] GET handler error: category=UNHANDLED_EXCEPTION")
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request)
    if (auth.errorResponse) return auth.errorResponse

    let body: any
    try {
      body = await request.json()
    } catch {
      return NextResponse.json({ error: "Invalid payload: Request body must be valid JSON" }, { status: 400 })
    }

    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "Invalid payload: Request body must be an object" }, { status: 400 })
    }

    const { userId, iceBreakers } = body

    // 1. Cross-user spoofing protection
    if (userId && String(userId) !== String(auth.session.userId)) {
      return NextResponse.json({ error: "Forbidden: Cannot update ice breakers for another user" }, { status: 403 })
    }

    // 2. Validate iceBreakers array
    if (!Array.isArray(iceBreakers)) {
      return NextResponse.json({ error: "Invalid payload: iceBreakers must be an array" }, { status: 400 })
    }

    if (iceBreakers.length > 4) {
      return NextResponse.json({ error: "Invalid payload: Maximum 4 Ice Breakers allowed by Instagram" }, { status: 400 })
    }

    // 3. Deep validation of all entries before ANY database mutation
    const validatedBreakers: Array<{ question: string; response: string }> = []

    for (let i = 0; i < iceBreakers.length; i++) {
      const item = iceBreakers[i]

      if (!item || typeof item !== "object" || Array.isArray(item)) {
        return NextResponse.json({ error: `Invalid payload: Ice breaker at index ${i} must be a valid object` }, { status: 400 })
      }

      if (typeof item.question !== "string" || typeof item.response !== "string") {
        return NextResponse.json({ error: `Invalid payload: question and response must be strings at index ${i}` }, { status: 400 })
      }

      const trimmedQuestion = item.question.trim()
      const trimmedResponse = item.response.trim()

      if (!trimmedQuestion || !trimmedResponse) {
        return NextResponse.json({ error: `Invalid payload: question and response cannot be empty at index ${i}` }, { status: 400 })
      }

      if (trimmedQuestion.length > 80) {
        return NextResponse.json({ error: `Invalid payload: question exceeds 80 characters limit at index ${i}` }, { status: 400 })
      }

      if (trimmedResponse.length > 2000) {
        return NextResponse.json({ error: `Invalid payload: response exceeds 2000 characters limit at index ${i}` }, { status: 400 })
      }

      validatedBreakers.push({ question: trimmedQuestion, response: trimmedResponse })
    }

    const supabase = await getSupabaseServerClient()

    // A successful database write is not a successful Instagram sync.
    // Keep the token out of request URLs so it is less likely to enter URL logs.
    const syncInstagram = async (payload: Array<{ question: string; payload: string }> | null): Promise<string | null> => {
      let accessToken = ""

      try {
        const { data: user, error: userError } = await supabase
          .from("users")
          .select("access_token")
          .eq("id", auth.session.userId)
          .maybeSingle()

        if (userError) {
          console.error(`[IceBreakers] Instagram connection lookup failed: code=${sanitizeDbErrorCode((userError as any)?.code)}`)
          return "Saved to database, but the Instagram connection could not be verified. Reconnect Instagram and try syncing again."
        }

        if (typeof user?.access_token !== "string" || !user.access_token.trim()) {
          return "Saved to database, but no Instagram access token was found. Reconnect Instagram to sync."
        }

        accessToken = user.access_token
      } catch {
        console.error("[IceBreakers] Instagram connection lookup failed: category=UNHANDLED_EXCEPTION")
        return "Saved to database, but the Instagram connection could not be verified. Reconnect Instagram and try syncing again."
      }

      try {
        const endpoint = "https://graph.instagram.com/v24.0/me/messenger_profile"
        const isDelete = payload === null
        const url = isDelete ? `${endpoint}?fields=['ice_breakers']` : endpoint

        let body: FormData | undefined = undefined
        if (!isDelete) {
          const formData = new FormData()
          formData.set("platform", "instagram")
          formData.set("ice_breakers", JSON.stringify(payload))
          body = formData
        }

        const response = await fetch(url, {
          method: isDelete ? "DELETE" : "POST",
          signal: AbortSignal.timeout(10000),
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
          body,
        })

        let igResult: any = null
        try {
          igResult = await response.json()
        } catch {
          igResult = null
        }

        const isSyncSuccessful =
          response.ok &&
          igResult !== null &&
          typeof igResult === "object" &&
          !Array.isArray(igResult) &&
          igResult.result === "success"

        if (!isSyncSuccessful) {
          const httpStatus = response.status >= 100 && response.status < 600 ? response.status : 0
          const providerCode = typeof igResult?.error?.code === "number" ? igResult.error.code : "UNKNOWN"
          console.error(`[IceBreakers] Instagram sync failed: http_status=${httpStatus} provider_code=${providerCode}`)
          return "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again."
        }

        return null
      } catch {
        console.error("[IceBreakers] Instagram sync network failure: category=FETCH_ERROR")
        return "Saved to database, but Instagram sync could not be confirmed because of a network error."
      }
    }

    // 4. Query existing records before making mutations to track old IDs
    const { data: existingRows, error: fetchError } = await supabase
      .from("ice_breakers")
      .select("id")
      .eq("user_id", auth.session.userId)

    if (fetchError) {
      console.error(`[IceBreakers] Database query error: code=${sanitizeDbErrorCode((fetchError as any)?.code)}`)
      return NextResponse.json({ error: "Failed to query existing ice breakers" }, { status: 500 })
    }

    const oldIds: string[] = (existingRows || []).map((r: any) => r.id)

    // Case A: Payload is empty array -> clear existing ice breakers via single bulk DELETE
    if (validatedBreakers.length === 0) {
      if (oldIds.length > 0) {
        let deleteErrorObj: any = null
        try {
          const { error: deleteError } = await supabase
            .from("ice_breakers")
            .delete()
            .in("id", oldIds)
            .eq("user_id", auth.session.userId)

          if (deleteError) {
            deleteErrorObj = deleteError
          }
        } catch (err) {
          deleteErrorObj = err || true
        }

        if (deleteErrorObj) {
          const dbCode = typeof deleteErrorObj?.code === "string" && /^[A-Za-z0-9]{1,10}$/.test(deleteErrorObj.code)
            ? deleteErrorObj.code
            : "UNKNOWN"
          console.error(`[IceBreakers] Database delete error or network failure: code=${dbCode}`)
          return NextResponse.json(
            {
              success: false,
              operationUncertain: true,
              warning: "Clearing Ice Breakers could not be confirmed. Old records may still exist. Please do not retry immediately.",
              error: "Failed to clear existing ice breakers. Removal of previous records could not be confirmed.",
            },
            { status: 500 }
          )
        }
      }

      // Keep the remote Instagram profile in sync even when the local list is already empty.
      const syncWarning = await syncInstagram(null)
      return NextResponse.json({
        success: true,
        data: [],
        ...(syncWarning ? { warning: syncWarning, error: "Instagram API synchronization failed" } : {}),
      })
    }

    // Case B: Safe Replacement — Insert replacement rows FIRST
    const rowsToInsert = validatedBreakers.map((ib) => ({
      user_id: auth.session.userId,
      question: ib.question,
      response: ib.response,
      is_active: true,
    }))

    let inserted: any[] | null = null
    let insertFailed = false
    let insertThrown = false
    let insertErrorCode = "UNKNOWN"

    try {
      const { data, error: insertError } = await supabase
        .from("ice_breakers")
        .insert(rowsToInsert)
        .select()

      if (insertError || !data || data.length === 0) {
        insertFailed = true
        if (typeof (insertError as any)?.code === "string" && /^[A-Za-z0-9]{1,10}$/.test((insertError as any).code)) {
          insertErrorCode = (insertError as any).code
        }
      } else {
        inserted = data
      }
    } catch {
      insertThrown = true
    }

    if (insertThrown) {
      console.error("[IceBreakers] Database insert network failure: category=FETCH_ERROR")
      // Treat database outcome as uncertain. Do NOT delete old records. Do NOT retry automatically.
      return NextResponse.json(
        {
          success: false,
          operationUncertain: true,
          warning: "Saving new records could not be confirmed due to a network error. Old records were preserved. Please do not retry immediately.",
          error: "Database insert outcome is uncertain. Please check your existing records.",
        },
        { status: 500 }
      )
    }

    if (insertFailed || !inserted) {
      console.error(`[IceBreakers] Database insert error: code=${insertErrorCode}`)
      // Confirmed failure: report confirmed failure, keep old records untouched
      return NextResponse.json(
        {
          success: false,
          error: "Failed to save new ice breakers. Existing records were preserved.",
        },
        { status: 500 }
      )
    }

    // Step 5: Remove old records ONLY after new records are confirmed inserted.
    // Wrap in explicit try/catch to handle both Supabase error responses and thrown network exceptions.
    // Skip if oldIds is empty.
    if (oldIds.length > 0) {
      let deleteSuccess = false
      let deleteErrorObj: any = null

      try {
        const { error: deleteError } = await supabase
          .from("ice_breakers")
          .delete()
          .in("id", oldIds)
          .eq("user_id", auth.session.userId)

        if (deleteError) {
          deleteErrorObj = deleteError
        } else {
          deleteSuccess = true
        }
      } catch (err) {
        deleteErrorObj = err || true
      }

      if (!deleteSuccess) {
        const dbCode = typeof deleteErrorObj?.code === "string" && /^[A-Za-z0-9]{1,10}$/.test(deleteErrorObj.code)
          ? deleteErrorObj.code
          : "UNKNOWN"
        console.error(`[IceBreakers] Database bulk delete error or network failure: code=${dbCode}`)

        // Never perform destructive rollback of newly inserted records.
        // Never claim old records were definitely preserved when the outcome is unknown.
        return NextResponse.json(
          {
            success: false,
            partialSuccess: true,
            operationUncertain: true,
            data: inserted,
            warning: "New records were saved, but removal of previous records could not be confirmed. Duplicate entries may remain.",
            error: "Ice Breaker replacement could not be fully confirmed.",
          },
          { status: 500 }
        )
      }
    }

    const igPayload = inserted.map((ib: any) => ({
      question: ib.question,
      payload: `ICE_BREAKER_${ib.id}`,
    }))
    const syncWarning = await syncInstagram(igPayload)

    if (syncWarning) {
      return NextResponse.json(
        {
          success: true,
          data: inserted,
          warning: syncWarning,
          error: "Instagram API synchronization failed",
        },
        { status: 200 }
      )
    }

    return NextResponse.json({ success: true, data: inserted })
  } catch {
    console.error("[IceBreakers] POST handler error: category=UNHANDLED_EXCEPTION")
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}
