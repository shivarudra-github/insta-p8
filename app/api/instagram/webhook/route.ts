/* @ts-nocheck */

import crypto from "crypto"
import { type NextRequest, NextResponse } from "next/server"
import { getSupabaseServerClient } from "@/lib/supabase-server"
import {
  sendTextDM,
  sendCardDM,
  sendMediaDM,
  sendSenderAction,
  replyToComment,
  fetchProfile,
  sleep,
  buildFollowGateCard,
} from "@/lib/instagram-api"
import { generateAIReply } from "@/lib/ai-reply"
import { bumpUnlockAttempt, clearUnlockAttempts, unlockKey } from "@/lib/unlock-tracking"

const WEBHOOK_VERIFY_TOKEN = process.env.INSTAGRAM_WEBHOOK_VERIFY_TOKEN
// Meta signs every webhook POST with HMAC-SHA256 of the raw body. Depending on app setup the
// signing key is the Instagram app secret or the parent Meta app secret, so accept either.
const APP_SECRETS = [process.env.INSTAGRAM_APP_SECRET, process.env.META_APP_SECRET].filter(
  (s): s is string => Boolean(s),
)

function isValidSignature(rawBody: string, signatureHeader: string | null): boolean {
  if (APP_SECRETS.length === 0 || !signatureHeader?.startsWith("sha256=")) return false
  const received = signatureHeader.slice("sha256=".length)
  return APP_SECRETS.some((secret) => {
    const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("hex")
    return (
      received.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(received, "utf8"), Buffer.from(expected, "utf8"))
    )
  })
}

const DEFAULT_PUBLIC_REPLIES = ["Check your DMs! 📥", "Sent! 🔥", "Check inbox! ✨"]

// Max times we'll send the gate card for an unverifiable follow status on a single unlock event.
// After this, we send a single "couldn't verify your follow" message and stop spamming the user.
const UNLOCK_GATE_MAX_ATTEMPTS = 3

// ============================================================
// Safe Logging Sanitization Helpers
// ============================================================
function sanitizeDbCode(code: unknown): string {
  if (typeof code === "string" && (/^[A-Z0-9]{5}$/i.test(code) || /^PGRST\d{3}$/i.test(code))) {
    return code.toUpperCase()
  }
  return "unknown_code"
}

function sanitizeErrorCategory(err: unknown): "timeout" | "network_error" | "error" | "unknown_error" {
  if (err instanceof Error) {
    if (err.name === "AbortError" || err.name === "TimeoutError") return "timeout"
    if (
      err.name === "FetchError" ||
      (err.name === "TypeError" && err.message.toLowerCase().includes("fetch failed") && (err as any).cause != null)
    ) {
      return "network_error"
    }
    return "error"
  }
  return "unknown_error"
}

function sanitizeHttpStatus(status: unknown): number | "unknown_status" {
  if (typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599) {
    return status
  }
  return "unknown_status"
}

// ============================================================
// Webhook Idempotency & Deduplication Helpers
// ============================================================
function createEventClaimId(eventKey: string): string {
  const hash = crypto.createHash("sha256").update(eventKey).digest("hex")
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`
}

async function claimWebhookEvent(
  supabase: any,
  eventKey: string,
  userId: any,
  eventType: string,
  eventData?: any,
): Promise<{ claimed: boolean; claimId: string }> {
  const claimId = createEventClaimId(eventKey)
  try {
    const { error } = await supabase.from("webhook_events").insert({
      id: claimId,
      event_type: eventType,
      user_id: userId,
      data: { event_key: eventKey, ...(eventData || {}) },
    })
    if (error) {
      return { claimed: false, claimId }
    }
    return { claimed: true, claimId }
  } catch (err) {
    console.error(`[webhook] Database error claiming webhook event: code=${sanitizeDbCode((err as any)?.code)} category=${sanitizeErrorCategory(err)}`)
    return { claimed: false, claimId }
  }
}

async function releaseWebhookEventClaim(supabase: any, claimId: string): Promise<void> {
  try {
    await supabase.from("webhook_events").delete().eq("id", claimId)
  } catch (err) {
    console.error(`[webhook] Database error releasing webhook event claim: code=${sanitizeDbCode((err as any)?.code)} category=${sanitizeErrorCategory(err)}`)
  }
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const mode = searchParams.get("hub.mode")
  const token = searchParams.get("hub.verify_token")
  const challenge = searchParams.get("hub.challenge")
console.info("[webhook verify diagnostic]", {
  mode: mode === "subscribe" ? "subscribe" : "other",
  hasExpectedToken: Boolean(WEBHOOK_VERIFY_TOKEN),
  hasReceivedToken: Boolean(token),
  tokenMatches: Boolean(WEBHOOK_VERIFY_TOKEN && token === WEBHOOK_VERIFY_TOKEN),
  challengePresent: Boolean(challenge),
})
  if (mode === "subscribe" && WEBHOOK_VERIFY_TOKEN && token === WEBHOOK_VERIFY_TOKEN && challenge) {
    return new NextResponse(challenge, { status: 200 })
  }
  return NextResponse.json({ error: "Invalid token" }, { status: 403 })
}

// ============================================================
// Content parsing — response_content may be object or JSON string
// ============================================================
function parseContent(raw: any) {
  if (!raw) return {}
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw)
    } catch {
      return { message: raw }
    }
  }
  return raw
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function keywordMatches(triggerValue: string, text: string): boolean {
  return triggerValue
    .split(",")
    .map((k: string) => k.trim())
    .filter(Boolean)
    .some((k: string) => {
      try {
        return new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(text)
      } catch {
        return text.includes(k.toLowerCase())
      }
    })
}

// ============================================================
// Unified response sender — handles text, card, media, quick
// replies, typing indicators, and human-like delays.
// ============================================================
async function sendAutomationResponse(
  token: string,
  recipient: { id?: string; comment_id?: string },
  content: any,
  opts: { skipTyping?: boolean } = {},
) {
  const delaySeconds = Number(content.delay_seconds) || 0
  const useTyping = content.typing_indicator === true && recipient.id && !opts.skipTyping

  if (useTyping) await sendSenderAction(token, recipient.id!, "typing_on")
  if (delaySeconds > 0) await sleep(delaySeconds * 1000)

  const quickReplies = Array.isArray(content.quick_replies)
    ? content.quick_replies
        .filter((q: any) => q?.title)
        .map((q: any) => ({ title: q.title, payload: q.payload || `QR_${q.title.toUpperCase().replace(/\s+/g, "_")}` }))
    : undefined

  let result
  if (content.media?.url) {
    result = await sendMediaDM(token, recipient, content.media.type || "image", content.media.url)
    if (result.ok && content.message) {
      result = await sendTextDM(token, recipient, content.message, quickReplies)
    }
  } else if (content.card) {
    result = await sendCardDM(token, recipient, content.card)
  } else if (content.message) {
    result = await sendTextDM(token, recipient, content.message, quickReplies)
  } else {
    result = { ok: false, error: "empty content" }
  }

  if (useTyping) await sendSenderAction(token, recipient.id!, "typing_off")
  return result
}

function responsePreviewText(content: any): string {
  if (content.message) return content.message
  if (content.card) return `[Card] ${content.card.title}`
  if (content.media?.url) return `[${content.media.type || "media"}]`
  return "[automation]"
}

// ============================================================
// Instagram API Helper: Verifies actual follow status
// API: GET https://graph.instagram.com/v21.0/{recipientId}?fields=is_user_follow_business
// Returns:
//   { follows: true, error: undefined }  → confirmed following
//   { follows: false, error: undefined } → confirmed NOT following
//   { follows: null, error: 'auth' } → auth/permission failure (401, 403) — fail CLOSED
//   { follows: null, error: 'transient' } → transient failure (5xx, timeout) — fail OPEN
// ============================================================
async function verifyFollowStatus(igScopedId: string, pageAccessToken: string): Promise<{ follows: boolean | null; error?: 'auth' | 'transient' }> {
  try {
    const url = `https://graph.instagram.com/v21.0/${igScopedId}?fields=is_user_follow_business&access_token=${pageAccessToken}`
    // 5s timeout -- Graph API is fast, anything longer means trouble
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) })
    if (!response.ok) {
      await response.text()
      console.error(`[webhook] Follow status check failed: status=${sanitizeHttpStatus(response.status)}`)
      // Distinguish auth failures (fail closed) from transient (fail open)
      if (response.status === 401 || response.status === 403) {
        return { follows: null, error: 'auth' }
      }
      // 5xx, 429, network timeout, etc. → transient, fail open
      return { follows: null, error: 'transient' }
    }
    const data = await response.json()
    const follows = data.is_user_follow_business === true
    console.log(`[webhook] Follow check completed: follows=${follows ? "true" : "false"}`)
    return { follows, error: undefined }
  } catch (error: any) {
    console.error(`[webhook] Error checking follow status: category=${sanitizeErrorCategory(error)}`)
    // AbortSignal.timeout throws AbortError/TimeoutError -- both are transient
    if (error?.name === "AbortError" || error?.name === "TimeoutError") {
      return { follows: null, error: 'transient' }
    }
    // Network error → transient, fail open
    return { follows: null, error: 'transient' }
  }
}

// Unlock-attempt counter is in lib/unlock-tracking.ts -- uses Supabase
// unlock_attempts table so the 3-attempt cap works across Vercel instances.

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text()
    const signature = request.headers.get("x-hub-signature-256")
    if (!isValidSignature(rawBody, signature)) {
      console.error(
        `[webhook] 401: ${!signature ? "no x-hub-signature-256 header" : "signature verification failed"}`,
      )
      if (process.env.NODE_ENV !== "production" && process.env.DISABLE_WEBHOOK_SIGNATURE_CHECK === "true") {
        console.warn("[webhook] SIGNATURE CHECK BYPASSED — remove DISABLE_WEBHOOK_SIGNATURE_CHECK after debugging")
      } else {
        return NextResponse.json({ error: "Invalid signature" }, { status: 401 })
      }
    }
    const body = JSON.parse(rawBody)
    if (!body.entry) return NextResponse.json({ ok: true })
    const supabase = await getSupabaseServerClient()

    for (const entry of body.entry) {
      // Skip pure system events (echo / read / delivery)
      if (entry.messaging) {
        const isSystemEvent = entry.messaging.every(
          (event: any) => event.read || event.delivery || (event.message && event.message.is_echo),
        )
        if (isSystemEvent) continue
      }

      const webhookId = entry.id
      if (typeof webhookId !== "string" || !/^\d+$/.test(webhookId)) {
        console.warn("[webhook] Invalid or malformed entry.id in payload")
        continue
      }

      // ---------- User resolution: direct, payload fallback, token verify ----------
      let { data: user } = await supabase
        .from("users")
        .select("*")
        .or(`id.eq.${webhookId},business_account_id.eq.${webhookId},page_id.eq.${webhookId}`)
        .single()

      if (!user) {
        const candidateIds = new Set<string>()
        if (entry.changes) {
          for (const change of entry.changes) {
            if (change.value?.media?.owner?.id) candidateIds.add(String(change.value.media.owner.id))
          }
        }
        if (entry.messaging) {
          for (const event of entry.messaging) {
            if (event.recipient?.id) candidateIds.add(String(event.recipient.id))
          }
        }
        for (const candidateId of candidateIds) {
          if (candidateId === webhookId) continue
          if (!/^\d+$/.test(candidateId)) continue
          const { data: fallbackUser } = await supabase
            .from("users")
            .select("*")
            .or(`id.eq.${candidateId},business_account_id.eq.${candidateId},page_id.eq.${candidateId}`)
            .single()
          if (fallbackUser) {
            await supabase.from("users").update({ page_id: webhookId }).eq("id", fallbackUser.id)
            user = fallbackUser
            break
          }
        }
      }

      if (!user) {
        console.log("[webhook] ❌ Could not resolve user for account ID")
        continue
      }

      const { data: automationsData } = await supabase
        .from("automations")
        .select("*")
        .eq("user_id", user.id)
        .eq("is_active", true)

      const automations = automationsData || []

      // ============================================================
      //  PART A: COMMENTS
      // ============================================================
      if (Array.isArray(entry.changes)) {
        for (const change of entry.changes) {
          let claimId: string | null = null
          try {
            if (change?.field !== "comments") continue

            const val = change?.value
            if (!val || typeof val !== "object") continue
            if (!val.id || typeof val.id !== "string" || !val.text || typeof val.text !== "string") continue
            if (!val.from?.id || typeof val.from.id !== "string") continue
            if (!val.media?.id || typeof val.media.id !== "string") continue

            const commentId = val.id
            const commentText = val.text.toLowerCase().trim()
            const senderId = val.from.id
            const mediaId = val.media.id
            const parentId = val.parent_id || null

            if (senderId === webhookId || senderId === user.business_account_id || senderId === user.page_id) continue

            const commentAutomations = automations.filter(
              (a: any) => a.trigger_source === "comment" && a.is_active === true,
            )
            if (commentAutomations.length === 0) continue

            // Priority: specific post reply-all → specific post keyword → global keyword
            let match = commentAutomations.find(
              (a: any) => a.specific_media_id === mediaId && a.trigger_type === "reply_all",
            )
            if (!match) {
              match = commentAutomations.find(
                (a: any) =>
                  a.specific_media_id === mediaId &&
                  a.trigger_type === "keyword" &&
                  keywordMatches(a.trigger_value, commentText),
              )
            }
            if (!match) {
              match = commentAutomations.find(
                (a: any) =>
                  !a.specific_media_id &&
                  a.trigger_type === "keyword" &&
                  keywordMatches(a.trigger_value, commentText),
              )
            }
            if (!match) continue

            const content = parseContent(match.response_content)

            // Skip nested replies unless user opted in
            if (parentId && content.include_replies !== true) continue

            // Deduplication / Idempotency claim
            const claimResult = await claimWebhookEvent(
              supabase,
              `comment:${commentId}`,
              user.id,
              "comment",
              { comment_id: commentId, media_id: mediaId, rule_id: match.id },
            )
            if (!claimResult.claimed) {
              console.log("[webhook] ⏭️ Duplicate comment skipped")
              continue
            }
            claimId = claimResult.claimId

            console.log("[webhook] ✅ Comment rule matched")

            // reply_mode: 'both' (default) | 'dm_only' | 'public_only'
            const replyMode = content.reply_mode || "both"

            // Helper: pick a public reply from user's rotation list (with defaults fallback)
            const getPublicReply = (): string => {
              const pool: string[] =
                Array.isArray(content.public_replies) && content.public_replies.filter(Boolean).length > 0
                  ? content.public_replies.filter(Boolean)
                  : DEFAULT_PUBLIC_REPLIES
              return pickRandom(pool)
            }

            let sendSucceeded = true

            // ===== FOLLOWER GATE FOR COMMENTS =====
            // The gate card is delivered as a *private reply* to the comment. recipient.id
            // alone won't open a DM with someone who has never messaged the account; private
            // replies to a comment need comment_id.
            if (content.check_follow === true) {
              const followResult = await verifyFollowStatus(senderId, user.access_token)

              if (followResult.follows === true) {
                console.log("[webhook] ✅ Comment follower gate: follower verified — sending content")
                if (replyMode !== "dm_only") {
                  const res = await replyToComment(user.access_token, commentId, getPublicReply())
                  if (!res?.ok) sendSucceeded = false
                }
                if (replyMode !== "public_only") {
                  const res = await sendAutomationResponse(
                    user.access_token,
                    { comment_id: commentId },
                    content,
                    { skipTyping: true },
                  )
                  if (!res?.ok) sendSucceeded = false
                }
              } else if (followResult.follows === false) {
                console.log("[webhook] 🔒 Comment follower gate: non-follower detected")
                if (replyMode !== "dm_only") {
                  const res = await replyToComment(user.access_token, commentId, getPublicReply())
                  if (!res?.ok) sendSucceeded = false
                }
                if (replyMode !== "public_only") {
                  const res = await sendCardDM(
                    user.access_token,
                    { comment_id: commentId },
                    buildFollowGateCard({ username: user.username, ruleId: match.id }),
                  )
                  if (!res?.ok) sendSucceeded = false
                }
              } else {
                // null → unverifiable. Distinguish auth vs transient.
                const isAuthError = followResult.error === 'auth'
                if (isAuthError) {
                  // Auth/permission failure — fail CLOSED: send gate card
                  console.warn("[webhook] ⚠️ Comment follower gate auth failure; sending gate")
                  if (replyMode !== "dm_only") {
                    const res = await replyToComment(user.access_token, commentId, getPublicReply())
                    if (!res?.ok) sendSucceeded = false
                  }
                  if (replyMode !== "public_only") {
                    const res = await sendCardDM(
                      user.access_token,
                      { comment_id: commentId },
                      buildFollowGateCard({ username: user.username, ruleId: match.id }),
                    )
                    if (!res?.ok) sendSucceeded = false
                  }
                } else {
                  // Transient failure — fail OPEN: deliver content (with public reply if allowed)
                  console.warn("[webhook] ⚠️ Comment follower gate transient failure; failing open")
                  if (replyMode !== "dm_only") {
                    const res = await replyToComment(user.access_token, commentId, getPublicReply())
                    if (!res?.ok) sendSucceeded = false
                  }
                  if (replyMode !== "public_only") {
                    const res = await sendAutomationResponse(
                      user.access_token,
                      { comment_id: commentId },
                      content,
                      { skipTyping: true },
                    )
                    if (!res?.ok) sendSucceeded = false
                  }
                }
              }
            } else {
              // No follower check required — send normally
              if (replyMode !== "dm_only") {
                const res = await replyToComment(user.access_token, commentId, getPublicReply())
                if (!res?.ok) sendSucceeded = false
              }
              if (replyMode !== "public_only") {
                const res = await sendAutomationResponse(
                  user.access_token,
                  { comment_id: commentId },
                  content,
                  { skipTyping: true },
                )
                if (!res?.ok) sendSucceeded = false
              }
            }

            if (!sendSucceeded && claimId) {
              console.warn("[webhook] Comment reply failed, releasing claim for retry")
              await releaseWebhookEventClaim(supabase, claimId)
            }
          } catch (commentErr) {
            console.error(`[webhook] Error processing comment change: category=${sanitizeErrorCategory(commentErr)}`)
            if (claimId) {
              await releaseWebhookEventClaim(supabase, claimId)
            }
          }
        }
      }

      // ============================================================
      //  PART A.5: STORY AUTOMATIONS (mention / reaction / reply)
      // ============================================================
      if (Array.isArray(entry.messaging)) {
        for (const event of entry.messaging) {
          try {
            if (!event || typeof event !== "object") continue
            if (!event.sender?.id || !event.recipient?.id) continue
            const senderId = event.sender.id
            const recipientId = event.recipient.id
            if (event.read || event.delivery || event.message?.is_echo || senderId === recipientId) continue

            const storyAutomations = automations.filter(
              (a: any) => a.trigger_source === "story" && a.is_active === true,
            )
            if (storyAutomations.length === 0) continue

            let match = null
            let storyMediaId: string | null = null

            if (event.message?.attachments?.[0]?.type === "story_mention") {
              storyMediaId = event.message.attachments[0].payload?.url || null
              match = storyAutomations.find(
                (a: any) => a.trigger_type === "mention" && (!a.specific_media_id || a.specific_media_id === storyMediaId),
              )
            } else if (event.reaction) {
              const reactionEmoji = event.reaction.emoji
              storyMediaId = event.reaction.mid || null
              match = storyAutomations.find((a: any) => {
                if (a.trigger_type !== "reaction") return false
                if (a.specific_media_id && a.specific_media_id !== storyMediaId) return false
                const triggers = a.trigger_value?.split(",").map((t: string) => t.trim()) || []
                if (triggers.length > 0 && triggers[0] !== "ALL" && triggers[0] !== "ALL_REACTIONS" && triggers[0] !== "") {
                  return triggers.includes(reactionEmoji)
                }
                return true
              })
            } else if (event.message?.reply_to?.story) {
              const messageText = event.message.text || ""
              storyMediaId = event.message.reply_to.story.id || null
              match = storyAutomations.find((a: any) => {
                if (a.trigger_type !== "reply") return false
                if (a.specific_media_id && a.specific_media_id !== storyMediaId) return false
                const triggers = a.trigger_value?.split(",").map((t: string) => t.trim()) || []
                if (
                  triggers.length > 0 &&
                  triggers[0] !== "ALL" &&
                  triggers[0] !== "ALL_MENTIONS" &&
                  triggers[0] !== ""
                ) {
                  return keywordMatches(a.trigger_value, messageText)
                }
                return true
              })
            }

            if (match) {
              console.log("[webhook] ✨ Story rule matched")
              const content = parseContent(match.response_content)

              if (content.check_follow === true) {
                const followResult = await verifyFollowStatus(senderId, user.access_token)

                if (followResult.follows === true) {
                  console.log("[webhook] ✅ Story follower gate: follower verified — sending content")
                  await sendAutomationResponse(user.access_token, { id: senderId }, content)
                } else if (followResult.follows === false) {
                  console.log("[webhook] 🔒 Story follower gate: non-follower detected")
                  await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id }))
                } else {
                  // null → unverifiable. Distinguish auth vs transient.
                  const isAuthError = followResult.error === 'auth'
                  if (isAuthError) {
                    // Auth failure — fail CLOSED: send gate
                    console.warn("[webhook] ⚠️ Story follower gate auth failure; sending gate")
                    await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id }))
                  } else {
                    // Transient failure — fail OPEN: deliver content
                    console.warn("[webhook] ⚠️ Story follower gate transient failure; failing open")
                    await sendAutomationResponse(user.access_token, { id: senderId }, content)
                  }
                }
              } else {
                // No follower check required — send normally
                await sendAutomationResponse(user.access_token, { id: senderId }, content)
              }
            }
          } catch (storyErr) {
            console.error(`[webhook] Error processing story event: category=${sanitizeErrorCategory(storyErr)}`)
          }
        }
      }

      // ============================================================
      //  PART B: DIRECT MESSAGES
      // ============================================================
      if (Array.isArray(entry.messaging)) {
        for (const event of entry.messaging) {
          let claimId: string | null = null
          try {
            if (!event || typeof event !== "object") continue
            if (!event.sender?.id || !event.recipient?.id) continue
            if (event.read || event.delivery || event.reaction || event.message?.is_echo) continue

            const senderId = event.sender.id
            if (senderId === webhookId || senderId === user.business_account_id || senderId === user.page_id) continue

            let triggerType = ""
            let triggerValue = ""

            if (event.message?.quick_reply?.payload) {
              triggerType = "postback"
              triggerValue = event.message.quick_reply.payload
            } else if (event.message?.text) {
              triggerType = "keyword"
              triggerValue = event.message.text.toLowerCase().trim()
            } else if (event.postback?.payload) {
              triggerType = "postback"
              triggerValue = event.postback.payload
            } else {
              continue
            }

            const mid = event.message?.mid
            const dedupKey = mid ? `dm:${mid}` : null

            if (dedupKey) {
              const claimResult = await claimWebhookEvent(
                supabase,
                dedupKey,
                user.id,
                "message",
                { mid, sender_id: senderId },
              )
              if (!claimResult.claimed) {
                console.log("[webhook] ⏭️ Duplicate DM event skipped")
                continue
              }
              claimId = claimResult.claimId
            }

            console.log("[webhook] 📩 Incoming DM received")

          // Inbox bookkeeping runs alongside delivery, not ahead of it. Always
          // joined below so serverless shutdown cannot discard pending writes.
          const incomingSaved = (async () => {
          let conv = null
          try {
            const { data: existing } = await supabase
              .from("conversations")
              .select("id")
              .eq("user_id", user.id)
              .eq("recipient_id", senderId)
              .single()

            if (!existing) {
              let realUsername = `cnt_${senderId.slice(0, 5)}...`
              const profile = await fetchProfile(user.access_token, senderId)
              if (profile?.username) realUsername = profile.username

              const { data: newConv } = await supabase
                .from("conversations")
                .insert({
                  user_id: user.id,
                  recipient_id: senderId,
                  recipient_username: realUsername,
                  last_message_at: new Date().toISOString(),
                })
                .select("id")
                .single()
              conv = newConv
            } else {
              conv = existing
              await supabase
                .from("conversations")
                .update({ last_message_at: new Date().toISOString() })
                .eq("id", existing.id)
            }

            if (conv) {
              await supabase.from("messages").upsert({
                id: mid || event.message?.mid || `mid_${Date.now()}_${Math.random()}`,
                conversation_id: conv.id,
                user_id: user.id,
                sender_id: senderId,
                sender_username: "User",
                content: triggerValue,
                is_from_instagram: true,
              })
            }
          } catch (err) {
            console.error(`[webhook] Database error saving incoming message: code=${sanitizeDbCode((err as any)?.code)} category=${sanitizeErrorCategory(err)}`)
          }
          return conv
          })()

          let sendSucceeded = true

          try {
            // ---------- Match automation ----------
            const dmAutomations = automations.filter(
              (a: any) => (a.trigger_source === "dm" || !a.trigger_source) && a.is_active === true,
            )
            let match = null

            const isUnlockEvent = triggerType === "postback" && triggerValue.startsWith("UNLOCK_CONTENT_")

            if (triggerType === "postback") {
              if (isUnlockEvent) {
                const ruleId = triggerValue.replace("UNLOCK_CONTENT_", "")
                match = dmAutomations.find((a: any) => a.id === ruleId)
              } else if (triggerValue.startsWith("ICE_BREAKER_")) {
                const iceBreakerId = triggerValue.replace("ICE_BREAKER_", "")
                const { data: ib } = await supabase
                  .from("ice_breakers")
                  .select("*")
                  .eq("id", iceBreakerId)
                  .eq("user_id", user.id)
                  .single()
                if (ib) {
                  match = { name: "Ice Breaker: " + ib.question, response_content: { message: ib.response }, id: `ib_${ib.id}` }
                }
              } else {
                match = dmAutomations.find((a: any) => a.trigger_type === "postback" && a.trigger_value === triggerValue)
                // Quick reply payloads can also match keyword rules
                if (!match) {
                  match = dmAutomations.find(
                    (a: any) => a.trigger_type === "keyword" && keywordMatches(a.trigger_value, triggerValue.toLowerCase()),
                  )
                }
              }
            } else {
              match = dmAutomations.find(
                (a: any) => a.trigger_type === "keyword" && keywordMatches(a.trigger_value, triggerValue),
              )
            }

            if (!match) {
              // AI fallback: if no keyword rule matched, try AI auto-reply
              if (user.groq_auto_reply_enabled && triggerType !== "postback") {
                console.log("[webhook] 🤖 No rule match — trying AI auto-reply for DM")
                await sendSenderAction(user.access_token, senderId, "mark_seen")
                const conv = await incomingSaved // AI needs history; keyword replies do not.
                const { data: recentMessages } = conv
                  ? await supabase
                      .from("messages")
                      .select("content, is_from_instagram")
                      .eq("conversation_id", conv.id)
                      .order("created_at", { ascending: false })
                      .limit(10)
                  : { data: [] }
                const history = (recentMessages || []).reverse().map((message: any) => ({
                  role: message.is_from_instagram ? "user" as const : "assistant" as const,
                  content: message.content,
                }))
                const aiReply = await generateAIReply(triggerValue, user.ai_context || "", history, user.groq_api_key, user.ai_base_url, user.ai_model)
                if (aiReply) {
                  await sendSenderAction(user.access_token, senderId, "typing_on")
                  const result = await sendTextDM(user.access_token, { id: senderId }, aiReply)
                  if (!result?.ok) {
                    sendSucceeded = false
                  }
                  if (result?.ok && conv) {
                    try {
                      await supabase.from("messages").insert({
                        id: `mid_ai_${Date.now()}_${Math.random()}`,
                        conversation_id: conv.id,
                        user_id: user.id,
                        sender_id: user.business_account_id,
                        sender_username: user.username,
                        content: aiReply,
                        is_from_instagram: false,
                      })
                    } catch (e) {
                      console.error(`[webhook] Database error saving AI reply: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                    }
                  }
                }
              }
              if (!sendSucceeded && claimId) {
                console.warn("[webhook] AI DM reply failed, releasing claim for retry")
                await releaseWebhookEventClaim(supabase, claimId)
              }
              continue
            }

                    if (!match) continue

                    console.log("[webhook] ✅ DM rule matched")
                    const content = parseContent(match.response_content)

                    // Mark message as seen for human-like flow
                    if (content.mark_seen !== false) {
                      await sendSenderAction(user.access_token, senderId, "mark_seen")
                    }

                    // ---------- Follow gate for DMs ----------
                    const attemptKey = unlockKey(senderId, match.id)

                    if (content.check_follow === true) {
                      if (isUnlockEvent) {
                        // Explicit unlock path: user tapped "I Followed!" — re-verify before delivering.
                        // Rate-limit gate cards on unverifiable results; after N attempts, send a single
                        // "we couldn't verify" message and stop responding for this sender+rule.
                        const followResult = await verifyFollowStatus(senderId, user.access_token)

                        if (followResult.follows === true) {
                          await clearUnlockAttempts(attemptKey)
                          console.log("[webhook] ✅ DM unlock verified")
                          const result = await sendAutomationResponse(user.access_token, { id: senderId }, content)
                          if (!result?.ok) sendSucceeded = false
                          const conv = await incomingSaved
                          if (result?.ok && conv) {
                            try {
                              await supabase.from("messages").insert({
                                id: `mid_reply_${Date.now()}_${Math.random()}`,
                                conversation_id: conv.id,
                                user_id: user.id,
                                sender_id: user.business_account_id,
                                sender_username: user.username,
                                content: responsePreviewText(content),
                                is_from_instagram: false,
                              })
                            } catch (e) {
                              console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                            }
                          }
                        } else if (followResult.follows === false) {
                          await clearUnlockAttempts(attemptKey)
                          console.log("[webhook] ❌ DM unlock rejected: follower check returned false")
                          const result = await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id, title: "❌ Not Following Yet!", subtitle: `We couldn't verify your follow. Please follow @${user.username} and click the button again.` }))
                          if (!result?.ok) sendSucceeded = false
                          const conv = await incomingSaved
                          if (result?.ok && conv) {
                            try {
                              await supabase.from("messages").insert({
                                id: `mid_reply_${Date.now()}_${Math.random()}`,
                                conversation_id: conv.id,
                                user_id: user.id,
                                sender_id: user.business_account_id,
                                sender_username: user.username,
                                content: "[Verification Failed]",
                                is_from_instagram: false,
                              })
                            } catch (e) {
                              console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                            }
                          }
                        } else {
                                                  // null → unverifiable. Cap the loop.
                                                  const attempts = await bumpUnlockAttempt(attemptKey)
                                                  if (attempts > UNLOCK_GATE_MAX_ATTEMPTS) {
                                                    await clearUnlockAttempts(attemptKey)
                                                    const safeAttempts = typeof attempts === "number" && Number.isInteger(attempts) && attempts > 0 ? attempts : "unknown"
                                                    console.warn(`[webhook] ⚠️ DM unlock gate capped after ${safeAttempts} unverifiable attempts`)
                                                    const result = await sendTextDM(
                                                      user.access_token,
                                                      { id: senderId },
                                                      "⚠️ We couldn't verify your follow yet. Please reach out if this keeps happening.",
                                                    )
                                                    if (!result?.ok) sendSucceeded = false
                                                    const conv = await incomingSaved
                                                    if (result?.ok && conv) {
                                                      try {
                                                        await supabase.from("messages").insert({
                                                          id: `mid_reply_${Date.now()}_${Math.random()}`,
                                                          conversation_id: conv.id,
                                                          user_id: user.id,
                                                          sender_id: user.business_account_id,
                                                          sender_username: user.username,
                                                          content: "[Verification Unavailable — capped]",
                                                          is_from_instagram: false,
                                                        })
                                                      } catch (e) {
                                                        console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                                                      }
                                                    }
                                                  } else {
                                                    const safeAttempts = typeof attempts === "number" && Number.isInteger(attempts) && attempts > 0 ? attempts : "unknown"
                                                    console.warn(`[webhook] ⚠️ DM unlock unverifiable (attempt ${safeAttempts}/${UNLOCK_GATE_MAX_ATTEMPTS})`)
                                                    const result = await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id, subtitle: `Please follow @${user.username} to see this!` }))
                                                    if (!result?.ok) sendSucceeded = false
                                                    const conv = await incomingSaved
                                                    if (result?.ok && conv) {
                                                      try {
                                                        await supabase.from("messages").insert({
                                                          id: `mid_reply_${Date.now()}_${Math.random()}`,
                                                          conversation_id: conv.id,
                                                          user_id: user.id,
                                                          sender_id: user.business_account_id,
                                                          sender_username: user.username,
                                                          content: `[Locked Content Gate — attempt ${attempts}/${UNLOCK_GATE_MAX_ATTEMPTS}]`,
                                                          is_from_instagram: false,
                                                        })
                                                      } catch (e) {
                                                        console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                                                      }
                                                    }
                                                  }
                                                }
                                              } else {
                                                // Initial keyword/postback (not the unlock event) — verify once before locking
                                                const followResult = await verifyFollowStatus(senderId, user.access_token)

                                                if (followResult.follows === true) {
                          await clearUnlockAttempts(attemptKey)
                          console.log("[webhook] ✅ DM follower gate: follower verified — sending content")
                          const result = await sendAutomationResponse(user.access_token, { id: senderId }, content)
                          if (!result?.ok) sendSucceeded = false
                          const conv = await incomingSaved
                          if (result?.ok && conv) {
                            try {
                              await supabase.from("messages").insert({
                                id: `mid_reply_${Date.now()}_${Math.random()}`,
                                conversation_id: conv.id,
                                user_id: user.id,
                                sender_id: user.business_account_id,
                                sender_username: user.username,
                                content: responsePreviewText(content),
                                is_from_instagram: false,
                              })
                            } catch (e) {
                              console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                            }
                          }
                        } else if (followResult.follows === false) {
                          await clearUnlockAttempts(attemptKey)
                          console.log("[webhook] 🔒 DM follower gate: non-follower detected")
                          const result = await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id, subtitle: `Please follow @${user.username} to see this!` }))
                          if (!result?.ok) sendSucceeded = false
                          const conv = await incomingSaved
                          if (result?.ok && conv) {
                            try {
                              await supabase.from("messages").insert({
                                id: `mid_reply_${Date.now()}_${Math.random()}`,
                                conversation_id: conv.id,
                                user_id: user.id,
                                sender_id: user.business_account_id,
                                sender_username: user.username,
                                content: "[Locked Content Gate]",
                                is_from_instagram: false,
                              })
                            } catch (e) {
                              console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                            }
                          }
                        } else {
                          // null → unverifiable. Distinguish auth vs transient. Auth fail-CLOSED:
                          // send gate, don't deliver content (matches comment/story branches).
                          // Only transient 5xx/timeouts fail OPEN and deliver content.
                          const isAuthError = followResult.error === 'auth'
                          if (isAuthError) {
                            console.warn("[webhook] ⚠️ DM follower gate auth failure; sending gate")
                            const result = await sendCardDM(user.access_token, { id: senderId }, buildFollowGateCard({ username: user.username, ruleId: match.id, title: "❌ Verification Failed", subtitle: `We can't verify your follow status. Please follow @${user.username} and try again.` }))
                            if (!result?.ok) sendSucceeded = false
                            const conv = await incomingSaved
                            if (result?.ok && conv) {
                              try {
                                await supabase.from("messages").insert({
                                  id: `mid_reply_${Date.now()}_${Math.random()}`,
                                  conversation_id: conv.id,
                                  user_id: user.id,
                                  sender_id: user.business_account_id,
                                  sender_username: user.username,
                                  content: "[Auth Failure — Gate Sent]",
                                  is_from_instagram: false,
                                })
                              } catch (e) {
                                console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                              }
                            }
                          } else {
                            // Transient failure — fail OPEN on initial trigger
                            console.warn("[webhook] ⚠️ DM follower gate transient failure; failing open on initial trigger")
                            const result = await sendAutomationResponse(user.access_token, { id: senderId }, content)
                            if (!result?.ok) sendSucceeded = false
                            const conv = await incomingSaved
                            if (result?.ok && conv) {
                              try {
                                await supabase.from("messages").insert({
                                  id: `mid_reply_${Date.now()}_${Math.random()}`,
                                  conversation_id: conv.id,
                                  user_id: user.id,
                                  sender_id: user.business_account_id,
                                  sender_username: user.username,
                                  content: responsePreviewText(content),
                                  is_from_instagram: false,
                                })
                              } catch (e) {
                                console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                              }
                            }
                          }
                        }
                      }
                    } else {
                      // No follower check required
                      const result = await sendAutomationResponse(user.access_token, { id: senderId }, content)
                      if (!result?.ok) sendSucceeded = false
                      const conv = await incomingSaved
                      if (result?.ok && conv) {
                        try {
                          await supabase.from("messages").insert({
                            id: `mid_reply_${Date.now()}_${Math.random()}`,
                            conversation_id: conv.id,
                            user_id: user.id,
                            sender_id: user.business_account_id,
                            sender_username: user.username,
                            content: responsePreviewText(content),
                            is_from_instagram: false,
                          })
                        } catch (e) {
                          console.error(`[webhook] Database error saving outgoing message: code=${sanitizeDbCode((e as any)?.code)} category=${sanitizeErrorCategory(e)}`)
                        }
                      }
                    }

              if (!sendSucceeded && claimId) {
                console.warn("[webhook] DM reply failed, releasing claim for retry")
                await releaseWebhookEventClaim(supabase, claimId)
              }
            } finally {
              await incomingSaved
            }
          } catch (dmErr) {
            console.error(`[webhook] Error processing DM event: category=${sanitizeErrorCategory(dmErr)}`)
            if (claimId) {
              await releaseWebhookEventClaim(supabase, claimId)
            }
          }
        }
      }
    }
    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error(`[webhook] Top-level handler error: category=${sanitizeErrorCategory(error)}`)
    return NextResponse.json({ ok: true })
  }
}
