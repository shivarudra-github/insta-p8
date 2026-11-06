const GRAPH = "https://graph.instagram.com/v24.0"

function sanitizeHttpStatus(status: unknown): number | "unknown_status" {
  if (typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599) {
    return status
  }
  return "unknown_status"
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

export interface IGButton {
  type: "web_url" | "postback"
  title: string
  url?: string
  payload?: string
}

export interface IGCard {
  title: string
  subtitle?: string
  image_url?: string
  buttons: IGButton[]
}

export interface QuickReply {
  title: string
  payload: string
}

/**
 * Typed provider outcome for every outgoing Meta Graph API call.
 *
 * - confirmed_success: Meta confirmed acceptance; safe to mark the action completed.
 * - confirmed_rejection: the response reliably establishes the message was NOT
 *   accepted (e.g. 4xx). Safe to mark retryable (429) or permanently_failed.
 * - ambiguous: a timeout, connection reset, lost response, uncertain 5xx, or
 *   malformed response after the request may have reached Meta. Never mark
 *   retryable — mark unknown and require review.
 */
export type SendOutcome =
  | { kind: "confirmed_success"; message_id: string }
  | { kind: "confirmed_rejection"; status: number; error?: any }
  | {
      kind: "ambiguous"
      reason: "timeout" | "network_error" | "uncertain_server" | "malformed_response"
      status?: number
      error?: any
    }

export interface SendResult {
  ok: boolean
  id?: string
  error?: any
}

function outcomeToSendResult(outcome: SendOutcome): SendResult {
  if (outcome.kind === "confirmed_success") {
    return { ok: true, id: outcome.message_id }
  }
  return { ok: false, error: outcome.error }
}

async function post(path: string, token: string, body: any): Promise<SendOutcome> {
  let res: Response
  try {
    res = await fetch(`${GRAPH}/${path}?access_token=${encodeURIComponent(token)}`, {
      method: "POST",
      signal: AbortSignal.timeout(15000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
  } catch (e) {
    // The request never reached Meta (timeout / DNS / connection reset).
    // Acceptance cannot be ruled out → ambiguous, never retryable.
    const category = sanitizeErrorCategory(e)
    return {
      kind: "ambiguous",
      reason: category === "timeout" ? "timeout" : "network_error",
      error: e,
    }
  }

  const status = res.status
  let json: Record<string, unknown> | null = null
  let parseError: unknown = null
  try {
    json = (await res.json()) as Record<string, unknown> | null
  } catch (e) {
    parseError = e
  }

  const hasJsonError = Boolean(json && json.error)

  // Confirmed acceptance: 2xx, no error in the body, AND a valid provider
  // message id. A 2xx without a provider message id is not a confirmed
  // message delivery — never manufacture an id (e.g. String(status)) to fake
  // success. Treat it as ambiguous so the action is marked unknown and never
  // auto-resent.
  if (res.ok && !hasJsonError) {
    const messageId = (json?.id || json?.message_id) as string | undefined
    if (messageId) {
      return { kind: "confirmed_success", message_id: messageId }
    }
    return {
      kind: "ambiguous",
      reason: "uncertain_server",
      status,
      error: "no_provider_message_id",
    }
  }

  // 4xx = definitive non-acceptance (confirmed rejection).
  if (status >= 400 && status < 500) {
    return { kind: "confirmed_rejection", status, error: hasJsonError ? json?.error : `HTTP ${status}` }
  }

  // 5xx or conflicting 2xx-with-error = ambiguous; Meta may have accepted
  // before the response was lost. Never retry automatically.
  return {
    kind: "ambiguous",
    reason: "uncertain_server",
    status,
    error: hasJsonError ? json?.error : parseError,
  }
}

export function buildCardAttachment(card: IGCard) {
  const buttons = (card.buttons || [])
    .filter((b) => b.title)
    .map((b) => ({
      type: b.type,
      title: b.title,
      url: b.type === "web_url" ? b.url : undefined,
      payload: b.type === "postback" ? b.payload : undefined,
    }))
  const element: any = { title: card.title, buttons }
  if (card.subtitle) element.subtitle = card.subtitle
  if (card.image_url?.startsWith("http")) element.image_url = card.image_url
  return {
    attachment: {
      type: "template",
      payload: { template_type: "generic", elements: [element] },
    },
  }
}

export function buildFollowGateCard(params: {
  username: string
  ruleId: string
  title?: string
  subtitle?: string
}): IGCard {
  return {
    title: params.title ?? "Before you lose me",
    subtitle: params.subtitle ?? `Follow @${params.username} to unlock this content!`,
    buttons: [
      { type: "web_url", url: `https://instagram.com/${params.username}`, title: "Follow" },
      { type: "postback", title: "I Followed! ✅", payload: `UNLOCK_CONTENT_${params.ruleId}` },
    ],
  }
}

export async function sendTextDM(
  token: string,
  recipient: { id?: string; comment_id?: string },
  text: string,
  quickReplies?: QuickReply[],
): Promise<SendOutcome> {
  const message: any = { text }
  if (quickReplies?.length) {
    message.quick_replies = quickReplies.slice(0, 13).map((q) => ({
      content_type: "text",
      title: q.title.slice(0, 20),
      payload: q.payload,
    }))
  }
  return await post("me/messages", token, { recipient, message })
}

export async function sendCardDM(
  token: string,
  recipient: { id?: string; comment_id?: string },
  card: IGCard,
): Promise<SendOutcome> {
  return await post("me/messages", token, { recipient, message: buildCardAttachment(card) })
}

export async function sendMediaDM(
  token: string,
  recipient: { id?: string; comment_id?: string },
  mediaType: "image" | "video" | "audio",
  url: string,
): Promise<SendOutcome> {
  return await post("me/messages", token, {
    recipient,
    message: { attachment: { type: mediaType, payload: { url } } },
  })
}

export async function sendSenderAction(
  token: string,
  recipientId: string,
  action: "typing_on" | "typing_off" | "mark_seen",
): Promise<SendOutcome> {
  return await post("me/messages", token, { recipient: { id: recipientId }, sender_action: action })
}

export async function sendMessageReaction(
  token: string,
  recipientId: string,
  messageId: string,
  reaction = "love",
): Promise<SendOutcome> {
  return await post("me/messages", token, {
    recipient: { id: recipientId },
    sender_action: "react",
    payload: { message_id: messageId, reaction },
  })
}

export async function replyToComment(token: string, commentId: string, message: string): Promise<SendOutcome> {
  return await post(`${commentId}/replies`, token, { message })
}

export async function fetchProfile(token: string, igUserId: string): Promise<{ username?: string; name?: string } | null> {
  try {
    const res = await fetch(`${GRAPH}/${igUserId}?fields=username,name&access_token=${encodeURIComponent(token)}`, { signal: AbortSignal.timeout(5000) })
    const json = await res.json()
    if (!res.ok || json.error) return null
    return json
  } catch {
    return null
  }
}

export async function verifyIdOwnership(token: string, id: string): Promise<boolean> {
  try {
    const res = await fetch(`${GRAPH}/${id}?fields=id&access_token=${encodeURIComponent(token)}`, { signal: AbortSignal.timeout(5000) })
    return res.ok
  } catch {
    return false
  }
}

export function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, Math.min(ms, 8000)))
}

export { sanitizeHttpStatus, sanitizeErrorCategory, outcomeToSendResult }
