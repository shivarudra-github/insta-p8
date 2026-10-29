import test, { describe, it, beforeEach } from "node:test"
import assert from "node:assert"
import crypto from "crypto"

// Set a dedicated high-entropy test SESSION_SECRET
const TEST_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
process.env.SESSION_SECRET = TEST_SECRET
process.env.TEST_USE_MOCK_SUPABASE = "true"

import { NextRequest } from "next/server.js"

// Unit modules
import {
  createSessionToken,
  verifySessionToken,
  parseAndValidatePayload,
  verifySessionSecretConfigured,
  getSessionSecret,
  getSessionCookieOptions,
} from "../lib/session.ts"

import { validateAiBaseUrl } from "../lib/ai-validation.ts"

// Actual Route Handlers (tested with NextRequest)
import * as authMe from "../app/api/auth/me/route.ts"
import * as authLogout from "../app/api/auth/logout/route.ts"
import * as automations from "../app/api/automations/route.ts"
import * as businessProfile from "../app/api/business-profile/route.ts"
import * as dashboardStats from "../app/api/dashboard/stats/route.ts"
import * as groqAutoReply from "../app/api/groq/auto-reply/route.ts"
import * as iceBreakers from "../app/api/ice-breakers/route.ts"
import * as inboxConversations from "../app/api/inbox/conversations/route.ts"
import * as inboxMessages from "../app/api/inbox/messages/route.ts"
import * as inboxSend from "../app/api/inbox/send/route.ts"
import * as instagramCallback from "../app/api/instagram/callback/route.ts"
import * as instagramMedia from "../app/api/instagram/media/route.ts"
import * as instagramSendMessage from "../app/api/instagram/send-message/route.ts"
import * as instagramTestLogin from "../app/api/instagram/test-login/route.ts"
import * as instagramWebhook from "../app/api/instagram/webhook/route.ts"

import { mockStore, resetMockStore } from "./supabase-mock.ts"

describe("Security Test Suite — Phase 1 Remediation", () => {
  // =========================================================================
  // SECTION A: UNIT TESTS (Helper & Crypto Logic, In-Process, Zero Mocks)
  // =========================================================================
  describe("[UNIT] Cryptographic Session Infrastructure (lib/session.ts)", () => {
    it("AUTH-01: Generates valid HMAC-SHA256 session token and verifies payload", () => {
      const token = createSessionToken({ userId: "1001", username: "creator_alice" })
      assert.ok(token.includes("."), "Token must contain payload and signature separator")

      const payload = verifySessionToken(token)
      assert.ok(payload !== null, "Verified payload must not be null")
      assert.strictEqual(payload.userId, "1001")
      assert.strictEqual(payload.username, "creator_alice")
      assert.ok(payload.issuedAt <= Date.now())
      assert.ok(payload.expiresAt > Date.now())
    })

    it("AUTH-02: Rejects tampered HMAC signature", () => {
      const token = createSessionToken({ userId: "1001", username: "creator_alice" })
      const [payloadPart, sigPart] = token.split(".")
      const tamperedSig = sigPart.slice(0, -1) + (sigPart.slice(-1) === "a" ? "b" : "a")
      const tamperedToken = `${payloadPart}.${tamperedSig}`

      assert.strictEqual(verifySessionToken(tamperedToken), null)
    })

    it("AUTH-02b: Rejects cross-matched payload and signature from different tokens", () => {
      const token1 = createSessionToken({ userId: "1001", username: "alice" })
      const token2 = createSessionToken({ userId: "1002", username: "bob" })
      const [payload1] = token1.split(".")
      const [, sig2] = token2.split(".")
      assert.strictEqual(verifySessionToken(`${payload1}.${sig2}`), null)
    })

    it("AUTH-03: Rejects expired session token", () => {
      const expiredToken = createSessionToken({ userId: "1001", username: "alice" }, -10 * 1000)
      assert.strictEqual(verifySessionToken(expiredToken), null)
    })

    it("AUTH-04: Rejects future clock-skew token claiming to be issued in future", () => {
      const now = Date.now()
      const futurePayload = {
        userId: "1001",
        username: "alice",
        issuedAt: now + 5 * 60 * 1000,
        expiresAt: now + 60 * 24 * 60 * 60 * 1000,
      }
      assert.strictEqual(parseAndValidatePayload(JSON.stringify(futurePayload)), null)
    })

    it("AUTH-05: Rejects malformed JSON or invalid types in payload", () => {
      assert.strictEqual(parseAndValidatePayload("not-json"), null)
      assert.strictEqual(parseAndValidatePayload(JSON.stringify({ userId: "", username: "alice" })), null)
      assert.strictEqual(parseAndValidatePayload(JSON.stringify({ userId: 12345, username: "alice" })), null)
      assert.strictEqual(parseAndValidatePayload(JSON.stringify({ userId: "123", username: "" })), null)
      assert.strictEqual(parseAndValidatePayload(JSON.stringify({ userId: "123", username: "alice", issuedAt: "nan" })), null)
    })

    it("AUTH-06: Fail-closed guard throws when SESSION_SECRET is missing or < 32 characters", () => {
      const original = process.env.SESSION_SECRET
      try {
        delete process.env.SESSION_SECRET
        assert.strictEqual(verifySessionSecretConfigured().configured, false)
        assert.throws(() => getSessionSecret(), /SESSION_SECRET missing or invalid/)

        process.env.SESSION_SECRET = "too-short-secret"
        assert.strictEqual(verifySessionSecretConfigured().adequateLength, false)
        assert.throws(() => getSessionSecret(), /SESSION_SECRET missing or invalid/)
      } finally {
        process.env.SESSION_SECRET = original
      }
    })

    it("AUTH-07: Cookie options enforce HttpOnly and SameSite=Lax", () => {
      const opts = getSessionCookieOptions()
      assert.strictEqual(opts.httpOnly, true)
      assert.strictEqual(opts.sameSite, "lax")
      assert.strictEqual(opts.path, "/")
    })
  })

  describe("[UNIT] OAuth State Timing-Safe Validation", () => {
    function verifyState(incoming, stored) {
      if (!incoming || !stored) return false
      const incomingBuf = Buffer.from(incoming, "utf8")
      const storedBuf = Buffer.from(stored, "utf8")
      if (incomingBuf.length === 0 || incomingBuf.length !== storedBuf.length) return false
      return crypto.timingSafeEqual(incomingBuf, storedBuf)
    }

    it("OAUTH-01: Accepts identical matching state nonce", () => {
      const state = crypto.randomBytes(32).toString("hex")
      assert.strictEqual(verifyState(state, state), true)
    })

    it("OAUTH-02: Rejects unequal length states without throwing RangeError", () => {
      assert.strictEqual(verifyState("short", "much_longer_state_string"), false)
    })

    it("OAUTH-03: Rejects missing, null, or empty states", () => {
      assert.strictEqual(verifyState(null, "state"), false)
      assert.strictEqual(verifyState("state", null), false)
      assert.strictEqual(verifyState("", "state"), false)
    })

    it("OAUTH-04: Rejects mismatched states of identical length", () => {
      assert.strictEqual(
        verifyState("0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdeg"),
        false
      )
    })
  })

  describe("[UNIT] AI Base URL SSRF Prevention (lib/ai-validation.ts)", () => {
    it("SSRF-01: Accepts approved providers over HTTPS", () => {
      assert.strictEqual(validateAiBaseUrl("https://api.groq.com/openai/v1").valid, true)
      assert.strictEqual(validateAiBaseUrl("https://api.openai.com/v1").valid, true)
      assert.strictEqual(validateAiBaseUrl("https://openrouter.ai/api/v1").valid, true)
    })

    it("SSRF-02: Rejects unapproved hostnames", () => {
      assert.strictEqual(validateAiBaseUrl("https://evil-attacker.com/v1").valid, false)
    })

    it("SSRF-03: Rejects non-HTTPS protocols", () => {
      assert.strictEqual(validateAiBaseUrl("http://api.groq.com/v1").valid, false)
      assert.strictEqual(validateAiBaseUrl("file:///etc/passwd").valid, false)
    })

    it("SSRF-04: Rejects embedded user credentials in URL", () => {
      assert.strictEqual(validateAiBaseUrl("https://user:password@api.groq.com/v1").valid, false)
    })

    it("SSRF-05: Rejects cloud metadata and loopback IP addresses", () => {
      assert.strictEqual(validateAiBaseUrl("http://169.254.169.254/latest/meta-data").valid, false)
      assert.strictEqual(validateAiBaseUrl("https://127.0.0.1:8000/").valid, false)
    })

    it("SSRF-06: Rejects non-standard ports", () => {
      assert.strictEqual(validateAiBaseUrl("https://api.groq.com:8443/v1").valid, false)
    })
  })

  // =========================================================================
  // SECTION B: INTEGRATION TESTS (Direct Route Handler Executions)
  // =========================================================================
  describe("[INTEGRATION] Route Handlers — Unauthenticated Rejection (HTTP 401)", () => {
    it("ROUTE-AUTH-01: GET /api/automations without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations")
      const res = await automations.GET(req)
      assert.strictEqual(res.status, 401)
      const data = await res.json()
      assert.ok(data.error?.includes("Unauthorized"))
    })

    it("ROUTE-AUTH-02: POST /api/automations without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations", {
        method: "POST",
        body: JSON.stringify({ name: "test", trigger_source: "comment", trigger_value: "hi", content: "hello" }),
      })
      const res = await automations.POST(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-03: DELETE /api/automations without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations?id=some_rule_id", { method: "DELETE" })
      const res = await automations.DELETE(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-04: GET /api/business-profile with legacy raw-JSON cookie -> 401 (Tamper rejection)", async () => {
      const req = new NextRequest("http://localhost:3000/api/business-profile", {
        headers: { Cookie: 'insta_session={"userId":"victim_user","username":"victim"}' },
      })
      const res = await businessProfile.GET(req)
      assert.strictEqual(res.status, 401)
      const data = await res.json()
      assert.ok(data.error?.includes("Unauthorized"))
    })

    it("ROUTE-AUTH-05: GET /api/dashboard/stats without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/dashboard/stats")
      const res = await dashboardStats.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-06: GET /api/groq/auto-reply without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/groq/auto-reply")
      const res = await groqAutoReply.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-07: PUT /api/groq/auto-reply without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/groq/auto-reply", {
        method: "PUT",
        body: JSON.stringify({ enabled: true }),
      })
      const res = await groqAutoReply.PUT(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-08: GET /api/ice-breakers without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/ice-breakers")
      const res = await iceBreakers.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-09: GET /api/inbox/conversations without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/inbox/conversations")
      const res = await inboxConversations.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-10: GET /api/inbox/messages without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/inbox/messages?conversationId=conv_123")
      const res = await inboxMessages.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-11: POST /api/inbox/send without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/inbox/send", {
        method: "POST",
        body: JSON.stringify({ recipientId: "rec_1", message: "hi" }),
      })
      const res = await inboxSend.POST(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-12: GET /api/instagram/media without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/media")
      const res = await instagramMedia.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-13: POST /api/instagram/send-message without session cookie -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/send-message", {
        method: "POST",
        body: JSON.stringify({ recipient_id: "rec_1", message: "hi" }),
      })
      const res = await instagramSendMessage.POST(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-14: GET /api/auth/me with expired session cookie -> 401", async () => {
      const expiredToken = createSessionToken({ userId: "alice_1", username: "alice" }, -1000)
      const req = new NextRequest("http://localhost:3000/api/auth/me", {
        headers: { Cookie: `insta_session=${expiredToken}` },
      })
      const res = await authMe.GET(req)
      assert.strictEqual(res.status, 401)
    })

    it("ROUTE-AUTH-15: GET /api/auth/me with valid session cookie -> 200", async () => {
      const validToken = createSessionToken({ userId: "alice_1", username: "alice" })
      const req = new NextRequest("http://localhost:3000/api/auth/me", {
        headers: { Cookie: `insta_session=${validToken}` },
      })
      const res = await authMe.GET(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.authenticated, true)
      assert.strictEqual(data.user.userId, "alice_1")
      assert.strictEqual(data.user.username, "alice")
    })
  })

  describe("[INTEGRATION] Route Handlers — Cross-User Isolation & IDOR Blocking", () => {
    const ALICE_ID = "user_alice_111"
    const BOB_ID = "user_bob_222"
    let aliceToken

    beforeEach(() => {
      resetMockStore()
      aliceToken = createSessionToken({ userId: ALICE_ID, username: "alice" })

      // Seed mock database with Bob's data
      mockStore.automations.push({
        id: "rule_bob_secret",
        user_id: BOB_ID,
        name: "Bob's Secret Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "secret",
        response_content: "Bob's response",
        is_active: true,
      })

      mockStore.conversations.push({
        id: "conv_bob_private",
        user_id: BOB_ID,
        recipient_id: "recipient_99",
      })

      mockStore.messages.push({
        id: "msg_bob_secret",
        conversation_id: "conv_bob_private",
        user_id: BOB_ID,
        content: "Top secret DM content of Bob",
      })

      mockStore.users.push({
        id: BOB_ID,
        access_token: "bob_confidential_ig_access_token",
        username: "bob_official",
      })
    })

    it("ROUTE-IDOR-01: Alice cannot query Bob's automations via ?userId=BOB_ID -> 403", async () => {
      const req = new NextRequest(`http://localhost:3000/api/automations?userId=${BOB_ID}`, {
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await automations.GET(req)
      assert.strictEqual(res.status, 403)
      const data = await res.json()
      assert.ok(data.error?.includes("Forbidden"))
    })

    it("ROUTE-IDOR-02: Alice cannot create an automation with body.userId = BOB_ID -> 403", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations", {
        method: "POST",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({
          userId: BOB_ID,
          name: "Alice Impersonating Bob",
          trigger_source: "comment",
          trigger_value: "spoof",
          content: "spoofed",
        }),
      })
      const res = await automations.POST(req)
      assert.strictEqual(res.status, 403)
      assert.strictEqual(mockStore.automations.filter((a) => a.user_id === BOB_ID).length, 1)
    })

    it("ROUTE-IDOR-03: Alice cannot delete Bob's automation rule -> 404 (Per-record ownership enforced)", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations?id=rule_bob_secret", {
        method: "DELETE",
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await automations.DELETE(req)
      assert.strictEqual(res.status, 404)
      // Confirm Bob's rule was NOT deleted
      assert.strictEqual(mockStore.automations.some((a) => a.id === "rule_bob_secret"), true)
    })

    it("ROUTE-IDOR-04: Alice cannot read Bob's business profile via ?userId=BOB_ID -> 403", async () => {
      const req = new NextRequest(`http://localhost:3000/api/business-profile?userId=${BOB_ID}`, {
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await businessProfile.GET(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-05: Alice cannot read Bob's dashboard stats via ?userId=BOB_ID -> 403", async () => {
      const req = new NextRequest(`http://localhost:3000/api/dashboard/stats?userId=${BOB_ID}`, {
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await dashboardStats.GET(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-06: Alice cannot read Bob's private messages by specifying Bob's conversationId -> 404", async () => {
      const req = new NextRequest("http://localhost:3000/api/inbox/messages?conversationId=conv_bob_private", {
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await inboxMessages.GET(req)
      assert.strictEqual(res.status, 404)
      const data = await res.json()
      assert.ok(data.error?.includes("not owned by user"))
    })

    it("ROUTE-IDOR-07: Alice cannot send DMs under Bob's identity with body.userId = BOB_ID -> 403", async () => {
      const req = new NextRequest("http://localhost:3000/api/inbox/send", {
        method: "POST",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({ userId: BOB_ID, recipientId: "target", message: "phish" }),
      })
      const res = await inboxSend.POST(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-08: Alice cannot query Bob's Instagram media with ?userId=BOB_ID -> 403", async () => {
      const req = new NextRequest(`http://localhost:3000/api/instagram/media?userId=${BOB_ID}`, {
        headers: { Cookie: `insta_session=${aliceToken}` },
      })
      const res = await instagramMedia.GET(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-09: Alice cannot save unapproved AI base URL via PUT /api/groq/auto-reply -> 400", async () => {
      const req = new NextRequest("http://localhost:3000/api/groq/auto-reply", {
        method: "PUT",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({ ai_base_url: "https://attacker-exfiltration.com/v1" }),
      })
      const res = await groqAutoReply.PUT(req)
      assert.strictEqual(res.status, 400)
      const data = await res.json()
      assert.ok(data.error?.includes("not approved"))
    })

    it("ROUTE-IDOR-10: Alice cannot update Bob's automation rule -> 404 (Per-record ownership enforced)", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations", {
        method: "PUT",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({
          id: "rule_bob_secret",
          name: "Alice Hacked Bob",
          trigger_source: "comment",
          trigger_value: "hacked",
          content: "hacked",
        }),
      })
      const res = await automations.PUT(req)
      assert.strictEqual(res.status, 404)
      const bobRule = mockStore.automations.find((a) => a.id === "rule_bob_secret")
      assert.strictEqual(bobRule.name, "Bob's Secret Rule")
    })

    it("ROUTE-IDOR-11: Alice cannot update automations with body.userId = BOB_ID -> 403", async () => {
      const req = new NextRequest("http://localhost:3000/api/automations", {
        method: "PUT",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({
          userId: BOB_ID,
          id: "rule_bob_secret",
          name: "Alice Spoofing Bob",
          trigger_value: "spoof",
          content: "spoof",
        }),
      })
      const res = await automations.PUT(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-12: Alice cannot send Instagram DM under Bob's user_id -> 403", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/send-message", {
        method: "POST",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({
          user_id: BOB_ID,
          recipient_id: "customer_99",
          message: "impersonation attempt",
        }),
      })
      const res = await instagramSendMessage.POST(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-IDOR-13: Alice cannot access Bob's Instagram token; session-scoped lookup returns 404 for unconfigured user", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/send-message", {
        method: "POST",
        headers: { Cookie: `insta_session=${aliceToken}` },
        body: JSON.stringify({
          recipient_id: "customer_99",
          message: "hello from alice",
        }),
      })
      const res = await instagramSendMessage.POST(req)
      assert.strictEqual(res.status, 404)
      const data = await res.json()
      assert.strictEqual(data.error, "User not found or Instagram not connected")
    })
  })

  describe("[INTEGRATION] Route Handlers — OAuth, Auth Lifecycle, Test-Login & Webhooks", () => {
    it("ROUTE-LIFECYCLE-01: POST /api/auth/logout clears session and state cookies symmetrically", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/logout", { method: "POST" })
      const res = await authLogout.POST(req)
      assert.strictEqual(res.status, 200)

      const cookieHeader = res.headers.get("set-cookie") || ""
      assert.ok(cookieHeader.includes("insta_session="), "Must set-cookie insta_session")
      assert.ok(cookieHeader.includes("Max-Age=0"), "Must set Max-Age=0 to delete session")
    })

    it("ROUTE-LIFECYCLE-02: POST /api/instagram/callback is disabled -> 405 Method Not Allowed", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/callback", {
        method: "POST",
        body: JSON.stringify({ code: "harvested_auth_code" }),
      })
      const res = await instagramCallback.POST(req)
      assert.strictEqual(res.status, 405)
      assert.strictEqual(res.headers.get("Allow"), "GET")
    })

    it("ROUTE-LIFECYCLE-03: POST /api/instagram/test-login in production -> 403 Forbidden", async () => {
      const originalEnv = process.env.NODE_ENV
      try {
        process.env.NODE_ENV = "production"
        const req = new NextRequest("http://localhost:3000/api/instagram/test-login", { method: "POST" })
        const res = await instagramTestLogin.POST(req)
        assert.strictEqual(res.status, 403)
        const data = await res.json()
        assert.strictEqual(data.error, "Not available in production")
      } finally {
        process.env.NODE_ENV = originalEnv
      }
    })

    it("ROUTE-LIFECYCLE-04: GET /api/instagram/webhook handshake verifies session-free with token -> 200", async () => {
      const req = new NextRequest(
        "http://localhost:3000/api/instagram/webhook?hub.mode=subscribe&hub.verify_token=test_webhook_verify_token_123&hub.challenge=test_challenge_999"
      )
      const res = await instagramWebhook.GET(req)
      assert.strictEqual(res.status, 200)
      const text = await res.text()
      assert.strictEqual(text, "test_challenge_999")
    })

    it("ROUTE-LIFECYCLE-05: GET /api/instagram/webhook rejects invalid token session-free -> 403", async () => {
      const req = new NextRequest(
        "http://localhost:3000/api/instagram/webhook?hub.mode=subscribe&hub.verify_token=wrong_token&hub.challenge=123"
      )
      const res = await instagramWebhook.GET(req)
      assert.strictEqual(res.status, 403)
    })

    it("ROUTE-LIFECYCLE-06: POST /api/instagram/webhook without x-hub-signature-256 is rejected -> 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/instagram/webhook", {
        method: "POST",
        body: JSON.stringify({ object: "instagram" }),
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 401)
      const data = await res.json()
      assert.strictEqual(data.error, "Invalid signature")
    })

    it("ROUTE-LIFECYCLE-07: POST /api/instagram/webhook with forged x-hub-signature-256 is rejected -> 401", async () => {
      const payload = JSON.stringify({ object: "instagram" })
      const forgedSig = "sha256=" + crypto.createHmac("sha256", "wrong_secret").update(payload).digest("hex")
      const req = new NextRequest("http://localhost:3000/api/instagram/webhook", {
        method: "POST",
        headers: { "x-hub-signature-256": forgedSig },
        body: payload,
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 401)
      const data = await res.json()
      assert.strictEqual(data.error, "Invalid signature")
    })

    it("ROUTE-LIFECYCLE-08: POST /api/instagram/webhook with valid HMAC-SHA256 signature succeeds session-free -> 200", async () => {
      const payload = JSON.stringify({ object: "instagram" })
      const validSig = "sha256=" + crypto.createHmac("sha256", "test_meta_app_secret_456").update(payload).digest("hex")
      const req = new NextRequest("http://localhost:3000/api/instagram/webhook", {
        method: "POST",
        headers: { "x-hub-signature-256": validSig },
        body: payload,
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)
    })
  })
})
