import test, { describe, it, beforeEach, afterEach } from "node:test"
import assert from "node:assert"
import crypto from "crypto"
import fs from "node:fs"
import path from "node:path"
import ts from "typescript"

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

  describe("[INTEGRATION] Webhook Reliability & Idempotency Phase 1", () => {
    const TEST_USER_ID = "99001"
    const TEST_WEBHOOK_ID = "ig_acc_99001"
    let originalFetch
    let capturedRequests

    function makeSignedWebhookRequest(payloadObj) {
      const payloadStr = JSON.stringify(payloadObj)
      const sig = "sha256=" + crypto.createHmac("sha256", "test_meta_app_secret_456").update(payloadStr).digest("hex")
      return new NextRequest("http://localhost:3000/api/instagram/webhook", {
        method: "POST",
        headers: { "x-hub-signature-256": sig, "Content-Type": "application/json" },
        body: payloadStr,
      })
    }

    beforeEach(() => {
      resetMockStore()
      capturedRequests = []
      originalFetch = globalThis.fetch

      mockStore.users.push({
        id: TEST_USER_ID,
        business_account_id: TEST_WEBHOOK_ID,
        page_id: "page_99001",
        username: "testcreator",
        access_token: "test_token_valid_123",
        groq_auto_reply_enabled: false,
      })

      globalThis.fetch = async (url, opts) => {
        const urlStr = String(url)
        const bodyStr = opts?.body ? (typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body)) : null
        capturedRequests.push({ url: urlStr, method: opts?.method || "GET", body: bodyStr })
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: "mock_resp_123", is_user_follow_business: true, username: "fan_account" }),
          text: async () => JSON.stringify({ id: "mock_resp_123" }),
        }
      }
    })

    afterEach(() => {
      globalThis.fetch = originalFetch
    })

    it("WEBHOOK-01: Comment keyword matching executes reply when keyword matches", async () => {
      mockStore.automations.push({
        id: "rule_comment_price",
        user_id: TEST_USER_ID,
        name: "Price Inquiry",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "price,cost",
        response_content: JSON.stringify({ message: "The price is $20", reply_mode: "both" }),
        is_active: true,
      })

      const req = makeSignedWebhookRequest({
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_test_101",
                  text: "What is the price?",
                  from: { id: "customer_456" },
                  media: { id: "media_888" },
                },
              },
            ],
          },
        ],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)

      // Verify outgoing replies were captured
      assert.ok(capturedRequests.length > 0, "Must have called Instagram API to send reply")
      // Verify idempotency claim was recorded in webhook_events
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].event_type, "comment")
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "comment_test_101")
    })

    it("WEBHOOK-02: Paused automation suppression (is_active: false) never triggers replies", async () => {
      mockStore.automations.push({
        id: "rule_paused_discount",
        user_id: TEST_USER_ID,
        name: "Paused Discount",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "discount,sale",
        response_content: JSON.stringify({ message: "Discount code: SAVE50" }),
        is_active: false,
      })

      const req = makeSignedWebhookRequest({
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_test_102",
                  text: "Can I get a discount?",
                  from: { id: "customer_456" },
                  media: { id: "media_888" },
                },
              },
            ],
          },
        ],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)

      // Verify NO replies were sent
      const replyCalls = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com"))
      assert.strictEqual(replyCalls.length, 0, "Paused automation must NOT trigger any reply")
    })

    it("WEBHOOK-03: DM persistence continues even with 0 active automations", async () => {
      mockStore.automations = [] // Zero active automations

      const req = makeSignedWebhookRequest({
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "fan_321" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: {
                  mid: "mid_test_321_001",
                  text: "Hey! Just wanted to say I love your videos!",
                },
              },
            ],
          },
        ],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)

      // Verify conversation was created
      const conv = mockStore.conversations.find((c) => c.recipient_id === "fan_321")
      assert.ok(conv, "Conversation record must be created")
      assert.strictEqual(conv.user_id, TEST_USER_ID)

      // Verify message was persisted
      const msg = mockStore.messages.find((m) => m.id === "mid_test_321_001")
      assert.ok(msg, "Message record must be saved")
      assert.strictEqual(msg.user_id, TEST_USER_ID)
      assert.strictEqual(msg.content, "hey! just wanted to say i love your videos!")

      // Verify deduplication claim was recorded
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.mid, "mid_test_321_001")
    })

    it("WEBHOOK-04: Duplicate comment suppression skips replies on replayed webhook", async () => {
      mockStore.automations.push({
        id: "rule_comment_guide",
        user_id: TEST_USER_ID,
        name: "Guide Request",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "guide",
        response_content: JSON.stringify({ message: "Here is your free guide!" }),
        is_active: true,
      })

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_dup_555",
                  text: "Send me the guide please",
                  from: { id: "customer_777" },
                  media: { id: "media_888" },
                },
              },
            ],
          },
        ],
      }

      // First webhook delivery
      const req1 = makeSignedWebhookRequest(payload)
      const res1 = await instagramWebhook.POST(req1)
      assert.strictEqual(res1.status, 200)
      const initialCallCount = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com")).length
      assert.ok(initialCallCount > 0, "First delivery must send reply")

      // Second webhook delivery (replay/retry of the exact same comment)
      const req2 = makeSignedWebhookRequest(payload)
      const res2 = await instagramWebhook.POST(req2)
      assert.strictEqual(res2.status, 200)

      const totalCallCount = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com")).length
      assert.strictEqual(totalCallCount, initialCallCount, "Duplicate delivery must NOT send duplicate replies")
    })

    it("WEBHOOK-05: Duplicate DM mid suppression skips redundant processing and replies", async () => {
      mockStore.automations.push({
        id: "rule_dm_info",
        user_id: TEST_USER_ID,
        name: "Info Rule",
        trigger_source: "dm",
        trigger_type: "keyword",
        trigger_value: "info",
        response_content: JSON.stringify({ message: "Here is the info packet!" }),
        is_active: true,
      })

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "customer_999" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: {
                  mid: "mid_dup_dm_999",
                  text: "info",
                },
              },
            ],
          },
        ],
      }

      // First delivery
      const req1 = makeSignedWebhookRequest(payload)
      const res1 = await instagramWebhook.POST(req1)
      assert.strictEqual(res1.status, 200)
      const initialCallCount = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com")).length
      assert.ok(initialCallCount > 0, "First DM must send reply")

      // Second delivery (replay)
      const req2 = makeSignedWebhookRequest(payload)
      const res2 = await instagramWebhook.POST(req2)
      assert.strictEqual(res2.status, 200)

      const totalCallCount = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com")).length
      assert.strictEqual(totalCallCount, initialCallCount, "Duplicate DM must NOT send duplicate reply")
      assert.strictEqual(mockStore.messages.filter((m) => m.id === "mid_dup_dm_999").length, 1, "Must not duplicate message")
    })

    it("WEBHOOK-06: Malformed comment event is skipped safely without aborting valid events in batch", async () => {
      mockStore.automations.push({
        id: "rule_comment_valid",
        user_id: TEST_USER_ID,
        name: "Batch Valid Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "start",
        response_content: JSON.stringify({ message: "Started successfully!" }),
        is_active: true,
      })

      const req = makeSignedWebhookRequest({
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            changes: [
              // Malformed change 1: missing from
              { field: "comments", value: { id: "bad_1", text: "start", media: { id: "m1" } } },
              // Malformed change 2: missing media
              { field: "comments", value: { id: "bad_2", text: "start", from: { id: "f1" } } },
              // Malformed change 3: missing id
              { field: "comments", value: { text: "start", from: { id: "f1" }, media: { id: "m1" } } },
              // Malformed change 4: value is null
              { field: "comments", value: null },
              // Valid change 5: complete and matching keyword
              {
                field: "comments",
                value: {
                  id: "valid_comment_in_batch",
                  text: "start now please",
                  from: { id: "customer_good" },
                  media: { id: "media_good" },
                },
              },
            ],
          },
        ],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)

      // The valid comment was processed and claimed
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "valid_comment_in_batch")
    })

    it("WEBHOOK-07: Resolves user when entry.id matches user primary key ID", async () => {
      mockStore.automations = []

      // Webhook where entry.id is TEST_USER_ID instead of TEST_WEBHOOK_ID
      const req = makeSignedWebhookRequest({
        object: "instagram",
        entry: [
          {
            id: TEST_USER_ID,
            messaging: [
              {
                sender: { id: "fan_primary_id" },
                recipient: { id: TEST_USER_ID },
                message: {
                  mid: "mid_primary_id_test",
                  text: "Testing primary key ID lookup",
                },
              },
            ],
          },
        ],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const msg = mockStore.messages.find((m) => m.id === "mid_primary_id_test")
      assert.ok(msg, "Message should be saved via user primary key ID resolution")
      assert.strictEqual(msg.user_id, TEST_USER_ID)
    })

    it("WEBHOOK-08: Failed processing releases claim so event remains retryable", async () => {
      mockStore.automations.push({
        id: "rule_retry_test",
        user_id: TEST_USER_ID,
        name: "Retry Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "retry",
        response_content: JSON.stringify({ message: "Will fail on first attempt" }),
        is_active: true,
      })

      // Simulate Instagram API failure on first attempt
      let shouldFail = true
      globalThis.fetch = async (url, opts) => {
        if (shouldFail && opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          return {
            ok: false,
            status: 500,
            json: async () => ({ error: { message: "Internal Instagram API transient error" } }),
            text: async () => JSON.stringify({ error: "transient" }),
          }
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: "mock_success_id", is_user_follow_business: true }),
          text: async () => JSON.stringify({ id: "mock_success_id" }),
        }
      }

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_retry_999",
                  text: "please retry",
                  from: { id: "customer_retry" },
                  media: { id: "media_retry" },
                },
              },
            ],
          },
        ],
      }

      // Attempt 1: fails
      const req1 = makeSignedWebhookRequest(payload)
      await instagramWebhook.POST(req1)

      // Claim should have been released because send failed
      assert.strictEqual(mockStore.webhook_events.length, 0, "Claim must be released on failure")

      // Attempt 2: succeeds
      shouldFail = false
      const req2 = makeSignedWebhookRequest(payload)
      const res2 = await instagramWebhook.POST(req2)
      assert.strictEqual(res2.status, 200)

      // Claim is now recorded because retry succeeded
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "comment_retry_999")
    })
  })

  // =========================================================================
  // SECTION E: UI REGRESSION TESTS (PostSelector State & Lifecycle)
  // =========================================================================
  describe("[REGRESSION] PostSelector UI State & Lifecycle", () => {
    function loadPostSelector() {
      const raw = fs.readFileSync(path.resolve(process.cwd(), "components/dashboard/PostSelector.tsx"), "utf8")
      const transpiled = ts.transpileModule(raw, {
        compilerOptions: {
          jsx: ts.JsxEmit.ReactJSX,
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
        },
      })

      function createHarness() {
        let stateSlots = []
        let effectSlots = []
        let stateIdx = 0
        let effectIdx = 0

        const mockReact = {
          useState(init) {
            const idx = stateIdx++
            if (idx >= stateSlots.length) {
              stateSlots.push(typeof init === "function" ? init() : init)
            }
            const setter = (val) => {
              const next = typeof val === "function" ? val(stateSlots[idx]) : val
              stateSlots[idx] = next
            }
            return [stateSlots[idx], setter]
          },
          useEffect(fn, deps) {
            const idx = effectIdx++
            if (idx >= effectSlots.length) {
              effectSlots.push({ fn, deps, hasRun: false })
            } else {
              const prev = effectSlots[idx]
              const changed = !deps || !prev.deps || deps.some((d, i) => !Object.is(d, prev.deps[i]))
              if (changed) {
                prev.fn = fn
                prev.deps = deps
                prev.hasRun = false
              }
            }
          },
          useMemo(fn) {
            return fn()
          },
        }

        const jsxRuntime = {
          jsx: (type, props) => ({ type, props }),
          jsxs: (type, props) => ({ type, props }),
          Fragment: "Fragment",
        }

        const m = { exports: {} }
        const fn = new Function("require", "module", "exports", transpiled.outputText)
        const mockRequire = (id) => {
          if (id === "react") return mockReact
          if (id === "react/jsx-runtime") return jsxRuntime
          if (id === "lucide-react") return new Proxy({}, { get: () => () => null })
          return {}
        }
        fn(mockRequire, m, m.exports)

        const Component = m.exports.PostSelector

        function runRender(props) {
          stateIdx = 0
          effectIdx = 0
          const tree = Component(props)
          for (const eff of effectSlots) {
            if (!eff.hasRun) {
              eff.fn()
              eff.hasRun = true
            }
          }
          return tree
        }

        return {
          runRender,
          getMode: () => stateSlots[0],
          getMediaList: () => stateSlots[1],
          getLoading: () => stateSlots[2],
          getError: () => stateSlots[3],
          getIsBrowsing: () => stateSlots[6],
          getSelectedMedia: () => stateSlots[7],
        }
      }

      return { createHarness }
    }

    it("POSTSELECTOR-01: Switching to Specific Post / Reel and receiving media response preserves specific mode without auto-closing", async () => {
      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({
            data: [
              { id: "post_1", caption: "First post", media_type: "IMAGE" },
              { id: "reel_2", caption: "Second reel", media_type: "VIDEO" },
            ],
          }),
        })

        const { createHarness } = loadPostSelector()
        const harness = createHarness()
        let selectedId = null
        let selectedItem = null
        const props = {
          userId: "test_user_1",
          selectedMediaId: selectedId,
          onSelect: (id, item) => {
            selectedId = id
            selectedItem = item
          },
        }

        // Mounts initially in 'all' mode
        let tree = harness.runRender(props)
        assert.strictEqual(harness.getMode(), "all", "Must initialize in 'all' mode when selectedMediaId is null")

        // User clicks 'Specific Post / Reel' button
        const specificBtn = tree.props.children[0].props.children[1]
        specificBtn.props.onClick()

        // Wait for async fetchMedia to complete and update mediaList
        await new Promise((r) => setTimeout(r, 25))

        // Re-render after state update
        tree = harness.runRender(props)

        // REGRESSION CHECK: mode must remain 'specific' and mediaList must be populated
        assert.strictEqual(harness.getMode(), "specific", "Mode must remain 'specific' after mediaList updates (bug was resetting to 'all')")
        assert.strictEqual(harness.getMediaList().length, 2, "Media list must contain the 2 returned posts")
        assert.strictEqual(harness.getLoading(), false, "Loading state must be false after fetch completes")
      } finally {
        global.fetch = origFetch
      }
    })

    it("POSTSELECTOR-02: Empty Instagram media response (0 posts) keeps specific mode open with empty message", async () => {
      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({ data: [] }),
        })

        const { createHarness } = loadPostSelector()
        const harness = createHarness()
        const props = {
          userId: "test_user_empty",
          selectedMediaId: null,
          onSelect: () => {},
        }

        let tree = harness.runRender(props)
        const specificBtn = tree.props.children[0].props.children[1]
        specificBtn.props.onClick()

        await new Promise((r) => setTimeout(r, 25))
        tree = harness.runRender(props)

        assert.strictEqual(harness.getMode(), "specific", "Specific mode must stay open when 0 posts are returned")
        assert.strictEqual(harness.getMediaList().length, 0, "Media list must be empty")
        assert.strictEqual(harness.getError(), null, "Error must be null for empty response")
      } finally {
        global.fetch = origFetch
      }
    })

    it("POSTSELECTOR-03: Media API error keeps specific mode open and sets error state for retry", async () => {
      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: false,
          json: async () => ({ error: "Instagram token expired. Please reconnect." }),
        })

        const { createHarness } = loadPostSelector()
        const harness = createHarness()
        const props = {
          userId: "test_user_err",
          selectedMediaId: null,
          onSelect: () => {},
        }

        let tree = harness.runRender(props)
        const specificBtn = tree.props.children[0].props.children[1]
        specificBtn.props.onClick()

        await new Promise((r) => setTimeout(r, 25))
        tree = harness.runRender(props)

        assert.strictEqual(harness.getMode(), "specific", "Specific mode must stay open when media fetch fails")
        assert.strictEqual(harness.getError(), "Instagram token expired. Please reconnect.")
      } finally {
        global.fetch = origFetch
      }
    })

    it("POSTSELECTOR-04: Clearing selected post retains specific browsing mode without auto-closing", async () => {
      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({
            data: [{ id: "post_42", caption: "Product showcase", media_type: "IMAGE" }],
          }),
        })

        const { createHarness } = loadPostSelector()
        const harness = createHarness()
        let selectedId = "post_42"
        let selectedItem = { id: "post_42", caption: "Product showcase" }
        const props = {
          userId: "test_user_select",
          selectedMediaId: selectedId,
          initialMedia: selectedItem,
          onSelect: (id, item) => {
            selectedId = id
            selectedItem = item
          },
        }

        // Mounts directly in specific mode because selectedMediaId is passed
        let tree = harness.runRender(props)
        assert.strictEqual(harness.getMode(), "specific", "Must mount in specific mode when selectedMediaId is provided")

        // Deselect post (click 'X' / clear selection)
        // In specific mode with selected item, children[1] is the specific container
        const specificContainer = tree.props.children[1]
        const selectedBanner = specificContainer.props.children
        const actionButtons = selectedBanner.props.children[2].props.children
        const clearBtn = actionButtons[1] // the 'X' button
        clearBtn.props.onClick()

        // After clearing: selectedId in parent became null
        props.selectedMediaId = selectedId
        tree = harness.runRender(props)

        assert.strictEqual(harness.getMode(), "specific", "Mode must remain specific after deselecting post")
        assert.strictEqual(selectedId, null, "Parent onSelect must have been called with null")
        assert.strictEqual(harness.getIsBrowsing(), true, "isBrowsing must be true to allow selecting another post")
      } finally {
        global.fetch = origFetch
      }
    })

    it("POSTSELECTOR-05: Switching to All Posts & Reels resets mode to all and clears selection", async () => {
      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({ data: [] }),
        })

        const { createHarness } = loadPostSelector()
        const harness = createHarness()
        let selectedId = "post_99"
        const props = {
          userId: "test_user_all",
          selectedMediaId: selectedId,
          onSelect: (id, item) => {
            selectedId = id
          },
        }

        let tree = harness.runRender(props)
        assert.strictEqual(harness.getMode(), "specific")

        // Click 'All Posts & Reels' button (index 0)
        const allBtn = tree.props.children[0].props.children[0]
        allBtn.props.onClick()

        props.selectedMediaId = selectedId
        tree = harness.runRender(props)

        assert.strictEqual(harness.getMode(), "all", "Mode must switch to all")
        assert.strictEqual(selectedId, null, "onSelect must be called with null")
        assert.strictEqual(harness.getSelectedMedia(), null, "currentSelectedMedia must be null")
      } finally {
        global.fetch = origFetch
      }
    })
  })
})
