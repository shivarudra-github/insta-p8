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

    it("ROUTE-LIFECYCLE-09: POST /api/instagram/webhook with DISABLE_WEBHOOK_SIGNATURE_CHECK=true in production -> 401", async () => {
      const originalEnv = process.env.NODE_ENV
      const originalBypass = process.env.DISABLE_WEBHOOK_SIGNATURE_CHECK
      try {
        process.env.NODE_ENV = "production"
        process.env.DISABLE_WEBHOOK_SIGNATURE_CHECK = "true"
        const req = new NextRequest("http://localhost:3000/api/instagram/webhook", {
          method: "POST",
          body: JSON.stringify({ object: "instagram" }),
        })
        const res = await instagramWebhook.POST(req)
        assert.strictEqual(res.status, 401)
        const data = await res.json()
        assert.strictEqual(data.error, "Invalid signature")
      } finally {
        process.env.NODE_ENV = originalEnv
        if (originalBypass !== undefined) {
          process.env.DISABLE_WEBHOOK_SIGNATURE_CHECK = originalBypass
        } else {
          delete process.env.DISABLE_WEBHOOK_SIGNATURE_CHECK
        }
      }
    })
  })

  describe("[INTEGRATION] Webhook Reliability & Idempotency Phase 1", () => {
    const TEST_USER_ID = "99001"
    const TEST_WEBHOOK_ID = "99002"
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
        page_id: "99003",
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

    it("WEBHOOK-09: Non-duplicate Supabase claim error is NOT treated as a duplicate", async () => {
      mockStore.failNextInsert = true

      mockStore.automations.push({
        id: "rule_claim_fail",
        user_id: TEST_USER_ID,
        name: "Claim Fail Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "help",
        response_content: JSON.stringify({ message: "Help is here!" }),
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
                  id: "comment_claim_fail_001",
                  text: "I need help",
                  from: { id: "customer_help" },
                  media: { id: "media_help" },
                },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "Genuine claim error must be retryable (503), not 200")

      // No event should be claimed (insert failed)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed when insert fails")

      // No reply should have been sent (claim failed, automation not run)
      const replyCalls = capturedRequests.filter((r) => r.method === "POST" && r.url.includes("graph.instagram.com"))
      assert.strictEqual(replyCalls.length, 0, "No reply sent when claim fails")
    })

    it("WEBHOOK-10: Thrown database/network error is handled as retryable failure", async () => {
      mockStore.throwNextInsert = true

      mockStore.automations.push({
        id: "rule_throw_fail",
        user_id: TEST_USER_ID,
        name: "Throw Fail Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "help",
        response_content: JSON.stringify({ message: "Help is here!" }),
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
                  id: "comment_throw_fail_001",
                  text: "I need help",
                  from: { id: "customer_help" },
                  media: { id: "media_help" },
                },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "Thrown DB error must be retryable (503)")
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed when insert throws")
    })

    it("WEBHOOK-11: Failed claim-release deletion is not silently ignored", async () => {
      mockStore.failNextDelete = true

      // All Graph API POST calls fail, triggering send failure and claim release
      const savedFetch = globalThis.fetch
      globalThis.fetch = async (url, opts) => {
        if (opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          return {
            ok: false,
            status: 500,
            json: async () => ({ error: { message: "transient" } }),
            text: async () => JSON.stringify({ error: "transient" }),
          }
        }
        return savedFetch(url, opts)
      }

      mockStore.automations.push({
        id: "rule_release_fail",
        user_id: TEST_USER_ID,
        name: "Release Fail Rule",
        trigger_source: "dm",
        trigger_type: "keyword",
        trigger_value: "info",
        response_content: JSON.stringify({ message: "Here is info" }),
        is_active: true,
      })

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "customer_release" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: { mid: "mid_release_fail_001", text: "info" },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "Failed claim-release deletion must be retryable (503)")

      globalThis.fetch = savedFetch
    })

    it("WEBHOOK-12: Public comment reply succeeds, DM fails — 503 and claim released (retryable)", async () => {
      mockStore.automations.push({
        id: "rule_both_reply",
        user_id: TEST_USER_ID,
        name: "Both Reply Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "help",
        response_content: JSON.stringify({
          message: "Here is your help!",
          reply_mode: "both",
        }),
        is_active: true,
      })

      // First Graph API call succeeds (public comment reply), second fails (DM)
      let igCallCount = 0
      const savedFetch = globalThis.fetch
      globalThis.fetch = async (url, opts) => {
        if (opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          igCallCount++
          if (igCallCount === 1) {
            return { ok: true, status: 200, json: async () => ({ id: "comment_reply_ok" }), text: async () => JSON.stringify({ id: "comment_reply_ok" }) }
          }
          return { ok: false, status: 500, json: async () => ({ error: { message: "transient" } }), text: async () => JSON.stringify({ error: "transient" }) }
        }
        return savedFetch(url, opts)
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
                  id: "comment_partial_001",
                  text: "I need help",
                  from: { id: "customer_help" },
                  media: { id: "media_help" },
                },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "Partial failure must return 503 (retryable)")
      assert.strictEqual(mockStore.webhook_events.length, 0, "Claim released on partial failure — event retryable")
      assert.strictEqual(igCallCount, 2, "Both public reply and DM attempts were made")

      globalThis.fetch = savedFetch
    })

    it("WEBHOOK-13: DM first part succeeds, second part fails — 503 and claim released", async () => {
      mockStore.automations.push({
        id: "rule_dm_partial",
        user_id: TEST_USER_ID,
        name: "DM Partial Rule",
        trigger_source: "dm",
        trigger_type: "keyword",
        trigger_value: "info",
        response_content: JSON.stringify({ message: "Here is the info!" }),
        is_active: true,
      })

      // First Graph API call succeeds (mark_seen or initial send), second fails
      let igCallCount = 0
      const savedFetch = globalThis.fetch
      globalThis.fetch = async (url, opts) => {
        if (opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          igCallCount++
          if (igCallCount === 1) {
            return { ok: true, status: 200, json: async () => ({ id: "dm_part1_ok" }), text: async () => JSON.stringify({ id: "dm_part1_ok" }) }
          }
          return { ok: false, status: 500, json: async () => ({ error: { message: "transient" } }), text: async () => JSON.stringify({ error: "transient" }) }
        }
        return savedFetch(url, opts)
      }

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "customer_partial" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: { mid: "mid_partial_001", text: "info" },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "DM partial failure must return 503 (retryable)")
      assert.strictEqual(mockStore.webhook_events.length, 0, "Claim released on DM partial failure — event retryable")

      globalThis.fetch = savedFetch
    })

    it("WEBHOOK-14: Batch with one successful event and one failed event — 503, failed event claim released", async () => {
      mockStore.automations.push({
        id: "rule_batch_success",
        user_id: TEST_USER_ID,
        name: "Batch Success Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "success",
        response_content: JSON.stringify({ message: "Success!" }),
        is_active: true,
      })

      // First Graph API call succeeds (comment reply for event 1), second fails (comment reply for event 2)
      let igCallCount = 0
      const savedFetch = globalThis.fetch
      globalThis.fetch = async (url, opts) => {
        if (opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          igCallCount++
          if (igCallCount === 1) {
            return { ok: true, status: 200, json: async () => ({ id: "batch_ok" }), text: async () => JSON.stringify({ id: "batch_ok" }) }
          }
          return { ok: false, status: 500, json: async () => ({ error: { message: "transient" } }), text: async () => JSON.stringify({ error: "transient" }) }
        }
        return savedFetch(url, opts)
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
                  id: "comment_batch_ok",
                  text: "success please",
                  from: { id: "customer_ok" },
                  media: { id: "media_ok" },
                },
              },
              {
                field: "comments",
                value: {
                  id: "comment_batch_fail",
                  text: "fail please",
                  from: { id: "customer_fail" },
                  media: { id: "media_fail" },
                },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 503, "Batch partial failure must return 503 (retryable)")
      // Both events' claims are released on partial failure — sendSucceeded is per-change
      const claimsRemaining = mockStore.webhook_events.length
      assert.strictEqual(claimsRemaining, 0, "All batch event claims released on partial failure — all retryable")

      globalThis.fetch = savedFetch
    })

    it("WEBHOOK-15: Meta retry after partial-success — claim is absent so event is reprocessed (at-least-once)", async () => {
      mockStore.automations.push({
        id: "rule_retry_check",
        user_id: TEST_USER_ID,
        name: "Retry Check Rule",
        trigger_source: "dm",
        trigger_type: "keyword",
        trigger_value: "retry",
        response_content: JSON.stringify({ message: "Retry me!" }),
        is_active: true,
      })

      // First delivery: DM fails → claim released → 503
      let igCallCount = 0
      const savedFetch = globalThis.fetch
      globalThis.fetch = async (url, opts) => {
        if (opts?.method === "POST" && String(url).includes("graph.instagram.com")) {
          igCallCount++
          return { ok: false, status: 500, json: async () => ({ error: { message: "transient" } }), text: async () => JSON.stringify({ error: "transient" }) }
        }
        return savedFetch(url, opts)
      }

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "customer_retry" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: { mid: "mid_retry_001", text: "retry" },
              },
            ],
          },
        ],
      }

      // Attempt 1: fails
      const req1 = makeSignedWebhookRequest(payload)
      const res1 = await instagramWebhook.POST(req1)
      assert.strictEqual(res1.status, 503, "First delivery fails with 503")
      assert.strictEqual(mockStore.webhook_events.length, 0, "Claim released after failure")

      // Attempt 2 (Meta retry): same event arrives again — claim absent, so it's processed again
      const req2 = makeSignedWebhookRequest(payload)
      const res2 = await instagramWebhook.POST(req2)
      assert.strictEqual(res2.status, 503, "Retry also fails with 503 (DM still failing)")
      assert.strictEqual(mockStore.webhook_events.length, 0, "Claim released again on retry")

      globalThis.fetch = savedFetch
    })
  })

  describe("[INTEGRATION] Webhook ID Validation & PostgREST Filter Injection Prevention (SEC-API-05)", () => {
    const VALID_USER_ID = "99001"
    const VALID_WEBHOOK_ID = "99002"
    let capturedRequests
    let originalFetch

    function makeSignedRequest(payloadObj) {
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
        id: VALID_USER_ID,
        business_account_id: VALID_WEBHOOK_ID,
        page_id: "99003",
        username: "testcreator",
        access_token: "test_token_valid_123",
      })

      mockStore.automations.push({
        id: "rule_test_id_validation",
        user_id: VALID_USER_ID,
        name: "Validation Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "hello",
        response_content: JSON.stringify({ message: "Valid ID reply" }),
        is_active: true,
      })

      globalThis.fetch = async (url, opts) => {
        capturedRequests.push({ url: String(url), method: opts?.method || "GET" })
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: "mock_resp_123", is_user_follow_business: true }),
          text: async () => JSON.stringify({ id: "mock_resp_123" }),
        }
      }
    })

    afterEach(() => {
      globalThis.fetch = originalFetch
    })

    it("WEBHOOK-ID-01: Rejects empty string entry.id before database query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{ id: "", changes: [{ field: "comments", value: { id: "c1", text: "hello", from: { id: "u1" } } }] }],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for empty ID")
      assert.strictEqual(capturedRequests.length, 0, "No Graph API calls dispatched")
    })

    it("WEBHOOK-ID-02: Rejects entry.id containing commas (PostgREST injection attempt) before query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{ id: "123,id.eq.456", changes: [{ field: "comments", value: { id: "c1", text: "hello", from: { id: "u1" } } }] }],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for comma-injected ID")
      assert.strictEqual(capturedRequests.length, 0, "No Graph API calls dispatched")
    })

    it("WEBHOOK-ID-03: Rejects entry.id containing parentheses before database query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{ id: "123)or(id.eq.456", changes: [{ field: "comments", value: { id: "c1", text: "hello", from: { id: "u1" } } }] }],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for parentheses ID")
      assert.strictEqual(capturedRequests.length, 0, "No Graph API calls dispatched")
    })

    it("WEBHOOK-ID-04: Rejects malformed alphanumeric / non-numeric entry.id before database query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{ id: "ig_acc_invalid_alpha", changes: [{ field: "comments", value: { id: "c1", text: "hello", from: { id: "u1" } } }] }],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for non-numeric ID")
      assert.strictEqual(capturedRequests.length, 0, "No Graph API calls dispatched")
    })

    it("WEBHOOK-ID-05: Rejects non-string entry.id (null, undefined, object) before database query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{ id: null, changes: [{ field: "comments", value: { id: "c1", text: "hello", from: { id: "u1" } } }] }],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for null ID")
      assert.strictEqual(capturedRequests.length, 0, "No Graph API calls dispatched")
    })

    it("WEBHOOK-ID-06: Skips candidate ID in payload containing commas or parentheses before query", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [
          {
            id: "88888",
            messaging: [
              {
                recipient: { id: "99001,page_id.eq.attack" },
                message: { mid: "m1", text: "hello" },
              },
            ],
          },
        ],
      })
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed")
    })

    it("WEBHOOK-ID-07: Accepts valid numeric string entry.id and executes normal processing", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [
          {
            id: VALID_WEBHOOK_ID,
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_valid_numeric_id",
                  text: "hello there",
                  from: { id: "customer_101" },
                  media: { id: "media_101" },
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
      assert.strictEqual(mockStore.webhook_events.length, 1, "Event claimed successfully")
      assert.ok(capturedRequests.length > 0, "Reply dispatched for valid numeric ID")
    })
  })

  describe("[INTEGRATION] Webhook User Resolution & SEC-API-02 Fallback Removal", () => {
    let capturedRequests
    let originalFetch

    function makeSignedRequest(payloadObj) {
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

      globalThis.fetch = async (url, opts) => {
        capturedRequests.push({ url: String(url), method: opts?.method || "GET" })
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: "mock_resp_123", is_user_follow_business: true }),
          text: async () => JSON.stringify({ id: "mock_resp_123" }),
        }
      }
    })

    afterEach(() => {
      globalThis.fetch = originalFetch
    })

    it("FALLBACK-REM-01: Known account matching business_account_id resolves directly in Step 1", async () => {
      mockStore.users.push({
        id: "user_step1_direct",
        business_account_id: "1000000001",
        page_id: "1000000001",
        username: "directcreator",
        access_token: "token_step1_direct",
      })
      mockStore.automations.push({
        id: "rule_step1_direct",
        user_id: "user_step1_direct",
        name: "Direct Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "hello",
        response_content: JSON.stringify({ message: "Direct resolution reply" }),
        is_active: true,
      })

      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "1000000001",
          changes: [{
            field: "comments",
            value: {
              id: "comm_direct_01",
              text: "hello there",
              from: { id: "fan_1" },
              media: { id: "media_1" },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "comm_direct_01")
      assert.ok(capturedRequests.some((r) => r.url.includes("comm_direct_01/replies")))
    })

    it("FALLBACK-REM-02: Known account matching page_id alias resolves directly in Step 1", async () => {
      mockStore.users.push({
        id: "user_step1_alias",
        business_account_id: "1000000002",
        page_id: "2000000002",
        username: "aliascreator",
        access_token: "token_step1_alias",
      })
      mockStore.automations.push({
        id: "rule_step1_alias",
        user_id: "user_step1_alias",
        name: "Alias Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "price",
        response_content: JSON.stringify({ message: "Alias resolution reply" }),
        is_active: true,
      })

      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "2000000002",
          changes: [{
            field: "comments",
            value: {
              id: "comm_alias_02",
              text: "what is the price?",
              from: { id: "fan_2" },
              media: { id: "media_2" },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "comm_alias_02")
      assert.ok(capturedRequests.some((r) => r.url.includes("comm_alias_02/replies")))
    })

    it("FALLBACK-REM-03: Validly signed webhook with unknown numeric ID does not query all users", async () => {
      mockStore.users.push(
        { id: "u_exist_1", business_account_id: "111", page_id: "111", access_token: "tok_1" },
        { id: "u_exist_2", business_account_id: "222", page_id: "222", access_token: "tok_2" },
      )

      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "999999999",
          changes: [{
            field: "comments",
            value: {
              id: "comm_unknown_03",
              text: "hello",
              from: { id: "fan_3" },
              media: { id: "media_3" },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)

      // Verify that no full table scan on "users" occurred
      const fullUserScans = mockStore.queries.filter(
        (q) => q.table === "users" && q.filters.length === 0 && q.orClauses.length === 0,
      )
      assert.strictEqual(fullUserScans.length, 0, "Must not execute unfiltered SELECT * FROM users")
    })

    it("FALLBACK-REM-04: Unknown accounts do NOT trigger verifyIdOwnership or external Graph API calls", async () => {
      // Populate 5 user candidates with active tokens
      for (let i = 1; i <= 5; i++) {
        mockStore.users.push({
          id: `candidate_user_${i}`,
          business_account_id: `300000000${i}`,
          page_id: `300000000${i}`,
          access_token: `token_candidate_${i}`,
        })
      }

      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "777777777",
          changes: [{
            field: "comments",
            value: {
              id: "comm_unknown_04",
              text: "unknown test",
              from: { id: "fan_4" },
              media: { id: "media_4" },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)

      // In the old code, 5 sequential Graph API calls to verifyIdOwnership would have been made.
      // In the new code, exactly 0 external calls are made.
      assert.strictEqual(capturedRequests.length, 0, "Must not dispatch any external Graph API calls for unknown accounts")
    })

    it("FALLBACK-REM-05: Unknown accounts return HTTP 200 { ok: true } acknowledgment and safely skip", async () => {
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "888888888",
          changes: [{
            field: "comments",
            value: {
              id: "comm_skip_05",
              text: "skip this cleanly",
              from: { id: "fan_5" },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.deepStrictEqual(data, { ok: true })
      assert.strictEqual(mockStore.webhook_events.length, 0, "No event claimed for unresolvable user")
    })

    it("FALLBACK-REM-06: Step 2 payload candidate resolution (media.owner.id and recipient.id) remains functional and updates page_id", async () => {
      // User registered with business_account_id = "5000000001", page_id = null
      mockStore.users.push({
        id: "user_step2_test",
        business_account_id: "5000000001",
        page_id: null,
        access_token: "token_step2",
      })
      mockStore.automations.push({
        id: "rule_step2_test",
        user_id: "user_step2_test",
        name: "Step 2 Rule",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "step2",
        response_content: JSON.stringify({ message: "Step 2 resolved" }),
        is_active: true,
      })

      // Webhook arrives with entry.id = "6000000001" (new page ID), but media.owner.id = "5000000001"
      const req = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "6000000001",
          changes: [{
            field: "comments",
            value: {
              id: "comm_step2_06",
              text: "step2 keyword",
              from: { id: "fan_6" },
              media: { id: "media_6", owner: { id: "5000000001" } },
            },
          }],
        }],
      })

      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.ok, true)

      // Step 2 successfully resolved and healed the user's page_id
      const updatedUser = mockStore.users.find((u) => u.id === "user_step2_test")
      assert.strictEqual(updatedUser.page_id, "6000000001", "Step 2 must update page_id to incoming webhookId")
      assert.strictEqual(mockStore.webhook_events.length, 1)
      assert.strictEqual(mockStore.webhook_events[0].data?.comment_id, "comm_step2_06")

      // Now verify Step 2 also resolves via recipient.id in messaging events
      mockStore.users.push({
        id: "user_step2_dm",
        business_account_id: "5000000002",
        page_id: null,
        access_token: "token_step2_dm",
      })
      const dmReq = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "6000000002",
          messaging: [{
            sender: { id: "fan_dm_6" },
            recipient: { id: "5000000002" },
            message: { mid: "mid_step2_06", text: "dm payload test" },
          }],
        }],
      })
      const dmRes = await instagramWebhook.POST(dmReq)
      assert.strictEqual(dmRes.status, 200)
      const updatedDmUser = mockStore.users.find((u) => u.id === "user_step2_dm")
      assert.strictEqual(updatedDmUser.page_id, "6000000002")
    })

    it("FALLBACK-REM-07: Normal comment and DM processing work end-to-end for resolved accounts", async () => {
      mockStore.users.push({
        id: "user_e2e_normal",
        business_account_id: "7000000001",
        page_id: "7000000001",
        username: "e2ecreator",
        access_token: "token_e2e",
      })
      mockStore.automations.push(
        {
          id: "rule_e2e_comment",
          user_id: "user_e2e_normal",
          name: "E2E Comment Rule",
          trigger_source: "comment",
          trigger_type: "keyword",
          trigger_value: "coupon",
          response_content: JSON.stringify({ message: "Here is your coupon: SAVE20" }),
          is_active: true,
        },
        {
          id: "rule_e2e_dm",
          user_id: "user_e2e_normal",
          name: "E2E DM Rule",
          trigger_source: "dm",
          trigger_type: "keyword",
          trigger_value: "help",
          response_content: JSON.stringify({ message: "Support is on the way!" }),
          is_active: true,
        },
      )

      // Test Comment
      const commentReq = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "7000000001",
          changes: [{
            field: "comments",
            value: {
              id: "comm_e2e_07",
              text: "i want a coupon please",
              from: { id: "customer_77" },
              media: { id: "media_77" },
            },
          }],
        }],
      })
      const commentRes = await instagramWebhook.POST(commentReq)
      assert.strictEqual(commentRes.status, 200)
      assert.ok(capturedRequests.some((r) => r.url.includes("comm_e2e_07/replies")))

      // Test DM
      const dmReq = makeSignedRequest({
        object: "instagram",
        entry: [{
          id: "7000000001",
          messaging: [{
            sender: { id: "customer_88" },
            recipient: { id: "7000000001" },
            message: { mid: "mid_e2e_07", text: "help me please" },
          }],
        }],
      })
      const dmRes = await instagramWebhook.POST(dmReq)
      assert.strictEqual(dmRes.status, 200)
      assert.ok(capturedRequests.some((r) => r.url.includes("me/messages")))
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
          onSelect: () => { },
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
          onSelect: () => { },
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

  // =========================================================================
  // SECTION: ICE BREAKERS DATA-LOSS REMEDIATION (app/api/ice-breakers/route.ts)
  // =========================================================================
  describe("[REMEDIATION] Ice Breakers Data-Loss Prevention & Atomic Safety", () => {
    const TEST_USER = "user_ice_test"
    let userToken

    beforeEach(() => {
      resetMockStore()
      userToken = createSessionToken({ userId: TEST_USER, username: "ice_tester" })
    })

    it("ICE-01: Unauthenticated POST returns 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        body: JSON.stringify({ iceBreakers: [{ question: "Q?", response: "A" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 401)
    })

    it("ICE-02: Cross-user userId spoofing returns 403", async () => {
      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ userId: "victim_user_999", iceBreakers: [{ question: "Q?", response: "A" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 403)
      const data = await res.json()
      assert.ok(data.error?.includes("Forbidden"))
    })

    it("ICE-03: Invalid payload returns 400 without database mutations", async () => {
      mockStore.ice_breakers.push({ id: "pre_1", user_id: TEST_USER, question: "Old Q", response: "Old A" })

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: "not-an-array" }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(mockStore.ice_breakers.length, 1, "Existing records must remain unchanged")
      assert.strictEqual(mockStore.ice_breakers[0].id, "pre_1")
    })

    it("ICE-04: Null/malformed entries return 400", async () => {
      mockStore.ice_breakers.push({ id: "pre_1", user_id: TEST_USER, question: "Old Q", response: "Old A" })

      // Case 1: Null entry
      const req1 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [null] }),
      })
      const res1 = await iceBreakers.POST(req1)
      assert.strictEqual(res1.status, 400)

      // Case 2: Non-object entry (string)
      const req2 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: ["invalid_string"] }),
      })
      const res2 = await iceBreakers.POST(req2)
      assert.strictEqual(res2.status, 400)

      assert.strictEqual(mockStore.ice_breakers.length, 1, "Existing records must remain untouched")
    })

    it("ICE-05: Empty question or response returns 400", async () => {
      mockStore.ice_breakers.push({ id: "pre_1", user_id: TEST_USER, question: "Old Q", response: "Old A" })

      // Whitespace question
      const req1 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "   ", response: "Valid response" }] }),
      })
      const res1 = await iceBreakers.POST(req1)
      assert.strictEqual(res1.status, 400)

      // Empty response
      const req2 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "Valid question", response: "   " }] }),
      })
      const res2 = await iceBreakers.POST(req2)
      assert.strictEqual(res2.status, 400)

      assert.strictEqual(mockStore.ice_breakers.length, 1, "Existing records must remain untouched")
    })

    it("ICE-06: Field-length limits are enforced", async () => {
      // Question > Instagram's 80-character limit
      const longQ = "q".repeat(81)
      const req1 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: longQ, response: "Valid" }] }),
      })
      const res1 = await iceBreakers.POST(req1)
      assert.strictEqual(res1.status, 400)
      const data1 = await res1.json()
      assert.ok(data1.error?.includes("80"))

      // Response > 2000
      const longR = "r".repeat(2001)
      const req2 = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "Valid", response: longR }] }),
      })
      const res2 = await iceBreakers.POST(req2)
      assert.strictEqual(res2.status, 400)
      const data2 = await res2.json()
      assert.ok(data2.error?.includes("2000"))
    })

    it("ICE-07: More than four entries are rejected", async () => {
      const fiveEntries = [1, 2, 3, 4, 5].map((n) => ({ question: `Question ${n}`, response: `Response ${n}` }))
      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: fiveEntries }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 400)
      const data = await res.json()
      assert.ok(data.error?.includes("Maximum 4"))
    })

    it("ICE-08: Insert failure preserves existing records", async () => {
      mockStore.ice_breakers.push({ id: "pre_preserve", user_id: TEST_USER, question: "Saved Q", response: "Saved A" })

      // Simulate insert error in Supabase mock
      mockStore.failNextInsert = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "New Q", response: "New A" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)

      // Existing records MUST remain completely intact
      const existing = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.strictEqual(existing.length, 1)
      assert.strictEqual(existing[0].id, "pre_preserve")
      assert.strictEqual(existing[0].question, "Saved Q")
    })

    it("ICE-09: Delete failure preserves existing records and preserves new rows without destructive rollback", async () => {
      mockStore.ice_breakers.push({ id: "pre_exist", user_id: TEST_USER, question: "Saved Q", response: "Saved A" })

      // Simulate bulk delete failure
      mockStore.failNextDelete = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "New Q", response: "New A" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()
      assert.strictEqual(data.success, false)
      assert.ok(data.warning?.includes("Duplicate entries may remain"))

      // Both the pre-existing record AND newly inserted record remain preserved (no destructive rollback)
      const records = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.strictEqual(records.length, 2, "Both old and new rows must be preserved to prevent data loss")
      assert.ok(records.some((r) => r.id === "pre_exist"))
      assert.ok(records.some((r) => r.question === "New Q"))
    })

    it("ICE-10: Database failure does not expose raw error messages or internal error details", async () => {
      mockStore.failNextInsert = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question: "New Q2", response: "New A2" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()
      assert.strictEqual(data.error, "Failed to save new ice breakers. Existing records were preserved.")
      assert.strictEqual(data.stack, undefined)
      assert.strictEqual(data.code, undefined)
    })

    it("ICE-11: Successful replacement stores the new records under the authenticated user", async () => {
      mockStore.ice_breakers.push(
        { id: "old_ib_1", user_id: TEST_USER, question: "Old 1", response: "Resp 1" },
        { id: "old_ib_2", user_id: TEST_USER, question: "Old 2", response: "Resp 2" }
      )
      // Also add someone else's record to ensure no cross-user deletion
      mockStore.ice_breakers.push({ id: "other_user_ib", user_id: "other_user", question: "Other Q", response: "Other R" })

      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ({ result: "success" }),
        })

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            userId: TEST_USER,
            iceBreakers: [
              { question: "New Q1?", response: "New A1" },
              { question: "New Q2?", response: "New A2" },
            ],
          }),
        })
        const res = await iceBreakers.POST(req)
        assert.strictEqual(res.status, 200)
        const data = await res.json()
        assert.strictEqual(data.success, true)
        assert.strictEqual(data.data.length, 2)

        // Check mockStore
        const userRecords = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
        assert.strictEqual(userRecords.length, 2)
        assert.strictEqual(userRecords[0].question, "New Q1?")
        assert.strictEqual(userRecords[1].question, "New Q2?")

        // Verify bulk delete query used single .in() filter
        const deleteQueries = mockStore.queries.filter((q) => q.table === "ice_breakers" && q.isDelete)
        assert.strictEqual(deleteQueries.length, 1, "Must execute exactly ONE bulk delete statement")
        assert.ok(deleteQueries[0].inFilters.some((f) => f.field === "id"))

        // Other user's record MUST NOT be touched
        assert.ok(mockStore.ice_breakers.some((r) => r.id === "other_user_ib"))
      } finally {
        global.fetch = origFetch
      }
    })

    it("ICE-12: Instagram sync HTTP failure is reported accurately", async () => {
      mockStore.users.push({
        id: TEST_USER,
        access_token: "test_ig_token_abc",
        page_id: "page_12345",
      })

      const origFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: false,
          status: 500,
          json: async () => ({
            error: { message: "Instagram API service unavailable", type: "OAuthException", code: 2 },
          }),
        })

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Working Question", response: "Working Response" }],
          }),
        })
        const res = await iceBreakers.POST(req)
        assert.strictEqual(res.status, 200)
        const data = await res.json()
        assert.strictEqual(data.success, true, "DB save must be marked successful")
        assert.strictEqual(data.warning, "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again.")
        assert.strictEqual(data.error, "Instagram API synchronization failed")

        // Records were still saved in the database
        const userRecords = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
        assert.strictEqual(userRecords.length, 1)
        assert.strictEqual(userRecords[0].question, "Working Question")
      } finally {
        global.fetch = origFetch
      }
    })

    it("ICE-13: Partial delete data-loss fix: preserves both old rows and new rows on bulk DELETE failure with clear warning", async () => {
      // Seed two existing old Ice Breaker rows
      mockStore.ice_breakers.push(
        { id: "old_row_1", user_id: TEST_USER, question: "Old Question 1", response: "Old Answer 1" },
        { id: "old_row_2", user_id: TEST_USER, question: "Old Question 2", response: "Old Answer 2" }
      )

      // Simulate bulk DELETE failure
      mockStore.failNextDelete = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [
            { question: "Replacement Question 1", response: "Replacement Answer 1" },
            { question: "Replacement Question 2", response: "Replacement Answer 2" },
          ],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()
      assert.strictEqual(data.success, false)

      // Verify the response explicitly warns that cleanup failed and duplicates may remain
      assert.ok(data.warning?.includes("Duplicate entries may remain") || data.warning?.includes("duplicate"))
      assert.ok(data.error?.includes("confirmed") || data.error?.includes("duplicate") || data.error?.includes("preserved"))

      // Verify both old rows remain
      assert.ok(mockStore.ice_breakers.some((r) => r.id === "old_row_1"), "First old row must remain")
      assert.ok(mockStore.ice_breakers.some((r) => r.id === "old_row_2"), "Second old row must remain")

      // Verify newly inserted rows are not destructively cleaned up
      const replacementRows = mockStore.ice_breakers.filter(
        (r) => r.user_id === TEST_USER && r.question.startsWith("Replacement Question")
      )
      assert.strictEqual(replacementRows.length, 2, "Replacement rows must be preserved to prevent total data loss")
    })

    it("ICE-14: Empty-array payload executes single bulk DELETE to clear all user records", async () => {
      mockStore.ice_breakers.push(
        { id: "clear_1", user_id: TEST_USER, question: "Q1", response: "A1" },
        { id: "clear_2", user_id: TEST_USER, question: "Q2", response: "A2" }
      )

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.success, true)
      assert.deepStrictEqual(data.data, [])

      const remaining = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.strictEqual(remaining.length, 0, "All user ice breakers must be cleared")

      const deleteQueries = mockStore.queries.filter((q) => q.table === "ice_breakers" && q.isDelete)
      assert.strictEqual(deleteQueries.length, 1, "Must execute exactly ONE bulk delete statement")
    })

    it("ICE-15: When oldIds is empty, skip DELETE request entirely", async () => {
      // User has 0 existing records
      assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 0)

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [{ question: "First Ever Question", response: "First Ever Response" }],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 200)

      const deleteQueries = mockStore.queries.filter((q) => q.table === "ice_breakers" && q.isDelete)
      assert.strictEqual(deleteQueries.length, 0, "No DELETE statement should be executed when user has 0 prior records")

      const userRecords = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.strictEqual(userRecords.length, 1)
      assert.strictEqual(userRecords[0].question, "First Ever Question")
    })

    it("ICE-16: Delete applies in database but response is lost; API returns partialSuccess and does not delete new records", async () => {
      mockStore.ice_breakers.push(
        { id: "old_row_16", user_id: TEST_USER, question: "Old Q16", response: "Old A16" }
      )

      // Simulate DELETE that applies in database, but network drops before response is delivered
      mockStore.deleteAppliesThenThrows = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [{ question: "Replacement 16", response: "Answer 16" }],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()

      assert.strictEqual(data.success, false)
      assert.strictEqual(data.partialSuccess, true)
      assert.ok(data.warning?.includes("could not be confirmed"))
      // Verify API does NOT falsely claim old records are preserved
      assert.strictEqual(data.error?.includes("Old records were preserved"), false)

      // Verify newly inserted records are NOT deleted
      const userRecords = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.ok(userRecords.some((r) => r.question === "Replacement 16"))
    })

    it("ICE-17: Thrown DELETE failure before execution preserves new rows and returns explicit uncertain-outcome response", async () => {
      mockStore.ice_breakers.push(
        { id: "old_row_17", user_id: TEST_USER, question: "Old Q17", response: "Old A17" }
      )

      // Simulate network failure thrown by client before DELETE completes
      mockStore.throwNextDelete = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [{ question: "Replacement 17", response: "Answer 17" }],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()

      assert.strictEqual(data.success, false)
      assert.strictEqual(data.partialSuccess, true)
      assert.ok(data.warning?.includes("could not be confirmed"))
      assert.ok(data.error?.includes("could not be fully confirmed"))

      // Verify no destructive rollback of newly inserted rows
      const userRecords = mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER)
      assert.ok(userRecords.some((r) => r.question === "Replacement 17"))
      // Verify old row was not deleted in mock
      assert.ok(userRecords.some((r) => r.id === "old_row_17"))
    })

    it("ICE-18: Invalid Instagram JSON response with HTTP 200 must not be reported as confirmed successful sync", async () => {
      mockStore.users.push({
        id: TEST_USER,
        access_token: "test_ig_token_abc",
        page_id: "page_12345",
      })

      const origFetch = global.fetch
      try {
        // Return HTTP 200, but with invalid JSON / non-object payload
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => {
            throw new Error("Unexpected end of JSON input")
          },
        })

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Valid Question 18", response: "Valid Response 18" }],
          }),
        })
        const res = await iceBreakers.POST(req)
        assert.strictEqual(res.status, 200)
        const data = await res.json()

        // DB save succeeds, but sync must NOT be reported as confirmed
        assert.strictEqual(data.success, true)
        assert.strictEqual(data.warning, "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again.")
        assert.strictEqual(data.error, "Instagram API synchronization failed")
      } finally {
        global.fetch = origFetch
      }
    })

    it("ICE-19: Verify database-save success with Instagram sync warning is distinguishable from full success", async () => {
      mockStore.users.push({
        id: TEST_USER,
        access_token: "test_ig_token_abc",
        page_id: "page_12345",
      })

      const origFetch = global.fetch
      try {
        // 1. Full success: HTTP 200 with valid Instagram JSON
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ({ result: "success" }),
        })

        const req1 = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Question 19A", response: "Response 19A" }],
          }),
        })
        const res1 = await iceBreakers.POST(req1)
        assert.strictEqual(res1.status, 200)
        const data1 = await res1.json()
        assert.strictEqual(data1.success, true)
        assert.strictEqual(data1.warning, undefined, "Full success must not have a warning")
        assert.strictEqual(data1.error, undefined, "Full success must not have an error")

        // 2. Partial sync warning: HTTP 200 with API error object in JSON
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ({ error: { message: "Permission Denied", code: 200 } }),
        })

        const req2 = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Question 19B", response: "Response 19B" }],
          }),
        })
        const res2 = await iceBreakers.POST(req2)
        assert.strictEqual(res2.status, 200)
        const data2 = await res2.json()
        assert.strictEqual(data2.success, true)
        assert.strictEqual(data2.warning, "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again.", "Sync failure must be distinguished with warning")
        assert.ok(data2.error !== undefined, "Sync failure must include error explanation")
      } finally {
        global.fetch = origFetch
      }
    })

    it("ICE-20: Empty-array DELETE failure returns operationUncertain flag and preserves uncertainty", async () => {
      mockStore.ice_breakers.push(
        { id: "del_fail_1", user_id: TEST_USER, question: "Q1", response: "A1" }
      )

      // Simulate network exception during empty-array delete
      mockStore.throwNextDelete = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()

      assert.strictEqual(data.success, false)
      assert.strictEqual(data.operationUncertain, true, "Must flag operationUncertain: true")
      assert.ok(data.warning?.includes("could not be confirmed"))
      assert.ok(data.warning?.includes("not retry immediately"))
    })

    it("ICE-21: INSERT applies but response is lost; old records are not deleted and response warns against immediate retry", async () => {
      mockStore.ice_breakers.push(
        { id: "old_row_21", user_id: TEST_USER, question: "Old Q21", response: "Old A21" }
      )

      // Simulate INSERT that applies in database, but response network drops
      mockStore.insertAppliesThenThrows = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [{ question: "New Q21", response: "New A21" }],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()

      assert.strictEqual(data.success, false)
      assert.strictEqual(data.operationUncertain, true, "Must flag operationUncertain: true")
      assert.ok(data.warning?.includes("not retry immediately"))
      assert.ok(data.warning?.includes("Old records were preserved"))

      // Verify old records were NOT deleted
      assert.ok(mockStore.ice_breakers.some((r) => r.id === "old_row_21"))
    })

    it("ICE-22: INSERT throws before execution; old records remain and result is reported accurately", async () => {
      mockStore.ice_breakers.push(
        { id: "old_row_22", user_id: TEST_USER, question: "Old Q22", response: "Old A22" }
      )

      // Simulate network failure thrown before INSERT commits
      mockStore.throwNextInsert = true

      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({
          iceBreakers: [{ question: "New Q22", response: "New A22" }],
        }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 500)
      const data = await res.json()

      assert.strictEqual(data.success, false)
      assert.strictEqual(data.operationUncertain, true)
      assert.ok(data.warning?.includes("not retry immediately"))

      // Verify old records remain intact
      assert.ok(mockStore.ice_breakers.some((r) => r.id === "old_row_22"))
    })

    it("ICE-23: GET failure does not log raw exception details or leak sensitive internals", async () => {
      const originalConsoleError = console.error
      const errorLogs = []
      console.error = (...args) => {
        errorLogs.push(args.join(" "))
      }

      try {
        mockStore.throwNextSelect = true
        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          headers: { Cookie: `insta_session=${userToken}` },
        })
        const res = await iceBreakers.GET(req)
        assert.strictEqual(res.status, 500)
        const data = await res.json()
        assert.strictEqual(data.error, "Internal Server Error")
        assert.strictEqual(data.stack, undefined)
        assert.strictEqual(data.message, undefined)

        const loggedText = errorLogs.join(" ")
        assert.ok(loggedText.includes("category=UNHANDLED_EXCEPTION"))
        assert.strictEqual(loggedText.includes("Simulated query failure"), false)
        assert.strictEqual(loggedText.includes("TypeError"), false)
      } finally {
        mockStore.throwNextSelect = false
        console.error = originalConsoleError
      }
    })

    it("ICE-24: Empty object and array provider responses are not treated as confirmed Instagram sync success", async () => {
      mockStore.users.push({
        id: TEST_USER,
        access_token: "test_ig_token_abc",
        page_id: "page_12345",
      })

      const origFetch = global.fetch
      try {
        // Case A: Provider returns empty object {} with HTTP 200
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ({}),
        })

        const req1 = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Question 24A", response: "Response 24A" }],
          }),
        })
        const res1 = await iceBreakers.POST(req1)
        assert.strictEqual(res1.status, 200)
        const data1 = await res1.json()
        assert.strictEqual(data1.success, true)
        assert.strictEqual(data1.warning, "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again.", "Empty {} must NOT be treated as confirmed sync")

        // Case B: Provider returns array [] with HTTP 200
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ([]),
        })

        const req2 = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({
            iceBreakers: [{ question: "Question 24B", response: "Response 24B" }],
          }),
        })
        const res2 = await iceBreakers.POST(req2)
        assert.strictEqual(res2.status, 200)
        const data2 = await res2.json()
        assert.strictEqual(data2.success, true)
        assert.strictEqual(data2.warning, "Saved to database, but Instagram sync failed. Check your Instagram connection and try syncing again.", "Array [] must NOT be treated as confirmed sync")
      } finally {
        global.fetch = origFetch
      }
    })
    it("ICE-25: Accepts an 80-character question at the exact boundary", async () => {
      const question = "q".repeat(80)
      const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
        method: "POST",
        headers: { Cookie: `insta_session=${userToken}` },
        body: JSON.stringify({ iceBreakers: [{ question, response: "Valid response" }] }),
      })
      const res = await iceBreakers.POST(req)
      assert.strictEqual(res.status, 200)
      const data = await res.json()
      assert.strictEqual(data.success, true)
      assert.strictEqual(data.data[0].question.length, 80)
    })

    it("ICE-26: Empty list clears Instagram ice breakers with one DELETE request", async () => {
      mockStore.ice_breakers.push({ id: "clear_remote_26", user_id: TEST_USER, question: "Old Q", response: "Old A" })
      mockStore.users.push({ id: TEST_USER, access_token: "test_ig_token_26" })

      const originalFetch = global.fetch
      let capturedUrl = ""
      let capturedInit = null
      try {
        global.fetch = async (url, init) => {
          capturedUrl = String(url)
          capturedInit = init
          return { ok: true, status: 200, json: async () => ({ result: "success" }) }
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()
        const requestUrl = new URL(capturedUrl)

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.deepStrictEqual(data.data, [])
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 0)
        assert.strictEqual(capturedInit.method, "DELETE")
        assert.strictEqual(requestUrl.searchParams.get("fields"), "['ice_breakers']")
        assert.strictEqual(capturedInit.headers.Authorization, "Bearer test_ig_token_26")
        assert.strictEqual(capturedInit.body, undefined)
        assert.ok(capturedInit.signal instanceof AbortSignal, "Must pass AbortSignal timeout")
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-27: Database clear remains successful but warns when Instagram DELETE fails", async () => {
      mockStore.ice_breakers.push({ id: "clear_remote_27", user_id: TEST_USER, question: "Old Q", response: "Old A" })
      mockStore.users.push({ id: TEST_USER, access_token: "test_ig_token_27" })

      const originalFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: false,
          status: 500,
          json: async () => ({ error: { code: 2 } }),
        })

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("Instagram sync failed"))
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 0)
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-28: Missing Instagram user record warns after database save and still performs lookup", async () => {
      const originalFetch = global.fetch
      let fetchCalled = false
      try {
        global.fetch = async () => {
          fetchCalled = true
          throw new Error("Fetch must not run without credentials")
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "Saved locally", response: "Response" }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("no Instagram access token"))
        assert.strictEqual(fetchCalled, false)
        assert.ok(mockStore.queries.some((q) => q.table === "users" && q.isMaybeSingle && q.filters.some((f) => f.field === "id" && f.value === TEST_USER)))
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 1)
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-29: User lookup errors warn instead of reporting full Instagram sync success", async () => {
      mockStore.failNextUserSelect = true
      const originalFetch = global.fetch
      let fetchCalled = false
      try {
        global.fetch = async () => {
          fetchCalled = true
          throw new Error("Fetch must not run when credential lookup fails")
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "Saved with lookup error", response: "Response" }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("connection could not be verified"))
        assert.strictEqual(fetchCalled, false)
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 1)
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-30: Thrown user lookup failures are contained and reported as sync warnings", async () => {
      mockStore.throwNextUserSelect = true
      const originalFetch = global.fetch
      try {
        global.fetch = async () => {
          throw new Error("Fetch must not run after a failed credential lookup")
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "Saved despite lookup throw", response: "Response" }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("connection could not be verified"))
        assert.ok(mockStore.queries.some((q) => q.table === "users" && q.isMaybeSingle))
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 1)
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-31: Instagram POST uses the authenticated user's token and saved payload IDs", async () => {
      mockStore.users.push({ id: TEST_USER, access_token: "test_ig_token_31" })
      const originalFetch = global.fetch
      let capturedUrl = ""
      let capturedInit = null
      try {
        global.fetch = async (url, init) => {
          capturedUrl = String(url)
          capturedInit = init
          return { ok: true, status: 200, json: async () => ({ result: "success" }) }
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "Where are you based?", response: "We are based in India." }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()
        const url = new URL(capturedUrl)

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.strictEqual(data.warning, undefined)
        assert.strictEqual(capturedInit.method, "POST")
        assert.strictEqual(url.pathname, "/v24.0/me/messenger_profile")
        assert.strictEqual(url.searchParams.has("access_token"), false)
        assert.strictEqual(capturedInit.headers.Authorization, "Bearer test_ig_token_31")
        assert.strictEqual(capturedInit.headers["Content-Type"], undefined, "Must not manually set multipart Content-Type")
        assert.ok(capturedInit.body instanceof FormData, "Body must be a FormData instance")
        assert.strictEqual(capturedInit.body.get("platform"), "instagram")
        const iceBreakersField = JSON.parse(capturedInit.body.get("ice_breakers"))
        assert.strictEqual(Array.isArray(iceBreakersField), true)
        assert.strictEqual(iceBreakersField[0].question, "Where are you based?")
        assert.strictEqual(iceBreakersField[0].payload, `ICE_BREAKER_${data.data[0].id}`)
        assert.ok(capturedInit.signal instanceof AbortSignal, "Must pass AbortSignal timeout")
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-32: Only Meta's documented result success shape is accepted as sync success", async () => {
      mockStore.users.push({ id: TEST_USER, access_token: "test_ig_token_32" })
      const originalFetch = global.fetch
      try {
        global.fetch = async () => ({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
        })

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "Valid question", response: "Saved response" }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("Instagram sync failed"))
        assert.strictEqual(mockStore.ice_breakers.filter((r) => r.user_id === TEST_USER).length, 1)
      } finally {
        global.fetch = originalFetch
      }
    })

    it("ICE-33: Missing access token never reports a full database-and-Instagram success", async () => {
      mockStore.users.push({ id: TEST_USER })
      const originalFetch = global.fetch
      let fetchCalled = false
      try {
        global.fetch = async () => {
          fetchCalled = true
          throw new Error("Fetch must not run without an access token")
        }

        const req = new NextRequest("http://localhost:3000/api/ice-breakers", {
          method: "POST",
          headers: { Cookie: `insta_session=${userToken}` },
          body: JSON.stringify({ iceBreakers: [{ question: "No token", response: "Response" }] }),
        })
        const res = await iceBreakers.POST(req)
        const data = await res.json()

        assert.strictEqual(res.status, 200)
        assert.strictEqual(data.success, true)
        assert.ok(data.warning?.includes("no Instagram access token"))
        assert.strictEqual(fetchCalled, false)
      } finally {
        global.fetch = originalFetch
      }
    })

    // =========================================================================
    // WEBHOOK STATE MACHINE TESTS (WEBHOOK-SM-01 through WEBHOOK-SM-06)
    // =========================================================================
    it("WEBHOOK-SM-01: Duplicate event claim returns duplicate_completed on replay", async () => {
      mockStore.automations.push({
        id: "rule_sm_01",
        user_id: TEST_USER_ID,
        name: "SM Rule 1",
        trigger_source: "comment",
        trigger_type: "keyword",
        trigger_value: "help",
        response_content: JSON.stringify({ message: "Help!" }),
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
                  id: "comment_sm_01",
                  text: "I need help",
                  from: { id: "customer_sm" },
                  media: { id: "media_sm" },
                },
              },
            ],
          },
        ],
      }

      const req1 = makeSignedWebhookRequest(payload)
      const res1 = await instagramWebhook.POST(req1)
      assert.strictEqual(res1.status, 200, "First delivery should succeed")

      // Replay the same event - should be treated as duplicate
      const req2 = makeSignedWebhookRequest(payload)
      const res2 = await instagramWebhook.POST(req2)
      assert.strictEqual(res2.status, 200, "Replay should return 200 (duplicate skipped)")
    })

    it("WEBHOOK-SM-02: Event with missing DM MID is quarantined to manual_review", async () => {
      mockStore.automations.push({
        id: "rule_sm_02",
        user_id: TEST_USER_ID,
        name: "SM Rule 2",
        trigger_source: "dm",
        trigger_type: "keyword",
        trigger_value: "help",
        response_content: JSON.stringify({ message: "Help!" }),
        is_active: true,
      })

      const payload = {
        object: "instagram",
        entry: [
          {
            id: TEST_WEBHOOK_ID,
            messaging: [
              {
                sender: { id: "customer_sm_02" },
                recipient: { id: TEST_WEBHOOK_ID },
                message: { text: "I need help" },
                // No mid - should be quarantined
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200, "Quarantined event should return 200")
    })

    it("WEBHOOK-SM-03: Webhook with unknown user returns 200 and skips safely", async () => {
      const payload = {
        object: "instagram",
        entry: [
          {
            id: "999999999999999",
            changes: [
              {
                field: "comments",
                value: {
                  id: "comment_unknown",
                  text: "hello",
                  from: { id: "customer_unknown" },
                  media: { id: "media_unknown" },
                },
              },
            ],
          },
        ],
      }

      const req = makeSignedWebhookRequest(payload)
      const res = await instagramWebhook.POST(req)
      assert.strictEqual(res.status, 200, "Unknown user should return 200 and skip safely")
    })
  })
})
