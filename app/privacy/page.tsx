import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "Privacy Policy — AutoReply Studio",
  description:
    "Privacy Policy for AutoReply Studio. Details the collection, transient processing, storage, retention, and protection of Instagram account information, direct messages, automations, and technical event metadata.",
  robots: {
    index: true,
    follow: true,
  },
}

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10 px-4 sm:px-6 py-4">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <Link
            href="/"
            className="font-serif-display text-xl font-bold tracking-tight hover:opacity-80 transition-opacity"
          >
            AutoReply Studio
          </Link>
          <nav className="flex items-center gap-4 text-xs font-mono-ui text-muted-foreground">
            <Link href="/" className="hover:text-foreground transition-colors">
              Home
            </Link>
            <span className="text-border">•</span>
            <Link
              href="/privacy"
              className="text-foreground font-semibold underline underline-offset-4"
            >
              Privacy
            </Link>
            <span className="text-border">•</span>
            <Link href="/terms" className="hover:text-foreground transition-colors">
              Terms
            </Link>
            <span className="text-border">•</span>
            <Link
              href="/data-deletion"
              className="hover:text-foreground transition-colors"
            >
              Data Deletion
            </Link>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-14 w-full space-y-10">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mb-3">
            Privacy Policy
          </h1>
          <div className="flex flex-wrap items-center gap-3 text-xs font-mono-ui text-muted-foreground pb-6 border-b border-border">
            <span>Application: <strong>AutoReply Studio</strong></span>
            <span>•</span>
            <span>Effective Date: November 2026</span>
            <span>•</span>
            <span>Contact: <strong>prishafindsofficial@gmail.com</strong></span>
          </div>
        </div>

        {/* Notice Box */}
        <div className="p-4 rounded-lg border border-border bg-muted/30 text-sm leading-relaxed">
          <p>
            <strong>AutoReply Studio</strong> is a cloud-hosted automation application built for Instagram creators and businesses (specifically developed for <strong>@prisha_finds_official</strong>). The application interfaces with the official Meta Instagram Graph API (v24.0) to provide keyword-triggered comment responses, direct message automations, and product/affiliate link delivery. This Privacy Policy outlines our exact data collection, processing, storage, and retention practices based on our live codebase and database architecture.
          </p>
        </div>

        {/* Section 1: Data Collection & Storage */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            1. Information We Collect, Process &amp; Store
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Data collection is limited strictly to information necessary to execute automations, maintain the creator inbox, and manage account authorization. Based on our source code and database implementation, data is categorized as follows:
          </p>

          <div className="space-y-4 text-sm">
            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                A. Connected Creator Account &amp; OAuth Credentials (<code>users</code> table)
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li>Numeric Instagram User ID (Meta-scoped account identifier).</li>
                <li>Connected Instagram Username (creator handle).</li>
                <li>Connected Instagram Professional / Business Account ID.</li>
                <li>Associated Facebook Page ID.</li>
                <li>Page Access Token (stored as text in our hosted database) and token expiration timestamp.</li>
                <li>Optional creator AI preferences, custom AI context instructions, and user-configured AI credentials (when AI auto-reply is enabled).</li>
                <li>Account profile creation and update timestamps.</li>
              </ul>
              <p className="text-xs text-muted-foreground mt-2 italic">
                Note: The application does not collect or store user passwords, creator full names, profile picture image files, or account subscription plan tiers.
              </p>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                B. Direct Message History &amp; Inbox Threads (<code>conversations</code> &amp; <code>messages</code> tables)
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li><strong>Conversation Threads:</strong> Recipient Instagram Scoped ID, recipient username, and timestamp of the latest interaction.</li>
                <li><strong>Message Records:</strong> Direct message text content, sender Instagram Scoped ID, sender username, message identifier, creation timestamp, and origin direction (incoming from fan vs. outgoing creator automated reply).</li>
              </ul>
              <p className="text-xs text-muted-foreground mt-2 italic">
                Note: Fan full names and profile picture URLs are not captured or stored in conversation or message records.
              </p>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                C. Transient Comment &amp; Media Processing (No Dedicated Comments Table)
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li><strong>Transient Comment Evaluation:</strong> Incoming public comment text received via webhook is processed entirely in serverless runtime memory to evaluate keyword match rules and follower gating. Comment text is <strong>not</strong> persistently stored in a dedicated database table.</li>
                <li><strong>On-Demand Media Fetching:</strong> Instagram media (posts, reels, thumbnails, captions) are queried live on-demand via the Meta Graph API when a creator selects media in the dashboard. Media assets and post thumbnails are not archived locally.</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                D. Automations &amp; Interaction Templates (<code>automations</code> &amp; <code>ice_breakers</code> tables)
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li><strong>Automations:</strong> Rule name, trigger source (comment, dm, story), trigger type and value, response type, response content (DM/comment reply text, media selection, follow-up steps), and active status.</li>
                <li><strong>Ice Breakers:</strong> Pre-configured FAQ questions and automated payload responses displayed in Instagram chat starters.</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                E. Technical Deduplication &amp; Rate-Limit Telemetry (<code>webhook_events</code> &amp; <code>unlock_attempts</code> tables)
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li><strong>Webhook Idempotency (<code>webhook_events</code> table):</strong> Technical event delivery metadata, including event delivery identifiers, event type (e.g., <code>message</code>, <code>comment</code>), processed timestamp, and operational payload metadata. In current application code, failed event claims are explicitly deleted upon processing release or failure, while successful event claims persist in the database to prevent duplicate processing on Meta retries until separately cleaned by an administrator; no automated retention or truncation schedule exists.</li>
                <li><strong>Follower-Gate Rate Limiting (<code>unlock_attempts</code> table):</strong> Rate-limit counters keyed by the plaintext composite format <code>senderId::ruleId</code> (composed of the interacting fan Scoped ID and the automation rule UUID). The database RPC function <code>bump_unlock_attempt</code> performs atomic counter increments without any time-based expiration cleanup. Individual counter keys are cleared in application code when a verification check succeeds, when a negative follower check completes, or when the configured maximum attempt cap is reached. Counter keys that do not reach one of these completion conditions remain in the database until manually cleaned by an administrator. These records are not hashed, do not contain the creator&apos;s user ID, and do not cascade automatically on automation or user deletion.</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                F. Session Security &amp; Client-Side Telemetry
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
                <li><strong>Browser Sessions:</strong> The dashboard utilizes a stateless, cryptographically signed session cookie (<code>insta_session</code>) sealed with HMAC-SHA256 (minimum 32-character secret) and marked <code>HttpOnly</code>, <code>SameSite=Lax</code>. There is no server-side database session table.</li>
                <li><strong>Web Analytics:</strong> The client application mounts the standard <code>&lt;Analytics /&gt;</code> component from <code>@vercel/analytics/next</code> in the root layout without custom event tracking or user-tracking payloads. Application code does not transmit message text, Instagram usernames, or account IDs to this component; standard web analytics telemetry (such as page paths and web vitals) is processed by Vercel according to Vercel&apos;s service terms.</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card">
              <h3 className="font-semibold text-foreground mb-1">
                G. Dormant Schema Objects Notice
              </h3>
              <p className="text-muted-foreground text-xs leading-relaxed">
                The database schema includes dormant tables (<code>media_cache</code>, <code>content_pool</code>, <code>scheduler_config</code>, <code>reels_posts</code>, <code>dm_queue</code>) and a private storage bucket (<code>reels</code>) from legacy publishing prototypes. These capabilities are inactive in current application code; no creator video files are uploaded or stored in Supabase Storage during active operations. Live row counts in production databases are unverified and are not assumed to be empty.
              </p>
            </div>
          </div>
        </section>

        {/* Section 2: How We Use Data */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            2. How We Use Collected Data
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Collected data is utilized exclusively to operate the automation platform as configured by the creator:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-muted-foreground">
            <li>
              <strong>Keyword Matching &amp; Trigger Evaluation:</strong> Inspecting incoming Instagram comments and direct messages in memory to detect trigger keywords and deliver automated responses or product links.
            </li>
            <li>
              <strong>Follower Status Verification:</strong> Querying Meta Graph API endpoints to determine whether an interacting user follows the creator account prior to unlocking gated links or bonus content.
            </li>
            <li>
              <strong>Dashboard Inbox Display:</strong> Presenting active conversation threads and direct message history in the authenticated creator dashboard (secured via HMAC-SHA256 signed session cookies; no passwords are stored or used) for operational oversight and manual follow-ups.
            </li>
            <li>
              <strong>Optional AI Reply Generation:</strong> When explicitly enabled by the creator, sending message text and conversation history to the configured AI provider to generate contextual draft replies.
            </li>
            <li>
              <strong>Idempotency &amp; Replay Protection:</strong> Using cryptographic webhook event claims to prevent duplicate message dispatch when Meta retries webhook deliveries.
            </li>
          </ul>
          <div className="p-4 rounded-lg border border-border bg-muted/20 text-sm">
            <strong>No Data Selling or Advertising Networks:</strong> We do <strong>not</strong> sell, rent, monetize, or broker personal data, customer messages, or Instagram account details to any data brokers, ad networks, or commercial third parties.
          </div>
        </section>

        {/* Section 3: Third-Party Service Providers */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            3. Third-Party Infrastructure &amp; Service Providers
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            AutoReply Studio relies on a restricted set of established cloud infrastructure providers:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div className="p-4 rounded-lg border border-border bg-card">
              <h4 className="font-semibold text-foreground">Meta Platforms, Inc.</h4>
              <p className="text-xs text-muted-foreground mt-1">
                Official Instagram Graph API (v24.0) for OAuth token exchange, real-time webhook event ingress, comment reply dispatch, and direct message transmission.
              </p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <h4 className="font-semibold text-foreground">Supabase Inc.</h4>
              <p className="text-xs text-muted-foreground mt-1">
                Cloud-hosted managed PostgreSQL database providing persistent storage for user profiles, automations, ice breakers, conversations, and messages, with Row Level Security (RLS) enforcement. (Note: Application OAuth tokens and account credentials are stored directly in database records to enable automated API interactions and are not individually encrypted at the application layer).
              </p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <h4 className="font-semibold text-foreground">Vercel Inc. (Hosting &amp; Runtime)</h4>
              <p className="text-xs text-muted-foreground mt-1">
                Serverless execution platform hosting application APIs and processing incoming webhook requests. Application-authored server logs are sanitized to exclude message text and personal IDs; standard platform-level edge HTTP access logs (such as request IP address, request path, HTTP status, and user-agent) are managed by Vercel under its platform operations. Application code does not configure or control platform log retention.
              </p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <h4 className="font-semibold text-foreground">AI Inference Providers (Optional)</h4>
              <p className="text-xs text-muted-foreground mt-1">
                Disabled by default. When enabled by the creator, requests are routed exclusively over HTTPS to approved hostnames: Groq (<code>api.groq.com</code>), OpenAI (<code>api.openai.com</code>), or OpenRouter (<code>openrouter.ai</code>).
              </p>
            </div>
          </div>
        </section>

        {/* Section 4: Security Architecture */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            4. Security Architecture &amp; Controls
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            We employ rigorous, evidence-based security controls across our codebase:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-sm text-muted-foreground">
            <li>
              <strong>Webhook Cryptographic Verification:</strong> All incoming Meta webhook notifications are verified using HMAC-SHA256 signatures (<code>x-hub-signature-256</code>) with timing-safe comparison prior to payload processing.
            </li>
            <li>
              <strong>Application Log Minimization:</strong> Application-authored server logs strictly exclude direct message content, comment text, fan Instagram IDs, usernames, and automation rule names. System logging utilizes validated HTTP statuses and standardized error categories.
            </li>
            <li>
              <strong>Cryptographic Browser Sessions:</strong> Dashboard access is protected by HMAC-SHA256 signed cookies. Tampered, expired, or malformed session tokens fail closed immediately.
            </li>
            <li>
              <strong>Tenant Isolation &amp; Single-Record Bounds:</strong> User-linked database queries enforce tenant isolation via Row Level Security (RLS). Webhook user lookups use single-record indexed queries, preventing table scans and query injection.
            </li>
            <li>
              <strong>Strict AI URL Whitelisting:</strong> AI endpoints are strictly validated against an approved HTTPS domain allowlist, blocking SSRF, unapproved hostnames, non-standard ports, and credential embedding.
            </li>
          </ul>
        </section>

        {/* Section 5: Data Retention & User Rights */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            5. Data Retention &amp; User Deletion Rights
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Our data retention and deletion policies reflect actual application operations:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-sm text-muted-foreground">
            <li>
              <strong>No Automated Deletion SLA:</strong> Production scheduled cleanup status for technical telemetry is unverified; persistent records in our database (including creator account profiles, automations, ice breakers, conversation threads, message logs, webhook events, and uncleared unlock attempts) remain until manually deleted upon verified request.
            </li>
            <li>
              <strong>Scope of Local Deletion vs. Third-Party Retention:</strong>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-xs">
                <li><em>Local Application Database:</em> Deletion requests permanently remove active records from our hosted Supabase database.</li>
                <li><em>Meta Platforms:</em> Revoking permissions in Instagram halts future API events; historical platform interactions previously processed by Meta remain governed by Meta&apos;s Data Policy.</li>
                <li><em>Third-Party AI Providers:</em> If optional AI replies were enabled, prompts and context previously transmitted to external AI providers are governed by their respective API retention policies.</li>
                <li><em>Vercel Infrastructure:</em> Standard serverless request metadata is maintained under Vercel&apos;s platform operational logging.</li>
                <li><em>Provider Backups &amp; Logs:</em> Local deletion applies to active operational database records. Provider-managed infrastructure backups or cloud platform logs (such as Supabase database snapshots or Vercel edge access logs) may retain copies under their respective provider policies. Local deletion does not guarantee immediate deletion from all provider backups, and no fixed retention SLA is offered.</li>
              </ul>
            </li>
            <li>
              <strong>Two Separate Actions Required:</strong>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-xs">
                <li><em>Action 1 (Revoke Meta Access):</em> Disconnect AutoReply Studio via <em>Instagram Settings &rarr; Website permissions &rarr; Apps and Websites &rarr; Remove</em>. This revokes Meta&apos;s authorization grant and stops future webhook delivery, but does not delete previously stored database records.</li>
                <li><em>Action 2 (Request Database Erasure):</em> Submit an email deletion request to our administrator. Deleting local database records does not automatically notify Meta to revoke authorization.</li>
              </ul>
            </li>
            <li>
              <strong>No Automated Turnaround Deadline:</strong> Deletion requests are processed manually by our operations team upon identity verification; we do not promise an automated turnaround SLA or fixed processing timeline.
            </li>
            <li>
              For full step-by-step instructions on submitting a deletion request, please visit our{" "}
              <Link
                href="/data-deletion"
                className="text-foreground underline underline-offset-4 hover:opacity-80"
              >
                User Data Deletion Instructions Page
              </Link>
              .
            </li>
          </ul>
        </section>

        {/* Section 6: Contact */}
        <section className="space-y-4 pt-4 border-t border-border">
          <h2 className="text-2xl font-semibold tracking-tight">
            6. Contact &amp; Inquiries
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            For inquiries regarding this Privacy Policy, your stored data, or to submit a data deletion request, contact:
          </p>
          <div className="p-4 rounded-lg border border-border bg-card inline-block text-sm">
            <p className="font-semibold text-foreground">AutoReply Studio Support</p>
            <p className="text-muted-foreground mt-1">
              Email:{" "}
              <a
                href="mailto:prishafindsofficial@gmail.com"
                className="text-foreground underline underline-offset-4"
              >
                prishafindsofficial@gmail.com
              </a>
            </p>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-border px-4 sm:px-6 py-8 mt-12 bg-card/30">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono-ui text-muted-foreground">
          <span>&copy; {new Date().getFullYear()} AutoReply Studio. All rights reserved.</span>
          <div className="flex items-center gap-4">
            <Link href="/privacy" className="hover:text-foreground transition-colors">
              Privacy Policy
            </Link>
            <Link href="/terms" className="hover:text-foreground transition-colors">
              Terms of Service
            </Link>
            <Link href="/data-deletion" className="hover:text-foreground transition-colors">
              Data Deletion
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
