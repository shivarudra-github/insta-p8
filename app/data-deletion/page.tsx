import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "User Data Deletion Instructions — AutoReply Studio",
  description:
    "Instructions for revoking Instagram application permissions and submitting a manual account data deletion request for AutoReply Studio.",
  robots: {
    index: true,
    follow: true,
  },
}

export default function DataDeletionPage() {
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
            <Link href="/privacy" className="hover:text-foreground transition-colors">
              Privacy
            </Link>
            <span className="text-border">•</span>
            <Link href="/terms" className="hover:text-foreground transition-colors">
              Terms
            </Link>
            <span className="text-border">•</span>
            <Link
              href="/data-deletion"
              className="text-foreground font-semibold underline underline-offset-4"
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
            User Data Deletion Instructions
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
            Pursuant to Meta Platform Terms and data privacy best practices, users of <strong>AutoReply Studio</strong> have the right to request the permanent deletion of their account profile, automations, ice breakers, conversation threads, message logs, and associated technical records. This document provides clear, manual instructions to disconnect the application and request complete data erasure.
          </p>
        </div>

        {/* Two Separate Actions Explanation */}
        <div className="p-4 rounded-lg border border-amber-500/20 bg-amber-500/5 text-sm space-y-2">
          <h2 className="font-semibold text-amber-200">Important: Two Separate Actions Required</h2>
          <p className="text-muted-foreground text-xs leading-relaxed">
            Complete account offboarding requires two independent steps:
          </p>
          <ol className="list-decimal pl-5 space-y-1 text-xs text-muted-foreground">
            <li><strong>Revoke Meta Authorization:</strong> Disconnect AutoReply Studio in your Instagram / Meta settings to prevent further API access. Deleting database records locally does not automatically notify or revoke Meta&apos;s OAuth authorization grant.</li>
            <li><strong>Request Local Data Deletion:</strong> Submit an email request to our administrator to delete stored database records. Removing the app in Instagram stops new communication, but existing stored records remain in our database until manually deleted.</li>
          </ol>
        </div>

        {/* Step-by-Step Instructions */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold tracking-tight">
            Step-by-Step Deletion Process
          </h2>

          <div className="space-y-6 text-sm">
            {/* Step 1: Meta Revocation */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  1
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Revoke AutoReply Studio in Instagram Settings
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                To revoke our application&apos;s authorization to communicate with your Instagram account via Meta&apos;s Graph API:
              </p>
              <ol className="list-decimal pl-13 space-y-1 text-muted-foreground text-xs">
                <li>Log in to your Instagram account on the mobile app or at <strong>instagram.com</strong>.</li>
                <li>Navigate to your <strong>Profile</strong> &rarr; open <strong>Settings and privacy</strong>.</li>
                <li>Under <em>&ldquo;Your app and media&rdquo;</em>, select <strong>Website permissions</strong> (or <strong>Apps and Websites</strong>).</li>
                <li>Locate <strong>AutoReply Studio</strong> under the <strong>Active</strong> tab.</li>
                <li>Select <strong>Remove</strong> to revoke the OAuth access token on Meta&apos;s servers.</li>
              </ol>
            </div>

            {/* Step 2: Email Deletion Request */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  2
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Submit a Manual Deletion Request via Email
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                AutoReply Studio utilizes a verified manual administrator workflow for data destruction (no automated Meta data-deletion callback endpoint exists). Send your deletion request to our official contact:
              </p>
              <div className="ml-8 p-4 rounded-md border border-border bg-muted/40 font-mono-ui text-xs space-y-1">
                <p><strong>To:</strong> prishafindsofficial@gmail.com</p>
                <p><strong>Subject:</strong> Data Deletion Request - [Your Instagram Username]</p>
                <p><strong>Body:</strong> Please state that you request the permanent deletion of all data associated with your Instagram handle (and numeric User ID if known) from AutoReply Studio.</p>
              </div>
            </div>

            {/* Step 3: Identity Verification */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  3
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Identity Verification
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                To protect accounts from fraudulent or malicious deletion requests, the system administrator verifies the origin of the request prior to executing deletion:
              </p>
              <ul className="list-disc pl-13 space-y-1 text-muted-foreground text-xs">
                <li>Verification that the request originates from the verified creator email address associated with the account, OR</li>
                <li>Confirmation via direct communication from the connected Instagram handle prior to permission revocation.</li>
              </ul>
            </div>

            {/* Step 4: Deletion Scope & Architecture Details */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  4
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Scope of Stored Data Deletion
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                Upon verified request, administrators identify and delete database records that can be reliably associated with your requesting account. Unlinked historical records may remain where association cannot be established, and technical exceptions must be disclosed upon completion:
              </p>
              <div className="ml-8 space-y-3 text-xs">
                <div className="p-3 rounded border border-border bg-background space-y-1">
                  <p className="font-semibold text-foreground">User-Linked Cascading Records</p>
                  <p className="text-muted-foreground">
                    Deleting the user record in the <code>users</code> table triggers foreign-key cascading deletion across associated tables: <code>automations</code>, <code>ice_breakers</code>, <code>conversations</code>, and <code>messages</code>.
                  </p>
                </div>
                <div className="p-3 rounded border border-border bg-background space-y-1">
                  <p className="font-semibold text-foreground">Unlinked Technical Records (Separate Manual Cleanup)</p>
                  <p className="text-muted-foreground">
                    <code>webhook_events</code> records do not share foreign-key cascade constraints with the <code>users</code> table. While failed claims are deleted by application code upon processing release, successful event claims persist to prevent duplicate event handling. During account offboarding, event claims matching your account&apos;s history are separately cleaned by the administrator; no automated cleanup schedule exists.
                  </p>
                  <p className="text-muted-foreground">
                    <code>unlock_attempts</code> rate-limiting counters are keyed by a plaintext composite string format (<code>senderId::ruleId</code>). The underlying RPC function (<code>bump_unlock_attempt</code>) performs atomic counter increments without any time-based expiration cleanup. Individual counter keys are cleared in application code when a verification check succeeds, when a negative follower check completes, or when the configured maximum attempt cap is reached. Counter keys that do not reach one of these completion conditions remain in the database. Because these records do not contain creator user IDs and do not cascade automatically, the administrator identifies and purges keys matching all currently associated automation rule IDs (both active and inactive) before parent records are removed. However, if an automation was deleted prior to the account offboarding request, its rule ID is no longer present in the database to associate with your creator account; such historical orphaned keys cannot be reliably attributed or deleted, and complete counter removal across historical untracked keys cannot be promised.
                  </p>
                </div>
                <div className="p-3 rounded border border-border bg-background space-y-1">
                  <p className="font-semibold text-foreground">Dormant Schema Objects &amp; Storage Review</p>
                  <p className="text-muted-foreground">
                    The administrator inspects dormant schema tables (<code>media_cache</code>, <code>content_pool</code>, <code>scheduler_config</code>, <code>reels_posts</code>, <code>dm_queue</code>) and private storage buckets to delete identifiable records or assets where an association to your account can be reliably established. Complete erasure cannot be guaranteed for unknown, unindexed, or unattributable objects.
                  </p>
                </div>
              </div>
            </div>

            {/* Step 5: Third-Party Retention & Deletion Boundaries */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  5
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Third-Party Retention &amp; Deletion Boundaries
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                Please note the following boundaries regarding data erasure:
              </p>
              <ul className="list-disc pl-13 space-y-1.5 text-muted-foreground text-xs">
                <li>
                  <strong>Local Application Database:</strong> Deletion permanently purges identified, account-linked active operational records across tables in our hosted Supabase PostgreSQL instance. It does not guarantee the removal of unknown, unindexed, or orphaned database records that cannot be reliably attributed to your account.
                </li>
                <li>
                  <strong>Meta Platforms:</strong> Revoking access in Instagram prevents future API communication; Meta maintains platform event logs, authorization histories, and message records on its own systems subject to Meta&apos;s Data Policy.
                </li>
                <li>
                  <strong>Third-Party AI Inference Providers:</strong> If optional AI auto-replies were enabled, message context and prompts previously transmitted to external AI providers (Groq, OpenAI, OpenRouter) are governed by the respective provider&apos;s retention and developer policies.
                </li>
                <li>
                  <strong>Vercel Infrastructure:</strong> Standard serverless execution request metadata (such as edge access IP addresses and request paths) is managed under Vercel&apos;s platform operational logging.
                </li>
                <li>
                  <strong>Provider-Managed Backups &amp; Logs:</strong> Local deletion applies strictly to active operational database records. Provider-managed infrastructure backups or cloud platform logs may retain copies subject to their respective provider policies. Local database deletion does not guarantee immediate or selective deletion from provider backups, and no fixed backup retention SLA is guaranteed.
                </li>
                <li>
                  <strong>No Turnaround Deadline:</strong> Deletions are processed manually upon verified creator request; we do not guarantee or advertise an automated turnaround SLA or fixed processing timeframe.
                </li>
              </ul>
            </div>

            {/* Step 6: Browser Session Termination */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  6
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Browser Session Invalidation
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                AutoReply Studio uses stateless signed browser cookies (<code>insta_session</code>). Because stateless cookies reside entirely on client devices and cannot be remotely cleared from your browser by an administrator:
              </p>
              <ul className="list-disc pl-13 space-y-1 text-muted-foreground text-xs">
                <li>You should log out of the dashboard or manually clear cookies for the application domain in your browser settings.</li>
                <li>Once the server-side user record is purged from the <code>users</code> table, subsequent requests presenting an existing session cookie will fail database user lookup and be denied access immediately.</li>
              </ul>
            </div>

            {/* Step 7: Confirmation */}
            <div className="p-5 rounded-lg border border-border bg-card space-y-3">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-primary/10 text-primary font-mono-ui text-xs font-bold flex items-center justify-center">
                  7
                </span>
                <h3 className="font-semibold text-foreground text-base">
                  Confirmation of Completion
                </h3>
              </div>
              <p className="text-muted-foreground leading-relaxed pl-8">
                Following execution of the manual database purge, the administrator will reply to your request email with formal written confirmation detailing the specific account records, automations, and message logs identified and deleted from the live application database, along with disclosure of any technical exceptions (such as unattributable historical rate-limit keys or unlinked delivery telemetry) where records could not be reliably linked to your account. Deletion from external provider infrastructure (Meta platform systems, third-party AI APIs, Vercel edge access logs, and provider backup snapshots) is not governed by local database deletion and remains subject to the respective providers&apos; policies.
              </p>
            </div>
          </div>
        </section>

        {/* Section: Questions */}
        <section className="space-y-4 pt-4 border-t border-border">
          <h2 className="text-2xl font-semibold tracking-tight">
            Questions Regarding Data Deletion
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            If you have questions about the data deletion workflow or need help disconnecting your Instagram account, please contact:
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
