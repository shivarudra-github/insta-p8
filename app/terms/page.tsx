import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "Terms of Service — AutoReply Studio",
  description:
    "Terms of Service for AutoReply Studio. Defines acceptable use, authorized account requirements, automation rules, platform compliance, and limitations of liability.",
  robots: {
    index: true,
    follow: true,
  },
}

export default function TermsPage() {
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
            <Link
              href="/terms"
              className="text-foreground font-semibold underline underline-offset-4"
            >
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
            Terms of Service
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
            Please read these Terms of Service (&ldquo;Terms&rdquo;) carefully before using <strong>AutoReply Studio</strong> (&ldquo;the Service&rdquo;). By connecting your Instagram account or using the application, you agree to be bound by these Terms. If you do not agree to these Terms, do not connect your account or use the Service.
          </p>
        </div>

        {/* Section 1: Service Description */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            1. Description of Service
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            AutoReply Studio is an independent software application designed to provide automated direct message replies, keyword-triggered comment responses, post link delivery, and content management for Instagram Professional and Business accounts via the official Meta Instagram Graph API (v24.0).
          </p>
          <div className="p-3 rounded-md border border-border bg-card text-xs text-muted-foreground">
            <strong>Disclaimer:</strong> AutoReply Studio is an independently developed application. It is not sponsored, endorsed, administered by, or associated with Meta Platforms, Inc., Instagram, or ManyChat. We do not claim any official corporate affiliation or regulatory certification.
          </div>
        </section>

        {/* Section 2: Authorized Account Use & Eligibility */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            2. Authorized Account Use & Eligibility
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            To use AutoReply Studio, you represent and warrant that:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-sm text-muted-foreground">
            <li>You are at least 18 years of age (or the age of legal majority in your jurisdiction).</li>
            <li>You are the authorized owner, administrator, or licensed manager of the Instagram Professional/Business account connected to the Service.</li>
            <li>You possess the legal authority to bind that account and grant the OAuth permissions requested by AutoReply Studio.</li>
            <li>You will maintain the security and confidentiality of your credentials and local session tokens.</li>
          </ul>
        </section>

        {/* Section 3: Compliance with Platform Rules & Acceptable Use */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold tracking-tight">
            3. Platform Compliance & Acceptable Use
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            You agree to comply with all applicable laws and third-party platform regulations, including:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-muted-foreground">
            <li>
              <strong>Meta Platform Terms & Guidelines:</strong> You must strictly adhere to the{" "}
              <em>Meta Platform Terms</em>, <em>Instagram Community Guidelines</em>, and <em>Instagram Commercial Terms</em> at all times.
            </li>
            <li>
              <strong>No Spam or Unsolicited Messaging:</strong> Automations must only be triggered in response to genuine user interactions (such as explicit comment keywords or incoming direct inquiries). You must not configure automations to send unsolicited bulk messages, spam, repetitive promotions, or deceptive content.
            </li>
            <li>
              <strong>No Abusive or Harassing Content:</strong> You must not configure automated replies that contain hate speech, harassment, threats, adult content, fraudulent schemes, or intellectual property violations.
            </li>
            <li>
              <strong>Messaging Windows & Rate Limits:</strong> You acknowledge that Meta strictly enforces standard 24-hour customer service messaging windows and API rate limits. You agree not to attempt to circumvent Meta&apos;s messaging policies or rate limitations.
            </li>
          </ul>
        </section>

        {/* Section 4: User Responsibilities */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            4. User Responsibilities & Automation Behavior
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            You maintain sole responsibility for the configuration and output of your automations:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-sm text-muted-foreground">
            <li>
              You are entirely responsible for the wording, links, media, and promises transmitted through automated comment replies and direct messages sent on your behalf.
            </li>
            <li>
              If you enable optional AI-assisted auto-replies, you are solely responsible for setting appropriate system prompts and monitoring AI-generated outputs for factual accuracy and compliance with advertising standards.
            </li>
            <li>
              You agree that AutoReply Studio is not liable for any account restrictions, shadowbans, feature blocks, or suspensions imposed by Meta on your Instagram account resulting from your automation configuration, volume, or policy violations.
            </li>
          </ul>
        </section>

        {/* Section 5: Third-Party Dependencies & Service Availability */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            5. Third-Party Dependencies & &ldquo;As Is&rdquo; Availability
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            The Service relies on third-party cloud infrastructure and external APIs, including the Meta Instagram Graph API, Supabase, and Vercel:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-sm text-muted-foreground">
            <li>
              <strong>&ldquo;As Is&rdquo; Provision:</strong> AutoReply Studio is provided on an <strong>&ldquo;AS IS&rdquo;</strong> and <strong>&ldquo;AS AVAILABLE&rdquo;</strong> basis without warranties of any kind, whether express or implied, including fitness for a particular purpose or continuous uptime.
            </li>
            <li>
              <strong>API Interruptions:</strong> Delivery of automated messages depends upon Meta&apos;s webhook routing and Graph API responsiveness. We do not guarantee uninterrupted message delivery or instant response latency during Instagram platform outages or network disruptions.
            </li>
            <li>
              <strong>Platform Modifications:</strong> Meta regularly updates its Graph API and platform requirements. Changes enacted by Meta may modify or deprecate specific features with or without notice.
            </li>
          </ul>
        </section>

        {/* Section 6: Account Disconnection & Termination */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            6. Disconnection & Service Termination
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            You may disconnect your Instagram account at any time through your Instagram application permissions or by contacting us for manual data deletion.
          </p>
          <p className="text-sm text-muted-foreground leading-relaxed">
            We reserve the right to suspend, disable, or terminate access to AutoReply Studio at our discretion, without prior notice, if we believe you have violated these Terms, engaged in abusive messaging, or generated excessive platform errors.
          </p>
        </section>

        {/* Section 7: Intellectual Property */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            7. Content Ownership & Intellectual Property
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            You retain all rights, title, and ownership in and to your Instagram media, post captions, custom message templates, and brand assets. AutoReply Studio claims no ownership rights over your content.
          </p>
        </section>

        {/* Section 8: Limitation of Liability */}
        <section className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">
            8. Limitation of Liability
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            To the maximum extent permitted by applicable law, in no event shall AutoReply Studio, its creators, developers, or affiliates be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of profits, data, follower reach, engagement, or business reputation, arising from or related to your use of or inability to use the Service or any actions taken by Meta Platforms, Inc. regarding your account.
          </p>
        </section>

        {/* Section 9: Contact */}
        <section className="space-y-4 pt-4 border-t border-border">
          <h2 className="text-2xl font-semibold tracking-tight">
            9. Contact & Inquiries
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            For questions or notices concerning these Terms of Service, please contact us at:
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
