import { getDefaultHeaders, renderPageLayout } from "./ui-templates.js";
import { HttpResponse } from "./auth-login.js";

export async function renderPrivacyPage(): Promise<HttpResponse> {
  const content = `
    <div style="max-width: 850px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div>
        <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; margin-bottom: 6px;">Privacy Policy & Plain-English Data Guarantees</h1>
        <p style="color: #64748b; font-size: 14px;">Our explicit, verifiable commitments regarding code privacy and metadata handling.</p>
      </div>

      <div class="ui-card" style="border-left: 4px solid #2563eb;">
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px;">✅ What IS Stored in Nantis Databases</h2>
        <ul style="padding-left: 20px; color: #334155; font-size: 14px; line-height: 1.7;">
          <li><strong>Repository Metadata</strong>: GitHub installation ID, repository name, default branch, commit SHA, and scan status logs.</li>
          <li><strong>Finding Metrics</strong>: Rule IDs (e.g. <code>stripe-webhook-no-signature</code>), deterministic findings fingerprints, severity levels, and file line ranges (e.g. <code>src/route.ts:L10-L15</code>).</li>
          <li><strong>False Positive Feedback</strong>: Rule ID, finding fingerprint, and plain text user note provided during false positive reports.</li>
          <li><strong>Audit Logs</strong>: Operational timestamps, IP addresses, user agent strings, and action types for security auditability.</li>
        </ul>
      </div>

      <div class="ui-card" style="border-left: 4px solid #dc2626;">
        <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px;">❌ What is NEVER Stored or Retained</h2>
        <ul style="padding-left: 20px; color: #334155; font-size: 14px; line-height: 1.7;">
          <li><strong>Source Code Files & Contents</strong>: Your source code, repository text files, and codebase contents are never saved or stored in our database. Scanning runs strictly in ephemeral memory.</li>
          <li><strong>Secret Credentials & API Keys</strong>: Secret values, environment variable payloads, and private key contents are masked in memory and never written to logs or database storage.</li>
          <li><strong>Source Snippets in Telemetry/Feedback</strong>: Reporting a false positive or sending telemetry transmits only rule IDs, fingerprints, and user notes—zero source code snippets are attached or retained.</li>
        </ul>
      </div>

      <p style="color: #64748b; font-size: 13px;">If you have any questions regarding data handling or privacy practices, please refer to our codebase documentation or reach out to our team.</p>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Privacy Policy",
      content,
    }),
  };
}
