import { HttpResponse } from "./auth-login.js";

export async function renderPrivacyPage(): Promise<HttpResponse> {
  const pageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nantis Privacy Policy & Data Guarantees</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    .container { max-width: 850px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 2.5rem; }
    h1 { font-size: 2.25rem; color: #60a5fa; margin-bottom: 0.5rem; }
    .subtitle { color: #94a3b8; font-size: 1.1rem; margin-bottom: 2rem; }
    .box { background: #0f172a; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; border-left: 4px solid #3b82f6; }
    .box-never { border-left-color: #ef4444; }
    h2 { font-size: 1.25rem; margin-top: 0; color: #f1f5f9; }
    ul { margin: 0; padding-left: 1.25rem; color: #cbd5e1; line-height: 1.7; }
    p { color: #cbd5e1; line-height: 1.6; }
  </style>
</head>
<body>
  <div style="background:#f59e0b;color:#000;text-align:center;padding:6px;font-weight:bold;">DEV MODE - In-Memory Local Development</div>
  <div class="container">
    <h1>Privacy Policy & Plain-English Data Guarantees</h1>
    <div class="subtitle">Our explicit, verifiable commitments regarding code privacy and metadata handling.</div>

    <div class="box">
      <h2>✅ What IS Stored in Nantis Databases</h2>
      <ul>
        <li><strong>Repository Metadata</strong>: GitHub installation ID, repository name, default branch, commit SHA, and scan status logs.</li>
        <li><strong>Finding Metrics</strong>: Rule IDs (e.g. <code>stripe-webhook-no-signature</code>), deterministic findings fingerprints, severity levels, and file line ranges (e.g. <code>src/route.ts:L10-L15</code>).</li>
        <li><strong>False Positive Feedback</strong>: Rule ID, finding fingerprint, and plain text user note provided during false positive reports.</li>
        <li><strong>Audit Logs</strong>: Operational timestamps, IP addresses, user agent strings, and action types for security auditability.</li>
      </ul>
    </div>

    <div class="box box-never">
      <h2>❌ What is NEVER Stored or Retained</h2>
      <ul>
        <li><strong>Source Code Files & Contents</strong>: Your source code, repository text files, and codebase contents are never saved or stored in our database. Scanning runs strictly in ephemeral memory.</li>
        <li><strong>Secret Credentials & API Keys</strong>: Secret values, environment variable payloads, and private key contents are masked in memory and never written to logs or database storage.</li>
        <li><strong>Source Snippets in Telemetry/Feedback</strong>: Reporting a false positive or sending telemetry transmits only rule IDs, fingerprints, and user notes—zero source code snippets are attached or retained.</li>
      </ul>
    </div>

    <p>If you have any questions regarding data handling or privacy practices, please refer to our codebase documentation or reach out to our team.</p>
  </div>
</body>
</html>`;

  return {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: pageHtml,
  };
}
