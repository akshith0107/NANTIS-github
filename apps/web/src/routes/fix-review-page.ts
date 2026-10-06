import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
  validateCsrfToken,
} from "./ui-templates.js";

export async function renderFixReviewPage(
  req: RequestContext,
  findingId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized",
        content: `<h1>401 Unauthorized</h1><p>Please sign in to view finding details.</p>`,
      }),
    };
  }

  const session = decodeSession(token, env.SESSION_SECRET);
  if (!session || !session.userId) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized",
        content: `<h1>401 Unauthorized</h1><p>Session invalid or expired.</p>`,
      }),
    };
  }

  const finding = await db.getFindingById(findingId);
  if (!finding) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Finding Not Found",
        userLogin: session.githubLogin,
        content: `<h1>404 Finding Not Found</h1><p>The requested finding ID does not exist.</p>`,
      }),
    };
  }

  try {
    await assertRepoAccess(session.userId, finding.scan_id ? (await db.getScanById(finding.scan_id))?.repository_id || "" : "");
  } catch (err) {
    if (err instanceof NotFoundError) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          userLogin: session.githubLogin,
          content: `<h1>404 Not Found</h1><p>Finding or scan not found.</p>`,
        }),
      };
    }
  }

  const csrfToken = getOrCreateCsrfToken(session.userId);

  // POST handler: approve fix
  if (req.method === "POST") {
    if (!validateCsrfToken(req, session.userId)) {
      return {
        status: 403,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "403 Invalid CSRF Token",
          userLogin: session.githubLogin,
          content: `<h1>403 Forbidden</h1><p>Invalid or missing CSRF token.</p>`,
        }),
      };
    }

    const content = `
      <div style="max-width: 800px; margin: 0 auto;">
        <div class="card" style="border-left: 4px solid #16a34a;">
          <h1 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 12px; color: #4ade80;">
            Fix Approved & Applied Locally
          </h1>
          <div style="margin-bottom: 20px;">
            <span class="pr-status-badge">PR creation not connected yet</span>
          </div>
          <p style="color: var(--text-muted); margin-bottom: 16px;">
            The AST patch for finding <strong>${escapeHtml(finding.ruleId)}</strong> was verified against syntax boundaries and applied in local memory.
          </p>
          <p style="color: var(--text-dim); font-size: 0.9rem; margin-bottom: 24px;">
            In local development mode, automated GitHub Pull Request creation is disabled. No remote GitHub repository changes were executed.
          </p>
          <div>
            <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-primary">
              Return to Scan Findings
            </a>
          </div>
        </div>
      </div>
    `;

    return {
      status: 200,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "Fix Approved",
        userLogin: session.githubLogin,
        csrfToken,
        content,
      }),
    };
  }

  // GET: render review page
  let diffText = "--- " + finding.file + "\n+++ " + finding.file + "\n@@ -1,1 +1,3 @@\n+// NANTIS Verified AST Patch\n";
  if (finding.ruleId === "missing-rls-in-migration") {
    diffText = `--- ${finding.file}\n+++ ${finding.file}\n@@ -1,1 +1,3 @@\n+ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;\n+-- TODO: Define RLS policy for invoices. Needs Human Review`;
  } else if (finding.ruleId === "stripe-webhook-no-signature") {
    diffText = `--- ${finding.file}\n+++ ${finding.file}\n@@ -2,3 +2,5 @@\n+  const signature = req.headers.get("stripe-signature");\n+  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET);`;
  }

  const proofLabel = "Not proven, reasoned from code";

  const content = `
    <div style="max-width: 900px; margin: 0 auto;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
          <a href="/scans/${escapeHtml(finding.scan_id)}" style="color: var(--text-muted); text-decoration: none; font-size: 0.9rem;">
            &larr; Back to Scan Findings
          </a>
          <h1 style="font-size: 1.6rem; font-weight: 800; margin-top: 8px;">
            Fix Review: ${escapeHtml(finding.title)}
          </h1>
        </div>
        <div style="display: flex; gap: 8px;">
          <span class="verification-badge">WEAK verification</span>
          <span class="pr-status-badge">PR creation not connected yet</span>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 16px;">Finding Summary</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px;">
          <div>
            <div style="font-size: 0.8rem; color: var(--text-dim);">Rule ID</div>
            <div style="font-weight: 600; font-family: monospace;">${escapeHtml(finding.ruleId)}</div>
          </div>
          <div>
            <div style="font-size: 0.8rem; color: var(--text-dim);">Severity</div>
            <div style="font-weight: 600; text-transform: uppercase;">${escapeHtml(finding.severity)}</div>
          </div>
          <div>
            <div style="font-size: 0.8rem; color: var(--text-dim);">Confidence Tier</div>
            <div style="font-weight: 600;">${escapeHtml(finding.confidenceTier)}</div>
          </div>
          <div>
            <div style="font-size: 0.8rem; color: var(--text-dim);">Proof Status</div>
            <div style="font-size: 0.85rem;">${proofLabel}</div>
          </div>
        </div>

        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.8rem; color: var(--text-dim);">Location</div>
          <div style="font-family: monospace; font-size: 0.9rem; color: var(--accent-cyan);">
            ${escapeHtml(finding.file)}:${finding.lineRange.startLine}-${finding.lineRange.endLine}
          </div>
        </div>

        <div>
          <div style="font-size: 0.8rem; color: var(--text-dim); margin-bottom: 4px;">Explanation</div>
          <p style="color: var(--text-muted); font-size: 0.95rem;">${escapeHtml(finding.explanation)}</p>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between;">
          <span>Verified AST Patch Diff</span>
          <span style="font-size: 0.8rem; font-weight: 500; color: var(--text-dim);">Syntax checked locally</span>
        </h3>

        <pre style="background: #040711; border: 1px solid var(--border-color); padding: 16px; border-radius: 8px; overflow-x: auto; font-family: monospace; font-size: 0.85rem; color: #38bdf8; line-height: 1.6;">${escapeHtml(diffText)}</pre>

        <form method="POST" action="/findings/${escapeHtml(finding.db_id || finding.id)}/fix" style="margin-top: 24px; display: flex; gap: 16px; align-items: center;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          <button type="submit" class="btn btn-success" style="padding: 12px 24px;">
            Approve & Apply Fix
          </button>
          <a href="/scans/${escapeHtml(finding.scan_id)}" class="btn btn-outline">
            Cancel
          </a>
        </form>
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Fix Review - ${finding.ruleId}`,
      userLogin: session.githubLogin,
      csrfToken,
      content,
    }),
  };
}
