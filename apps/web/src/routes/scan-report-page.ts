import { ConfidenceTier, Finding } from "@nantis/core";
import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

const CONFIDENCE_TIER_ORDER: { tier: ConfidenceTier; label: string }[] = [
  { tier: "proven", label: "Proven Confidence" },
  { tier: "likely", label: "Likely Confidence" },
  { tier: "needs-review", label: "Needs Review" },
  { tier: "hygiene", label: "Hygiene" },
];

export async function renderScanReportPage(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  if (!userId) {
    return {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: `<!DOCTYPE html><html><body><h1>Authentication Required</h1></body></html>`,
    };
  }

  const scan = await db.getScanById(scanId);
  const targetRepoId = scan ? scan.repository_id : `non_existent_${scanId}`;

  let repo;
  try {
    const access = await assertRepoAccess(userId, targetRepoId);
    repo = access.repository;
  } catch (err) {
    if (err instanceof NotFoundError) {
      return {
        status: 404,
        headers: { "Content-Type": "text/html; charset=utf-8" },
        body: `<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>`,
      };
    }
    throw err;
  }

  if (!scan) {
    return {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: `<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>`,
    };
  }

  const findings = await db.getFindingsForScan(scanId);

  let reportHtml = "";

  if (scan.status === "done" || scan.status === "completed") {
    if (findings.length === 0) {
      reportHtml = `<p class="no-findings">no issues found in the checks we run</p>`;
    } else {
      // Group findings by confidence tier
      const groupedFindings = new Map<ConfidenceTier, Finding[]>();
      for (const t of CONFIDENCE_TIER_ORDER) {
        groupedFindings.set(t.tier, []);
      }
      for (const f of findings) {
        const tier = f.confidenceTier || "proven";
        const list = groupedFindings.get(tier) || [];
        list.push(f);
        groupedFindings.set(tier, list);
      }

      const sections: string[] = [];
      for (const { tier, label } of CONFIDENCE_TIER_ORDER) {
        const tierFindings = groupedFindings.get(tier) || [];
        if (tierFindings.length === 0) continue;

        const findingCards = tierFindings
          .map((f) => {
            const intro = f.introducedIn;
            let introducedInText = "Introduced-in: Information unavailable";
            if (intro) {
              const commitText = intro.commit ? `Commit: ${intro.commit}` : "";
              const prText = intro.pr ? `PR #${intro.pr}` : "";
              const authorText = intro.author ? `Author: ${intro.author}` : "";
              const dateText = intro.date ? `Date: ${intro.date}` : "";
              const reasonText = intro.confidenceReason ? `(${intro.confidenceReason})` : "";
              introducedInText = `Introduced-in: ${[commitText, prText, authorText, dateText, reasonText].filter(Boolean).join(" | ")}`;
            }

            const evidenceHops = f.evidenceChain
              .map(
                (hop) =>
                  `<li><strong>[${hop.kind.toUpperCase()}]</strong> ${hop.file}:${hop.line} - <code>${hop.maskedSnippet}</code> (${hop.note})</li>`
              )
              .join("\n");

            return `
            <div class="finding-card" data-severity="${f.severity}" data-confidence="${f.confidenceTier}">
              <h3>[${f.severity.toUpperCase()}] ${f.title}</h3>
              <p><strong>Rule ID:</strong> ${f.ruleId}</p>
              <p><strong>Location:</strong> ${f.file}:${f.lineRange.startLine}-${f.lineRange.endLine}</p>
              <p><strong>Explanation:</strong> ${f.explanation}</p>
              <p><strong>Introduced:</strong> ${introducedInText}</p>
              <h4>Evidence Chain (masked):</h4>
              <ul>
                ${evidenceHops}
              </ul>
            </div>
            `;
          })
          .join("\n");

        sections.push(`
          <section class="confidence-tier-section" data-tier="${tier}">
            <h2>${label} (${tierFindings.length})</h2>
            ${findingCards}
          </section>
        `);
      }

      reportHtml = `<div class="grouped-report-findings">${sections.join("\n")}</div>`;
    }
  } else if (scan.status === "failed") {
    reportHtml = `<div class="scan-error">
      <h2>Scan Execution Failed</h2>
      <p class="error-reason">${scan.error_message || "Scan execution encountered an unexpected error"}</p>
    </div>`;
  } else {
    reportHtml = `<div class="scan-progress">
      <h2>Scan in progress...</h2>
      <p>Current Status: <strong>${scan.status}</strong></p>
    </div>`;
  }

  const html = `<!DOCTYPE html>
<html>
  <head>
    <title>Scan Report - ${repo.full_name}</title>
  </head>
  <body>
    <h1>Scan Security Report for ${repo.full_name}</h1>
    <div class="scan-meta">
      <p><strong>Repository:</strong> ${repo.full_name}</p>
      <p><strong>Scan ID:</strong> ${scan.id}</p>
      <p><strong>Status:</strong> ${scan.status}</p>
      <p><strong>Commit SHA:</strong> ${scan.commit_sha}</p>
      <p><strong>Branch:</strong> ${scan.branch}</p>
      <p><strong>Report Generated At:</strong> ${new Date().toISOString()}</p>
    </div>
    <hr />
    ${reportHtml}
  </body>
</html>`;

  return {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: html,
  };
}
