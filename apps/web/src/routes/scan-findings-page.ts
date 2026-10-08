import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import { renderScanFindingsContent, ScanFindingsRenderData } from "./scan-findings-renderer.js";
import {
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
} from "./ui-templates.js";

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

export async function renderScanFindingsPage(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);

  if (!scan) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Not Found",
        content: `
          <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
            <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
            <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
          </div>
        `,
      }),
    };
  }

  let repo;
  let isAnonymous = false;

  if (userId) {
    try {
      const access = await assertRepoAccess(userId, scan.repository_id);
      repo = access.repository;
    } catch (err) {
      if (err instanceof NotFoundError) {
        return {
          status: 404,
          headers: getDefaultHeaders(),
          body: renderPageLayout({
            title: "404 Not Found",
            content: `
              <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
                <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
                <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
                <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
              </div>
            `,
          }),
        };
      }
      throw err;
    }
  } else {
    repo = await db.getRepositoryById(scan.repository_id);
    if (!repo || repo.private) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          content: `
            <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
              <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
              <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
              <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
            </div>
          `,
        }),
      };
    }
    isAnonymous = true;
  }

  const csrfToken = getOrCreateCsrfToken(userId || "anonymous");
  const findings = await db.getFindingsForScan(scanId);
  const totalScansCount = (await db.getScansForRepository(scan.repository_id)).length;
  const prevScan = await db.getPreviousCompletedScan(scan.repository_id, scan.id);

  let prevCrit = 0, prevHigh = 0, prevMed = 0, prevLow = 0;
  if (prevScan) {
    const prevFindings = await db.getFindingsForScan(prevScan.id);
    prevCrit = prevFindings.filter((f) => f.severity === "critical").length;
    prevHigh = prevFindings.filter((f) => f.severity === "high").length;
    prevMed = prevFindings.filter((f) => f.severity === "medium").length;
    prevLow = prevFindings.filter((f) => f.severity === "low").length;
  }

  const userLabels = new Map<string, string>();
  for (const f of findings) {
    const lbl = userId ? await db.getFindingLabel(userId, f.db_id || f.id) : null;
    if (lbl) {
      userLabels.set(f.db_id || f.id, lbl.label);
    }
  }

  const userRepos = userId ? await db.getUserAccessibleRepositories(userId) : [];
  const diagnostics = await db.getScanDiagnostics(scanId);

  const content = renderScanFindingsContent({
    scan,
    repo,
    isAnonymous,
    csrfToken,
    findings: findings as unknown as ScanFindingsRenderData["findings"],
    prevScan,
    prevCounts: { crit: prevCrit, high: prevHigh, med: prevMed, low: prevLow },
    userLabels,
    totalScansCount,
    diagnostics,
  });

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Scan Findings - ${repo.full_name}`,
      userLogin: userId ? "test-user" : undefined,
      csrfToken,
      content,
      activeNav: "findings",
      repoName: repo.full_name,
      userRepos,
      scansCount: totalScansCount,
    }),
  };
}
