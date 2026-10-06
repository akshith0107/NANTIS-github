import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
} from "./ui-templates.js";

export async function renderHomePage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  let userLogin: string | undefined = undefined;
  let userId: string = "dev-user-id";

  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session) {
      userLogin = session.githubLogin;
      userId = session.userId;
    }
  }

  const csrfToken = getOrCreateCsrfToken(userId);

  // Get recent scans from db
  const repos = await db.getUserAccessibleRepositories(userId);
  const recentScansList: { scanId: string; repoName: string; status: string; date: string }[] = [];

  for (const repo of repos) {
    const scans = await db.getScansForRepository(repo.id);
    for (const scan of scans) {
      recentScansList.push({
        scanId: scan.id,
        repoName: repo.full_name,
        status: scan.status,
        date: scan.started_at || "Recent",
      });
    }
  }

  const recentScansHtml =
    recentScansList.length === 0
      ? `<p style="color: var(--text-dim); font-size: 0.9rem;">No recent scans. Paste a repository URL above to initiate your first AST security review.</p>`
      : `<div style="display: flex; flex-direction: column; gap: 8px;">
          ${recentScansList
            .slice(-5)
            .reverse()
            .map(
              (s) => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #0d1322; border-radius: 8px; border: 1px solid var(--border-color);">
              <div>
                <strong>${escapeHtml(s.repoName)}</strong>
                <span style="font-size: 0.8rem; color: var(--text-dim); margin-left: 8px;">Scan ID: ${escapeHtml(s.scanId)}</span>
              </div>
              <div>
                <a href="/scans/${escapeHtml(s.scanId)}" class="btn btn-outline" style="padding: 4px 12px; font-size: 0.8rem;">View Findings</a>
              </div>
            </div>
          `
            )
            .join("")}
        </div>`;

  const content = `
    <div style="max-width: 840px; margin: 0 auto;">
      <div style="text-align: center; margin-bottom: 40px;">
        <h1 style="font-size: 2.2rem; font-weight: 800; margin-bottom: 12px; background: linear-gradient(135deg, #f8fafc, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
          AST Vulnerability & Static Security Review
        </h1>
        <p style="color: var(--text-muted); font-size: 1.05rem; max-width: 650px; margin: 0 auto;">
          High-fidelity AST security analysis, deterministic fix engine, and interactive finding classification.
        </p>
      </div>

      <div class="card" style="border: 1px solid rgba(59, 130, 246, 0.3); background: radial-gradient(circle at top right, #151d30, #111827);">
        <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
          <span style="color: var(--accent-blue);">🔍</span> Scan Public GitHub Repository
        </h2>
        
        <form action="/api/dev/scan-public-repo" method="POST" style="display: flex; flex-direction: column; gap: 16px;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          
          <div>
            <label style="display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;">
              Paste a public GitHub repository link
            </label>
            <input 
              type="url" 
              name="repoUrl" 
              placeholder="https://github.com/owner/repository" 
              required 
              style="font-family: monospace; font-size: 1rem; padding: 14px 18px;"
            />
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
            <div style="font-size: 0.8rem; color: var(--text-dim);">
              Strict server-side validation: <code style="color: #60a5fa;">https://github.com/</code> only
            </div>
            <button type="submit" class="btn btn-primary" style="padding: 12px 28px; font-size: 0.95rem;">
              Scan Repository
            </button>
          </div>
        </form>
      </div>

      <div class="card" style="background: rgba(17, 24, 39, 0.6);">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 16px; color: var(--text-main);">
          ⚡ Quick Actions & Local Scanning
        </h3>
        
        <form action="/api/dev/scan" method="POST" style="display: flex; gap: 12px; align-items: center; margin-bottom: 20px;">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          <input 
            type="text" 
            name="folder" 
            value="${escapeHtml(process.cwd())}" 
            placeholder="Local folder path"
            style="flex: 1; font-family: monospace; font-size: 0.85rem;"
          />
          <button type="submit" class="btn btn-secondary" style="white-space: nowrap;">
            Scan Local Directory
          </button>
        </form>

        <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 20px 0;" />

        <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 12px; color: var(--text-muted);">
          Recent Local Scans
        </h4>
        ${recentScansHtml}
      </div>
    </div>
  `;

  const html = renderPageLayout({
    title: "Public Repo Scan Console",
    userLogin,
    csrfToken,
    content,
  });

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: html,
  };
}
