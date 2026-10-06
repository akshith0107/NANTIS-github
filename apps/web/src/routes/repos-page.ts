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

export async function renderRepositoriesPage(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized",
        content: `<h1>401 Authentication Required</h1><p>Please sign in to view repositories.</p>`,
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
        content: `<h1>401 Authentication Required</h1><p>Session invalid or expired.</p>`,
      }),
    };
  }

  const csrfToken = getOrCreateCsrfToken(session.userId);
  const repos = await db.getUserAccessibleRepositories(session.userId);

  const repoItems = await Promise.all(
    repos.map(async (r) => {
      const scans = await db.getScansForRepository(r.id);
      const scanLinks = scans
        .map(
          (s) =>
            `<a href="/scans/${escapeHtml(s.id)}" class="btn btn-outline" style="padding: 2px 8px; font-size: 0.75rem;">${escapeHtml(
              s.status.toUpperCase()
            )} (${escapeHtml(s.commit_sha.slice(0, 7))})</a>`
        )
        .join(" ");

      return `
        <div class="card" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 16px 20px;">
          <div>
            <h3 style="font-size: 1.1rem; font-weight: 700;">
              ${escapeHtml(r.full_name)} 
              <span style="font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 9999px; background: #1f2937; color: var(--text-muted); margin-left: 8px;">
                ${r.private ? "private" : "public"}
              </span>
            </h3>
            ${scanLinks ? `<div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-dim);">Scans: ${scanLinks}</div>` : ""}
          </div>
          <div>
            <form action="/api/dev/scan-public-repo" method="POST" style="display: inline;" onclick="if (event.target.tagName === 'BUTTON') this.submit();">
              <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
              <input type="hidden" name="repoUrl" value="https://github.com/${escapeHtml(r.full_name)}" />
              <button type="button" data-repo-id="${r.id}">Scan</button>
            </form>
          </div>
        </div>
      `;
    })
  );

  const repoListHtml =
    repos.length === 0
      ? `<p style="color: var(--text-dim);">No accessible repositories found in in-memory session store.</p>`
      : repoItems.join("\n");

  const content = `
    <div style="max-width: 900px; margin: 0 auto;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
          <h1 style="font-size: 1.8rem; font-weight: 800;">
            Accessible Repositories
          </h1>
          <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 4px;">
            Signed in as <strong>${escapeHtml(session.githubLogin)}</strong>
          </p>
        </div>
        <a href="/" class="btn btn-primary" style="font-size: 0.85rem;">
          + Scan Public Repo
        </a>
      </div>

      ${repoListHtml}
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Repositories",
      userLogin: session.githubLogin,
      csrfToken,
      content,
    }),
  };
}
