import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession, serializeCookie } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import { escapeHtml, getDefaultHeaders, renderPageLayout } from "./ui-templates.js";

export async function handleAuthDisconnect(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const isProd = env.NODE_ENV === "production";
  const token = req.sessionToken || req.cookies?.["nantis_session"];

  if (!token) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Authentication Required",
        content: `<h1>401 Authentication Required</h1><p>Please sign in to manage connected GitHub access.</p>`,
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

  const userInstallations = await db.getUserInstallations(session.userId);
  const primaryInstUrl = userInstallations[0]?.html_url || `https://github.com/settings/installations`;

  // Revoke user snapshot and repo access in DB
  await db.clearUserRepoSnapshot(session.userId);
  db.revokeAllAccessForUser(session.userId);

  await db.createAuditLog({
    user_id: session.userId,
    action: "user.disconnect_github",
    target_resource: `user:${session.userId}`,
    ip_address: req.clientIp || "127.0.0.1",
    user_agent: req.headers?.["user-agent"] || "Unknown",
    details: { github_login: session.githubLogin },
  });

  const clearSessionCookie = serializeCookie({
    name: "nantis_session",
    value: "",
    httpOnly: true,
    secure: isProd,
    sameSite: "Lax",
    path: "/",
    maxAge: 0,
  });

  const content = `
    <div style="max-width: 650px; margin: 40px auto; text-align: center;" class="ui-card">
      <div style="font-size: 40px; margin-bottom: 16px;">🔌</div>
      <h1 style="font-size: 24px; font-weight: 800; color: #0f172a; margin-bottom: 12px;">GitHub Account Disconnected</h1>
      <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-bottom: 24px;">
        Disconnect GitHub removes local NANTIS session access. GitHub access remains until removed on GitHub.
      </p>
      <div style="display: flex; justify-content: center; gap: 12px;">
        <a href="${escapeHtml(primaryInstUrl)}" target="_blank" rel="noreferrer" class="btn btn-white-outline" style="font-size: 13px;">
          Manage access on GitHub ↗
        </a>
        <a href="/" class="btn btn-black" style="font-size: 13px;">
          Return to Dashboard
        </a>
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: {
      ...getDefaultHeaders(),
      "Set-Cookie": clearSessionCookie,
    },
    body: renderPageLayout({
      title: "GitHub Disconnected",
      userLogin: undefined,
      content,
    }),
  };
}
