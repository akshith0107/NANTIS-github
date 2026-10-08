import http from "http";
import url from "url";
import { validateWebEnv } from "./lib/env.js";
import { RequestContext } from "./routes/api-routes.js";
import {
  handleDevLogin,
  handleDevScan,
  handleExportLabels,
  handlePublicRepoScan,
  handleSetFindingLabel,
} from "./routes/dev-routes.js";
import { renderFixReviewPage } from "./routes/fix-review-page.js";
import { renderHomePage } from "./routes/home-page.js";
import { renderPrivacyPage } from "./routes/privacy-page.js";
import { renderRepositoriesPage } from "./routes/repos-page.js";
import { renderRulesCatalogPage } from "./routes/rules-catalog-page.js";
import { renderScanFindingsPage } from "./routes/scan-findings-page.js";
import { renderScanReportPage } from "./routes/scan-report-page.js";
import { API_ROUTE_REGISTRY } from "./routes/registry.js";
import { decodeSession } from "./lib/session.js";
import { db } from "./db/client.js";
import { getDefaultHeaders, renderPageLayout } from "./routes/ui-templates.js";

// 1. Enforce NODE_ENV check on startup
const nodeEnv = process.env.NODE_ENV || "development";
if (nodeEnv === "production") {
  console.error("FATAL ERROR: Refusing to start dev web server in production mode.");
  process.exit(1);
}

const env = validateWebEnv({
  GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID || "dev_client_id",
  GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET || "dev_client_secret",
  GITHUB_APP_ID: process.env.GITHUB_APP_ID || "99999",
  GITHUB_APP_SLUG: process.env.GITHUB_APP_SLUG || "nantis-app",
  GITHUB_APP_PRIVATE_KEY: process.env.GITHUB_APP_PRIVATE_KEY || "dev_private_key",
  GITHUB_WEBHOOK_SECRET: process.env.GITHUB_WEBHOOK_SECRET || "dev_webhook_secret",
  SESSION_SECRET: process.env.SESSION_SECRET || "dev_session_secret_32_characters_key_here",
  DATABASE_URL: process.env.DATABASE_URL || "postgresql://localhost:5432/dev",
  NODE_ENV: nodeEnv,
});

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = "127.0.0.1";

async function renderNotConnectedPage(
  navName: "dashboard" | "repositories" | "scans" | "findings" | "fixes" | "pull-requests" | "settings",
  title: string,
  sessionToken?: string
) {
  let userLogin: string | undefined;
  let userRepos: { id: string; name: string; full_name: string }[] = [];
  if (sessionToken) {
    const session = decodeSession(sessionToken, env.SESSION_SECRET);
    if (session?.userId) {
      userLogin = session.githubLogin;
      userRepos = await db.getUserAccessibleRepositories(session.userId);
    }
  }

  return renderPageLayout({
    title,
    userLogin,
    activeNav: navName,
    userRepos,
    content: `
      <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
        <div style="font-size: 3rem; margin-bottom: 16px;">🔌</div>
        <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 8px;">Connect GitHub Required</h2>
        <p style="color: var(--text-dim); margin-bottom: 24px; font-size: 0.95rem;">
          This view requires an active GitHub repository connection. Sign in with GitHub or select repositories to access this page.
        </p>
        <div style="display: flex; gap: 12px; justify-content: center;">
          <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
          <a href="/" class="btn btn-outline">Back to Home</a>
        </div>
      </div>
    `,
  });
}

export const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url || "/", true);
  const pathName = parsedUrl.pathname || "/";

  const cookies: Record<string, string> = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(";").forEach((cookie) => {
      const parts = cookie.split("=");
      if (parts.length === 2) {
        cookies[parts[0].trim()] = parts[1].trim();
      }
    });
  }

  let bodyText = "";
  if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
    req.on("data", (chunk) => {
      bodyText += chunk;
    });
    await new Promise((resolve) => req.on("end", resolve));
  }

  const reqContext: RequestContext = {
    cookies,
    body: bodyText,
    ip: req.socket.remoteAddress || "127.0.0.1",
    userAgent: req.headers["user-agent"] || "Unknown",
    method: req.method,
    path: pathName,
    headers: req.headers as Record<string, string>,
    clientIp: req.socket.remoteAddress || "127.0.0.1",
    query: parsedUrl.query as Record<string, string>,
  };

  // Route: /
  if (pathName === "/") {
    const response = await renderHomePage(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /rules
  if (pathName === "/rules") {
    const response = await renderRulesCatalogPage();
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /privacy
  if (pathName === "/privacy") {
    const response = await renderPrivacyPage();
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /auth/login
  if (pathName === "/auth/login") {
    const { handleAuthLogin } = await import("./routes/auth-login.js");
    const response = handleAuthLogin(env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /auth/callback
  if (pathName === "/auth/callback") {
    const { handleAuthCallback } = await import("./routes/auth-callback.js");
    const response = await handleAuthCallback(
      {
        code: parsedUrl.query.code as string,
        state: parsedUrl.query.state as string,
        installation_id: parsedUrl.query.installation_id as string,
        cookies,
        ip: reqContext.clientIp,
        userAgent: reqContext.userAgent,
      },
      env
    );
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /auth/logout
  if (pathName === "/auth/logout") {
    const { handleAuthLogout } = await import("./routes/auth-logout.js");
    const response = await handleAuthLogout(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /auth/disconnect
  if (pathName === "/auth/disconnect") {
    const { handleAuthDisconnect } = await import("./routes/auth-disconnect.js");
    const response = await handleAuthDisconnect(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /repos
  if (pathName === "/repos") {
    const response = await renderRepositoriesPage(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /scans/:id
  const scanMatch = pathName.match(/^\/scans\/([^\/]+)$/);
  if (scanMatch) {
    const scanId = scanMatch[1];
    const response = await renderScanFindingsPage(reqContext, scanId, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /scans/:id/report
  const reportMatch = pathName.match(/^\/scans\/([^\/]+)\/report$/);
  if (reportMatch) {
    const scanId = reportMatch[1];
    const response = await renderScanReportPage(reqContext, scanId, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Route: /findings/:id/fix
  const fixMatch = pathName.match(/^\/findings\/([^\/]+)\/fix$/);
  if (fixMatch) {
    const findingId = fixMatch[1];
    const response = await renderFixReviewPage(reqContext, findingId, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Navigation pages requiring GitHub connection when unauthenticated
  if (pathName === "/scans") {
    const html = await renderNotConnectedPage("scans", "Scans", reqContext.cookies?.["nantis_session"]);
    res.writeHead(200, getDefaultHeaders());
    res.end(html);
    return;
  }

  if (pathName === "/findings") {
    const html = await renderNotConnectedPage("findings", "Scan Findings", reqContext.cookies?.["nantis_session"]);
    res.writeHead(200, getDefaultHeaders());
    res.end(html);
    return;
  }

  if (pathName === "/fixes") {
    const html = await renderNotConnectedPage("fixes", "Fix Review", reqContext.cookies?.["nantis_session"]);
    res.writeHead(200, getDefaultHeaders());
    res.end(html);
    return;
  }

  if (pathName === "/pull-requests") {
    const html = await renderNotConnectedPage("pull-requests", "Pull Requests", reqContext.cookies?.["nantis_session"]);
    res.writeHead(200, getDefaultHeaders());
    res.end(html);
    return;
  }

  if (pathName === "/settings") {
    const html = await renderNotConnectedPage("settings", "Settings", reqContext.cookies?.["nantis_session"]);
    res.writeHead(200, getDefaultHeaders());
    res.end(html);
    return;
  }

  // Dev routes (Local development only)
  if (pathName === "/auth/dev-login") {
    const response = await handleDevLogin(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  if (pathName === "/api/dev/scan") {
    const response = await handleDevScan(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  if (pathName === "/api/dev/scan-public-repo") {
    const response = await handlePublicRepoScan(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  const labelMatch = pathName.match(/^\/api\/findings\/([^\/]+)\/label$/);
  if (labelMatch) {
    const response = await handleSetFindingLabel(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  if (pathName === "/api/findings/export-labels") {
    const response = await handleExportLabels(reqContext, env);
    res.writeHead(response.status, response.headers);
    res.end(response.body);
    return;
  }

  // Dispatch to API Route Registry
  for (const route of API_ROUTE_REGISTRY) {
    if (route.method === req.method) {
      const regex = new RegExp("^" + route.path.replace(/:[^\/]+/g, "([^/]+)") + "$");
      const match = pathName.match(regex);
      if (match) {
        const params = match.slice(1);
        const response = await route.handler(reqContext, ...params, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }
    }
  }

  // 404 Not Found Page
  const sessionToken = reqContext.cookies?.["nantis_session"];
  let userLogin: string | undefined;
  if (sessionToken) {
    const session = decodeSession(sessionToken, env.SESSION_SECRET);
    userLogin = session?.githubLogin;
  }

  res.writeHead(404, getDefaultHeaders());
  res.end(
    renderPageLayout({
      title: "404 Page Not Found",
      userLogin,
      content: `
        <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 500px; margin: 40px auto;">
          <h1 style="font-size: 4rem; font-weight: 800; color: #cbd5e1; margin-bottom: 8px;">404</h1>
          <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 12px;">Page Not Found</h2>
          <p style="color: var(--text-dim); margin-bottom: 24px; font-size: 0.9rem;">
            The page you requested could not be found or has been moved.
          </p>
          <a href="/" class="btn btn-black">Return Home</a>
        </div>
      `,
    })
  );
});

if (process.env.NODE_ENV !== "test") {
  server.listen(PORT, HOST, () => {
    console.log(`[NANTIS Web App] Server listening at http://${HOST}:${PORT}`);
  });
}
