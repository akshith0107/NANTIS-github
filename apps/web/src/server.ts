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
    title: `${title} - Not Connected`,
    activeNav: navName,
    userLogin,
    userRepos,
    content: `
      <div class="ui-card" style="text-align: center; padding: 60px 24px; max-width: 600px; margin: 40px auto;">
        <div style="font-size: 40px; margin-bottom: 16px;">🔌</div>
        <h2 style="font-size: 24px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">${title}</h2>
        <div style="display: inline-block; background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; font-size: 12px; font-weight: 700; padding: 4px 12px; border-radius: 999px; margin-bottom: 16px;">
          Not connected yet
        </div>
        <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-bottom: 24px;">
          This section is currently running in local development mode. Remote GitHub integration for ${title.toLowerCase()} is not connected.
        </p>
        <a href="/" class="btn btn-black">Back to Dashboard</a>
      </div>
    `,
  });
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      const key = pair.substring(0, idx).trim();
      const val = pair.substring(idx + 1).trim();
      cookies[key] = val;
    }
  }
  return cookies;
}

export function createWebServer() {
  return http.createServer(async (req, res) => {
    try {
      const parsedUrl = url.parse(req.url || "/", true);
      const pathname = parsedUrl.pathname || "/";
      const cookies = parseCookies(req.headers.cookie);
      const clientIp = req.socket.remoteAddress || "127.0.0.1";

      let bodyObj: unknown = undefined;
      if (req.method === "POST" || req.method === "PUT") {
        const buffers: Buffer[] = [];
        for await (const chunk of req) {
          buffers.push(chunk);
        }
        const bodyStr = Buffer.concat(buffers).toString("utf-8");
        if (req.headers["content-type"]?.includes("application/json")) {
          try {
            bodyObj = JSON.parse(bodyStr);
          } catch {
            bodyObj = bodyStr;
          }
        } else if (req.headers["content-type"]?.includes("application/x-www-form-urlencoded")) {
          bodyObj = Object.fromEntries(new URLSearchParams(bodyStr));
        } else {
          bodyObj = bodyStr;
        }
      }

      const reqContext: RequestContext = {
        method: req.method || "GET",
        path: pathname,
        headers: req.headers as Record<string, string>,
        cookies,
        sessionToken: cookies["nantis_session"],
        clientIp,
        query: parsedUrl.query as Record<string, string>,
        body: bodyObj,
      };

      // Home Page
      if (pathname === "/") {
        const response = await renderHomePage(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // Dev Routes & Actions
      if (pathname === "/auth/dev-login") {
        const response = await handleDevLogin(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/api/dev/scan") {
        const response = await handleDevScan(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/api/dev/scan-public-repo") {
        const response = await handlePublicRepoScan(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // Labeling and Export
      if (pathname.match(/^\/api\/findings\/[a-zA-Z0-9_-]+\/label$/) && req.method === "POST") {
        const response = await handleSetFindingLabel(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/api/labels/export" && req.method === "GET") {
        const response = await handleExportLabels(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // Page Renderers
      if (pathname === "/repos") {
        const response = await renderRepositoriesPage(reqContext, env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/privacy") {
        const response = await renderPrivacyPage();
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/rules") {
        const response = await renderRulesCatalogPage();
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      if (pathname === "/fixes") {
        res.writeHead(200, getDefaultHeaders());
        res.end(await renderNotConnectedPage("fixes", "Fixes Management", reqContext.sessionToken));
        return;
      }

      if (pathname === "/pull-requests") {
        res.writeHead(200, getDefaultHeaders());
        res.end(await renderNotConnectedPage("pull-requests", "Pull Requests", reqContext.sessionToken));
        return;
      }

      if (pathname === "/settings") {
        res.writeHead(200, getDefaultHeaders());
        res.end(await renderNotConnectedPage("settings", "Settings", reqContext.sessionToken));
        return;
      }

      const scanMatch = pathname.match(/^\/scans\/([a-zA-Z0-9_-]+)$/);
      if (scanMatch && req.method === "GET") {
        const response = await renderScanFindingsPage(reqContext, scanMatch[1], env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      const scanReportMatch = pathname.match(/^\/scans\/([a-zA-Z0-9_-]+)\/report$/);
      if (scanReportMatch && req.method === "GET") {
        const response = await renderScanReportPage(reqContext, scanReportMatch[1], env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // Finding Detail & Fix Review Page
      const fixReviewMatch = pathname.match(/^\/findings\/([a-zA-Z0-9_-]+)\/fix$/);
      if (fixReviewMatch) {
        const response = await renderFixReviewPage(reqContext, fixReviewMatch[1], env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // Legacy Approve Endpoint Compatibility
      const findingApproveMatch = pathname.match(/^\/api\/findings\/([a-zA-Z0-9_-]+)\/approve$/);
      if (findingApproveMatch) {
        const response = await renderFixReviewPage(reqContext, findingApproveMatch[1], env);
        res.writeHead(response.status, response.headers);
        res.end(response.body);
        return;
      }

      // API Routes
      for (const route of API_ROUTE_REGISTRY) {
        if (route.method === req.method) {
          const routePattern = new RegExp(
            "^" + route.path.replace(/:[a-zA-Z0-9_]+/g, "([a-zA-Z0-9_-]+)") + "$"
          );
          if (routePattern.test(pathname)) {
            const response = await route.handler(reqContext, env);
            res.writeHead(response.status, response.headers);
            res.end(typeof response.body === "string" ? response.body : JSON.stringify(response.body));
            return;
          }
        }
      }

      // 404 Not Found
      let userLogin: string | undefined;
      let userRepos: { id: string; name: string; full_name: string }[] = [];
      if (reqContext.sessionToken) {
        const session = decodeSession(reqContext.sessionToken, env.SESSION_SECRET);
        if (session?.userId) {
          userLogin = session.githubLogin;
          userRepos = await db.getUserAccessibleRepositories(session.userId);
        }
      }

      res.writeHead(404, getDefaultHeaders());
      res.end(
        renderPageLayout({
          title: "404 Page Not Found",
          userLogin,
          userRepos,
          content: `<div class="ui-card" style="text-align: center; padding: 60px 24px; max-width: 600px; margin: 40px auto;"><h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404</h1><h2 style="font-size: 20px; font-weight: 700; color: #475569; margin-bottom: 16px;">Page Not Found</h2><p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">The page you requested does not exist or has been moved.</p><a href="/" class="btn btn-black">Back to Dashboard</a></div>`,
        })
      );
    } catch (err) {
      console.error("HTTP Server Error:", err);
      res.writeHead(500, getDefaultHeaders());
      res.end(
        renderPageLayout({
          title: "500 Internal Error",
          content: `<h1>500 Internal Server Error</h1><p>An unexpected server error occurred.</p>`,
        })
      );
    }
  });
}

export function startDevServer() {
  const server = createWebServer();
  server.listen(PORT, HOST, () => {
    console.log(`\n============================================================`);
    console.log(`NANTIS Web Server running at http://${HOST}:${PORT}`);
    console.log(`In-memory data. Everything resets on restart.`);
    console.log(`============================================================\n`);
  });
  return server;
}

// Auto-start server if executed directly
if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  startDevServer();
}
