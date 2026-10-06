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
      res.writeHead(404, getDefaultHeaders());
      res.end(
        renderPageLayout({
          title: "404 Page Not Found",
          content: `<h1>404 Page Not Found</h1><p>The page you requested does not exist.</p>`,
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
