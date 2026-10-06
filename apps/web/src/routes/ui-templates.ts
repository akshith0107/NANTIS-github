import { RequestContext } from "./api-routes.js";

/**
 * Escapes HTML characters to protect against XSS injection attacks.
 */
export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return "";
  const s = String(str);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * In-memory CSRF token store per session
 */
const csrfTokens = new Map<string, string>();

export function getOrCreateCsrfToken(userId: string): string {
  if (!csrfTokens.has(userId)) {
    const token = crypto.randomUUID();
    csrfTokens.set(userId, token);
  }
  return csrfTokens.get(userId)!;
}

export function validateCsrfToken(req: RequestContext, userId: string): boolean {
  if (!userId) return false;
  const expected = csrfTokens.get(userId);
  if (!expected) return false;

  let tokenFromReq = "";
  if (typeof req.body === "object" && req.body !== null && "_csrf" in req.body) {
    tokenFromReq = String((req.body as Record<string, unknown>)._csrf);
  } else if (req.headers && req.headers["x-csrf-token"]) {
    tokenFromReq = req.headers["x-csrf-token"];
  }

  return tokenFromReq === expected;
}

export function getDefaultHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';",
    ...extraHeaders,
  };
}

export const BASE_CSS = `
  :root {
    --bg-main: #090d16;
    --bg-card: #111827;
    --bg-card-hover: #1f2937;
    --border-color: #1f2937;
    --border-highlight: #374151;
    --text-main: #f9fafb;
    --text-muted: #9ca3af;
    --text-dim: #6b7280;
    --accent-blue: #3b82f6;
    --accent-blue-hover: #2563eb;
    --accent-cyan: #06b6d4;
    --badge-proven: #8b5cf6;
    --badge-likely: #f59e0b;
    --badge-review: #ef4444;
    --badge-hygiene: #10b981;
    --btn-label-real: #16a34a;
    --btn-label-fp: #dc2626;
    --btn-label-sure: #4b5563;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-main);
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .top-banner {
    background: linear-gradient(90deg, #d97706, #b45309);
    color: #ffffff;
    text-align: center;
    padding: 6px 16px;
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
  }

  .top-banner .badge {
    background: rgba(0,0,0,0.3);
    padding: 2px 8px;
    border-radius: 9999px;
    font-size: 0.75rem;
    text-transform: uppercase;
  }

  header {
    background-color: #0d1322;
    border-bottom: 1px solid var(--border-color);
    padding: 14px 24px;
  }

  .header-content {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--text-main);
    text-decoration: none;
  }

  .logo-icon {
    width: 28px;
    height: 28px;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 800;
    color: #fff;
  }

  .nav-links {
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .nav-links a {
    color: var(--text-muted);
    text-decoration: none;
    font-size: 0.9rem;
    font-weight: 500;
    transition: color 0.15s ease;
  }

  .nav-links a:hover {
    color: var(--text-main);
  }

  .user-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #111827;
    border: 1px solid var(--border-color);
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  .user-avatar {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: #374151;
  }

  main {
    flex: 1;
    max-width: 1200px;
    width: 100%;
    margin: 0 auto;
    padding: 32px 24px;
  }

  .card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 10px 20px;
    font-size: 0.9rem;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    text-decoration: none;
    transition: background-color 0.15s ease, transform 0.1s ease;
  }

  .btn-primary {
    background-color: var(--accent-blue);
    color: #ffffff;
  }
  .btn-primary:hover {
    background-color: var(--accent-blue-hover);
  }

  .btn-success {
    background-color: #16a34a;
    color: #ffffff;
  }
  .btn-success:hover {
    background-color: #15803d;
  }

  .btn-secondary {
    background-color: #374151;
    color: #ffffff;
  }
  .btn-secondary:hover {
    background-color: #4b5563;
  }

  .btn-outline {
    background: transparent;
    border: 1px solid var(--border-highlight);
    color: var(--text-main);
  }
  .btn-outline:hover {
    background: var(--bg-card-hover);
  }

  input[type="text"], input[type="url"], select {
    width: 100%;
    padding: 12px 16px;
    font-size: 0.95rem;
    background-color: #0d1322;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-main);
    outline: none;
    transition: border-color 0.15s ease;
  }

  input[type="text"]:focus, input[type="url"]:focus, select:focus {
    border-color: var(--accent-blue);
  }

  footer {
    border-top: 1px solid var(--border-color);
    padding: 24px;
    text-align: center;
    color: var(--text-dim);
    font-size: 0.85rem;
    background-color: #070a12;
  }

  .footer-notice {
    max-width: 800px;
    margin: 0 auto;
    line-height: 1.6;
  }

  /* Status Badges */
  .badge-tier {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    display: inline-block;
  }
  .tier-proven { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }
  .tier-likely { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
  .tier-review { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
  .tier-hygiene { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }

  /* Verification Tag */
  .verification-badge {
    background: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.3);
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .pr-status-badge {
    background: rgba(59, 130, 246, 0.15);
    color: #60a5fa;
    border: 1px solid rgba(59, 130, 246, 0.3);
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
`;

export function renderPageLayout(options: {
  title: string;
  userLogin?: string;
  csrfToken?: string;
  content: string;
}): string {
  const { title, userLogin, content } = options;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - NANTIS AST Code Scan</title>
  <style>
    ${BASE_CSS}
  </style>
</head>
<body>
  <div class="top-banner">
    <span>DEV MODE — In-Memory Local Development</span>
    <span class="badge">Local mode</span>
  </div>

  <header>
    <div class="header-content">
      <a href="/" class="logo">
        <div class="logo-icon">N</div>
        <span>NANTIS AST Review</span>
      </a>
      <div class="nav-links">
        <a href="/">Home</a>
        <a href="/repos">Repositories</a>
        <a href="/rules">Rules Catalog</a>
        <a href="/api/labels/export">Export Labels</a>
        ${
          userLogin
            ? `<div class="user-badge"><div class="user-avatar"></div><span>${escapeHtml(userLogin)}</span></div>`
            : `<a href="/auth/dev-login" class="btn btn-outline" style="padding:4px 12px;font-size:0.8rem;">Dev Sign-In</a>`
        }
      </div>
    </div>
  </header>

  <main>
    ${content}
  </main>

  <footer>
    <div class="footer-notice">
      <p><strong>Ethical & Scope Notice:</strong> NANTIS AST Scan is a static analysis helper tool. No issues found means no findings matched active static rules, not a guarantee that no bugs exist. Only scan public repositories or repositories you have explicit authorization to test. No external LLM code execution or remote repository mutations take place in local mode.</p>
    </div>
  </footer>
</body>
</html>`;
}
