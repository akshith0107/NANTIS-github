# NANTIS Local Web App Audit & UI Report

> [!NOTE]
> **Server Endpoint**: Running locally on `http://127.0.0.1:3000` (`NODE_ENV=development`).
> **In-Memory Storage**: Local development mode uses transient in-memory maps. Everything resets on server restart.

---

## 1. Executive Summary & Verification

The **NANTIS Web Application** has been configured and tested for local development using Node's built-in HTTP server (`http.createServer`). It provides a modern, dark-first UI for scanning public GitHub repositories via static AST analysis, reviewing detected security findings categorized by confidence/severity tier, classifying findings using interactive testing aid labels, exporting label JSON, and inspecting/approving deterministic AST fixes.

---

## 2. Page & Route Breakdown

| Page / Route | URL Path | Method | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Home Page / Scan Console** | `/` | `GET` | ✅ Working | Prominent GitHub repository link input (`https://github.com/owner/repo`), local folder scanner, recent scans list, CSRF protection, and ethical scope notice. |
| **Public Repo Scan Action** | `/api/dev/scan-public-repo` | `POST` | ✅ Working | Validates GitHub URL on server side, enforces rate limiting, performs shallow `git clone` with security flags, executes AST scan without running code, saves findings, and immediately deletes temp folder. |
| **Repositories List** | `/repos` | `GET` | ✅ Working | Lists accessible in-memory repositories and historical scan runs for the dev user. |
| **Scan Findings Dashboard** | `/scans/:id` | `GET` | ✅ Working | Displays tier summary bar (Proven, Likely, Needs Review, Hygiene), interactive filter/search controls, zero-findings state (`"no issues found in the checks we run"`), interactive classification label buttons (`"Real issue"`, `"False positive"`, `"Not sure"`), and Export Labels button. |
| **Finding Fix Review** | `/findings/:id/fix` | `GET` / `POST` | ✅ Working | Displays finding details, AST diff preview, `"WEAK verification"` badge, CSRF-protected approval button, and `"PR creation not connected yet"` status badge. |
| **Label Classification API** | `/api/findings/:id/label` | `POST` | ✅ Working | Saves user testing aid label (`real_issue`, `false_positive`, `not_sure`) in memory for the current session. |
| **Label Export Endpoint** | `/api/labels/export` | `GET` | ✅ Working | Downloads JSON file (`nantis-finding-labels.json`) containing all user-assigned finding labels. |

---

## 3. Security & Safety Controls

> [!IMPORTANT]
> **Zero Code Execution**: Scanned repositories are parsed purely via AST static analysis. NPM scripts, build commands, and Git hooks are strictly disabled.

1. **Localhost & NODE_ENV Restriction**:
   - Web server binds exclusively to `127.0.0.1`.
   - Server immediately aborts startup if `NODE_ENV === "production"`.
2. **GitHub URL Validation**:
   - Enforces `https://github.com/owner/repo` syntax.
   - Rejects non-HTTPS schemes (`file://`, `git://`, `ssh://`), IP hostnames, non-github domains, embedded URL credentials, and path traversal attempts.
3. **Cloning Isolation & Automatic Cleanup**:
   - Executed with flags: `-c core.hooksPath=/dev/null`, `-c filter.lfs.smudge=`, `-c filter.lfs.clean=`, `-c filter.lfs.process=`, `-c core.symlinks=false`.
   - Temporary clone directories are deleted immediately inside a `finally` block post-scan.
4. **Rate Limiting & Cooldown**:
   - Enforces a 5-second cooldown and maximum 1 active scan per user.
5. **CSRF & XSS Safeguards**:
   - All forms include hidden `_csrf` tokens validated server-side.
   - All dynamic strings pass through `escapeHtml()` before DOM interpolation.
   - Security Headers enforced on all responses: `X-Content-Type-Options: nosniff` and `Content-Security-Policy: frame-ancestors 'none'`.

---

## 4. Honest Status of Unconnected Features

- **Verification Engine**: Displayed as **`"WEAK verification"`** badge (indicates local syntactic AST check only, not dynamic sandbox execution).
- **GitHub PR Pipeline**: Displayed as **`"PR creation not connected yet"`** badge upon fix approval (no fake GitHub PR success URLs are generated).
