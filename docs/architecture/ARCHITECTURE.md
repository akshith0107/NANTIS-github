# NANTIS Architecture & System Map

## 1. Overview

NANTIS is a static security analysis web application and CLI suite designed for TypeScript, JavaScript, Next.js, Stripe, Supabase, and CI workflow configurations. It scans source code repositories for security flaws, builds deterministic evidence chains, redacts sensitive credentials, generates AST code transformations/patches, and presents findings via an interactive HTTP dashboard and REST API.

---

## 2. Main Data & Control Flows

```
[Connect / URL Input] ──► [OAuth / CSRF / Rate Limit] ──► [Dual-Lock Auth Check]
                                                                  │
                                                                  ▼
[Findings UI / Export] ◄── [In-Memory Storage] ◄── [AST Engine] ◄── [Sandboxed Clone]
          │
          ▼
[AST Fix Generator] ──► [Patch Verification (Sandbox)] ──► [PR Publisher / Diff Review]
```

### Flow Step Breakdown:
1. **Connect & Authenticate**: Users authenticate via GitHub OAuth (`/auth/login` ➔ `/auth/callback`) or paste a public repository URL on the home page.
2. **Dual-Lock Scan Verification**: Every scan request checks Lock 1 (User repo access snapshot taken via temporary user OAuth token, 1-hour TTL) and Lock 2 (Live GitHub App installation repo list via installation access token).
3. **Sandboxed Repository Clone**: Clones source code shallowly (`--depth 1`) in an isolated temporary directory with git hooks disabled, LFS smudge filters disabled, symlinks disabled, and git authentication passed strictly via `GIT_CONFIG_COUNT`/`KEY`/`VALUE` environment variables.
4. **AST Security Analysis**: Scans project files using 19 detector modules evaluating 23 security rules across AST nodes, lockfiles, CI workflows, and project config files.
5. **Findings Storage & UI**: Findings are stored in the `DatabaseClient` (in-memory `Map` collections) and rendered on the Scan Findings Dashboard with severity badge counts, code snippets, and evidence chains.
6. **AST Patch Generation & Verification**: Automatically generates code transformations (e.g., enabling RLS, adding Stripe webhook signatures, bumping vulnerable dependencies) and runs isolated sandbox verification checks.

---

## 3. Package & Module Map

### Monorepo Structure:
- `packages/core`: Core static analysis engine, detectors, fix generators, AST transformations, CLI tools, and rule documentation catalog.
- `packages/worker`: Queue processing, sandboxed git clone operations, job queue manager, and cleanup janitor.
- `apps/web`: HTTP web application server, OAuth handlers, session manager, UI templates, and API endpoints.

---

## 4. Module Status Matrix (REAL / PARTIAL / STUB / DEAD)

| Module / Component | Path | Status | Evidence & Details |
|---|---|---|---|
| **AST Detector Suite** | `packages/core/src/detectors/` | **REAL** | 19 detector files evaluating 23 rules. Tested against unit tests & mutation harness. |
| **AST Fix Generators** | `packages/core/src/fixes/rules/` | **PARTIAL** | Implements automated AST fix generators for 3 rules (`missing-rls-in-migration`, `stripe-webhook-no-signature`, `vulnerable-dependency`). |
| **PR Publisher** | `packages/core/src/fixes/pr-publisher.ts` | **STUB** | Returns mock/stub responses in dev mode; displays "PR creation not connected yet" badge. |
| **Sandboxed Git Clone** | `packages/worker/src/git/clone-sandbox.ts` | **REAL** | Hardened shallow clone with `--depth 1`, disabled hooks/symlinks/LFS, `GIT_CONFIG_COUNT` env credentials, size & file limits. |
| **Scan Job Queue** | `packages/worker/src/queue/job-queue.ts` | **REAL** | In-memory asynchronous job queue executing scan tasks and updating scan statuses. |
| **Web Server & UI** | `apps/web/src/` | **REAL** | Native Node HTTP web app handling OAuth login, snapshot TTL, scan dashboards, findings classification, JSON exports. |
| **Database Layer** | `apps/web/src/db/client.ts` | **PARTIAL** | Volatile in-memory JavaScript `Map` storage. Implements full schema interfaces but resets on process restart. |
| **Experimental Scripts** | `scratch/` | **DEAD** | Dev-only test/proof scripts (`capture_screenshots.ts`, `test_browser_journey.ts`, `contrast_check.ts`) not imported by runtime. |
| **Compiled JS Artifacts** | `packages/worker/src/*.js`, `packages/core/test-utils/*.js` | **DEAD** | Leftover compiled JS/D.TS map files sitting in source tree instead of build output. |

---

## 5. Security Boundaries & Credential Isolation

1. **Untrusted Code Execution Boundary**:
   - Repositories are cloned inside isolated temporary directories (`temp/scans/...`).
   - `core.hooksPath=` prevents malicious git hook execution upon checkout.
   - `core.symlinks=false` prevents arbitrary file read access outside clone root.
   - `filter.lfs.smudge=` prevents remote executable downloads during checkout.
   - Verification checks (e.g. `tsc` or tests) execute inside isolated runner sub-processes (`containerRunner`), never on the host main looper thread.

2. **Credential & Token Isolation Boundary**:
   - **User OAuth Tokens**: Used strictly in memory during OAuth callback / Refresh to fetch identity and repository snapshot, then immediately discarded. NEVER stored in database or session cookies.
   - **Installation Access Tokens (`ghs_...`)**: Minted on demand from GitHub App private key, cached in volatile memory only with short lifespan (max 50 mins), and passed to Git via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0` environment variables. Tokens never appear in process arguments (`ps aux` clean) or `.git/config` on disk.
   - **Session Cookies**: Signed with HMAC-SHA256 (`SESSION_SECRET`), set with `HttpOnly`, `SameSite=Lax`, and `Secure` flags in production. Session IDs rotated on login.

---

## 6. Environment Variables Reference

| Variable Name | Required | Default / Fallback | Purpose & Constraints |
|---|:---:|---|---|
| `GITHUB_CLIENT_ID` | Yes | — | GitHub App OAuth Client ID for user authentication. |
| `GITHUB_CLIENT_SECRET` | Yes | — | GitHub App OAuth Client Secret. |
| `GITHUB_APP_ID` | Yes | — | GitHub App ID for Installation Access Token minting. |
| `GITHUB_APP_SLUG` | Yes | — | GitHub App URL slug. Production boot fails without it. |
| `GITHUB_APP_PRIVATE_KEY` | Yes | — | RSA Private Key PEM for signing GitHub App JWTs. |
| `GITHUB_WEBHOOK_SECRET` | Yes | — | HMAC secret for verifying incoming GitHub Webhook signatures (`X-Hub-Signature-256`). |
| `SESSION_SECRET` | Yes | — | Secret key for signing session cookies (`nantis_session`). |
| `DATABASE_URL` | No | `postgresql://localhost:5432/nantis_db` | Database connection string. |
| `NODE_ENV` | No | `development` | App environment (`development`, `production`, `test`). Dev login prohibited in `production`. |
| `USER_REPO_SNAPSHOT_TTL_MS` | No | `3600000` (1 hr) | TTL in milliseconds for user repository access snapshots. |
