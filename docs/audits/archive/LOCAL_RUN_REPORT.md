# NANTIS Web Application Local Execution Report

> [!IMPORTANT]
> **Environment & Scope**: This report documents local development execution of the NANTIS web application on `http://127.0.0.1:3000` with in-memory state and mock PR publishing.

---

## 1. Startup & Shutdown Commands

### Server URL
- **URL**: `http://127.0.0.1:3000`
- **Host Binding**: `127.0.0.1` (Strict local loopback only)
- **Port**: `3000` (Configurable via `PORT` environment variable)

### Commands to Start
```bash
# Set development mode and allowed scan root (optional)
export NODE_ENV=development
export ALLOWED_SCAN_ROOT=E:/gnu

# Start the web app HTTP server
npm run dev:web
```

### Commands to Stop
- **Terminal**: Press `Ctrl + C` in the running server terminal.
- **Process Termination (PowerShell / Windows)**:
  ```powershell
  Stop-Process -Name "node" -Force
  ```

---

## 2. Route & Journey Functionality Audit

| Page / Route | Works? | What's Fake, Mocked, or In-Memory | Errors Observed |
| :--- | :---: | :--- | :--- |
| **Home Page (`GET /`)** | ✅ YES | In-memory session check; Dev Login button presented. | None (HTTP 200) |
| **Dev Login (`GET /auth/dev-login`)** | ✅ YES | Fake test user (`devuser`, GitHub ID `99999`) minted in-memory without real GitHub OAuth handshake. | None (HTTP 302 -> `/repos`) |
| **Repo List Page (`GET /repos`)** | ✅ YES | Repository list loaded from in-memory `DatabaseClient`. | None (HTTP 200) |
| **Local Folder Scanner (`POST /api/dev/scan`)** | ✅ YES | Scans local filesystem AST using `runScan`. Results stored in in-memory DB map. Restricted to `ALLOWED_SCAN_ROOT`. | None (HTTP 302 -> `/scans/:scanId`) |
| **Scan Findings Page (`GET /scans/:scanId`)** | ✅ YES | Findings and evidence chain loaded from in-memory DB map. | None (HTTP 200) |
| **Fix Approval Card (`GET /api/findings/:id/approve`)** | ✅ YES | Patch diff rendered in browser. Shows `"PR creation not connected yet"`. | None (HTTP 200) |
| **Fix Approval Action (`POST /api/findings/:id/approve`)** | ✅ YES | Real GitHub PR creation is not connected. Displays `"PR creation not connected yet"`. No external GitHub API calls made. | None (HTTP 200) |
| **Rules Catalog Page (`GET /rules`)** | ✅ YES | Renders public rule catalog definitions. | None (HTTP 200) |
| **Privacy Policy Page (`GET /privacy`)** | ✅ YES | Renders static privacy policy and data guarantees. | None (HTTP 200) |

---

## 3. Dev-Only Security Controls Audit

1. **Production Mode Start Refusal**:
   - Setting `NODE_ENV=production` causes `server.ts` to immediately log `FATAL ERROR: Refusing to start dev web server in production mode.` and abort with exit code `1`.
   - `handleDevLogin` returns `HTTP 403 Forbidden` if invoked under `NODE_ENV=production`.

2. **Non-Local Connection Rejection**:
   - `handleDevLogin` checks client remote IP. Any request coming from a non-localhost IP address (e.g. `192.168.1.100`) is rejected with `HTTP 403 Forbidden`.

3. **Path Traversal Protection**:
   - `handleDevScan` resolves the requested target directory path and verifies `resolvedPath.startsWith(allowedRoot)`.
   - Attempting to scan directories outside `ALLOWED_SCAN_ROOT` is blocked with `HTTP 400 Bad Request ("Path traversal blocked: target folder is outside ALLOWED_SCAN_ROOT")`.

4. **Zero Untrusted Code Execution**:
   - Folder scanning uses static AST analysis (`runScan`) only. No package scripts (`npm test`, `postinstall`, `build`) or untrusted binaries are executed.

---

## 4. Unsupported & Unconnected Features

- **GitHub OAuth Flow**: Direct GitHub OAuth redirection and access token exchange are bypassed in local dev mode in favor of `/auth/dev-login`.
- **Database Persistence**: State is stored strictly in-memory (`Map` structures in `DatabaseClient`). All users, repositories, scans, and findings reset when the process terminates.
- **Real PR Publishing**: GitHub Pull Request creation is disconnected. Approving a fix updates local sandbox state and displays `"PR creation not connected yet"`.
- **Background Worker Process**: Scanning is executed inline via static AST analysis rather than dispatching jobs to a separate background Redis/PostgreSQL queue.
