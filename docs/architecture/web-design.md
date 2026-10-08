# NANTIS Web Application & Security Architecture Plan

This document outlines the architectural specification, data model, authentication flow, authorization access rules, and threat mitigation strategy for the NANTIS web platform.

---

## 1. Data Model Specification

The database design strictly enforces tenant isolation, zero source code persistence, and zero long-lived credential storage.

### `users`

- **Purpose**: Represents authenticated web application users.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `github_user_id` (BigInt, Unique, Indexed) — Immutable GitHub User ID
  - `github_login` (VarChar) — Current GitHub username
  - `avatar_url` (VarChar) — User profile picture URL
  - `created_at`, `updated_at` (Timestamps)
- **Deliberately NOT Stored**:
  - **No user OAuth access tokens**: User sessions rely on encrypted, server-signed session cookies. OAuth tokens are discarded after identity verification or held strictly in transient session memory.
  - **No passwords or private keys**.
  - **No personal emails** (unless explicitly exposed by GitHub public profile).

### `github_installations`

- **Purpose**: Records GitHub App installations on user accounts or organizations.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `installation_id` (BigInt, Unique, Indexed) — GitHub Installation ID assigned by GitHub
  - `target_type` (Enum: `User` | `Organization`)
  - `target_id` (BigInt) — GitHub User/Org ID where installed
  - `account_name` (VarChar) — Name of user/org account
  - `created_at`, `updated_at` (Timestamps)
- **Deliberately NOT Stored**:
  - **No GitHub App private keys**: The App's RSA private key is stored securely in environment vault variables, NEVER in database tables.
  - **No Installation Access Tokens (IATs)**: Short-lived IATs (1-hour lifespan) are generated in-memory on demand by workers and never persisted to disk or DB.

### `repositories`

- **Purpose**: Tracks repositories enabled for scanning under an active installation.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `installation_id` (UUID, Foreign Key -> `github_installations.id`)
  - `github_repo_id` (BigInt, Unique, Indexed) — GitHub Repository ID
  - `name` (VarChar) — e.g. `my-app`
  - `full_name` (VarChar) — e.g. `owner/my-app`
  - `private` (Boolean) — Repository visibility flag
  - `default_branch` (VarChar) — Primary branch (e.g., `main`)
  - `created_at`, `updated_at` (Timestamps)
- **Deliberately NOT Stored**:
  - **NO SOURCE CODE**: Code tree files, contents, diffs, git objects, or AST representations are NEVER stored in the database or permanent storage.
  - **No deploy keys, SSH keys, or access tokens**.

### `scans`

- **Purpose**: Records execution metadata and status for scanning jobs.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `repository_id` (UUID, Foreign Key -> `repositories.id`)
  - `status` (Enum: `pending` | `running` | `completed` | `failed`)
  - `trigger_type` (Enum: `manual` | `webhook_push` | `webhook_pr`)
  - `commit_sha` (VarChar) — Target commit SHA scanned
  - `branch` (VarChar) — Git ref / branch scanned
  - `triggered_by_user_id` (UUID, Foreign Key -> `users.id`, Nullable)
  - `started_at`, `completed_at` (Timestamps, Nullable)
  - `error_message` (Text, Nullable) — High-level non-sensitive failure reason if failed
- **Deliberately NOT Stored**:
  - **No raw git repositories or cloned file systems**: Temporary scan directories are deleted immediately post-scan.
  - **No stdout/stderr logs containing raw secrets**.

### `findings`

- **Purpose**: Stores masked security findings matching the core Finding Schema.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `scan_id` (UUID, Foreign Key -> `scans.id`)
  - `rule_id` (VarChar) — Detector rule identifier
  - `title` (VarChar) — Plain English short description
  - `severity` (Enum: `critical` | `high` | `medium` | `low` | `info`)
  - `confidence_tier` (Enum: `proven` | `likely` | `needs-review` | `hygiene`)
  - `file_path` (VarChar) — Relative repository path
  - `start_line`, `end_line` (Integer) — Line location
  - `masked_evidence_chain` (JSONB) — Evidence hops with masked snippets
  - `explanation` (Text) — Detailed description
  - `fix_recommendation` (Text, Nullable) — Remediation details
  - `fingerprint` (VarChar) — Deterministic line-invariant SHA-256 fingerprint
  - `introduced_in_sha`, `introduced_in_author`, `introduced_in_date` (Nullable fields)
  - `status` (Enum: `new` | `fixed` | `unchanged` | `reintroduced`)
- **Deliberately NOT Stored**:
  - **NO UNMASKED SECRETS**: All evidence snippets are masked at construction time using `maskSecrets()`. Raw secret strings are impossible to store in `findings`.
  - **No full file contents or unmasked code blocks**.

### `audit_log`

- **Purpose**: Tracks operational security events for auditing and compliance.
- **Stored**:
  - `id` (UUID, Primary Key)
  - `user_id` (UUID, Foreign Key -> `users.id`, Nullable for webhooks/system)
  - `action` (VarChar) — e.g. `user.login`, `scan.triggered`, `finding.viewed`
  - `target_resource` (VarChar) — Identifies resource type and ID (e.g. `scan:123`)
  - `ip_address` (VarChar) — Masked/hashed IP address for audit trace
  - `user_agent` (VarChar) — Request browser context
  - `timestamp` (Timestamp)
  - `details` (JSONB) — Sanitized event metadata
- **Deliberately NOT Stored**:
  - **No credentials, session tokens, or unmasked payload secrets**.

---

## 2. Authentication & Authorization Flow

NANTIS employs a strict separation of concerns between user authentication and repository access rights.

```
+-------------------------------------------------------------------------------+
|                                  USER LOGIN                                   |
|  User  <--->  NANTIS Web App  <--->  GitHub OAuth App (Read-Only Identity)    |
+-------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------+
|                             REPOSITORY OPERATIONS                             |
|  Worker Backend  <--->  GitHub App Installation (Read-Only Repo Access)      |
+-------------------------------------------------------------------------------+
```

### GitHub OAuth App (User Login)

- **Purpose**: Authenticates the human user sitting at the web browser.
- **Permissions Required**: Read-only user identity:
  - `read:user` — Access basic profile information (`github_user_id`, login name, avatar).
  - `user:email` — Access primary email address if required for notifications.
- **Flow**:
  1. User clicks "Sign in with GitHub".
  2. App redirects user to `https://github.com/login/oauth/authorize` with state token.
  3. GitHub redirects back to NANTIS callback endpoint with authorization code.
  4. NANTIS exchanges code for access token via `POST https://github.com/login/oauth/access_token`.
  5. NANTIS fetches user identity (`GET https://api.github.com/user`), creates/updates `users` record, and issues an HTTP-only, `Secure`, `SameSite=Lax` session cookie.
- **Documentation Citation**:
  - [GitHub Docs: Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)

### GitHub App (Repository Access & Webhooks)

- **Purpose**: Grants NANTIS backend system permission to read repository metadata, download source archives for scanning, and listen to push/PR webhooks.
- **Permissions Required (Strictly Read-Only to Start)**:
  - **Repository Permissions**:
    - `Contents: Read-only` — Allows downloading code tarballs/zipballs or git trees for scanning.
    - `Metadata: Read-only` — Mandatory permission for repository listing and branch references.
    - `Pull requests: Read-only` — Allows viewing PR context for incoming pull request scans. _(Write permission for creating fix PRs will only be requested in future explicit user-approved steps)_.
  - **Organization/Account Permissions**:
    - `Members: Read-only` — Enables verifying organization membership for user access control.
  - **Webhooks**: `push`, `pull_request`, `installation`, `installation_repositories`.
- **Flow**:
  1. NANTIS authenticates as a GitHub App using an RS256 JWT signed with the App's RSA Private Key (`POST /app/installations/{installation_id}/access_tokens`).
  2. GitHub returns a short-lived **Installation Access Token (IAT)** valid for 1 hour.
  3. Workers use the IAT to fetch repository contents in ephemeral memory during scan execution.
- **Documentation Citations**:
  - [GitHub Docs: Authenticating as a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app)
  - [GitHub Docs: Generating an Installation Access Token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
  - [GitHub Docs: REST API endpoints for GitHub App installations](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)

### Key Architectural Differences

| Dimension         | GitHub OAuth App                       | GitHub App Installation                       |
| :---------------- | :------------------------------------- | :-------------------------------------------- |
| **Primary Scope** | Authenticates the web user identity    | Grants system access to repositories          |
| **Token Type**    | User Access Token (User-scoped)        | Installation Access Token (App-scoped)        |
| **Lifespan**      | Long/Short-lived, discarded post-login | Strictly 1 hour max, kept in worker memory    |
| **Repo Scope**    | NO repository permissions requested    | Explicitly chosen repos per organization/user |

---

## 3. The Strict Access Rule

### Core Rule Statement

> **A logged-in user $U$ may access scans, findings, or metadata for repository $R$ IF AND ONLY IF GitHub confirms that $U$ currently possesses read access to $R$ within the GitHub App installation $I$ where $R$ is registered.**

### Real-Time Verification Algorithm

When User $U$ requests any endpoint for Repository $R$ or Scan $S$ (which resolves to $R$):

1. **Session Check**: Extract `github_user_id` from $U$'s verified session cookie.
2. **Resource Resolution**: Lookup $R$'s `github_repo_id` and `installation_id` from the database.
3. **Live GitHub Access Query**:
   - Query GitHub API using either the user's token or the installation's IAT:
     `GET https://api.github.com/user/collaborators/{owner}/{repo}/permission` or check membership via GitHub Apps API.
   - Verify that user $U$ has `admin`, `write`, or `read` permission on repository $R$.
4. **Caching & TTL**:
   - Cache positive permissions in transient memory/Redis for **at most 5 minutes**.
   - Instantly invalidate permission cache for an installation when GitHub delivers `installation_member.removed`, `organization.member_removed`, or `installation_repositories.removed` webhooks.
5. **Enforcement & Non-Disclosure**:
   - If GitHub responds that user $U$ lacks permission (or returns HTTP 404/403), NANTIS returns **HTTP 404 Not Found**.
   - _Rationale_: Returning HTTP 403 Forbidden leaks the existence of a private repository or scan to unauthorized users. HTTP 404 prevents resource enumeration.

---

## 4. Top 10 Data Leakage Threat Scenarios & Controls

| #      | Threat Scenario                                                   | Attack Vector                                                                                                                           | Security Control                                                                                                                                                                                                                |
| ------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**  | **Insecure Direct Object Reference (IDOR)**                       | User A alters URL from `/scans/101` to `/scans/102` to view User B's scan findings.                                                     | **Mandatory Authorization Middleware**: Every API request resolves `scan_id -> repository_id -> github_repo_id` and executes the Strict Access Rule check against GitHub before fetching findings. Returns HTTP 404 on failure. |
| **2**  | **Stale Local Permissions after Revocation on GitHub**            | User A is removed from an Organization on GitHub, but continues accessing findings via NANTIS's cached DB permissions.                  | **Short-TTL Cache + Webhook Invalidation**: Permission checks cached for max 5 minutes. Real-time cache eviction triggered by GitHub `organization.member_removed` and `installation_repositories` webhooks.                    |
| **3**  | **Cross-Tenant SQL Injection / Query Bleed**                      | Query flaw or SQL injection returns findings across repository boundaries.                                                              | **Strict Parameterization + Database RLS**: All queries use parameterized ORMs (Prisma/Drizzle) with compile-time type safety. PostgreSQL Row Level Security (RLS) policies mandate `repository_id` boundary scoping.           |
| **4**  | **Spoofed GitHub Webhook Payload**                                | Attacker posts forged `push` webhooks to trigger unauthorized scans or exfiltrate repo metadata.                                        | **HMAC-SHA256 Signature Verification**: Every incoming webhook must pass signature check (`X-Hub-Signature-256`) against the GitHub App Webhook Secret before processing.                                                       |
| **5**  | **Unmasked Secret Leakage in Logs or Audit Trail**                | Detector discovers secret; raw string is written to `scans.error_message`, `audit_log`, or server logs.                                 | **Construction-Time Masking**: Secrets are masked immediately via `maskSecrets()` at construction in `packages/core`. Loggers strictly redact patterns resembling secrets/tokens.                                               |
| **6**  | **Database Theft / Credential Exfiltration**                      | Attacker accesses DB dump and extracts GitHub private keys or long-lived repo tokens.                                                   | **Zero Long-Lived Token Storage**: DB stores zero source code, zero GitHub App private keys (kept in secure key vaults), and zero Installation Access Tokens (transient 1-hour lifespan in memory).                             |
| **7**  | **Session Hijacking via XSS or Network Interception**             | Attacker steals session token to impersonate a legitimate user.                                                                         | **Hardened Session Security**: Cookies set with `HttpOnly`, `Secure`, `SameSite=Lax`, and `Host-` prefix. Strict Content Security Policy (CSP) headers disallow inline scripts. Session IDs stored hashed (SHA-256) in DB.      |
| **8**  | **Worker File System Cross-Scan Contamination**                   | Scan job for Repo A leaves source files or extracted findings in temporary disk space read by Repo B scan.                              | **Isolated Ephemeral Sandboxing**: Each scan job executes in an isolated temporary container/directory with strict `umask`. Directories are wiped recursively (`rm -rf`) in `finally` blocks post-scan.                         |
| **9**  | **Resource Enumeration via HTTP Response Timing or Status Codes** | Attacker probes `/api/repos/{id}` to discover private repository names by comparing HTTP 403 vs 404 response codes or response latency. | **Uniform Error & Constant-Time Handling**: Returns identical HTTP 404 (Not Found) responses for non-existent resources and unauthorized resources alike. Permission checks execute with constant-time response behavior.       |
| **10** | **Server-Side Request Forgery (SSRF) via User Input**             | Attacker inputs malicious callback URLs pointing to internal worker infrastructure (`http://169.254.169.254`).                          | **Strict Outbound Egress Restriction**: Backend worker network egress restricted exclusively to official GitHub API domains (`api.github.com`, `codeload.github.com`). No arbitrary user-defined webhooks allowed.              |
