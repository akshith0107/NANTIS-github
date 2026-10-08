# NANTIS - Task P2: "Connect GitHub" Implementation & Audit Report

## 1. Executive Summary

Task P2 introduces the "Connect GitHub" integration for the NANTIS web application, supporting two distinct scanning entry points while guaranteeing zero persistent OAuth token storage, dual-lock authorization verification, and strict credential isolation during git clone operations.

All 47 test files and 207 unit/integration tests in the workspace pass with 100% success rate.

---

## 2. Architecture & Entry Points

NANTIS is a central web service (nothing is installed on the user's local machine). It operates using a GitHub App under the hood and provides two scanning workflows:

```
                  ┌─────────────────────────────────────────────────────────────┐
                  │                 ENTRY POINT A: CONNECTED                   │
                  │   User signs in with GitHub -> Selects Repositories        │
                  └──────────────────────────────┬──────────────────────────────┘
                                                 │
                                                 ▼
                  ┌─────────────────────────────────────────────────────────────┐
                  │             Lock 1: User Repo Snapshot (TTL: 1 hr)          │
                  │  (Derived via temporary user token, then token discarded)   │
                  └──────────────────────────────┬──────────────────────────────┘
                                                 │
                                                 ▼
                  ┌─────────────────────────────────────────────────────────────┐
                  │                 ENTRY POINT B: PASTE A LINK                 │
                  │  Public GitHub repos only (https://github.com/owner/repo)   │
                  │              Rate limit: 20 scans / day / IP                │
                  └──────────────────────────────┬──────────────────────────────┘
                                                 │
                                                 ▼
                  ┌─────────────────────────────────────────────────────────────┐
                  │                 DUAL-LOCK SCAN VERIFICATION                 │
                  │    - Lock 1: Unexpired user repo snapshot match (by ID)     │
                  │    - Lock 2: Live GitHub App installation match (by ID)     │
                  └──────────────────────────────┬──────────────────────────────┘
                                                 │
                                                 ▼
                                ┌────────────────────────────────┐
                                │       SCAN FINDINGS PAGE       │
                                └────────────────────────────────┘
```

### Entry Point A: Connected Flow
1. User clicks **"Connect GitHub"** on the home page or navigation bar.
2. User authenticates via GitHub OAuth (`/auth/login`) with single-use CSRF `state` parameter validation.
3. Upon callback (`/auth/callback`), NANTIS exchanges the code for a temporary user OAuth token.
4. NANTIS calls `GET /user/installations/:id/repositories` (paginated) to capture a snapshot of repositories accessible to the user for that installation.
5. The snapshot (`user_repo_snapshots`) is persisted with a configurable TTL (`USER_REPO_SNAPSHOT_TTL_MS`, default 1 hour).
6. **The user OAuth token is immediately discarded**; it is NEVER stored in the database or written to disk.
7. The session cookie is rotated to prevent session fixation attacks.

### Entry Point B: Paste a Link Flow
1. Anonymous or unauthenticated users can paste any public GitHub repository URL (`https://github.com/owner/repo`) directly into the home page input.
2. The scan runs against the public repository with a strict rate limit of **20 scans per 24 hours per client IP**.
3. Results display on the standard Scan Findings Page, with a callout banner linking to "Connect GitHub" for private repo support and higher scan limits.

---

## 3. Dual-Lock Scan Authorization Protocol

To ensure security across multi-tenant environments and prevent confused-deputy attacks, every scan request must satisfy **both** locks evaluated strictly by numeric `github_repo_id`:

```
                 Incoming Scan Request (repo_id)
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │   Lock 1: User Snapshot Valid Check   │
            │  Is repo_id in user's active,        │
            │  unexpired snapshot?                  │
            └──────────────────┬────────────────────┘
                               │
                      YES      │      NO
                ┌──────────────┴──────────────┐
                ▼                             ▼
   ┌──────────────────────────┐    ┌────────────────────┐
   │ Lock 2: GitHub App Live  │    │  403 FORBIDDEN     │
   │ Repository List Check    │    │ (Snapshot Expired  │
   │ Is repo_id in App live   │    │    or Missing)      │
   │ installation repo list?  │    └────────────────────┘
   └────────────┬─────────────┘
                │
       YES      │      NO
 ┌──────────────┴──────────────┐
 ▼                             ▼
 201 SCAN CREATED    403 FORBIDDEN
                     (Removed/Suspended on GitHub)
```

1. **Lock 1 (User Snapshot)**: Verifies that the requested repository's `github_repo_id` is present in the current user's unexpired `user_repo_snapshots` record. If missing or expired, the request is denied with `403 Forbidden`.
2. **Lock 2 (Live Installation List)**: Fetches the live list of accessible repositories for the installation via `GET /installation/repositories` using a short-lived App Installation Token. If the repository has been removed on GitHub or the installation was suspended, the scan is denied with `403 Forbidden`.

---

## 4. Git Authentication & Credential Isolation

To prevent token leakage via command-line exposure, process lists, or `.git/config` files on disk:

1. Installation tokens (`ghs_...`) are requested on demand from GitHub's App Installation API (`POST /app/installations/:id/access_tokens`).
2. Clone operations do **NOT** append credentials to the repository URL (e.g. `https://x-access-token:token@github.com/...` is strictly prohibited).
3. Clone operations pass the installation token using environment-based Git configuration parameters:
   ```bash
   GIT_CONFIG_COUNT=1
   GIT_CONFIG_KEY_0=http.extraHeader
   GIT_CONFIG_VALUE_0=Authorization: Bearer <installation_token>
   ```
4. Zero tokens are stored in `.git/config` or passed as process CLI arguments (`ps aux` clean).

---

## 5. Disconnect Flow & Wording Compliance

### Wording Rules Enforced
- **Button Labels**: "Connect GitHub" (Sign-in), "Choose repositories" (Repo selection), "Disconnect GitHub" (Revocation).
- **Required Read-Only Statement**:
  > *"NANTIS gets read-only access to only the repositories you choose, and you can change this anytime on GitHub."*
- **Disconnect Notice**:
  > *"Disconnect GitHub removes local NANTIS session access. GitHub access remains until removed on GitHub."*
- **Forbidden Words**: The words `"install"`, `"secure"`, `"safe"`, and `"production ready"` are strictly absent from all user-facing pages and UI routes.

### Revocation Logic (`/auth/disconnect`)
1. Deletes all `user_repo_snapshots` entries for the user.
2. Clears the `user_installations` link.
3. Clears the `nantis_session` cookie.
4. Renders the Disconnect Page containing the mandatory wording and a direct link (`html_url`) to the user's installation settings on GitHub.

---

## 6. Official GitHub Documentation References

All endpoint invocations, authentication formats, and webhook schemas were built against official GitHub REST API and Webhook documentation:

| Scope / Operation | GitHub Documentation Reference Page | Verification Status |
|---|---|---|
| **Git HTTPS Authentication Format** | [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation) | **NOT VERIFIED** (Pending live GitHub App test) |
| **User Authorized Repositories** | [List repositories accessible to the user access token for an installation](https://docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28#list-repositories-accessible-to-the-user-access-token-for-an-installation) | Verified via Vitest unit mock & contract tests |
| **App Installation Repositories** | [List repositories accessible to the app installation](https://docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28#list-repositories-accessible-to-the-app-installation) | Verified via Vitest unit mock & contract tests |
| **Webhook Events & Payloads** | [Installation event](https://docs.github.com/en/webhooks/webhook-events-and-payloads#installation) & [InstallationRepositories event](https://docs.github.com/en/webhooks/webhook-events-and-payloads#installation_repositories) | Verified via Vitest unit mock & contract tests |

> [!WARNING]
> **Real GitHub App Behavior Note**: While all mock contract tests, header isolation, and authorization endpoints pass automated test suites, real end-to-end communication with live GitHub App infrastructure is marked **NOT VERIFIED** until manual test execution against a live GitHub organization/app instance.

---

## 7. Automated Test Results

The Task P2 test suite (`apps/web/test/github_connect_flow.test.ts`) verifies 8 critical scenarios:

```
✓ 1. Dual-Lock Verification: Same-installation Repo X blocked (no snapshot) / Repo Y allowed (has snapshot)
✓ 2. Access removed on GitHub + manual Refresh blocks scan
✓ 3. Expired snapshot blocks scan until refreshed
✓ 4. Snapshot vs live installation mismatch blocks scan (Lock 2 failure)
✓ 5. Disconnect revokes local session snapshot and displays disconnect note + html_url
✓ 6. Single-use CSRF state validation in OAuth callback
✓ 7. Path B rate limit (20 scans/day max per client IP)
✓ 8. Production startup enforcement for GITHUB_APP_SLUG
```

**Overall Workspace Test Suite Summary**:
- **Test Files**: 47 passed (47 total)
- **Tests**: 207 passed (207 total)
- **Pass Rate**: 100%
