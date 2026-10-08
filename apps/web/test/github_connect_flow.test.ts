import { describe, expect, it, beforeEach, vi } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv, validateWebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
import { clearInstallationTokenCache } from "../src/lib/github-app.js";
import { handleAuthCallback } from "../src/routes/auth-callback.js";
import { handleAuthDisconnect } from "../src/routes/auth-disconnect.js";
import { handleCreateScan } from "../src/routes/api-routes.js";
import { RequestContext } from "../src/routes/api-routes.js";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "test_client_id",
  GITHUB_CLIENT_SECRET: "test_client_secret",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_SLUG: "nantis-security-app",
  GITHUB_APP_PRIVATE_KEY: "test_key",
  GITHUB_WEBHOOK_SECRET: "test_webhook_secret",
  SESSION_SECRET: "super_secret_32_characters_key_here",
  DATABASE_URL: "postgresql://localhost:5432/test",
  NODE_ENV: "test",
  USER_REPO_SNAPSHOT_TTL_MS: 3600000,
};

describe("Task P2: Connect GitHub & Dual-Lock Verification Suite", () => {
  beforeEach(async () => {
    db.resetInMemoryData();
    clearInstallationTokenCache();
    vi.restoreAllMocks();
  });

  it("1. Dual-Lock Verification: Same-installation Repo X blocked (no snapshot) / Repo Y allowed (has snapshot)", async () => {
    const user = await db.upsertUser({
      github_user_id: 1001,
      github_login: "devuser_a",
      avatar_url: "https://github.com/avatar.png",
    });

    const inst = await db.upsertInstallation({
      installation_id: 5001,
      target_type: "User",
      target_id: 1001,
      account_name: "devuser_a",
    });

    const repoX = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 2001,
      name: "repo-x-secret",
      full_name: "devuser_a/repo-x-secret",
      private: true,
      default_branch: "main",
    });

    const repoY = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 2002,
      name: "repo-y-allowed",
      full_name: "devuser_a/repo-y-allowed",
      private: true,
      default_branch: "main",
    });

    db.grantRepoAccess(user.id, repoX.id);
    db.grantRepoAccess(user.id, repoY.id);

    // Save user snapshot containing ONLY Repo Y (github_repo_id: 2002), no Repo X
    await db.saveUserRepoSnapshot(user.id, [
      {
        github_repo_id: 2002,
        repo_name: "repo-y-allowed",
        full_name: "devuser_a/repo-y-allowed",
        installation_id: 5001,
        private: true,
        html_url: "https://github.com/devuser_a/repo-y-allowed",
      },
    ]);

    await db.linkUserInstallation(user.id, 5001);

    const token = encodeSession(
      { userId: user.id, githubUserId: 1001, githubLogin: "devuser_a", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    const reqContext: RequestContext = {
      method: "POST",
      path: `/api/repos/${repoX.id}/scans`,
      headers: {},
      cookies: { nantis_session: token },
      sessionToken: token,
      clientIp: "127.0.0.1",
      query: {},
      body: {},
    };

    // Attempt scan on Repo X (no snapshot entry) -> Lock 1 fails (403)
    const mockFetcher = vi.fn().mockResolvedValue(undefined);
    const resX = await handleCreateScan(reqContext, repoX.id, TEST_ENV, mockFetcher);
    expect(resX.status).toBe(403);
    const bodyX = JSON.parse(resX.body as string);
    expect(bodyX.error).toContain("snapshot expired or missing");

    // Mock live installation repo list for Repo Y check (Lock 2)
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      const urlStr = String(url);
      if (urlStr.includes("/app/installations/5001/access_tokens")) {
        return new Response(JSON.stringify({ token: "ghs_mock_token_123" }), { status: 200 });
      }
      if (urlStr.includes("/installation/repositories")) {
        return new Response(
          JSON.stringify({
            total_count: 1,
            repositories: [{ id: 2002, full_name: "devuser_a/repo-y-allowed", private: true }],
          }),
          { status: 200 }
        );
      }
      return new Response("Not Found", { status: 404 });
    });

    // Attempt scan on Repo Y (has snapshot entry & live installation match) -> 201 Created
    const reqContextY: RequestContext = { ...reqContext, path: `/api/repos/${repoY.id}/scans` };
    const resY = await handleCreateScan(reqContextY, repoY.id, TEST_ENV, mockFetcher);
    expect(resY.status).toBe(201);
    const bodyY = JSON.parse(resY.body as string);
    expect(bodyY.scan).toBeDefined();
    expect(bodyY.scan.repository_id).toBe(repoY.id);
  });

  it("2. Access removed on GitHub + manual Refresh blocks scan", async () => {
    const user = await db.upsertUser({
      github_user_id: 1002,
      github_login: "user_b",
      avatar_url: "https://github.com/user_b.png",
    });
    const inst = await db.upsertInstallation({
      installation_id: 5002,
      target_type: "User",
      target_id: 1002,
      account_name: "user_b",
    });
    const repoZ = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 2003,
      name: "repo-z-revoked",
      full_name: "user_b/repo-z-revoked",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(user.id, repoZ.id);

    // Initial snapshot contains Repo Z
    await db.saveUserRepoSnapshot(user.id, [
      {
        github_repo_id: 2003,
        repo_name: "repo-z-revoked",
        full_name: "user_b/repo-z-revoked",
        installation_id: 5002,
        private: true,
      },
    ]);

    // Access removed on GitHub -> Manual Refresh updates snapshot to empty (does not contain Repo Z)
    await db.saveUserRepoSnapshot(user.id, []);

    const token = encodeSession(
      { userId: user.id, githubUserId: 1002, githubLogin: "user_b", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );
    const reqContext: RequestContext = {
      method: "POST",
      path: `/api/repos/${repoZ.id}/scans`,
      headers: {},
      cookies: { nantis_session: token },
      sessionToken: token,
      clientIp: "127.0.0.1",
      query: {},
      body: {},
    };

    const res = await handleCreateScan(reqContext, repoZ.id, TEST_ENV, vi.fn());
    expect(res.status).toBe(403);
    const body = JSON.parse(res.body as string);
    expect(body.error).toContain("snapshot expired or missing");
  });

  it("3. Expired snapshot blocks scan until refreshed", async () => {
    const user = await db.upsertUser({
      github_user_id: 1003,
      github_login: "user_c",
      avatar_url: "https://github.com/user_c.png",
    });
    const inst = await db.upsertInstallation({
      installation_id: 5003,
      target_type: "User",
      target_id: 1003,
      account_name: "user_c",
    });
    const repoExp = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 2004,
      name: "repo-exp",
      full_name: "user_c/repo-exp",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(user.id, repoExp.id);

    // Save snapshot with TTL of 10ms (will expire immediately)
    await db.saveUserRepoSnapshot(
      user.id,
      [
        {
          github_repo_id: 2004,
          repo_name: "repo-exp",
          full_name: "user_c/repo-exp",
          installation_id: 5003,
          private: true,
        },
      ],
      10
    );

    // Sleep 20ms so snapshot expires
    await new Promise((r) => setTimeout(r, 20));

    const token = encodeSession(
      { userId: user.id, githubUserId: 1003, githubLogin: "user_c", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );
    const reqContext: RequestContext = {
      method: "POST",
      path: `/api/repos/${repoExp.id}/scans`,
      headers: {},
      cookies: { nantis_session: token },
      sessionToken: token,
      clientIp: "127.0.0.1",
      query: {},
      body: {},
    };

    const resExpired = await handleCreateScan(reqContext, repoExp.id, TEST_ENV, vi.fn());
    expect(resExpired.status).toBe(403);

    // Refresh snapshot with standard 1 hour TTL
    await db.saveUserRepoSnapshot(
      user.id,
      [
        {
          github_repo_id: 2004,
          repo_name: "repo-exp",
          full_name: "user_c/repo-exp",
          installation_id: 5003,
          private: true,
        },
      ],
      3600000
    );

    vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      const urlStr = String(url);
      if (urlStr.includes("/app/installations/5003/access_tokens")) {
        return new Response(JSON.stringify({ token: "ghs_token" }), { status: 200 });
      }
      if (urlStr.includes("/installation/repositories")) {
        return new Response(
          JSON.stringify({ total_count: 1, repositories: [{ id: 2004, full_name: "user_c/repo-exp", private: true }] }),
          { status: 200 }
        );
      }
      return new Response("Not Found", { status: 404 });
    });

    const resRefreshed = await handleCreateScan(reqContext, repoExp.id, TEST_ENV, vi.fn());
    expect(resRefreshed.status).toBe(201);
  });

  it("4. Snapshot vs live installation mismatch blocks scan (Lock 2 failure)", async () => {
    const user = await db.upsertUser({
      github_user_id: 1004,
      github_login: "user_d",
      avatar_url: "https://github.com/user_d.png",
    });
    const inst = await db.upsertInstallation({
      installation_id: 5004,
      target_type: "User",
      target_id: 1004,
      account_name: "user_d",
    });
    const repoMismatch = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 2005,
      name: "repo-mismatch",
      full_name: "user_d/repo-mismatch",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(user.id, repoMismatch.id);

    // Unexpired snapshot has repo 2005
    await db.saveUserRepoSnapshot(user.id, [
      {
        github_repo_id: 2005,
        repo_name: "repo-mismatch",
        full_name: "user_d/repo-mismatch",
        installation_id: 5004,
        private: true,
      },
    ]);

    // Live installation API returns EMPTY list (Lock 2 fails)
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      const urlStr = String(url);
      if (urlStr.includes("/app/installations/5004/access_tokens")) {
        return new Response(JSON.stringify({ token: "ghs_token" }), { status: 200 });
      }
      if (urlStr.includes("/installation/repositories")) {
        return new Response(JSON.stringify({ total_count: 0, repositories: [] }), { status: 200 });
      }
      return new Response("Not Found", { status: 404 });
    });

    const token = encodeSession(
      { userId: user.id, githubUserId: 1004, githubLogin: "user_d", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );
    const reqContext: RequestContext = {
      method: "POST",
      path: `/api/repos/${repoMismatch.id}/scans`,
      headers: {},
      cookies: { nantis_session: token },
      sessionToken: token,
      clientIp: "127.0.0.1",
      query: {},
      body: {},
    };

    const res = await handleCreateScan(reqContext, repoMismatch.id, TEST_ENV, vi.fn());
    expect(res.status).toBe(403);
    const body = JSON.parse(res.body as string);
    expect(body.error).toContain("removed or suspended on GitHub");
  });

  it("5. Disconnect revokes local session snapshot and displays disconnect note + html_url", async () => {
    const user = await db.upsertUser({
      github_user_id: 1005,
      github_login: "user_e",
      avatar_url: "https://github.com/user_e.png",
    });
    await db.linkUserInstallation(user.id, 5005, "https://github.com/settings/installations/5005");
    await db.saveUserRepoSnapshot(user.id, [
      {
        github_repo_id: 2006,
        repo_name: "repo-e",
        full_name: "user_e/repo-e",
        installation_id: 5005,
        private: true,
      },
    ]);

    const token = encodeSession(
      { userId: user.id, githubUserId: 1005, githubLogin: "user_e", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );
    const reqContext: RequestContext = {
      method: "GET",
      path: "/auth/disconnect",
      headers: {},
      cookies: { nantis_session: token },
      sessionToken: token,
      clientIp: "127.0.0.1",
      query: {},
    };

    const res = await handleAuthDisconnect(reqContext, TEST_ENV);
    expect(res.status).toBe(200);

    // Mandatory wording check
    expect(res.body).toContain("Disconnect GitHub removes local NANTIS session access. GitHub access remains until removed on GitHub.");
    expect(res.body).toContain("https://github.com/settings/installations/5005");

    // Local snapshot & session access should be deleted from DB
    const remainingSnapshots = await db.getUserUnexpiredSnapshot(user.id);
    expect(remainingSnapshots.length).toBe(0);
    expect(res.headers["Set-Cookie"]).toContain("nantis_session=;");
  });

  it("6. Single-use CSRF state validation in OAuth callback", async () => {
    const res = await handleAuthCallback({ code: "mock_code", state: "invalid_state", cookies: {} }, TEST_ENV);
    expect(res.status).toBe(400);
    expect(res.body).toContain("Invalid CSRF state token");
  });

  it("7. Path B rate limit (20 scans/day max per client IP)", async () => {
    const clientIp = "198.51.100.42";
    for (let i = 0; i < 20; i++) {
      const res = await db.checkAnonymousRateLimit(clientIp, 20);
      expect(res.allowed).toBe(true);
    }
    const resBlocked = await db.checkAnonymousRateLimit(clientIp, 20);
    expect(resBlocked.allowed).toBe(false);
    expect(resBlocked.remaining).toBe(0);
  });

  it("8. Production startup enforcement for GITHUB_APP_SLUG", () => {
    const prodEnv: Record<string, string> = {
      NODE_ENV: "production",
      GITHUB_CLIENT_ID: "id",
      GITHUB_CLIENT_SECRET: "secret",
      GITHUB_APP_ID: "123",
      GITHUB_APP_PRIVATE_KEY: "key",
      GITHUB_WEBHOOK_SECRET: "webhook_secret",
      SESSION_SECRET: "12345678901234567890123456789012",
      DATABASE_URL: "postgresql://localhost:5432/db",
    };

    expect(() => validateWebEnv(prodEnv)).toThrow("GITHUB_APP_SLUG");
  });
});
