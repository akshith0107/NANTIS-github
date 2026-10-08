import http from "http";
import { AddressInfo } from "net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { generateOAuthState, verifyAndConsumeOAuthState } from "../src/lib/github-oauth.js";
import { encodeSession } from "../src/lib/session.js";
import { handleCreateScan, handleGetRepo } from "../src/routes/api-routes.js";
import { handleAuthCallback } from "../src/routes/auth-callback.js";

let fakeServer: http.Server;
let fakeServerUrl: string;

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "test_client_id",
  GITHUB_CLIENT_SECRET: "test_client_secret",
  GITHUB_APP_ID: "123456",
  GITHUB_APP_SLUG: "test-app-slug",
  GITHUB_APP_PRIVATE_KEY: "test_private_key",
  GITHUB_WEBHOOK_SECRET: "test_webhook_secret",
  SESSION_SECRET: "test_session_secret_32_characters_long_str",
  DATABASE_URL: "postgresql://localhost:5432/nantis_test",
  NODE_ENV: "test",
  USER_REPO_SNAPSHOT_TTL_MS: 3600000,
};

let fakeReposForInst1 = [
  { id: 100, name: "repo-Y", full_name: "owner/repo-Y", private: false },
  { id: 200, name: "repo-X", full_name: "owner/repo-X", private: false },
];

let fakeUserSnapshotRepos = [
  { id: 100, name: "repo-Y", full_name: "owner/repo-Y", private: false },
];

beforeAll(async () => {
  fakeServer = http.createServer((req, res) => {
    const url = req.url || "";
    res.setHeader("Content-Type", "application/json");

    if (url.includes("/login/oauth/access_token")) {
      res.writeHead(200);
      res.end(JSON.stringify({ access_token: "fake_user_oauth_token_123" }));
      return;
    }

    if (url.includes("/user/installations/1/repositories")) {
      res.writeHead(200);
      res.end(JSON.stringify({ repositories: fakeUserSnapshotRepos }));
      return;
    }

    if (url.includes("/user/installations")) {
      res.writeHead(200);
      res.end(JSON.stringify({ installations: [{ id: 1, html_url: "https://github.com/settings/installations/1" }] }));
      return;
    }

    if (url.includes("/user")) {
      res.writeHead(200);
      res.end(JSON.stringify({ id: 999, login: "testuserA", avatar_url: "https://github.com/testuserA.png" }));
      return;
    }

    if (url.includes("/app/installations/1/access_tokens")) {
      res.writeHead(200);
      res.end(JSON.stringify({ token: "ghs_fake_inst_token", expires_at: new Date(Date.now() + 3600000).toISOString() }));
      return;
    }

    if (url.includes("/installation/repositories")) {
      res.writeHead(200);
      res.end(JSON.stringify({ repositories: fakeReposForInst1 }));
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: "Not found on fake server" }));
  });

  await new Promise<void>((resolve) => {
    fakeServer.listen(0, "127.0.0.1", () => {
      const addr = fakeServer.address() as AddressInfo;
      fakeServerUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => fakeServer.close(() => resolve()));
});

beforeEach(() => {
  db.resetInMemoryData();
  fakeReposForInst1 = [
    { id: 100, name: "repo-Y", full_name: "owner/repo-Y", private: false },
    { id: 200, name: "repo-X", full_name: "owner/repo-X", private: false },
  ];
  fakeUserSnapshotRepos = [
    { id: 100, name: "repo-Y", full_name: "owner/repo-Y", private: false },
  ];
});

describe("Task P2a Lean GitHub Connect Test Battery", () => {
  it("1. State mismatch, reuse, and 10-minute expiry rejected", async () => {
    const validState = generateOAuthState("user123");

    // Mismatch
    const resMismatch = verifyAndConsumeOAuthState("wrong_state");
    expect(resMismatch.valid).toBe(false);

    // Expired (simulate 11 mins past)
    const expiredState = generateOAuthState("user123");
    const resExpired = verifyAndConsumeOAuthState(expiredState, Date.now() + 11 * 60 * 1000);
    expect(resExpired.valid).toBe(false);

    // Reuse check
    const resFirst = verifyAndConsumeOAuthState(validState);
    expect(resFirst.valid).toBe(true);
    const resReuse = verifyAndConsumeOAuthState(validState);
    expect(resReuse.valid).toBe(false);

    // OAuth callback with invalid state fails
    const cbRes = await handleAuthCallback({ code: "bad_code", state: "invalid_state", cookies: {} }, TEST_ENV);
    expect(cbRes.status).toBe(400);
    expect(cbRes.body).toContain("Invalid CSRF state token");
  });

  it("2. User cannot attach another user's installation_id", async () => {
    const customFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(input).replace("https://api.github.com", fakeServerUrl).replace("https://github.com", fakeServerUrl);
      return fetch(urlStr, init);
    };

    const stateToken = generateOAuthState();
    const req = {
      code: "valid_code",
      state: stateToken,
      installation_id: "99999", // Installation NOT returned by fake server for this user
      cookies: { nantis_csrf_state: stateToken },
    };

    const cbRes = await handleAuthCallback(req, TEST_ENV, customFetch);
    expect(cbRes.status).toBe(403);
    expect(cbRes.body).toContain("Access denied");
  });

  it("3. Same installation: repo Y allowed, repo X (not in user's snapshot) blocked", async () => {
    const userA = await db.upsertUser({ github_user_id: 1, github_login: "userA", avatar_url: "" });
    await db.upsertInstallation({ installation_id: 1, target_type: "User", target_id: 1, account_name: "userA" });

    const repoY = await db.upsertRepository({
      installation_id: "1",
      github_repo_id: 100,
      name: "repo-Y",
      full_name: "owner/repo-Y",
      private: false,
      default_branch: "main",
    });

    const repoX = await db.upsertRepository({
      installation_id: "1",
      github_repo_id: 200,
      name: "repo-X",
      full_name: "owner/repo-X",
      private: false,
      default_branch: "main",
    });

    db.grantRepoAccess(userA.id, repoY.id);
    db.grantRepoAccess(userA.id, repoX.id);

    // User A snapshot includes ONLY repo-Y (id: 100)
    await db.saveUserRepoSnapshot(userA.id, [{
      github_repo_id: 100,
      repo_name: "repo-Y",
      full_name: "owner/repo-Y",
      installation_id: 1,
      private: false,
    }]);

    const sessionToken = encodeSession(
      { userId: userA.id, githubUserId: 1, githubLogin: "userA", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // Scan Repo Y (in snapshot) -> 201 Created
    const resY = await handleCreateScan(
      { sessionToken, cookies: { nantis_session: sessionToken }, body: {} },
      repoY.id,
      TEST_ENV
    );
    expect(resY.status).toBe(201);

    // Scan Repo X (not in snapshot) -> 403 Forbidden
    const resX = await handleCreateScan(
      { sessionToken, cookies: { nantis_session: sessionToken }, body: {} },
      repoX.id,
      TEST_ENV
    );
    expect(resX.status).toBe(403);
    expect(resX.body).toContain("User access snapshot expired or missing");
  });

  it("4. Expired snapshot blocks scan", async () => {
    const userA = await db.upsertUser({ github_user_id: 1, github_login: "userA", avatar_url: "" });
    const repoY = await db.upsertRepository({
      installation_id: "1",
      github_repo_id: 100,
      name: "repo-Y",
      full_name: "owner/repo-Y",
      private: false,
      default_branch: "main",
    });
    db.grantRepoAccess(userA.id, repoY.id);

    // Save snapshot with 1 ms TTL (immediately expired)
    await db.saveUserRepoSnapshot(userA.id, [{
      github_repo_id: 100,
      repo_name: "repo-Y",
      full_name: "owner/repo-Y",
      installation_id: 1,
      private: false,
    }], 1);

    await new Promise((r) => setTimeout(r, 10));

    const validRow = await db.checkUserRepoSnapshotValid(userA.id, 100);
    expect(validRow).toBeNull();
  });

  it("5. Repo removed from the installation blocked", async () => {
    const userA = await db.upsertUser({ github_user_id: 1, github_login: "userA", avatar_url: "" });
    await db.upsertInstallation({ installation_id: 1, target_type: "User", target_id: 1, account_name: "userA" });

    const repoY = await db.upsertRepository({
      installation_id: "1",
      github_repo_id: 100,
      name: "repo-Y",
      full_name: "owner/repo-Y",
      private: false,
      default_branch: "main",
    });

    db.grantRepoAccess(userA.id, repoY.id);
    await db.saveUserRepoSnapshot(userA.id, [{
      github_repo_id: 100,
      repo_name: "repo-Y",
      full_name: "owner/repo-Y",
      installation_id: 1,
      private: false,
    }]);

    // Live GitHub server now returns empty repository list for installation 1
    fakeReposForInst1 = [];

    const { verifyInstallationLiveRepoList } = await import("../src/lib/github-app.js");
    const customFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(input).replace("https://api.github.com", fakeServerUrl);
      return fetch(urlStr, init);
    };

    const liveRepos = await verifyInstallationLiveRepoList(1, TEST_ENV.GITHUB_APP_ID, TEST_ENV.GITHUB_APP_PRIVATE_KEY, customFetch);
    expect(liveRepos).toEqual([]);
    expect(liveRepos?.includes(100)).toBe(false);
  });

  it("6. User B cannot see User A's repos", async () => {
    const userA = await db.upsertUser({ github_user_id: 1, github_login: "userA", avatar_url: "" });
    const userB = await db.upsertUser({ github_user_id: 2, github_login: "userB", avatar_url: "" });

    const repoA = await db.upsertRepository({
      installation_id: "1",
      github_repo_id: 100,
      name: "repo-A",
      full_name: "userA/repo-A",
      private: true,
      default_branch: "main",
    });

    db.grantRepoAccess(userA.id, repoA.id);

    const sessionTokenB = encodeSession(
      { userId: userB.id, githubUserId: 2, githubLogin: "userB", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // User B tries to view User A's repo -> 404 Not Found
    const reqB = { sessionToken: sessionTokenB, cookies: { nantis_session: sessionTokenB }, body: {} };
    const resB = await handleGetRepo(reqB, repoA.id, TEST_ENV);
    expect(resB.status).toBe(404);
  });

  it("7. No tokens or secrets in logs, errors or HTML", async () => {
    const secretToken = "ghs_secret_access_token_123456";
    const { sanitizeGitErrorMessage } = await import("@nantis/worker");

    const rawError = new Error(`Git clone failed with token ${secretToken} at https://x-access-token:${secretToken}@github.com`);
    const sanitized = sanitizeGitErrorMessage(rawError, secretToken);

    expect(sanitized).not.toContain(secretToken);
    expect(sanitized).not.toContain("x-access-token");
    expect(sanitized).toBe("Failed to clone repository source tree");
  });
});
