import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
import { handleCreateScan, scanJobQueue } from "../src/routes/api-routes.js";
import { renderScanFindingsPage } from "../src/routes/scan-findings-page.js";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "fake_client_id_123",
  GITHUB_CLIENT_SECRET: "fake_client_secret_abc",
  GITHUB_APP_ID: "99999",
  GITHUB_APP_PRIVATE_KEY: "fake_private_key",
  GITHUB_WEBHOOK_SECRET: "fake_webhook_secret_xyz",
  SESSION_SECRET: "super_secret_32_characters_key_here",
  DATABASE_URL: "postgresql://localhost:5432/test",
  NODE_ENV: "test",
};

describe("Scan Job Trigger & Scan Findings Viewer UI (apps/web)", () => {
  beforeEach(async () => {
    db.resetInMemoryData();
  });

  it("should trigger scan, run worker execution, and render findings with evidence chain hops", async () => {
    // 1. Setup Alice & Her Repo
    const alice = await db.upsertUser({
      github_user_id: 101,
      github_login: "alice",
      avatar_url: "https://github.com/alice.png",
    });
    const inst = await db.upsertInstallation({
      installation_id: 301,
      target_type: "User",
      target_id: 101,
      account_name: "alice",
    });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "alice-web-app",
      full_name: "alice/alice-web-app",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(alice.id, repo.id);

    const aliceToken = encodeSession(
      { userId: alice.id, githubUserId: 101, githubLogin: "alice", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // 2. Trigger scan via API route with mock source code fetcher containing a secret finding
    const createRes = await handleCreateScan(
      { sessionToken: aliceToken, body: { commit_sha: "abc1234", branch: "main" } },
      repo.id,
      TEST_ENV,
      async (dir) => {
        const fs = await import("fs");
        const path = await import("path");
        fs.writeFileSync(
          path.join(dir, "stripe.ts"),
          `export const stripeKey = "sk_test_51MzX1234567890abcdef1234567890abcdef";`
        );
      }
    );

    expect(createRes.status).toBe(201);
    const { scan } = JSON.parse(createRes.body!);
    expect(scan.id).toBeDefined();

    // 3. Wait for scan job queue completion
    const jobState = await scanJobQueue.waitForJobCompletion(scan.id, 5000);
    expect(jobState.status).toBe("done");

    // 4. Render scan findings page
    const pageRes = await renderScanFindingsPage({ sessionToken: aliceToken }, scan.id, TEST_ENV);

    expect(pageRes.status).toBe(200);
    expect(pageRes.body).toContain("Scan Findings for alice/alice-web-app");
    expect(pageRes.body).toContain("Hardcoded Secret Detected");
    expect(pageRes.body).toContain("[SINK]");
    expect(pageRes.body).toContain("[REDACTED_SECRET]");
  });

  it("should render compliant zero-findings message when scan detects no issues", async () => {
    const bob = await db.upsertUser({
      github_user_id: 202,
      github_login: "bob",
      avatar_url: "https://github.com/bob.png",
    });
    const inst = await db.upsertInstallation({
      installation_id: 302,
      target_type: "User",
      target_id: 202,
      account_name: "bob",
    });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 802,
      name: "clean-repo",
      full_name: "bob/clean-repo",
      private: false,
      default_branch: "main",
    });
    db.grantRepoAccess(bob.id, repo.id);

    const bobToken = encodeSession(
      { userId: bob.id, githubUserId: 202, githubLogin: "bob", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // Trigger scan on clean codebase
    const createRes = await handleCreateScan(
      { sessionToken: bobToken, body: { commit_sha: "clean123", branch: "main" } },
      repo.id,
      TEST_ENV,
      async (dir) => {
        const fs = await import("fs");
        const path = await import("path");
        fs.writeFileSync(path.join(dir, "index.ts"), `console.log("Hello world");`);
      }
    );

    const { scan } = JSON.parse(createRes.body!);
    await scanJobQueue.waitForJobCompletion(scan.id, 5000);

    const pageRes = await renderScanFindingsPage({ sessionToken: bobToken }, scan.id, TEST_ENV);

    expect(pageRes.status).toBe(200);

    // MANDATORY WORDING CHECK: Must contain "no issues found in the checks we run"
    expect(pageRes.body).toContain("no issues found in the checks we run");

    // ABSOLUTE FORBIDDEN WORDS CHECK: Must NEVER contain "secure", "safe", or "production ready"
    const lowerBody = (pageRes.body || "").toLowerCase();
    expect(lowerBody).not.toContain("secure");
    expect(lowerBody).not.toContain("safe");
    expect(lowerBody).not.toContain("production ready");
  });

  it("should enforce strict tenant isolation and deny unauthorized user access to scan findings (404)", async () => {
    const alice = await db.upsertUser({
      github_user_id: 101,
      github_login: "alice",
      avatar_url: "a",
    });
    const bob = await db.upsertUser({ github_user_id: 202, github_login: "bob", avatar_url: "b" });

    const inst = await db.upsertInstallation({
      installation_id: 301,
      target_type: "User",
      target_id: 101,
      account_name: "alice",
    });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "alice-repo",
      full_name: "alice/alice-repo",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(alice.id, repo.id);

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "sha123",
      branch: "main",
      triggered_by_user_id: alice.id,
    });

    const bobToken = encodeSession(
      { userId: bob.id, githubUserId: 202, githubLogin: "bob", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // Bob attempts to request Alice's scan findings page
    const res = await renderScanFindingsPage({ sessionToken: bobToken }, scan.id, TEST_ENV);

    // Must yield identical 404 response
    expect(res.status).toBe(404);
    expect(res.body).toContain("404 Not Found");
  });
});
