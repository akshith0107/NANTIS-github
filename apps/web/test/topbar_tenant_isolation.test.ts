import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
import { renderHomePage } from "../src/routes/home-page.js";
import { renderRepositoriesPage } from "../src/routes/repos-page.js";

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

describe("Top-Bar Repo Selector Tenant Isolation Suite", () => {
  beforeEach(async () => {
    db.resetInMemoryData();
  });

  it("User B never sees User A's repository names in the header dropdown", async () => {
    // 1. Setup User A and Repo A
    const uA = await db.upsertUser({
      github_user_id: 7001,
      github_login: "user_a",
      avatar_url: "https://github.com/user_a.png",
    });
    const instA = await db.upsertInstallation({
      installation_id: 8001,
      target_type: "User",
      target_id: 7001,
      account_name: "user_a",
    });
    const rA = await db.upsertRepository({
      installation_id: instA.id,
      github_repo_id: 9101,
      name: "super-secret-repo-a",
      full_name: "user_a/super-secret-repo-a",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(uA.id, rA.id);

    // 2. Setup User B and Repo B
    const uB = await db.upsertUser({
      github_user_id: 7002,
      github_login: "user_b",
      avatar_url: "https://github.com/user_b.png",
    });
    const instB = await db.upsertInstallation({
      installation_id: 8002,
      target_type: "User",
      target_id: 7002,
      account_name: "user_b",
    });
    const rB = await db.upsertRepository({
      installation_id: instB.id,
      github_repo_id: 9102,
      name: "user-b-public-app",
      full_name: "user_b/user-b-public-app",
      private: false,
      default_branch: "main",
    });
    db.grantRepoAccess(uB.id, rB.id);

    const tokenB = encodeSession(
      { userId: uB.id, githubUserId: 7002, githubLogin: "user_b", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // 3. Render home page as User B
    const resHomeB = await renderHomePage({ sessionToken: tokenB }, TEST_ENV);
    expect(resHomeB.status).toBe(200);
    expect(resHomeB.body).toContain("user_b/user-b-public-app");
    expect(resHomeB.body).not.toContain("user_a/super-secret-repo-a");

    // 4. Render repos page as User B
    const resReposB = await renderRepositoriesPage({ sessionToken: tokenB }, TEST_ENV);
    expect(resReposB.status).toBe(200);
    expect(resReposB.body).toContain("user_b/user-b-public-app");
    expect(resReposB.body).not.toContain("user_a/super-secret-repo-a");
  });

  it("User with zero scanned repositories sees 'No repositories yet' fallback in top-bar", async () => {
    const uNew = await db.upsertUser({
      github_user_id: 7003,
      github_login: "newuser",
      avatar_url: "https://github.com/newuser.png",
    });

    const tokenNew = encodeSession(
      { userId: uNew.id, githubUserId: 7003, githubLogin: "newuser", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    const resHome = await renderHomePage({ sessionToken: tokenNew }, TEST_ENV);
    expect(resHome.status).toBe(200);
    expect(resHome.body).toContain("No repositories yet");
  });
});
