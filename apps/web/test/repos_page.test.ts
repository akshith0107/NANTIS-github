import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
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

describe("Plain Accessible Repositories Page (apps/web)", () => {
  beforeEach(async () => {
    db.resetInMemoryData();
  });

  it("should return HTTP 401 when request is unauthenticated", async () => {
    const res = await renderRepositoriesPage({}, TEST_ENV);

    expect(res.status).toBe(401);
    expect(res.body).toContain("Authentication Required");
  });

  it("should list signed-in user's accessible repos with a 'Scan' button (server-side access check)", async () => {
    // Setup User A & Repo A
    const uA = await db.upsertUser({
      github_user_id: 101,
      github_login: "alice",
      avatar_url: "https://github.com/alice.png",
    });
    const instA = await db.upsertInstallation({
      installation_id: 301,
      target_type: "User",
      target_id: 101,
      account_name: "alice",
    });
    const repoA = await db.upsertRepository({
      installation_id: instA.id,
      github_repo_id: 801,
      name: "alice-app",
      full_name: "alice/alice-app",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(uA.id, repoA.id);

    // Setup User B & Repo B
    const uB = await db.upsertUser({
      github_user_id: 202,
      github_login: "bob",
      avatar_url: "https://github.com/bob.png",
    });
    const instB = await db.upsertInstallation({
      installation_id: 302,
      target_type: "User",
      target_id: 202,
      account_name: "bob",
    });
    const repoB = await db.upsertRepository({
      installation_id: instB.id,
      github_repo_id: 802,
      name: "bob-app",
      full_name: "bob/bob-app",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(uB.id, repoB.id);

    // Session for Alice
    const sessionTokenA = encodeSession(
      { userId: uA.id, githubUserId: 101, githubLogin: "alice", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // Render page for Alice
    const resA = await renderRepositoriesPage({ sessionToken: sessionTokenA }, TEST_ENV);

    expect(resA.status).toBe(200);
    expect(resA.body).toContain("Signed in as <strong>alice</strong>");
    expect(resA.body).toContain("alice/alice-app");
    expect(resA.body).toContain(
      '<button type="button" data-repo-id="' + repoA.id + '">Scan</button>'
    );

    // Server-side isolation check: Alice's page MUST NOT contain Bob's repo
    expect(resA.body).not.toContain("bob/bob-app");
  });
});
