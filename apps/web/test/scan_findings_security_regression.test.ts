import { describe, expect, it, beforeEach } from "vitest";
import { Finding } from "@nantis/core";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { encodeSession } from "../src/lib/session.js";
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

describe("Scan Findings Route Security Regression Tests (apps/web)", () => {
  beforeEach(async () => {
    db.resetInMemoryData();
  });

  it("1. unauthenticated request - public repo allowed (200), private repo forbidden (404)", async () => {
    const user = await db.upsertUser({ github_user_id: 1, github_login: "owner", avatar_url: "u" });
    const inst = await db.upsertInstallation({ installation_id: 1, target_type: "User", target_id: 1, account_name: "owner" });
    
    // Public repo
    const pubRepo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 10,
      name: "pub-repo",
      full_name: "owner/pub-repo",
      private: false,
      default_branch: "main",
    });
    const pubScan = await db.createScan({
      repository_id: pubRepo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "pub123",
      branch: "main",
      triggered_by_user_id: user.id,
    });

    const pubRes = await renderScanFindingsPage({}, pubScan.id, TEST_ENV);
    expect(pubRes.status).toBe(200);
    expect(pubRes.body).toContain("Scan Findings for owner/pub-repo");

    // Private repo
    const privRepo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 11,
      name: "priv-repo",
      full_name: "owner/priv-repo",
      private: true,
      default_branch: "main",
    });
    const privScan = await db.createScan({
      repository_id: privRepo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "priv123",
      branch: "main",
      triggered_by_user_id: user.id,
    });

    const privRes = await renderScanFindingsPage({}, privScan.id, TEST_ENV);
    expect(privRes.status).toBe(404);
    expect(privRes.body).toContain("404 Not Found");
  });

  it("2. authenticated unauthorized request - returns 404", async () => {
    const alice = await db.upsertUser({ github_user_id: 101, github_login: "alice", avatar_url: "a" });
    const bob = await db.upsertUser({ github_user_id: 202, github_login: "bob", avatar_url: "b" });

    const inst = await db.upsertInstallation({ installation_id: 301, target_type: "User", target_id: 101, account_name: "alice" });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "alice-secret",
      full_name: "alice/alice-secret",
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

    const res = await renderScanFindingsPage({ sessionToken: bobToken }, scan.id, TEST_ENV);
    expect(res.status).toBe(404);
    expect(res.body).toContain("404 Not Found");
  });

  it("3. authorized request - returns 200 with scan findings content", async () => {
    const alice = await db.upsertUser({ github_user_id: 101, github_login: "alice", avatar_url: "a" });
    const inst = await db.upsertInstallation({ installation_id: 301, target_type: "User", target_id: 101, account_name: "alice" });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "alice-secret",
      full_name: "alice/alice-secret",
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

    const aliceToken = encodeSession(
      { userId: alice.id, githubUserId: 101, githubLogin: "alice", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    const res = await renderScanFindingsPage({ sessionToken: aliceToken }, scan.id, TEST_ENV);
    expect(res.status).toBe(200);
    expect(res.body).toContain("Scan Findings for alice/alice-secret");
  });

  it("4. missing scan - returns 404", async () => {
    const res = await renderScanFindingsPage({}, "non-existent-scan-id-9999", TEST_ENV);
    expect(res.status).toBe(404);
    expect(res.body).toContain("404 Not Found");
  });

  it("5. empty findings - returns 200 with compliant zero-findings message", async () => {
    const alice = await db.upsertUser({ github_user_id: 101, github_login: "alice", avatar_url: "a" });
    const inst = await db.upsertInstallation({ installation_id: 301, target_type: "User", target_id: 101, account_name: "alice" });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "clean-repo",
      full_name: "alice/clean-repo",
      private: false,
      default_branch: "main",
    });

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "clean123",
      branch: "main",
      triggered_by_user_id: alice.id,
    });

    const res = await renderScanFindingsPage({}, scan.id, TEST_ENV);
    expect(res.status).toBe(200);
    expect(res.body).toContain("no issues found in the checks we run");
  });

  it("6 & 7. findings containing attacker-controlled strings and HTML/script-like content are escaped", async () => {
    const alice = await db.upsertUser({ github_user_id: 101, github_login: "alice", avatar_url: "a" });
    const inst = await db.upsertInstallation({ installation_id: 301, target_type: "User", target_id: 101, account_name: "alice" });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "xss-test-repo",
      full_name: "alice/xss-test-repo",
      private: false,
      default_branch: "main",
    });

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "xss123",
      branch: "main",
      triggered_by_user_id: alice.id,
    });

    // Save finding with malicious XSS injection vectors
    await db.saveScanFindings(scan.id, [
      {
        id: "finding-xss-1",
        fingerprint: "fp-xss-1",
        ruleId: "XSS_RULE",
        title: 'Attacker <script>alert("XSS")</script> Title',
        severity: "high",
        confidenceTier: "proven",
        file: 'app/<img src=x onerror=alert("XSS")>.ts',
        lineRange: { startLine: 10, endLine: 12 },
        explanation: 'Malformed input <svg/onload=alert(1)> in route',
        codeSnippet: 'const userInput = "<script>alert(1)</script>";',
      } as unknown as Finding,
    ]);

    const res = await renderScanFindingsPage({}, scan.id, TEST_ENV);
    expect(res.status).toBe(200);

    // Verify raw unescaped script tag is NOT rendered directly in HTML structure
    expect(res.body).not.toContain('<script>alert("XSS")</script>');
    expect(res.body).not.toContain('<img src=x onerror=alert("XSS")>');

    // Verify escaped HTML output
    expect(res.body).toContain("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;");
    expect(res.body).toContain("&lt;svg/onload=alert(1)&gt;");
  });

  it("8. error path - unexpected thrown error during access check bubbles up or is handled", async () => {
    const alice = await db.upsertUser({ github_user_id: 101, github_login: "alice", avatar_url: "a" });
    const inst = await db.upsertInstallation({ installation_id: 301, target_type: "User", target_id: 101, account_name: "alice" });
    const repo = await db.upsertRepository({
      installation_id: inst.id,
      github_repo_id: 801,
      name: "err-repo",
      full_name: "alice/err-repo",
      private: true,
      default_branch: "main",
    });
    db.grantRepoAccess(alice.id, repo.id);

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "done",
      trigger_type: "manual",
      commit_sha: "err123",
      branch: "main",
      triggered_by_user_id: alice.id,
    });

    const aliceToken = encodeSession(
      { userId: alice.id, githubUserId: 101, githubLogin: "alice", createdAt: Date.now() },
      TEST_ENV.SESSION_SECRET
    );

    // Mock db.getFindingsForScan to throw a simulated database error
    const originalGetFindings = db.getFindingsForScan;
    db.getFindingsForScan = async () => {
      throw new Error("Simulated Database Connection Failure");
    };

    try {
      await expect(
        renderScanFindingsPage({ sessionToken: aliceToken }, scan.id, TEST_ENV)
      ).rejects.toThrow("Simulated Database Connection Failure");
    } finally {
      db.getFindingsForScan = originalGetFindings;
    }
  });
});
