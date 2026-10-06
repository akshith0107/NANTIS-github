import crypto from "crypto";
import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { handleGitHubWebhook, resetPushDeduplicationMap } from "../src/routes/webhook.js";

function computeSignature(payloadString: string, secret?: string): string {
  const hmac = crypto
    .createHmac("sha256", secret || "whsec_test_secret_12345")
    .update(payloadString)
    .digest("hex");
  return `sha256=${hmac}`;
}

describe("GitHub Push Webhook Handler Suite", () => {
  const mockEnv: WebEnv = {
    GITHUB_CLIENT_ID: "client_id_test",
    GITHUB_CLIENT_SECRET: "client_secret_test",
    GITHUB_APP_ID: "app_id_test",
    GITHUB_APP_PRIVATE_KEY: "private_key_test",
    GITHUB_WEBHOOK_SECRET: "whsec_test_secret_12345",
    SESSION_SECRET: "test_secret_32_bytes_long_string!",
    DATABASE_URL: "postgresql://localhost:5432/nantis_db",
    NODE_ENV: "test",
  };

  beforeEach(() => {
    db.resetInMemoryData();
    resetPushDeduplicationMap();
  });

  it("should reject push webhook requests with invalid or missing HMAC signatures (401)", async () => {
    const payload = JSON.stringify({
      ref: "refs/heads/main",
      repository: { id: 101, name: "demo-repo", full_name: "acme/demo-repo" },
    });

    const res = await handleGitHubWebhook(
      {
        rawBody: payload,
        headers: {
          "x-github-event": "push",
          "x-hub-signature-256": "sha256=invalid_signature_hash_xyz",
        },
      },
      mockEnv
    );

    expect(res.status).toBe(401);
    expect(res.body).toContain("Invalid or missing webhook signature");
  });

  it("should queue a rescan when a valid push webhook arrives for a connected repo's default branch", async () => {
    const repo = await db.upsertRepository({
      installation_id: "101",
      github_repo_id: 101,
      name: "demo-repo",
      full_name: "acme/demo-repo",
      private: true,
      default_branch: "main",
    });

    const payload = JSON.stringify({
      ref: "refs/heads/main",
      before: "0000000000000000000000000000000000000000",
      after: "1111111111111111111111111111111111111111",
      repository: {
        id: 101,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        default_branch: "main",
      },
      head_commit: {
        id: "1111111111111111111111111111111111111111",
        message: "Fix security issue",
        timestamp: new Date().toISOString(),
      },
    });

    const signature: string = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

    const res = await handleGitHubWebhook(
      {
        rawBody: payload,
        headers: {
          "x-github-event": "push",
          "x-hub-signature-256": signature,
        },
      },
      mockEnv
    );

    expect(res.status).toBe(200);
    const body = JSON.parse(res.body!);
    expect(body.ok).toBe(true);
    expect(body.queued).toBe(true);
    expect(body.scanId).toBeDefined();

    const scans = await db.getScansForRepository(repo.id);
    expect(scans.length).toBe(1);
    expect(scans[0].trigger_type).toBe("webhook_push");
    expect(scans[0].branch).toBe("main");
  });

  it("should ignore push webhooks for non-default branches", async () => {
    const repo = await db.upsertRepository({
      installation_id: "101",
      github_repo_id: 101,
      name: "demo-repo",
      full_name: "acme/demo-repo",
      private: true,
      default_branch: "main",
    });

    const payload = JSON.stringify({
      ref: "refs/heads/feature/experimental-ui",
      repository: {
        id: 101,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        default_branch: "main",
      },
    });

    const signature: string = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

    const res = await handleGitHubWebhook(
      {
        rawBody: payload,
        headers: {
          "x-github-event": "push",
          "x-hub-signature-256": signature,
        },
      },
      mockEnv
    );

    expect(res.status).toBe(200);
    const body = JSON.parse(res.body!);
    expect(body.ok).toBe(true);
    expect(body.ignored).toBe("non_default_branch");

    const scans = await db.getScansForRepository(repo.id);
    expect(scans.length).toBe(0);
  });

  it("should de-duplicate rapid pushes to the same repository & branch within the deduplication window", async () => {
    const repo = await db.upsertRepository({
      installation_id: "101",
      github_repo_id: 101,
      name: "demo-repo",
      full_name: "acme/demo-repo",
      private: true,
      default_branch: "main",
    });

    const payload1 = JSON.stringify({
      ref: "refs/heads/main",
      repository: {
        id: 101,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        default_branch: "main",
      },
      head_commit: { id: "sha_push_1", message: "Commit 1", timestamp: new Date().toISOString() },
    });

    const signature1: string = computeSignature(payload1, mockEnv.GITHUB_WEBHOOK_SECRET);

    // Push 1
    const res1 = await handleGitHubWebhook(
      {
        rawBody: payload1,
        headers: { "x-github-event": "push", "x-hub-signature-256": signature1 },
      },
      mockEnv
    );
    expect(res1.status).toBe(200);
    const body1 = JSON.parse(res1.body!);
    expect(body1.queued).toBe(true);

    // Push 2 immediately following Push 1 (rapid push)
    const payload2 = JSON.stringify({
      ref: "refs/heads/main",
      repository: {
        id: 101,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        default_branch: "main",
      },
      head_commit: { id: "sha_push_2", message: "Commit 2", timestamp: new Date().toISOString() },
    });
    const signature2: string = computeSignature(payload2, mockEnv.GITHUB_WEBHOOK_SECRET);

    const res2 = await handleGitHubWebhook(
      {
        rawBody: payload2,
        headers: { "x-github-event": "push", "x-hub-signature-256": signature2 },
      },
      mockEnv
    );

    expect(res2.status).toBe(200);
    const body2 = JSON.parse(res2.body!);
    expect(body2.ok).toBe(true);
    expect(body2.deduplicated).toBe(true);
    expect(body2.scanId).toBe(body1.scanId);

    // Verify only 1 scan job was created in DB
    const scans = await db.getScansForRepository(repo.id);
    expect(scans.length).toBe(1);
  });
});
