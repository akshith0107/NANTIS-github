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

describe("Phase 1C: GitHub Webhook Completion & Security Suite", () => {
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

  describe("1. Webhook Signature Verification (HMAC-SHA256)", () => {
    it("1.1 accepts valid HMAC signature", async () => {
      const payload = JSON.stringify({ action: "test" });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": signature,
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const body = JSON.parse(res.body!);
      expect(body.ok).toBe(true);
      expect(body.event).toBe("ping");
    });

    it("1.2 rejects invalid HMAC signature with 401", async () => {
      const payload = JSON.stringify({ action: "test" });

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(401);
      expect(res.body).toContain("Invalid or missing webhook signature");
    });

    it("1.3 rejects missing HMAC signature header with 401", async () => {
      const payload = JSON.stringify({ action: "test" });

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "ping",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(401);
      expect(res.body).toContain("Invalid or missing webhook signature");
    });

    it("1.4 rejects modified payload (tampered body) with 401", async () => {
      const originalPayload = JSON.stringify({ action: "test" });
      const signature = computeSignature(originalPayload, mockEnv.GITHUB_WEBHOOK_SECRET);
      const tamperedPayload = JSON.stringify({ action: "tampered" });

      const res = await handleGitHubWebhook(
        {
          rawBody: tamperedPayload,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": signature,
          },
        },
        mockEnv
      );

      expect(res.status).toBe(401);
      expect(res.body).toContain("Invalid or missing webhook signature");
    });

    it("1.5 safely handles malformed JSON body with 400", async () => {
      const malformedBody = "{ invalid_json: ";
      const signature = computeSignature(malformedBody, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: malformedBody,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": signature,
          },
        },
        mockEnv
      );

      expect(res.status).toBe(400);
      expect(res.body).toContain("Malformed JSON payload");
    });
  });

  describe("2. Persistent Webhook Delivery Deduplication", () => {
    it("2.1 processes first delivery and ignores duplicate delivery delivery_id", async () => {
      const deliveryId = "delivery-uuid-12345";
      const payload = JSON.stringify({ action: "ping" });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      // First delivery
      const res1 = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": signature,
            "x-github-delivery": deliveryId,
          },
        },
        mockEnv
      );

      expect(res1.status).toBe(200);
      const body1 = JSON.parse(res1.body!);
      expect(body1.ok).toBe(true);
      expect(body1.duplicate).toBeUndefined();

      // Second delivery with same delivery_id
      const res2 = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "ping",
            "x-hub-signature-256": signature,
            "x-github-delivery": deliveryId,
          },
        },
        mockEnv
      );

      expect(res2.status).toBe(200);
      const body2 = JSON.parse(res2.body!);
      expect(body2.ok).toBe(true);
      expect(body2.duplicate).toBe(true);
      expect(body2.deliveryId).toBe(deliveryId);
    });
  });

  describe("3. GitHub App Installation Lifecycle Events", () => {
    it("3.1 handles installation.created event", async () => {
      const payload = JSON.stringify({
        action: "created",
        installation: {
          id: 999,
          account: {
            id: 888,
            login: "org-acme",
            type: "Organization",
          },
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "installation",
            "x-hub-signature-256": signature,
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const inst = await db.getInstallationByGithubId(999);
      expect(inst).toBeDefined();
      expect(inst?.account_name).toBe("org-acme");
    });

    it("3.2 handles installation.deleted event", async () => {
      await db.upsertInstallation({
        installation_id: 999,
        target_type: "Organization",
        target_id: 888,
        account_name: "org-acme",
      });

      const payload = JSON.stringify({
        action: "deleted",
        installation: { id: 999 },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "installation",
            "x-hub-signature-256": signature,
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const inst = await db.getInstallationByGithubId(999);
      expect(inst).toBeNull();
    });
  });

  describe("4. Pull Request Webhook Events", () => {
    it("4.1 creates scan and enqueues job for PR opened action", async () => {
      const repo = await db.upsertRepository({
        installation_id: "500",
        github_repo_id: 500,
        name: "pr-repo",
        full_name: "acme/pr-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        action: "opened",
        installation: { id: 500 },
        repository: {
          id: 500,
          name: "pr-repo",
          full_name: "acme/pr-repo",
        },
        pull_request: {
          number: 42,
          head: {
            sha: "pr_head_sha_999",
            ref: "feature/security-fix",
          },
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "pull_request",
            "x-hub-signature-256": signature,
            "x-github-delivery": "pr-delivery-1",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const body = JSON.parse(res.body!);
      expect(body.ok).toBe(true);
      expect(body.queued).toBe(true);
      expect(body.prNumber).toBe(42);

      const scans = await db.getScansForRepository(repo.id);
      expect(scans.length).toBe(1);
      expect(scans[0].trigger_type).toBe("webhook_pr");
      expect(scans[0].commit_sha).toBe("pr_head_sha_999");
      expect(scans[0].branch).toBe("feature/security-fix");
    });

    it("4.2 creates scan and enqueues job for PR synchronize action", async () => {
      const repo = await db.upsertRepository({
        installation_id: "500",
        github_repo_id: 500,
        name: "pr-repo",
        full_name: "acme/pr-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        action: "synchronize",
        installation: { id: 500 },
        repository: {
          id: 500,
          name: "pr-repo",
          full_name: "acme/pr-repo",
        },
        pull_request: {
          number: 42,
          head: {
            sha: "pr_head_sha_updated_1000",
            ref: "feature/security-fix",
          },
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "pull_request",
            "x-hub-signature-256": signature,
            "x-github-delivery": "pr-delivery-2",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const body = JSON.parse(res.body!);
      expect(body.ok).toBe(true);
      expect(body.queued).toBe(true);

      const scans = await db.getScansForRepository(repo.id);
      expect(scans.length).toBe(1);
      expect(scans[0].commit_sha).toBe("pr_head_sha_updated_1000");
    });

    it("4.3 ignores PR closed action safely without creating scan", async () => {
      const repo = await db.upsertRepository({
        installation_id: "500",
        github_repo_id: 500,
        name: "pr-repo",
        full_name: "acme/pr-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        action: "closed",
        installation: { id: 500 },
        repository: {
          id: 500,
          name: "pr-repo",
          full_name: "acme/pr-repo",
        },
        pull_request: {
          number: 42,
          head: {
            sha: "pr_head_sha_999",
            ref: "feature/security-fix",
          },
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "pull_request",
            "x-hub-signature-256": signature,
            "x-github-delivery": "pr-delivery-closed",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const body = JSON.parse(res.body!);
      expect(body.ok).toBe(true);
      expect(body.ignored).toBe("pr_closed");

      const scans = await db.getScansForRepository(repo.id);
      expect(scans.length).toBe(0);
    });
  });

  describe("5. Repository & Installation Authorization Enforcement", () => {
    it("5.1 ignores webhook for unconnected repository", async () => {
      const payload = JSON.stringify({
        ref: "refs/heads/main",
        repository: {
          id: 99999,
          name: "unknown-repo",
          full_name: "acme/unknown-repo",
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

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
      expect(body.ignored).toBe("unconnected_repository");
    });

    it("5.2 ignores webhook if repository belongs to a different installation ID", async () => {
      await db.upsertRepository({
        installation_id: "100",
        github_repo_id: 600,
        name: "secure-repo",
        full_name: "acme/secure-repo",
        private: true,
        default_branch: "main",
      });

      // Payload claiming installation ID 999 (mismatch!)
      const payload = JSON.stringify({
        ref: "refs/heads/main",
        installation: { id: 999 },
        repository: {
          id: 600,
          name: "secure-repo",
          full_name: "acme/secure-repo",
        },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

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
      expect(body.ignored).toBe("unauthorized_installation");
    });
  });

  describe("6. Zero Secret Sanitization Audit", () => {
    it("6.1 ensures audit logs and scan records contain zero secret credentials", async () => {
      await db.upsertRepository({
        installation_id: "700",
        github_repo_id: 700,
        name: "audit-repo",
        full_name: "acme/audit-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        action: "opened",
        installation: { id: 700 },
        repository: { id: 700, name: "audit-repo", full_name: "acme/audit-repo" },
        pull_request: { number: 1, head: { sha: "abc", ref: "main" } },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "pull_request",
            "x-hub-signature-256": signature,
            "x-github-delivery": "delivery-audit-check",
          },
        },
        mockEnv
      );

      const logs = await db.getAuditLogs();
      const logsJson = JSON.stringify(logs);
      expect(logsJson).not.toContain(mockEnv.GITHUB_WEBHOOK_SECRET);
      expect(logsJson).not.toContain(mockEnv.GITHUB_APP_PRIVATE_KEY);
      expect(logsJson).not.toContain(mockEnv.GITHUB_CLIENT_SECRET);
    });
  });
});
