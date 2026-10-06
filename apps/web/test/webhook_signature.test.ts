import crypto from "crypto";
import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { verifyGitHubWebhookSignature } from "../src/lib/webhook-signature.js";
import { handleGitHubWebhook } from "../src/routes/webhook.js";

const TEST_ENV: WebEnv = {
  GITHUB_CLIENT_ID: "fake_client_id_123",
  GITHUB_CLIENT_SECRET: "fake_client_secret_abc",
  GITHUB_APP_ID: "99999",
  GITHUB_APP_PRIVATE_KEY: "fake_private_key",
  GITHUB_WEBHOOK_SECRET: "my_super_secret_webhook_key_12345",
  SESSION_SECRET: "super_secret_32_characters_key_here",
  DATABASE_URL: "postgresql://localhost:5432/test",
  NODE_ENV: "test",
};

function signPayload(body: string, secret: string): string {
  const hmac = crypto.createHmac("sha256", secret).update(body).digest("hex");
  return `sha256=${hmac}`;
}

describe("GitHub Webhook HMAC Signature Verification (apps/web)", () => {
  beforeEach(() => {
    db.resetInMemoryData();
  });

  it("should verify valid HMAC-SHA256 signatures and reject invalid ones", () => {
    const body = JSON.stringify({ action: "test" });
    const validSig = signPayload(body, TEST_ENV.GITHUB_WEBHOOK_SECRET);
    const badSig =
      "sha256=invalid_hmac_hex_digest_9999999999999999999999999999999999999999999999999999999999999999";

    expect(verifyGitHubWebhookSignature(body, validSig, TEST_ENV.GITHUB_WEBHOOK_SECRET)).toBe(true);
    expect(verifyGitHubWebhookSignature(body, badSig, TEST_ENV.GITHUB_WEBHOOK_SECRET)).toBe(false);
    expect(verifyGitHubWebhookSignature(body, null, TEST_ENV.GITHUB_WEBHOOK_SECRET)).toBe(false);
  });

  it("should reject webhook request with HTTP 401 when signature is bad or missing", async () => {
    const rawBody = JSON.stringify({ action: "created", installation: { id: 100 } });

    // Missing signature header
    const resNoSig = await handleGitHubWebhook({ rawBody, headers: {} }, TEST_ENV);
    expect(resNoSig.status).toBe(401);
    expect(resNoSig.body).toContain("Invalid or missing webhook signature");

    // Invalid signature header
    const resBadSig = await handleGitHubWebhook(
      {
        rawBody,
        headers: {
          "x-hub-signature-256":
            "sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
      },
      TEST_ENV
    );
    expect(resBadSig.status).toBe(401);
    expect(resBadSig.body).toContain("Invalid or missing webhook signature");

    const logs = await db.getAuditLogs();
    expect(logs.some((l) => l.action === "webhook.rejected_bad_signature")).toBe(true);
  });

  it("should process installation created and deleted events when HMAC signature is valid", async () => {
    // 1. Process installation.created
    const createPayload = JSON.stringify({
      action: "created",
      installation: {
        id: 777,
        account: { id: 888, login: "test-org", type: "Organization" },
      },
    });
    const validCreateSig = signPayload(createPayload, TEST_ENV.GITHUB_WEBHOOK_SECRET);

    const resCreate = await handleGitHubWebhook(
      {
        rawBody: createPayload,
        headers: {
          "x-hub-signature-256": validCreateSig,
          "x-github-event": "installation",
        },
      },
      TEST_ENV
    );

    expect(resCreate.status).toBe(200);

    const inst = await db.getInstallationByGithubId(777);
    expect(inst).not.toBeNull();
    expect(inst?.account_name).toBe("test-org");
    expect(inst?.target_type).toBe("Organization");

    // 2. Process installation.deleted
    const deletePayload = JSON.stringify({
      action: "deleted",
      installation: { id: 777 },
    });
    const validDeleteSig = signPayload(deletePayload, TEST_ENV.GITHUB_WEBHOOK_SECRET);

    const resDelete = await handleGitHubWebhook(
      {
        rawBody: deletePayload,
        headers: {
          "x-hub-signature-256": validDeleteSig,
          "x-github-event": "installation",
        },
      },
      TEST_ENV
    );

    expect(resDelete.status).toBe(200);

    const instAfterDelete = await db.getInstallationByGithubId(777);
    expect(instAfterDelete).toBeNull();
  });
});
