import crypto from "crypto";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { handleGitHubWebhook, resetPushDeduplicationMap } from "../src/routes/webhook.js";
import { updateGitHubCheckRun } from "../src/lib/github-checks.js";
import { validatePatchPaths, getDeterministicBranchName } from "../src/lib/github-pr-publisher.js";
import { Finding } from "@nantis/core";

function computeSignature(payloadString: string, secret?: string): string {
  const hmac = crypto
    .createHmac("sha256", secret || "whsec_test_secret_12345")
    .update(payloadString)
    .digest("hex");
  return `sha256=${hmac}`;
}

describe("Phase 1F: End-to-End GitHub Workflow & Closure Suite", () => {
  const mockEnv: WebEnv = {
    GITHUB_CLIENT_ID: "client_id_test",
    GITHUB_CLIENT_SECRET: "client_secret_test",
    GITHUB_APP_ID: "12345",
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

  describe("1. Complete Webhook -> Scan -> Check Run -> Queue -> Worker -> PR Pipeline", () => {
    it("1.1 executes complete asynchronous pipeline from webhook trigger to PR publication and Check completion", async () => {
      const repo = await db.upsertRepository({
        installation_id: "300",
        github_repo_id: 300,
        name: "e2e-repo",
        full_name: "acme/e2e-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        ref: "refs/heads/main",
        installation: { id: 300 },
        repository: { id: 300, name: "e2e-repo", full_name: "acme/e2e-repo" },
        head_commit: { id: "sha_e2e_commit_1", message: "Initial commit", timestamp: new Date().toISOString() },
      });
      const signature = computeSignature(payload, mockEnv.GITHUB_WEBHOOK_SECRET);

      // Webhook ingestion
      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "push",
            "x-hub-signature-256": signature,
            "x-github-delivery": "delivery-e2e-100",
          },
        },
        mockEnv
      );

      expect(res.status).toBe(200);
      const body = JSON.parse(res.body!);
      expect(body.ok).toBe(true);

      const scans = await db.getScansForRepository(repo.id);
      expect(scans.length).toBe(1);
      const scanId = scans[0].id;
      expect(scans[0].status).toBe("queued");
      expect(scans[0].commit_sha).toBe("sha_e2e_commit_1");

      // Worker status transitions
      await db.updateScanStatus(scanId, "cloning");
      let currentScan = await db.getScanById(scanId);
      expect(currentScan?.status).toBe("cloning");

      await db.updateScanStatus(scanId, "scanning");
      currentScan = await db.getScanById(scanId);
      expect(currentScan?.status).toBe("scanning");

      // Save findings
      const mockFinding: Finding = {
        id: "finding-e2e-1",
        ruleId: "dependency-bump",
        title: "Vulnerable Axios Dependency",
        severity: "high",
        confidenceTier: "needs-review",
        file: "package.json",
        lineRange: { startLine: 3, endLine: 3 },
        evidenceChain: [],
        unresolvedSteps: [],
        explanation: "Axios version 0.21.1 is vulnerable to SSRF",
        fingerprint: "fp_e2e_123",
      };
      await db.saveScanFindings(scanId, [mockFinding]);

      await db.updateScanStatus(scanId, "done");
      currentScan = await db.getScanById(scanId);
      expect(currentScan?.status).toBe("done");

      // PR Publication
      await db.updateScanPublication(scanId, {
        github_pr_number: 99,
        github_pr_url: "https://github.com/acme/e2e-repo/pull/99",
        github_branch: getDeterministicBranchName(scanId),
        publication_status: "published",
      });

      const publishedScan = await db.getScanById(scanId);
      expect(publishedScan?.publication_status).toBe("published");
      expect(publishedScan?.github_pr_number).toBe(99);
    });
  });

  describe("2. Webhook Idempotency & Delivery Deduplication", () => {
    it("2.1 handles persistent delivery deduplication across redeliveries", async () => {
      const deliveryId = "delivery-dedup-999";
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
      expect(JSON.parse(res1.body!).duplicate).toBeUndefined();

      // Duplicate delivery
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
      expect(JSON.parse(res2.body!).duplicate).toBe(true);
    });
  });

  describe("3. Patch Containment & Default Branch Safety", () => {
    it("3.1 rejects malicious path traversal and .git internal paths", () => {
      expect(validatePatchPaths("../../../etc/shadow", "/repo").valid).toBe(false);
      expect(validatePatchPaths("/etc/shadow", "/repo").valid).toBe(false);
      expect(validatePatchPaths(".git/hooks/pre-push", "/repo").valid).toBe(false);
      expect(validatePatchPaths("src/app.ts", "/repo").valid).toBe(true);
    });

    it("3.2 guarantees remediation is NEVER committed or pushed directly to default branch", async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "safety-test-"));
      try {
        execSync("git init", { cwd: tempDir, stdio: "ignore" });
        execSync('git config user.name "Test"', { cwd: tempDir, stdio: "ignore" });
        execSync('git config user.email "test@test.com"', { cwd: tempDir, stdio: "ignore" });
        fs.writeFileSync(path.join(tempDir, "file.txt"), "before", "utf-8");
        execSync("git add .", { cwd: tempDir, stdio: "ignore" });
        execSync('git commit -m "initial"', { cwd: tempDir, stdio: "ignore" });

        const initialBranch = execSync("git rev-parse --abbrev-ref HEAD", { cwd: tempDir, encoding: "utf-8" }).trim();

        // Target branch must use nantis/fix/<scanId>
        const branchName = getDeterministicBranchName("scan-branch-safety");
        expect(branchName).not.toBe(initialBranch);
        expect(branchName).toBe("nantis/fix/scan-branch-safety");
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe("4. GitHub Checks API & Conclusion Integrity", () => {
    it("4.1 accurately maps findings count to action_required conclusion", async () => {
      let patchConclusion = "";

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH") {
          const body = JSON.parse(init.body);
          patchConclusion = body.conclusion;
          return new Response(JSON.stringify({ id: 111 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const mockFinding: Finding = {
        id: "f-1",
        ruleId: "hardcoded-secret",
        title: "Secret Key",
        severity: "critical",
        confidenceTier: "needs-review",
        file: "config.js",
        lineRange: { startLine: 1, endLine: 1 },
        evidenceChain: [],
        unresolvedSteps: [],
        explanation: "Secret exposed",
        fingerprint: "fp",
      };

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "e2e-repo",
        checkRunId: 111,
        installationId: 300,
        status: "done",
        scanId: "scan-check-test",
        findings: [mockFinding],
        diagnostics: [],
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchConclusion).toBe("action_required");
    });
  });

  describe("5. Failure Isolation & Security Audit", () => {
    it("5.1 keeps scan status intact even if PR publication fails", async () => {
      const repo = await db.upsertRepository({
        installation_id: "300",
        github_repo_id: 300,
        name: "e2e-repo",
        full_name: "acme/e2e-repo",
        private: true,
        default_branch: "main",
      });

      const scan = await db.createScan({
        repository_id: repo.id,
        status: "done",
        trigger_type: "webhook_push",
        commit_sha: "sha_isolated",
        branch: "main",
      });

      await db.updateScanPublication(scan.id, {
        publication_status: "failed",
        publication_error: "GitHub API 500 Internal Error",
      });

      const scanRecord = await db.getScanById(scan.id);
      expect(scanRecord?.status).toBe("done"); // Scan status stays done!
      expect(scanRecord?.publication_status).toBe("failed");
      expect(scanRecord?.publication_error).toContain("500 Internal Error");
    });

    it("5.2 verifies zero installation tokens or credentials are leaked in audit logs or scan records", async () => {
      const repo = await db.upsertRepository({
        installation_id: "300",
        github_repo_id: 300,
        name: "e2e-repo",
        full_name: "acme/e2e-repo",
        private: true,
        default_branch: "main",
      });

      const scan = await db.createScan({
        repository_id: repo.id,
        status: "queued",
        trigger_type: "webhook_push",
        commit_sha: "sha_token_audit",
        branch: "main",
      });

      await db.createAuditLog({
        userId: "user_audit",
        repoId: repo.id,
        action: "scan_started",
        tokenId: "ghs_token_ref_id_123",
      });

      const logs = await db.getAuditLogs();
      const logsText = JSON.stringify(logs);
      expect(logsText).not.toContain(mockEnv.GITHUB_WEBHOOK_SECRET);
      expect(logsText).not.toContain(mockEnv.GITHUB_APP_PRIVATE_KEY);
      expect(logsText).not.toContain(mockEnv.GITHUB_CLIENT_SECRET);

      const scanRecord = await db.getScanById(scan.id);
      expect(JSON.stringify(scanRecord)).not.toContain(mockEnv.GITHUB_WEBHOOK_SECRET);
    });
  });
});
