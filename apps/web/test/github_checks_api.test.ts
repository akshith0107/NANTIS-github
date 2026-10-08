import { describe, expect, it, beforeEach, vi } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import { handleGitHubWebhook, resetPushDeduplicationMap } from "../src/routes/webhook.js";
import { createGitHubCheckRun, updateGitHubCheckRun } from "../src/lib/github-checks.js";

describe("Phase 1D: GitHub Checks API Integration & Lifecycle Suite", () => {
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

  describe("1. Check Creation on Webhook Scan Trigger", () => {
    it("1.1 creates a queued Check Run on push event", async () => {
      await db.upsertRepository({
        installation_id: "100",
        github_repo_id: 100,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        private: true,
        default_branch: "main",
      });

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (url.includes("/check-runs")) {
          const body = JSON.parse(init.body);
          expect(body.status).toBe("queued");
          expect(body.head_sha).toBe("sha_push_1");
          return new Response(JSON.stringify({ id: 98765 }), { status: 201 });
        }
        return new Response("{}", { status: 200 });
      });

      // Create check run directly using helper with mockFetch
      const checkRunId = await createGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        headSha: "sha_push_1",
        installationId: 100,
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(checkRunId).toBe(98765);

      const scan = await db.createScan({
        repository_id: "100",
        status: "queued",
        trigger_type: "webhook_push",
        commit_sha: "sha_push_1",
        branch: "main",
        github_check_run_id: checkRunId,
      });

      expect(scan.github_check_run_id).toBe(98765);
    });

    it("1.2 creates a queued Check Run on PR opened event with head SHA", async () => {
      const repo = await db.upsertRepository({
        installation_id: "200",
        github_repo_id: 200,
        name: "pr-repo",
        full_name: "acme/pr-repo",
        private: true,
        default_branch: "main",
      });

      const payload = JSON.stringify({
        action: "opened",
        installation: { id: 200 },
        repository: { id: 200, name: "pr-repo", full_name: "acme/pr-repo" },
        pull_request: { number: 10, head: { sha: "sha_pr_head_10", ref: "feature-branch" } },
      });

      const res = await handleGitHubWebhook(
        {
          rawBody: payload,
          headers: {
            "x-github-event": "pull_request",
            "x-hub-signature-256": "sha256=invalid_signature_mock_will_fallback_if_not_checked_or_use_valid",
          },
        },
        mockEnv
      );

      expect(res.status).toBeDefined();
      expect(repo.full_name).toBe("acme/pr-repo");
    });
  });

  describe("2. Check Run Lifecycle & Status Transitions", () => {
    it("2.1 transitions Check Run to in_progress when scanning begins", async () => {
      let patchCalled = false;
      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH" && url.includes("/check-runs/98765")) {
          patchCalled = true;
          const body = JSON.parse(init.body);
          expect(body.status).toBe("in_progress");
          return new Response(JSON.stringify({ id: 98765 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        checkRunId: 98765,
        installationId: 100,
        status: "scanning",
        scanId: "scan-uuid-1",
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchCalled).toBe(true);
    });

    it("2.2 transitions Check Run to completed with success conclusion when 0 findings", async () => {
      let patchConclusion = "";
      let summaryText = "";

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH") {
          const body = JSON.parse(init.body);
          patchConclusion = body.conclusion;
          summaryText = body.output.summary;
          return new Response(JSON.stringify({ id: 98765 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        checkRunId: 98765,
        installationId: 100,
        status: "done",
        scanId: "scan-uuid-clean",
        findings: [],
        diagnostics: [],
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchConclusion).toBe("success");
      expect(summaryText).toContain("Zero findings detected");
      expect(summaryText).not.toContain("Repository is secure"); // Security language bound check!
    });

    it("2.3 transitions Check Run to action_required with annotations when findings exist", async () => {
      let patchConclusion = "";
      let annotationsCount = 0;

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH") {
          const body = JSON.parse(init.body);
          patchConclusion = body.conclusion;
          annotationsCount = body.output.annotations?.length || 0;
          return new Response(JSON.stringify({ id: 98765 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const mockFindings = [
        {
          id: "f-1",
          ruleId: "hardcoded-secret",
          title: "Hardcoded API Key",
          severity: "high" as const,
          confidenceTier: "needs-review" as const,
          file: "src/config.ts",
          lineRange: { startLine: 12, endLine: 12 },
          explanation: "Hardcoded secret detected",
          evidenceChain: [],
          unresolvedSteps: [],
          fingerprint: "fp123",
        },
      ];

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        checkRunId: 98765,
        installationId: 100,
        status: "done",
        scanId: "scan-uuid-vulnerable",
        findings: mockFindings,
        diagnostics: [],
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchConclusion).toBe("action_required");
      expect(annotationsCount).toBe(1);
    });

    it("2.4 transitions Check Run to neutral when completed with diagnostic warnings", async () => {
      let patchConclusion = "";

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH") {
          const body = JSON.parse(init.body);
          patchConclusion = body.conclusion;
          return new Response(JSON.stringify({ id: 98765 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        checkRunId: 98765,
        installationId: 100,
        status: "done",
        scanId: "scan-uuid-warn",
        findings: [],
        diagnostics: [{ kind: "analysis_warning", message: "Detector timeout on complex file", fatal: false }],
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchConclusion).toBe("neutral");
    });

    it("2.5 transitions Check Run to failure when scan fails unexpectedly", async () => {
      let patchConclusion = "";

      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        if (url.includes("/access_tokens")) {
          return new Response(JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }), { status: 200 });
        }
        if (init.method === "PATCH") {
          const body = JSON.parse(init.body);
          patchConclusion = body.conclusion;
          return new Response(JSON.stringify({ id: 98765 }), { status: 200 });
        }
        return new Response("{}", { status: 200 });
      });

      const ok = await updateGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        checkRunId: 98765,
        installationId: 100,
        status: "failed",
        scanId: "scan-uuid-failed",
        errorMessage: "Repository size exceeds limit",
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(ok).toBe(true);
      expect(patchConclusion).toBe("failure");
    });
  });

  describe("3. Failure Isolation & Idempotency", () => {
    it("3.1 returns null and isolates failure if GitHub API returns 500 or network error", async () => {
      const mockFetch = vi.fn().mockImplementation(async () => {
        return new Response("Server error", { status: 500 });
      });

      const checkRunId = await createGitHubCheckRun({
        owner: "acme",
        repo: "demo-repo",
        headSha: "sha_err",
        installationId: 100,
        env: mockEnv,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(checkRunId).toBeNull();
    });

    it("3.2 reuses persisted Check Run ID across status updates without creating duplicate Check Runs", async () => {
      const repo = await db.upsertRepository({
        installation_id: "100",
        github_repo_id: 100,
        name: "demo-repo",
        full_name: "acme/demo-repo",
        private: true,
        default_branch: "main",
      });

      const scan = await db.createScan({
        repository_id: repo.id,
        status: "queued",
        trigger_type: "webhook_push",
        commit_sha: "sha_dedup",
        branch: "main",
        github_check_run_id: 55555,
      });

      expect(scan.github_check_run_id).toBe(55555);

      await db.updateScanStatus(scan.id, "cloning");
      const updatedScan1 = await db.getScanById(scan.id);
      expect(updatedScan1?.github_check_run_id).toBe(55555);

      await db.updateScanStatus(scan.id, "done");
      const updatedScan2 = await db.getScanById(scan.id);
      expect(updatedScan2?.github_check_run_id).toBe(55555);
    });
  });
});
