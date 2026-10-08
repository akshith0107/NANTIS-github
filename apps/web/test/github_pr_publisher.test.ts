import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { db } from "../src/db/client.js";
import { WebEnv } from "../src/lib/env.js";
import {
  publishRemediationPR,
  validatePatchPaths,
  getDeterministicBranchName,
} from "../src/lib/github-pr-publisher.js";
import { Finding } from "@nantis/core";

describe("Phase 1E: PR Findings Annotation & Publisher Suite", () => {
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
  });

  describe("1. Branch Name Sanitization & Deterministic Naming", () => {
    it("1.1 generates clean deterministic branch names", () => {
      const branch1 = getDeterministicBranchName("scan-123-abc");
      expect(branch1).toBe("nantis/fix/scan-123-abc");
    });

    it("1.2 strips malicious control characters or path elements from branch names", () => {
      const branch2 = getDeterministicBranchName("../../../bad;branch\n$VAR");
      expect(branch2).toBe("nantis/fix/badbranchVAR");
      expect(branch2).not.toContain("..");
      expect(branch2).not.toContain("\n");
      expect(branch2).not.toContain("$");
    });
  });

  describe("2. Patch Safety & Worktree Containment", () => {
    it("2.1 rejects path traversal attempts (../outside)", () => {
      const check = validatePatchPaths("../../../etc/passwd", "/repo/workspace");
      expect(check.valid).toBe(false);
      expect(check.reason).toContain("Path traversal rejected");
    });

    it("2.2 rejects absolute path attempts (/absolute/path)", () => {
      const check = validatePatchPaths("/var/log/syslog", "/repo/workspace");
      expect(check.valid).toBe(false);
      expect(check.reason).toContain("Path traversal rejected");
    });

    it("2.3 rejects access to .git directory or internals", () => {
      const check1 = validatePatchPaths(".git/config", "/repo/workspace");
      expect(check1.valid).toBe(false);

      const check2 = validatePatchPaths("subfolder/.git/hooks/pre-commit", "/repo/workspace");
      expect(check2.valid).toBe(false);
    });

    it("2.4 accepts safe relative workspace file paths", () => {
      const check = validatePatchPaths("src/app/api/route.ts", "/repo/workspace");
      expect(check.valid).toBe(true);
    });
  });

  describe("3. PR Publisher Execution & Idempotency", () => {
    it("3.1 reuses existing PR if PR already exists on GitHub for the branch (Idempotency)", async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pub-test-idempotent-"));
      try {
        const mockFetch = vi.fn().mockImplementation(async (url) => {
          if (url.includes("/access_tokens")) {
            return new Response(
              JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }),
              { status: 200 }
            );
          }
          if (url.includes("/pulls?head=")) {
            return new Response(
              JSON.stringify([{ number: 77, html_url: "https://github.com/acme/demo-repo/pull/77" }]),
              { status: 200 }
            );
          }
          return new Response("{}", { status: 200 });
        });

        const res = await publishRemediationPR({
          repoPath: tempDir,
          repoFullName: "acme/demo-repo",
          defaultBranch: "main",
          scanId: "scan-id-existing-123",
          installationId: 100,
          findings: [],
          remediationEdits: [{ targetFile: "package.json", targetContent: "a", replacementContent: "b" }],
          env: mockEnv,
          fetchFn: mockFetch as unknown as typeof fetch,
        });

        expect(res.success).toBe(true);
        expect(res.prNumber).toBe(77);
        expect(res.prUrl).toContain("/pull/77");
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it("3.2 isolates failure and does NOT crash or alter scan state if GitHub REST API returns HTTP error", async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pub-test-fail-"));
      try {
        execSync("git init", { cwd: tempDir, stdio: "ignore" });
        execSync('git config user.name "Test"', { cwd: tempDir, stdio: "ignore" });
        execSync('git config user.email "test@test.com"', { cwd: tempDir, stdio: "ignore" });
        fs.writeFileSync(path.join(tempDir, "package.json"), '{\n  "dependencies": {\n    "axios": "0.21.1"\n  }\n}', "utf-8");
        execSync("git add .", { cwd: tempDir, stdio: "ignore" });
        execSync('git commit -m "initial"', { cwd: tempDir, stdio: "ignore" });

        const mockFetch = vi.fn().mockImplementation(async (url) => {
          if (url.includes("/access_tokens")) {
            return new Response(
              JSON.stringify({ token: "ghs_mock_token", expires_at: new Date(Date.now() + 3600000).toISOString() }),
              { status: 200 }
            );
          }
          if (url.includes("/pulls")) {
            return new Response("Internal Error", { status: 500 });
          }
          return new Response("[]", { status: 200 });
        });

        const mockFinding: Finding = {
          id: "f-1",
          ruleId: "dependency-bump",
          title: "Outdated Dependency",
          severity: "high",
          confidenceTier: "needs-review",
          file: "package.json",
          lineRange: { startLine: 3, endLine: 3 },
          evidenceChain: [],
          unresolvedSteps: [],
          explanation: "Axios vulnerable",
          fingerprint: "fp123",
        };

        const res = await publishRemediationPR({
          repoPath: tempDir,
          repoFullName: "acme/demo-repo",
          defaultBranch: "main",
          scanId: "scan-id-api-fail",
          installationId: 100,
          findings: [mockFinding],
          remediationEdits: [{ targetFile: "package.json", targetContent: '"axios": "0.21.1"', replacementContent: '"axios": "^1.7.4"' }],
          env: mockEnv,
          fetchFn: mockFetch as unknown as typeof fetch,
        });

        expect(res.success).toBe(false);
        expect(res.error).toBeDefined();
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe("4. Database & Scan Publication Model", () => {
    it("4.1 updates scan publication fields idempotently in database client", async () => {
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
        status: "done",
        trigger_type: "webhook_pr",
        commit_sha: "sha123",
        branch: "main",
      });

      await db.updateScanPublication(scan.id, {
        github_pr_number: 42,
        github_pr_url: "https://github.com/acme/demo-repo/pull/42",
        github_branch: "nantis/fix/scan123",
        publication_status: "published",
      });

      const updated = await db.getScanById(scan.id);
      expect(updated?.github_pr_number).toBe(42);
      expect(updated?.github_pr_url).toBe("https://github.com/acme/demo-repo/pull/42");
      expect(updated?.publication_status).toBe("published");
    });
  });
});
