import fs from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import {
  InMemoryDbAdapter,
  processScanJob,
  sanitizeUserFacingErrorMessage,
  ScanJobQueue,
} from "../src/index.js";

describe("Scan Job Queue & Worker Ephemeral Sandbox (packages/worker)", () => {
  it("TEST 1: Job Timeout — Job running longer than maxJobTimeMs times out and transitions to failed status", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const scanId = "test_scan_timeout_1001";
    const jobTempDir = path.resolve(process.cwd(), "temp/scans", scanId);

    const payload = {
      scanId,
      repoId: "repo_101",
      installationId: 501,
      requestedByUserId: "user_777",
    };

    // Simulate a slow clone/fetcher that exceeds 100ms maxJobTimeMs
    const slowFetcher = async () => {
      await new Promise((resolve) => setTimeout(resolve, 500));
    };

    const { state } = await processScanJob(payload, dbAdapter, { maxJobTimeMs: 100 }, slowFetcher);

    expect(state.status).toBe("failed");
    expect(state.errorMessage).toBe("Scan job timed out prior to completion");

    const statusInDb = await dbAdapter.getScanStatus(scanId);
    expect(statusInDb.status).toBe("failed");
    expect(statusInDb.errorMessage).toBe("Scan job timed out prior to completion");

    // CRITICAL: Cleanup check
    expect(fs.existsSync(jobTempDir)).toBe(false);
  });

  it("TEST 2: Retry with Backoff — Transient errors trigger retries up to maxRetries", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const queue = new ScanJobQueue(dbAdapter, {
      maxRetries: 2,
      retryBackoffSeconds: 0.01, // 10ms backoff for fast unit test execution
    });

    const scanId = "test_scan_retry_2002";
    let attempts = 0;

    const failingFetcher = async (targetDir: string) => {
      attempts++;
      if (attempts <= 2) {
        throw new Error("Transient network error during clone");
      }
      fs.writeFileSync(path.join(targetDir, "index.ts"), "export const a = 1;");
    };

    await queue.enqueueJob(
      {
        scanId,
        repoId: "repo_202",
        installationId: 502,
        requestedByUserId: "user_888",
      },
      {},
      failingFetcher
    );

    // Wait deterministically for queue processing and retries to complete
    await queue.waitForJobCompletion(scanId, 2000);

    expect(attempts).toBe(3); // 1 initial + 2 retries
    const finalStatus = await dbAdapter.getScanStatus(scanId);
    expect(finalStatus.status).toBe("done");
  });

  it("TEST 3: Failed Job Leaves No Leftover Files — Failed jobs recursively delete temporary sandbox", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const scanId = "test_scan_cleanup_3003";
    const jobTempDir = path.resolve(process.cwd(), "temp/scans", scanId);

    const payload = {
      scanId,
      repoId: "repo_303",
      installationId: 503,
      requestedByUserId: "user_999",
    };

    // Fetcher that creates files then throws an error
    const faultyFetcher = async (targetDir: string) => {
      fs.writeFileSync(path.join(targetDir, "secret_leaked_file.txt"), "fake_content_secret");
      throw new Error("Fatal build or parse error inside container");
    };

    const { state } = await processScanJob(payload, dbAdapter, {}, faultyFetcher);

    expect(state.status).toBe("failed");

    // CRITICAL: Verify NO leftover files exist on disk
    expect(fs.existsSync(jobTempDir)).toBe(false);
  });

  it("TEST 4: User-Facing Error Sanitization — Stack traces and internal secrets are NEVER leaked", () => {
    const rawErrorWithStackTrace = new Error(
      "Uncaught Error: at /var/internal/worker/node_modules/git/index.js:142\n    at Object.clone (internal.js:12)\n    Secret: sk_test_FAKE_SECRET_123"
    );

    const sanitizedMsg = sanitizeUserFacingErrorMessage(rawErrorWithStackTrace);

    expect(sanitizedMsg).toBe("Scan execution encountered an unexpected error");
    expect(sanitizedMsg).not.toContain("stack");
    expect(sanitizedMsg).not.toContain("node_modules");
    expect(sanitizedMsg).not.toContain("sk_test_");
  });

  it("TEST 5: Worker OSV Mode — Worker path executes with offlineMode: false and handles OSV lookup failure with 'dependency check incomplete'", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const scanId = "test_scan_osv_5005";

    const payload = {
      scanId,
      repoId: "repo_505",
      installationId: 505,
      requestedByUserId: "user_505",
    };

    // Fetcher that writes package.json & package-lock.json with an unresolvable package
    const customFetcher = async (targetDir: string) => {
      fs.writeFileSync(
        path.join(targetDir, "package.json"),
        JSON.stringify({ dependencies: { "non-existent-pkg-nantis-test": "1.0.0" } })
      );
      fs.writeFileSync(
        path.join(targetDir, "package-lock.json"),
        JSON.stringify({ packages: { "node_modules/non-existent-pkg-nantis-test": { version: "1.0.0" } } })
      );
    };

    const { state, findings } = await processScanJob(payload, dbAdapter, {}, customFetcher);

    expect(state.status).toBe("done");
    // Verify OSV lookup ran online and generated finding (either vulnerable or dependency-data-unavailable fallback)
    const osvFinding = findings.find(
      (f) => f.ruleId === "dependency-data-unavailable" || f.ruleId === "vulnerable-dependency"
    );
    expect(osvFinding).toBeDefined();
    if (osvFinding?.ruleId === "dependency-data-unavailable") {
      expect(osvFinding.explanation).toContain("dependency check incomplete");
    }
  });
});
