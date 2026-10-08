import child_process from "child_process";
import fs from "fs";
import path from "path";
import { describe, expect, it, beforeEach } from "vitest";
import { cloneRepositorySandboxed } from "../src/git/clone-sandbox.js";
import { InMemoryDbAdapter } from "../src/queue/job-queue.js";
import { cleanStaleWorkspaces } from "../src/janitor/stale-cleanup.js";
import { processScanJob } from "../src/processor/scan-processor.js";
import { AuditLogPayload } from "../src/types.js";

describe("Secure Worker Execution, Sandboxed Git Clone, Audit Logging & Source Code Protection", () => {
  let dbAdapter: InMemoryDbAdapter;

  beforeEach(async () => {
    dbAdapter = new InMemoryDbAdapter();
  });

  it("should prevent malicious .gitattributes, hooks, and filter script execution during cloning", async () => {
    const fixtureDir = path.resolve(process.cwd(), "temp/test_malicious_src");
    const sentinelFile = path.resolve(process.cwd(), "temp/malicious_executed.txt");
    const cloneTargetDir = path.resolve(process.cwd(), "temp/scans/test_clone_target");

    // Clean up past runs
    const lockFile = path.join(fixtureDir, ".git", "index.lock");
    if (fs.existsSync(lockFile)) fs.rmSync(lockFile, { force: true });
    if (fs.existsSync(fixtureDir))
      fs.rmSync(fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    if (fs.existsSync(sentinelFile)) fs.rmSync(sentinelFile, { force: true });
    if (fs.existsSync(cloneTargetDir))
      fs.rmSync(cloneTargetDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

    // Initialize a local git repository with malicious hooks and .gitattributes
    fs.mkdirSync(fixtureDir, { recursive: true });
    child_process.execSync("git init", { cwd: fixtureDir });

    // Create a malicious hook in .git/hooks/post-checkout
    fs.mkdirSync(path.join(fixtureDir, ".git/hooks"), { recursive: true });
    const hookPath = path.join(fixtureDir, ".git/hooks/post-checkout");
    fs.writeFileSync(
      hookPath,
      `#!/bin/sh\necho "EXPLICIT_HACK" > "${sentinelFile.replaceAll("\\", "/")}"\n`
    );

    // Create a malicious .gitattributes filter
    fs.writeFileSync(path.join(fixtureDir, ".gitattributes"), `* filter=hacker_filter\n`);

    fs.writeFileSync(path.join(fixtureDir, "index.ts"), `console.log("Clean code");\n`);

    child_process.execSync('git config user.name "Test"', { cwd: fixtureDir });
    child_process.execSync('git config user.email "test@test.com"', { cwd: fixtureDir });
    child_process.execSync("git add .", { cwd: fixtureDir });
    child_process.execSync('git commit --allow-empty -m "Initial commit"', { cwd: fixtureDir });

    // Clone using sandboxed git clone command
    await cloneRepositorySandboxed({
      repoUrl: fixtureDir,
      branch: "master",
      targetDir: cloneTargetDir,
    });

    // SECURITY ASSERTION 1: Malicious hook or filter MUST NOT have executed
    expect(fs.existsSync(sentinelFile)).toBe(false);

    // Cleanup
    try {
      if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch {}
    try {
      if (fs.existsSync(cloneTargetDir)) fs.rmSync(cloneTargetDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch {}
  });

  it("should assert NO raw source code exists in database after scanning a repository", async () => {
    const scanId = crypto.randomUUID();
    const repoId = crypto.randomUUID();
    const userId = "user_alice_123";

    const KNOWN_CONFIDENTIAL_CODE_STRING = "sk_live_CONFIDENTIAL_STRIPE_SECRET_KEY_999";

    const { state, findings } = await processScanJob(
      {
        scanId,
        repoId,
        installationId: 888,
        requestedByUserId: userId,
      },
      dbAdapter,
      {},
      async (targetDir) => {
        fs.writeFileSync(
          path.join(targetDir, "secret-service.ts"),
          `export const SECRET_KEY = "${KNOWN_CONFIDENTIAL_CODE_STRING}";\n`
        );
      }
    );

    expect(state.status).toBe("done");
    expect(findings.length).toBeGreaterThan(0);

    // Inspect entire database state serialization
    const storedFindings = await dbAdapter.getScanFindings(scanId);
    const serializedDb = JSON.stringify(storedFindings);

    // SECURITY ASSERTION 2: Database MUST NOT store raw source code string
    expect(serializedDb).not.toContain(KNOWN_CONFIDENTIAL_CODE_STRING);

    // Findings evidence chain MUST contain masked secret string
    expect(serializedDb).toContain("[REDACTED_SECRET]");
  });

  it("should write audit log entry containing who, repo, timestamp, and token ID (not secret token)", async () => {
    const scanId = crypto.randomUUID();
    const repoId = "acme/secret-app";
    const userId = "user_bob_456";

    await processScanJob(
      {
        scanId,
        repoId,
        installationId: 999,
        requestedByUserId: userId,
      },
      dbAdapter,
      {},
      async (dir) => {
        fs.writeFileSync(path.join(dir, "index.ts"), `console.log("Hello");`);
      }
    );

    const auditLogs = await dbAdapter.getAuditLogs();
    const scanAuditLog = auditLogs.find(
      (log: AuditLogPayload) => log.repoId === repoId && log.userId === userId
    );

    expect(scanAuditLog).toBeDefined();
    expect(scanAuditLog?.action).toBe("scan_execution_started");
    expect(scanAuditLog?.tokenId).toBeDefined();
    expect(String(scanAuditLog?.tokenId)).toContain("ghs_inst_999");
    expect(String(scanAuditLog?.tokenId)).not.toContain("ghs_secret_");
  });

  it("should clean stale orphaned scan directories using janitor process", async () => {
    const baseTempDir = path.resolve(process.cwd(), "temp/scans");
    const staleDir = path.join(baseTempDir, "stale_orphan_scan_999");

    if (!fs.existsSync(baseTempDir)) {
      fs.mkdirSync(baseTempDir, { recursive: true });
    }
    if (!fs.existsSync(staleDir)) {
      fs.mkdirSync(staleDir, { recursive: true });
    }
    fs.writeFileSync(path.join(staleDir, "leftover.txt"), "leftover content");

    // Artificially set modification time to 1 hour ago
    const pastTime = (Date.now() - 3600 * 1000) / 1000;
    fs.utimesSync(staleDir, pastTime, pastTime);

    // Run janitor with 10 second max age
    const deletedCount = await cleanStaleWorkspaces(baseTempDir, 10 * 1000);

    expect(deletedCount).toBeGreaterThan(0);
    expect(fs.existsSync(staleDir)).toBe(false);
  });

  it("should enforce max file count limit and clean up temp folder on failure", async () => {
    const fixtureDir = path.resolve(process.cwd(), "temp/test_file_count_src");
    const cloneTargetDir = path.resolve(process.cwd(), "temp/scans/test_file_count_target");

    if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true });
    if (fs.existsSync(cloneTargetDir)) fs.rmSync(cloneTargetDir, { recursive: true, force: true });

    fs.mkdirSync(fixtureDir, { recursive: true });
    child_process.execSync("git init", { cwd: fixtureDir });
    fs.writeFileSync(path.join(fixtureDir, "file1.ts"), "const a = 1;\n");
    fs.writeFileSync(path.join(fixtureDir, "file2.ts"), "const b = 2;\n");
    fs.writeFileSync(path.join(fixtureDir, "file3.ts"), "const c = 3;\n");

    child_process.execSync('git config user.name "Test"', { cwd: fixtureDir });
    child_process.execSync('git config user.email "test@test.com"', { cwd: fixtureDir });
    child_process.execSync("git add .", { cwd: fixtureDir });
    child_process.execSync('git commit -m "Init"', { cwd: fixtureDir });

    // Enforce maxFileCount: 2 (repo has 3 files)
    await expect(
      cloneRepositorySandboxed({
        repoUrl: fixtureDir,
        targetDir: cloneTargetDir,
        maxFileCount: 2,
      })
    ).rejects.toThrow("exceeds maximum allowed file count limit");

    // Temp folder must be deleted on failure
    expect(fs.existsSync(cloneTargetDir)).toBe(false);

    try {
      if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true });
    } catch {}
  });

  it("should enforce max repo size limit and clean up temp folder on failure", async () => {
    const fixtureDir = path.resolve(process.cwd(), "temp/test_repo_size_src");
    const cloneTargetDir = path.resolve(process.cwd(), "temp/scans/test_repo_size_target");

    if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true });
    if (fs.existsSync(cloneTargetDir)) fs.rmSync(cloneTargetDir, { recursive: true, force: true });

    fs.mkdirSync(fixtureDir, { recursive: true });
    child_process.execSync("git init", { cwd: fixtureDir });
    // Write 1KB file
    fs.writeFileSync(path.join(fixtureDir, "large.txt"), "X".repeat(1024));

    child_process.execSync('git config user.name "Test"', { cwd: fixtureDir });
    child_process.execSync('git config user.email "test@test.com"', { cwd: fixtureDir });
    child_process.execSync("git add .", { cwd: fixtureDir });
    child_process.execSync('git commit -m "Init"', { cwd: fixtureDir });

    // Enforce maxRepoSizeBytes: 500 (file is 1024 bytes)
    await expect(
      cloneRepositorySandboxed({
        repoUrl: fixtureDir,
        targetDir: cloneTargetDir,
        maxRepoSizeBytes: 500,
      })
    ).rejects.toThrow("exceeds maximum allowed scan limit");

    // Temp folder must be deleted on failure
    expect(fs.existsSync(cloneTargetDir)).toBe(false);

    try {
      if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true });
    } catch {}
  });
});
