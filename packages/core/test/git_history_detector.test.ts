import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanGitHistory } from "../src/detectors/git-history.js";

describe("Git History Secrets Scanner (packages/core/src/detectors/git-history.ts)", () => {
  let tmpGitDir: string;

  beforeEach(() => {
    tmpGitDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-githistory-test-"));

    // Initialize temporary git repo
    execSync("git init", { cwd: tmpGitDir });
    execSync('git config user.name "Test Author"', { cwd: tmpGitDir });
    execSync('git config user.email "test@example.com"', { cwd: tmpGitDir });
  });

  afterEach(() => {
    fs.rmSync(tmpGitDir, { recursive: true, force: true });
  });

  it("should scan git history and detect a secret that was added and subsequently deleted in a later commit", async () => {
    const fakeSecret = "sk_live_FAKE_HISTORICAL_STRIPE_KEY_998877";

    // Commit 1: Add file with secret
    const secretFilePath = path.join(tmpGitDir, "src/config.ts");
    fs.mkdirSync(path.join(tmpGitDir, "src"), { recursive: true });
    fs.writeFileSync(secretFilePath, `export const STRIPE_KEY = "${fakeSecret}";\n`);
    execSync("git add .", { cwd: tmpGitDir });
    execSync('git commit -m "Add stripe configuration with key"', { cwd: tmpGitDir });

    const commit1Hash = execSync("git rev-parse HEAD", { cwd: tmpGitDir }).toString().trim();

    // Commit 2: Delete the secret from file (replacing with env var)
    fs.writeFileSync(secretFilePath, `export const STRIPE_KEY = process.env.STRIPE_KEY;\n`);
    execSync("git add .", { cwd: tmpGitDir });
    execSync('git commit -m "Remove hardcoded stripe key and use env var"', { cwd: tmpGitDir });

    // Run git history scanner
    const findings = await scanGitHistory(tmpGitDir);

    expect(findings.length).toBeGreaterThan(0);
    const finding = findings.find((f) => f.ruleId === "git-history-secret-leak");

    expect(finding).toBeDefined();
    expect(finding?.file).toBe("src/config.ts");
    expect(finding?.introducedIn?.commit).toBe(commit1Hash);
    expect(finding?.introducedIn?.author).toContain("Test Author");
    expect(finding?.introducedIn?.date).toBeDefined();

    // Verify secret masking
    expect(finding?.evidenceChain[0].maskedSnippet).not.toContain(fakeSecret);
    expect(finding?.evidenceChain[0].maskedSnippet).toContain("[REDACTED_SECRET]");

    // Verify rotation warning explanation
    expect(finding?.explanation).toContain("ROTATE THIS KEY IMMEDIATELY");
    expect(finding?.explanation.toLowerCase()).toContain("removing from history is not enough");
  });
});
