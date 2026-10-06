import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { attachGitAttribution, parsePrNumber } from "../src/git/attribution.js";
import { Finding } from "../src/types.js";

describe("Git Attribution & PR Number Extraction (packages/core/src/git/attribution.ts)", () => {
  let tmpRepoDir: string;

  beforeEach(() => {
    tmpRepoDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-attribution-test-"));
    execSync("git init", { cwd: tmpRepoDir });
    execSync('git config user.name "Alice Dev"', { cwd: tmpRepoDir });
    execSync('git config user.email "alice@example.com"', { cwd: tmpRepoDir });
  });

  afterEach(() => {
    fs.rmSync(tmpRepoDir, { recursive: true, force: true });
  });

  it("should extract PR numbers from commit messages correctly", () => {
    expect(parsePrNumber("feat: add stripe webhook handler (#142)")).toBe(142);
    expect(parsePrNumber("Merge pull request #99 from repo/feature")).toBe(99);
    expect(parsePrNumber("fix: resolve auth bypass PR #54")).toBe(54);
    expect(parsePrNumber("chore: routine cleanup")).toBeUndefined();
  });

  it("should attach commit SHA, author, ISO date, PR number, and high confidence to a finding", async () => {
    const filePath = "src/stripe.ts";
    const fullPath = path.join(tmpRepoDir, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Commit 1: Add hardcoded secret with PR #88 in commit message
    fs.writeFileSync(fullPath, `export const KEY = "sk_test_FAKE_KEY_123";\n`);
    execSync("git add .", { cwd: tmpRepoDir });
    execSync('git commit -m "feat: setup stripe client (#88)"', { cwd: tmpRepoDir });

    const commitSha = execSync("git rev-parse HEAD", { cwd: tmpRepoDir }).toString().trim();

    const initialFinding: Finding = {
      id: "test-finding-1",
      ruleId: "hardcoded-secret",
      title: "Hardcoded Secret Detected",
      severity: "high",
      confidenceTier: "proven",
      file: filePath,
      lineRange: { startLine: 1, endLine: 1 },
      evidenceChain: [],
      unresolvedSteps: [],
      explanation: "Secret key found",
      fingerprint: "abc123hash",
    };

    const enriched = await attachGitAttribution(initialFinding, tmpRepoDir);

    expect(enriched.introducedIn).toBeDefined();
    expect(enriched.introducedIn?.commit).toBe(commitSha);
    expect(enriched.introducedIn?.author).toBe("Alice Dev");
    expect(enriched.introducedIn?.pr).toBe(88);
    expect(enriched.introducedIn?.date).toBeDefined();
    expect(enriched.introducedIn?.confidence).toBe("high");
    expect(enriched.introducedIn?.confidenceReason).toBeUndefined();
  });

  it("should assign medium confidence and explanation for uncommitted working tree changes", async () => {
    const filePath = "src/uncommitted.ts";
    const fullPath = path.join(tmpRepoDir, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Initial commit
    fs.writeFileSync(fullPath, "const a = 1;\n");
    execSync("git add .", { cwd: tmpRepoDir });
    execSync('git commit -m "initial commit"', { cwd: tmpRepoDir });

    // Add uncommitted change on line 2
    fs.writeFileSync(fullPath, "const a = 1;\nconst secret = 'sk_test_UNCOMMITTED';\n");

    const finding: Finding = {
      id: "test-finding-2",
      ruleId: "hardcoded-secret",
      title: "Hardcoded Secret Detected",
      severity: "high",
      confidenceTier: "proven",
      file: filePath,
      lineRange: { startLine: 2, endLine: 2 },
      evidenceChain: [],
      unresolvedSteps: [],
      explanation: "Secret key found",
      fingerprint: "def456hash",
    };

    const enriched = await attachGitAttribution(finding, tmpRepoDir);

    expect(enriched.introducedIn).toBeDefined();
    expect(enriched.introducedIn?.commit).toBe("working-tree-uncommitted");
    expect(enriched.introducedIn?.confidence).toBe("medium");
    expect(enriched.introducedIn?.confidenceReason).toContain(
      "Uncommitted local working tree changes"
    );
  });
});
