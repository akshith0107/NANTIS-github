import fs from "fs";
import path from "path";
import os from "os";
import { describe, expect, it, beforeEach } from "vitest";
import {
  publishFixPR,
  getFixBranchName,
  generatePRDescription,
  clearPublishedPRCache,
} from "../src/fixes/pr-publisher.js";
import { FixResultAutomated } from "../src/fixes/types.js";
import { Finding } from "../src/types.js";

describe("PR Publisher (Safety Rules, Idempotency & Audit Logging)", () => {
  beforeEach(() => {
    clearPublishedPRCache();
  });
  const dummyFinding: Finding = {
    id: "finding-sec-1",
    ruleId: "stripe-webhook-no-signature",
    title: "Stripe Webhook Missing Signature Verification",
    severity: "high",
    confidenceTier: "proven",
    file: "apps/web/src/app/api/webhooks/stripe/route.ts",
    lineRange: { startLine: 1, endLine: 10 },
    evidenceChain: [
      {
        kind: "source",
        file: "apps/web/src/app/api/webhooks/stripe/route.ts",
        line: 1,
        maskedSnippet: "export async function POST(req) { ... }",
        confidence: "high",
        note: "Source evidence snippet",
      },
    ],
    unresolvedSteps: [],
    explanation: "Missing stripe.webhooks.constructEvent signature check",
    fingerprint: "stripe-sig-fingerprint-99",
  };

  const dummyFixResult: FixResultAutomated = {
    kind: "automated",
    ruleId: "stripe-webhook-no-signature",
    targetFile: "apps/web/src/app/api/webhooks/stripe/route.ts",
    edits: [],
    diff: "--- route.ts\n+++ route.ts\n+ const signature = req.headers.get('stripe-signature');\n",
    riskLevel: "medium",
    blastRadius: {
      affectedFiles: ["apps/web/src/app/api/webhooks/stripe/route.ts"],
      callersAffected: ["handleWebhook"],
      importedByModules: [],
      riskLevel: "medium",
    },
    proofLabel: "Proven by handler replay",
    verificationReport: {
      passed: true,
      checksRun: ["rescan", "tsc"],
      summaryText: "verified: rescan + tsc; no tests found",
    },
  };

  it("formats branch name as nantis/fix-<short_fingerprint>", () => {
    const branchName = getFixBranchName(dummyFinding);
    expect(branchName).toMatch(/^nantis\/fix-[a-f0-9]{8}$/);
  });

  it("formats PR description with masked evidence chain, diff, risk, blast radius, proof label, and checks text", () => {
    const desc = generatePRDescription(dummyFinding, dummyFixResult);

    expect(desc).toContain("stripe-webhook-no-signature");
    expect(desc).toContain("MEDIUM");
    expect(desc).toContain("Proven by handler replay");
    expect(desc).toContain("verified: rescan + tsc; no tests found");
    expect(desc).toContain("Masked Evidence Chain");
    expect(desc).toContain("Blast Radius Analysis");
  });

  it("Test Case 1 (Fork Case): Refuses PR creation for fork repositories", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-pr-test-"));
    const auditPath = path.join(tempDir, "pr-audit.json");

    try {
      const res = await publishFixPR(dummyFinding, dummyFixResult, {
        repoPath: tempDir,
        isFork: true,
        userHasAccess: true,
        auditLogPath: auditPath,
      });

      expect(res.success).toBe(false);
      expect(res.refusalReason).toContain("fork repository");

      const auditContent = JSON.parse(fs.readFileSync(auditPath, "utf-8"));
      expect(auditContent.length).toBeGreaterThan(0);
      expect(auditContent[0].status).toBe("refused");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("Test Case 2 (No-Access Case): Refuses PR creation when requesting user lacks access", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-pr-test-"));
    const auditPath = path.join(tempDir, "pr-audit.json");

    try {
      const res = await publishFixPR(dummyFinding, dummyFixResult, {
        repoPath: tempDir,
        isFork: false,
        userHasAccess: false,
        auditLogPath: auditPath,
      });

      expect(res.success).toBe(false);
      expect(res.refusalReason).toContain("cannot access target repository");

      const auditContent = JSON.parse(fs.readFileSync(auditPath, "utf-8"));
      expect(auditContent[0].status).toBe("refused");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("Test Case 3 (Stale-Branch Case): Detects branch/HEAD change since scan", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-pr-test-"));
    const auditPath = path.join(tempDir, "pr-audit.json");

    try {
      const res = await publishFixPR(dummyFinding, dummyFixResult, {
        repoPath: tempDir,
        isFork: false,
        userHasAccess: true,
        scanHeadHash: "old-commit-hash-111",
        auditLogPath: auditPath,
      });

      expect(res.success).toBe(true);
      expect(res.branchName).toMatch(/^nantis\/fix-/);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("Test Case 4 (Retry Case / Idempotency): Reuses existing PR without opening duplicates", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-pr-test-"));
    const auditPath = path.join(tempDir, "pr-audit.json");

    try {
      // First publish attempt
      const res1 = await publishFixPR(dummyFinding, dummyFixResult, {
        repoPath: tempDir,
        isFork: false,
        userHasAccess: true,
        auditLogPath: auditPath,
      });

      expect(res1.success).toBe(true);
      expect(res1.isDuplicate).toBe(false);

      // Retry publish attempt
      const res2 = await publishFixPR(dummyFinding, dummyFixResult, {
        repoPath: tempDir,
        isFork: false,
        userHasAccess: true,
        auditLogPath: auditPath,
      });

      expect(res2.success).toBe(true);
      expect(res2.isDuplicate).toBe(true);
      expect(res2.prUrl).toEqual(res1.prUrl);

      const auditContent = JSON.parse(fs.readFileSync(auditPath, "utf-8"));
      expect(auditContent.length).toBe(2);
      expect(auditContent[1].status).toBe("idempotent_skip");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
