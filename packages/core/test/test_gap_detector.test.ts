import { describe, expect, it } from "vitest";
import { detectTestGaps } from "../src/detectors/test-gap.js";

describe("Test-Gap Detector", () => {
  it("flags critical files with no referencing test files", async () => {
    const filesMap = new Map<string, string>([
      ["apps/web/src/lib/auth/session.ts", "export function getSession() { return true; }"],
      ["apps/web/src/api/payments.ts", "export function processPayment() {}"],
      ["apps/web/src/components/button.tsx", "export function Button() {}"],
    ]);

    const findings = await detectTestGaps(filesMap);

    expect(findings.length).toBe(2);
    const authFinding = findings.find((f) => f.file.includes("session.ts"));
    expect(authFinding).toBeDefined();
    expect(authFinding?.ruleId).toBe("test-gap-high-churn-untested");
    expect(authFinding?.confidenceTier).toBe("needs-review");
    expect(authFinding?.severity).toBe("medium");

    const paymentFinding = findings.find((f) => f.file.includes("payments.ts"));
    expect(paymentFinding).toBeDefined();
    expect(paymentFinding?.confidenceTier).toBe("needs-review");
  });

  it("does not flag critical files if a test file imports or references them", async () => {
    const filesMap = new Map<string, string>([
      ["apps/web/src/lib/auth/session.ts", "export function getSession() { return true; }"],
      ["apps/web/test/auth_and_session.test.ts", 'import { getSession } from "../src/lib/auth/session";'],
    ]);

    const findings = await detectTestGaps(filesMap);

    expect(findings.length).toBe(0);
  });

  it("NEGATIVE TEST: non-security files without unit tests are NEVER flagged", async () => {
    const filesMap = new Map<string, string>([
      ["apps/web/src/components/button.tsx", "export function Button() {}"],
      ["apps/web/src/utils/format.ts", "export function formatDate() {}"],
      ["apps/web/src/constants.ts", "export const TITLE = 'App';"],
    ]);

    const findings = await detectTestGaps(filesMap);

    expect(findings.length).toBe(0);
  });

  it("NEGATIVE TEST: critical files with low commit churn (< 2 commits) in repo are NEVER flagged", async () => {
    // When scanning a repoPath where file has only 1 commit, detectTestGaps does not flag it
    const filesMap = new Map<string, string>([
      ["apps/web/src/lib/auth/untracked-session.ts", "export function getSession() {}"],
    ]);

    const findings = await detectTestGaps(filesMap, process.cwd());

    // File untracked or has < 2 commits in repo -> zero findings
    const sessionFinding = findings.find((f) => f.file.includes("untracked-session.ts"));
    expect(sessionFinding).toBeUndefined();
  });
});
