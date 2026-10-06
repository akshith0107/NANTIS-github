import { describe, expect, it } from "vitest";
import { compareScanResults, createBaseline, updateBaseline } from "../src/baseline.js";
import { createFinding } from "../src/evidence.js";
import { Finding } from "../src/types.js";

describe("Scan-to-Scan Comparison & Baseline Engine", () => {
  const findingA: Finding = createFinding({
    ruleId: "hardcoded-secret",
    title: "Hardcoded API Secret Key",
    severity: "critical",
    confidenceTier: "proven",
    file: "src/config.ts",
    lineRange: { startLine: 10, endLine: 10 },
    explanation: "Found hardcoded secret key in source file",
    evidenceChain: [
      {
        kind: "source",
        file: "src/config.ts",
        line: 10,
        maskedSnippet: "const API_KEY = 'sk_test_12345';",
        confidence: "high",
        note: "Hardcoded secret",
      },
    ],
    unresolvedSteps: [],
  });

  const findingB: Finding = createFinding({
    ruleId: "mass-assignment",
    title: "Mass Assignment in Profile Route",
    severity: "high",
    confidenceTier: "likely",
    file: "app/api/profile/route.ts",
    lineRange: { startLine: 5, endLine: 12 },
    explanation: "Raw body passed to insert()",
    evidenceChain: [
      {
        kind: "source",
        file: "app/api/profile/route.ts",
        line: 5,
        maskedSnippet: "const body = await req.json();",
        confidence: "high",
        note: "Request body",
      },
    ],
    unresolvedSteps: [],
  });

  const findingC: Finding = createFinding({
    ruleId: "stripe-webhook-no-signature",
    title: "Stripe Webhook Missing Signature Verification",
    severity: "critical",
    confidenceTier: "proven",
    file: "app/api/webhooks/stripe/route.ts",
    lineRange: { startLine: 8, endLine: 20 },
    explanation: "Webhook handler executes without constructEvent()",
    evidenceChain: [
      {
        kind: "source",
        file: "app/api/webhooks/stripe/route.ts",
        line: 8,
        maskedSnippet: "export async function POST(req: Request) { ... }",
        confidence: "high",
        note: "Webhook handler",
      },
    ],
    unresolvedSteps: [],
  });

  it("should categorize findings as 'new' when no baseline exists", () => {
    const result = compareScanResults([findingA, findingB], null);

    expect(result.summary.newCount).toBe(2);
    expect(result.summary.fixedCount).toBe(0);
    expect(result.summary.unchangedCount).toBe(0);
    expect(result.summary.reintroducedCount).toBe(0);
    expect(result.newFindings.every((f) => f.status === "new")).toBe(true);
  });

  it("should correctly identify 'unchanged', 'new', and 'fixed' findings against a baseline", () => {
    // 1. Initial baseline containing findingA and findingB
    const initialBaseline = createBaseline([findingA, findingB]);

    // 2. Second scan where findingA is present (unchanged), findingB is removed (fixed), and findingC is added (new)
    const currentScan = [findingA, findingC];
    const comparison = compareScanResults(currentScan, initialBaseline);

    expect(comparison.summary.unchangedCount).toBe(1);
    expect(comparison.summary.newCount).toBe(1);
    expect(comparison.summary.fixedCount).toBe(1);
    expect(comparison.summary.reintroducedCount).toBe(0);

    expect(comparison.unchangedFindings[0].fingerprint).toBe(findingA.fingerprint);
    expect(comparison.unchangedFindings[0].status).toBe("unchanged");

    expect(comparison.newFindings[0].fingerprint).toBe(findingC.fingerprint);
    expect(comparison.newFindings[0].status).toBe("new");

    expect(comparison.fixedFindings[0].fingerprint).toBe(findingB.fingerprint);
    expect(comparison.fixedFindings[0].status).toBe("fixed");
  });

  it("should categorize a finding as 'reintroduced' if it was marked fixed in a prior baseline update", () => {
    // 1. Initial baseline with findingA and findingB
    const initialBaseline = createBaseline([findingA, findingB]);

    // 2. Intermediate scan where findingB is fixed
    const intermediateComparison = compareScanResults([findingA], initialBaseline);
    expect(intermediateComparison.summary.fixedCount).toBe(1);

    // Update baseline to record findingB as fixed
    const updatedBaseline = updateBaseline(initialBaseline, intermediateComparison);
    const fixedBEntry = updatedBaseline.findings.find(
      (e) => e.fingerprint === findingB.fingerprint
    );
    expect(fixedBEntry?.status).toBe("fixed");

    // 3. Later scan where findingB is REINTRODUCED
    const laterScan = [findingA, findingB];
    const laterComparison = compareScanResults(laterScan, updatedBaseline);

    expect(laterComparison.summary.reintroducedCount).toBe(1);
    expect(laterComparison.summary.newCount).toBe(0);
    expect(laterComparison.summary.unchangedCount).toBe(1);

    const reintroduced = laterComparison.reintroducedFindings[0];
    expect(reintroduced.fingerprint).toBe(findingB.fingerprint);
    expect(reintroduced.status).toBe("reintroduced");
  });

  it("should enforce baseline mode CI exit code logic (0 when only unchanged findings exist)", () => {
    const baseline = createBaseline([findingA]);

    // Scan with only findingA (unchanged)
    const comparisonNoNew = compareScanResults([findingA], baseline);
    const exitCodeNoNew =
      comparisonNoNew.summary.newCount + comparisonNoNew.summary.reintroducedCount > 0 ? 1 : 0;
    expect(exitCodeNoNew).toBe(0);

    // Scan with findingC (new finding added)
    const comparisonWithNew = compareScanResults([findingA, findingC], baseline);
    const exitCodeWithNew =
      comparisonWithNew.summary.newCount + comparisonWithNew.summary.reintroducedCount > 0 ? 1 : 0;
    expect(exitCodeWithNew).toBe(1);
  });
});
