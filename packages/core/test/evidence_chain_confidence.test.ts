import { describe, expect, it } from "vitest";
import {
  createFinding,
  normalizeFindingConfidence,
  renderEvidenceChainAsStepsHtml,
  renderEvidenceChainAsStepsText,
  Finding,
  detectApiRouteAuthIssues,
  detectMissingOwnershipChecks,
} from "../src/index.js";

describe("Evidence Chain Confidence Invariants & Step Renderer", () => {
  it("must NEVER label a finding with an unresolved hop as 'likely' or 'proven'", () => {
    const findingWithUnresolved: Finding = {
      id: "test-1",
      ruleId: "api-route-no-auth",
      title: "API Route Missing Authentication Check",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/user/route.ts",
      lineRange: { startLine: 5, endLine: 10 },
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/user/route.ts",
          line: 5,
          maskedSnippet: "export async function GET()",
          confidence: "high",
          note: "Route handler entry point",
        },
      ],
      unresolvedSteps: [
        {
          description: "Dynamic import detected on path",
          location: { file: "app/api/user/route.ts", line: 6 },
          reason: "dynamic-import",
        },
      ],
      explanation: "Route handler uses dynamic import",
      fingerprint: "fingerprint-1",
    };

    // 1. If confidenceTier was initially "likely", it must become "needs-review"
    const normalizedLikely = normalizeFindingConfidence(findingWithUnresolved);
    expect(normalizedLikely.confidenceTier).toBe("needs-review");
    expect(normalizedLikely.confidenceTier).not.toBe("likely");
    expect(normalizedLikely.confidenceTier).not.toBe("proven");

    // 2. If confidenceTier was initially "proven", it must become "needs-review"
    const findingProvenWithUnresolved = {
      ...findingWithUnresolved,
      confidenceTier: "proven" as const,
    };
    const normalizedProven = normalizeFindingConfidence(findingProvenWithUnresolved);
    expect(normalizedProven.confidenceTier).toBe("needs-review");
    expect(normalizedProven.confidenceTier).not.toBe("proven");
    expect(normalizedProven.confidenceTier).not.toBe("likely");

    // 3. createFinding wrapper must enforce the same invariant
    const createdFinding = createFinding({
      ruleId: "missing-ownership-check",
      title: "Missing Ownership Check",
      severity: "high",
      confidenceTier: "proven",
      file: "app/api/doc/route.ts",
      lineRange: { startLine: 1, endLine: 5 },
      evidenceChain: [],
      unresolvedSteps: [
        {
          description: "Opaque database helper called",
          location: { file: "app/api/doc/route.ts", line: 3 },
          reason: "opaque-call",
        },
      ],
      explanation: "Delegated to external function",
      fingerprint: "fingerprint-2",
    });
    expect(createdFinding.confidenceTier).toBe("needs-review");
  });

  it("retains 'likely' or 'proven' when unresolvedSteps is empty", () => {
    const cleanFinding = createFinding({
      ruleId: "hardcoded-secret",
      title: "Hardcoded Secret",
      severity: "high",
      confidenceTier: "proven",
      file: "src/secret.ts",
      lineRange: { startLine: 2, endLine: 2 },
      evidenceChain: [
        {
          kind: "sink",
          file: "src/secret.ts",
          line: 2,
          maskedSnippet: "const key = 'sk_test_123';",
          confidence: "high",
          note: "Hardcoded API secret key",
        },
      ],
      unresolvedSteps: [],
      explanation: "Hardcoded secret detected in source file",
      fingerprint: "fingerprint-clean",
    });

    expect(cleanFinding.confidenceTier).toBe("proven");

    const likelyFinding = createFinding({
      ruleId: "api-route-no-auth",
      title: "API Route Missing Auth",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/test/route.ts",
      lineRange: { startLine: 1, endLine: 10 },
      evidenceChain: [],
      unresolvedSteps: [],
      explanation: "No auth check found",
      fingerprint: "fingerprint-likely",
    });

    expect(likelyFinding.confidenceTier).toBe("likely");
  });

  it("verifies detectors demote findings with unresolved hops to 'needs-review'", async () => {
    // Code with dynamic import causing unresolved step in Next.js route analyzer
    const files = new Map<string, string>([
      [
        "app/api/dynamic/route.ts",
        `
export async function GET() {
  const module = await import("./helper");
  return Response.json(module.getData());
}
        `.trim(),
      ],
      [
        "app/api/orders/[id]/route.ts",
        `
export async function POST(req: Request, { params }: { params: { id: string } }) {
  const result = await getOrderById(params.id);
  return Response.json(result);
}
        `.trim(),
      ],
    ]);

    const apiRouteFindings = await detectApiRouteAuthIssues(files);
    const dynamicFinding = apiRouteFindings.find((f) => f.file.includes("dynamic"));
    if (dynamicFinding && dynamicFinding.unresolvedSteps.length > 0) {
      expect(dynamicFinding.confidenceTier).toBe("needs-review");
      expect(dynamicFinding.confidenceTier).not.toBe("likely");
      expect(dynamicFinding.confidenceTier).not.toBe("proven");
    }

    const ownershipFindings = await detectMissingOwnershipChecks(files);
    const orderFinding = ownershipFindings.find((f) => f.file.includes("orders"));
    if (orderFinding && orderFinding.unresolvedSteps.length > 0) {
      expect(orderFinding.confidenceTier).toBe("needs-review");
      expect(orderFinding.confidenceTier).not.toBe("likely");
      expect(orderFinding.confidenceTier).not.toBe("proven");
    }
  });

  it("renders evidence chains into structured HTML UI steps", () => {
    const finding: Finding = createFinding({
      ruleId: "missing-ownership-check",
      title: "Database Query Missing User Ownership Filter",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/documents/[id]/route.ts",
      lineRange: { startLine: 4, endLine: 8 },
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/documents/[id]/route.ts",
          line: 4,
          maskedSnippet: "params.id",
          confidence: "high",
          note: "Request parameter 'id' extracted from client request",
        },
        {
          kind: "flow",
          file: "app/api/documents/[id]/route.ts",
          line: 5,
          maskedSnippet: "const id = params.id",
          confidence: "high",
          note: "Parameter 'id' flows into database query variable",
        },
        {
          kind: "sink",
          file: "app/api/documents/[id]/route.ts",
          line: 8,
          maskedSnippet: ".eq('id', id)",
          confidence: "high",
          note: "Database query filters strictly by resource ID",
        },
      ],
      unresolvedSteps: [
        {
          description: "Database call delegated to external helper function",
          location: { file: "app/api/documents/[id]/route.ts", line: 8 },
          reason: "opaque-call",
        },
      ],
      explanation: "Handler queries database without filtering by user ownership",
      fingerprint: "test-render-fingerprint",
    });

    // The unresolved step automatically forces confidenceTier to 'needs-review'
    expect(finding.confidenceTier).toBe("needs-review");

    const html = renderEvidenceChainAsStepsHtml(finding);
    expect(html).toContain("evidence-chain-container");
    expect(html).toContain("Step 1");
    expect(html).toContain("[SOURCE]");
    expect(html).toContain("app/api/documents/[id]/route.ts:4");
    expect(html).toContain("params.id");

    expect(html).toContain("Step 4");
    expect(html).toContain("[UNRESOLVED]");
    expect(html).toContain("Reason: opaque-call");
    expect(html).toContain("Database call delegated to external helper function");

    const text = renderEvidenceChainAsStepsText(finding);
    expect(text).toContain("Evidence Chain (4 steps):");
    expect(text).toContain("Step 1 [SOURCE]");
    expect(text).toContain("Step 4 [UNRESOLVED]");
  });
});
