import { describe, it, expect } from "vitest";
import { createFinding } from "../src/evidence.js";
import { RefutationEngine } from "../src/refutation/engine.js";
import { runComparativeBenchmark } from "../src/idor/benchmark.js";

describe("Deterministic Refutation Pass (Phase 4)", () => {
  const engine = new RefutationEngine();

  const dummyFinding = createFinding({
    ruleId: "idor.owner-column.v1",
    title: "Candidate IDOR Finding",
    severity: "high",
    confidenceTier: "likely",
    file: "app/api/orders/route.ts",
    lineRange: { startLine: 10, endLine: 12 },
    evidenceChain: [],
    unresolvedSteps: [],
    explanation: "Candidate IDOR finding",
    fingerprint: "idor.owner-column.v1:app/api/orders/route.ts:id:orders",
  });

  it("should refute candidate finding when concrete ownership check is present in code", async () => {
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

    const result = await engine.refuteFinding(dummyFinding, filesMap);

    expect(result.isRefuted).toBe(true);
    expect(result.closure.blockingRefutingClaims).toContain("ownership_enforced");
    expect(result.closure.reasonCodes).toContain("REFUTED_BY_DIRECT_OWNERSHIP_CHECK");
    expect(result.closure.closureHash).toBeDefined();
    expect(result.closure.closureHash.length).toBe(16);
  });

  it("should refute candidate finding when assertRepoAccess guard is present", async () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  await assertRepoAccess(req, params.id);
  const { data } = await supabase.from("orders").select("*").eq("id", params.id);
  return Response.json(data);
}
        `,
      ],
    ]);

    const result = await engine.refuteFinding(dummyFinding, filesMap);

    expect(result.isRefuted).toBe(true);
    expect(result.closure.blockingRefutingClaims).toContain("auth_guard_present");
    expect(result.closure.reasonCodes).toContain("REFUTED_BY_AUTH_GUARD");
  });

  it("should refute candidate finding when table is protected by RLS policy in migration", async () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("orders").select("*").eq("id", params.id);
  return Response.json(data);
}
        `,
      ],
      [
        "supabase/migrations/001_orders.sql",
        `
CREATE TABLE orders (id text primary key, user_id text);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Tenant isolation" ON orders FOR SELECT USING (auth.uid() = user_id);
        `,
      ],
    ]);

    const result = await engine.refuteFinding(dummyFinding, filesMap);

    expect(result.isRefuted).toBe(true);
    expect(result.closure.blockingRefutingClaims).toContain("rls_policy_verified");
    expect(result.closure.reasonCodes).toContain("REFUTED_BY_RLS_POLICY");
  });

  it("should refute candidate finding when higher-order withAuth wrapper function is used", async () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export const GET = withAuth(async function(req, { params }) {
  const { data } = await supabase.from("orders").select("*").eq("id", params.id);
  return Response.json(data);
});
        `,
      ],
    ]);

    const result = await engine.refuteFinding(dummyFinding, filesMap);

    expect(result.isRefuted).toBe(true);
    expect(result.closure.blockingRefutingClaims).toContain("wrapper_protection_verified");
  });

  it("should return unverifiable status for adversarial dynamic dispatch cases", async () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const authModule = await import("./dynamic-auth-guard");
  await authModule.verify(req);
  const { data } = await supabase.from("orders").select("*").eq("id", params.id);
  return Response.json(data);
}
        `,
      ],
    ]);

    const result = await engine.refuteFinding(dummyFinding, filesMap);

    expect(result.isRefuted).toBe(false);
    expect(result.closure.reasonCodes).toContain("UNVERIFIABLE_DYNAMIC_DISPATCH");
    expect(result.closure.coverage.completionState).toBe("depth-limited");
  });

  it("should run 3-way comparative benchmark evaluating Deterministic vs LLM vs LLM+Refutation", async () => {
    const comparison = await runComparativeBenchmark();

    console.log("\n================ NANTIS PHASE 4 3-WAY COMPARATIVE BENCHMARK ================\n");
    console.log(`[Mode 1: Deterministic]          Precision: ${comparison.deterministic.precision.toFixed(1)}% | Recall: ${comparison.deterministic.recall.toFixed(1)}%`);
    console.log(`[Mode 2: Deterministic + LLM]     Precision: ${comparison.deterministicPlusLlm.precision.toFixed(1)}% | Recall: ${comparison.deterministicPlusLlm.recall.toFixed(1)}%`);
    console.log(`[Mode 3: Det + LLM + Refutation]  Precision: ${comparison.deterministicPlusLlmPlusRefutation.precision.toFixed(1)}% | Recall: ${comparison.deterministicPlusLlmPlusRefutation.recall.toFixed(1)}%`);
    console.log("============================================================================\n");

    expect(comparison.deterministic.precision).toBeGreaterThanOrEqual(90.0);
    expect(comparison.deterministicPlusLlm.precision).toBeGreaterThanOrEqual(90.0);
    expect(comparison.deterministicPlusLlmPlusRefutation.precision).toBeGreaterThanOrEqual(90.0);
    expect(comparison.deterministicPlusLlmPlusRefutation.recall).toBeGreaterThanOrEqual(80.0);
  });
});
