import { detectDeterministicIdor } from "./detector.js";

export interface BenchmarkTestCase {
  id: string;
  name: string;
  expectedVerdict: "vulnerable" | "safe" | "abstain";
  filesMap: Map<string, string>;
}

export interface BenchmarkMetrics {
  totalCases: number;
  vulnerableCases: number;
  safeCases: number;
  abstainCases: number;

  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  abstentions: number;

  precision: number;
  recall: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  abstentionRate: number;
  overallCoverage: number;
}

/**
 * Constructs the canonical 30-case IDOR benchmark suite.
 */
export function buildIdorBenchmarkSuite(): BenchmarkTestCase[] {
  const cases: BenchmarkTestCase[] = [];

  // Helper to make single-file + optional migration test case
  const makeCase = (
    id: string,
    name: string,
    expectedVerdict: "vulnerable" | "safe" | "abstain",
    codeContent: string,
    sqlContent?: string
  ) => {
    const filesMap = new Map<string, string>();
    filesMap.set("app/api/resource/route.ts", codeContent);
    if (sqlContent) {
      filesMap.set("supabase/migrations/20260101_schema.sql", sqlContent);
    }
    cases.push({ id, name, expectedVerdict, filesMap });
  };

  // --- 17 Vulnerable Cases ---
  makeCase(
    "VULN-01",
    "Route GET selecting documents by ID without user filter or RLS",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("documents").select("*").eq("id", params.id);
  return Response.json(data);
}
    `,
    `CREATE TABLE documents (id text primary key, title text);`
  );

  makeCase(
    "VULN-02",
    "Route DELETE updating orders by searchParams ID without user filter",
    "vulnerable",
    `
export async function DELETE(req: Request) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  await supabase.from("orders").delete().eq("id", id);
  return Response.json({ success: true });
}
    `,
    `CREATE TABLE orders (id text primary key, total numeric);`
  );

  makeCase(
    "VULN-03",
    "Server Action mutating user_profiles by req JSON ID without user filter",
    "vulnerable",
    `
"use server";
export async function updateProfile(req: Request) {
  const body = await req.json();
  await supabase.from("user_profiles").update(body).eq("id", body.id);
}
    `,
    `CREATE TABLE user_profiles (id text primary key, bio text);`
  );

  makeCase(
    "VULN-04",
    "Route PATCH updating invoices without ENABLE ROW LEVEL SECURITY",
    "vulnerable",
    `
export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  await supabase.from("invoices").update({ paid: true }).eq("id", params.id);
  return Response.json({ status: "ok" });
}
    `,
    `CREATE TABLE invoices (id text primary key, amount numeric);`
  );

  makeCase(
    "VULN-05",
    "Route POST updating projects with permissive USING (true) policy",
    "vulnerable",
    `
export async function POST(req: Request, { params }: { params: { id: string } }) {
  await supabase.from("projects").update({ name: "Updated" }).eq("id", params.id);
  return Response.json({ status: "ok" });
}
    `,
    `
CREATE TABLE projects (id text primary key, name text);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public write" ON projects FOR UPDATE USING (true);
    `
  );

  makeCase(
    "VULN-06",
    "Route GET selecting accounts by accountId without session auth",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { accountId: string } }) {
  const { data } = await supabase.from("accounts").select("*").eq("id", params.accountId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "VULN-07",
    "Route GET selecting tickets by ticketId without tenant scoping",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { ticketId: string } }) {
  const { data } = await supabase.from("tickets").select("*").eq("id", params.ticketId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "VULN-08",
    "Server Action deleting comments by commentId without author check",
    "vulnerable",
    `
"use server";
export async function deleteComment(commentId: string) {
  await supabase.from("comments").delete().eq("id", commentId);
}
    `
  );

  makeCase(
    "VULN-09",
    "Route PUT updating user_settings by settingsId without session check",
    "vulnerable",
    `
export async function PUT(req: Request, { params }: { params: { settingsId: string } }) {
  const body = await req.json();
  await supabase.from("user_settings").update(body).eq("id", params.settingsId);
  return Response.json({ updated: true });
}
    `
  );

  makeCase(
    "VULN-10",
    "Route GET selecting payment_methods by id without owner check",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("payment_methods").select("*").eq("id", params.id);
  return Response.json(data);
}
    `
  );

  makeCase(
    "VULN-11",
    "Route DELETE deleting files by fileId without uploader check",
    "vulnerable",
    `
export async function DELETE(req: Request, { params }: { params: { fileId: string } }) {
  await supabase.from("files").delete().eq("id", params.fileId);
  return Response.json({ deleted: true });
}
    `
  );

  makeCase(
    "VULN-12",
    "Server Action updating organizations by orgId without membership check",
    "vulnerable",
    `
"use server";
export async function updateOrg(orgId: string, data: any) {
  await supabase.from("organizations").update(data).eq("id", orgId);
}
    `
  );

  makeCase(
    "VULN-13",
    "Route GET selecting api_keys by keyId without user filter",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { keyId: string } }) {
  const { data } = await supabase.from("api_keys").select("*").eq("id", params.keyId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "VULN-14",
    "Route PATCH updating subscriptions by subId without customer filter",
    "vulnerable",
    `
export async function PATCH(req: Request, { params }: { params: { subId: string } }) {
  await supabase.from("subscriptions").update({ status: "canceled" }).eq("id", params.subId);
  return Response.json({ status: "canceled" });
}
    `
  );

  makeCase(
    "VULN-15",
    "Server Action deleting notifications by notifId without user check",
    "vulnerable",
    `
"use server";
export async function clearNotification(notifId: string) {
  await supabase.from("notifications").delete().eq("id", notifId);
}
    `
  );

  makeCase(
    "VULN-16",
    "Route GET selecting audit_logs by logId without org_id check",
    "vulnerable",
    `
export async function GET(req: Request, { params }: { params: { logId: string } }) {
  const { data } = await supabase.from("audit_logs").select("*").eq("id", params.logId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "VULN-17",
    "Route POST updating shipments by shipmentId without sender check",
    "vulnerable",
    `
export async function POST(req: Request, { params }: { params: { shipmentId: string } }) {
  await supabase.from("shipments").update({ delivered: true }).eq("id", params.shipmentId);
  return Response.json({ ok: true });
}
    `
  );

  // --- 10 Safe Cases ---
  makeCase(
    "SAFE-01",
    "Route GET with direct user_id filter matched to session",
    "safe",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  const { data } = await supabase.from("documents").select("*").eq("id", params.id).eq("user_id", session.user.id);
  return Response.json(data);
}
    `,
    `CREATE TABLE documents (id text primary key, user_id text);`
  );

  makeCase(
    "SAFE-02",
    "Route GET on table protected by valid user-scoped RLS policy",
    "safe",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("documents").select("*").eq("id", params.id);
  return Response.json(data);
}
    `,
    `
CREATE TABLE documents (id text primary key, user_id text);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "User tenant isolation" ON documents FOR SELECT USING (auth.uid() = user_id);
    `
  );

  makeCase(
    "SAFE-03",
    "Route protected by assertRepoAccess authorization check",
    "safe",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  await assertRepoAccess(req, params.id);
  const { data } = await supabase.from("repos").select("*").eq("id", params.id);
  return Response.json(data);
}
    `
  );

  makeCase(
    "SAFE-04",
    "Route with verifySession() and owner_id filter",
    "safe",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await verifySession(req);
  const { data } = await supabase.from("items").select("*").eq("id", params.id).eq("owner_id", session.userId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "SAFE-05",
    "Server Action with tenant_id filter matched to session",
    "safe",
    `
"use server";
export async function updateItem(id: string, body: any) {
  const session = await getServerSession();
  await supabase.from("items").update(body).eq("id", id).eq("tenant_id", session.tenantId);
}
    `
  );

  makeCase(
    "SAFE-06",
    "Route DELETE with author_id filter",
    "safe",
    `
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  await supabase.from("posts").delete().eq("id", params.id).eq("author_id", session.user.id);
  return Response.json({ success: true });
}
    `
  );

  makeCase(
    "SAFE-07",
    "Route GET with auth() check and creator_id filter",
    "safe",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { userId } = auth();
  const { data } = await supabase.from("tasks").select("*").eq("id", params.id).eq("creator_id", userId);
  return Response.json(data);
}
    `
  );

  makeCase(
    "SAFE-08",
    "Route PUT with supabase.auth.getUser() and user_id filter",
    "safe",
    `
export async function PUT(req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  await supabase.from("profiles").update({ bio: "new" }).eq("id", params.id).eq("user_id", user.id);
  return Response.json({ ok: true });
}
    `
  );

  makeCase(
    "SAFE-09",
    "Route POST with account_id filter",
    "safe",
    `
export async function POST(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  await supabase.from("billing").update({ active: true }).eq("id", params.id).eq("account_id", session.accountId);
  return Response.json({ ok: true });
}
    `
  );

  makeCase(
    "SAFE-10",
    "Public catalog table explicitly configured without user parameters",
    "safe",
    `
export async function GET() {
  const { data } = await supabase.from("public_catalog").select("*");
  return Response.json(data);
}
    `
  );

  // --- 3 Abstain Cases ---
  makeCase(
    "ABSTAIN-01",
    "Opaque dynamic import wrapper hides route authorization logic",
    "abstain",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const authModule = await import("./dynamic-auth-guard");
  await authModule.verify(req);
  const { data } = await supabase.from("secret_vault").select("*").eq("id", params.id);
  return Response.json(data);
}
    `
  );

  makeCase(
    "ABSTAIN-02",
    "Eval-wrapped remote script check hides authorization",
    "abstain",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  eval("customRemoteAuthCheck(req)");
  const { data } = await supabase.from("secret_vault").select("*").eq("id", params.id);
  return Response.json(data);
}
    `
  );

  makeCase(
    "ABSTAIN-03",
    "Complex dynamic property access where authorization cannot be resolved statically",
    "abstain",
    `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const dynamicKey = getDynamicKey(req);
  const { data } = await supabase.from("secret_vault").select("*").eq(dynamicKey, params.id);
  return Response.json(data);
}
    `
  );

  return cases;
}

/**
 * Runs the complete 30-case IDOR benchmark suite and evaluates performance metrics.
 */
export async function runIdorBenchmark(): Promise<BenchmarkMetrics> {
  const suite = buildIdorBenchmarkSuite();

  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;
  let abstentions = 0;
  let completedCount = 0;

  for (const tc of suite) {
    try {
      const findings = await detectDeterministicIdor(tc.filesMap);
      completedCount++;

      const hasIdorFinding = findings.some(
        (f) => f.ruleId === "idor.owner-column.v1" && f.confidenceTier !== "needs-review"
      );
      const hasNeedsReviewFinding = findings.some(
        (f) => f.ruleId === "idor.owner-column.v1" && f.confidenceTier === "needs-review"
      );

      if (tc.expectedVerdict === "vulnerable") {
        if (hasIdorFinding) {
          truePositives++;
        } else {
          falseNegatives++;
        }
      } else if (tc.expectedVerdict === "safe") {
        if (hasIdorFinding) {
          falsePositives++;
        } else {
          trueNegatives++;
        }
      } else if (tc.expectedVerdict === "abstain") {
        if (hasNeedsReviewFinding || findings.length === 0) {
          abstentions++;
        } else if (hasIdorFinding) {
          falsePositives++;
        }
      }
    } catch {
      // Failed to run case
    }
  }

  const vulnerableCases = suite.filter((c) => c.expectedVerdict === "vulnerable").length;
  const safeCases = suite.filter((c) => c.expectedVerdict === "safe").length;
  const abstainCases = suite.filter((c) => c.expectedVerdict === "abstain").length;

  const precision =
    truePositives + falsePositives > 0
      ? (truePositives / (truePositives + falsePositives)) * 100
      : 100;

  const recall =
    truePositives + falseNegatives > 0
      ? (truePositives / (truePositives + falseNegatives)) * 100
      : 100;

  const falsePositiveRate =
    falsePositives + trueNegatives > 0
      ? (falsePositives / (falsePositives + trueNegatives)) * 100
      : 0;

  const falseNegativeRate =
    falseNegatives + truePositives > 0
      ? (falseNegatives / (truePositives + falseNegatives)) * 100
      : 0;

  const abstentionRate = (abstentions / suite.length) * 100;

  const overallCoverage = (completedCount / suite.length) * 100;

  return {
    totalCases: suite.length,
    vulnerableCases,
    safeCases,
    abstainCases,
    truePositives,
    falsePositives,
    trueNegatives,
    falseNegatives,
    abstentions,
    precision,
    recall,
    falsePositiveRate,
    falseNegativeRate,
    abstentionRate,
    overallCoverage,
  };
}

export interface BenchmarkComparisonResult {
  deterministic: BenchmarkMetrics;
  deterministicPlusLlm: BenchmarkMetrics & { totalCostUsd: number; totalLatencyMs: number };
  deterministicPlusLlmPlusRefutation: BenchmarkMetrics & { totalCostUsd: number; totalLatencyMs: number };
}

/**
 * Runs 3-way comparative benchmark evaluation:
 * 1. Deterministic Baseline
 * 2. Deterministic + LLM Security Hunter
 * 3. Deterministic + LLM + Refutation Pass
 */
export async function runComparativeBenchmark(): Promise<BenchmarkComparisonResult> {
  const { LlmSecurityHunter } = await import("../ai/investigator.js");
  const { MockLlmProvider } = await import("../ai/provider.js");
  const { RefutationEngine } = await import("../refutation/engine.js");

  const deterministicMetrics = await runIdorBenchmark();
  const suite = buildIdorBenchmarkSuite();
  const hunter = new LlmSecurityHunter({ enabled: true }, new MockLlmProvider("default"));
  const refutationEngine = new RefutationEngine();

  // --- Mode 2: Deterministic + LLM ---
  let tp2 = 0, fp2 = 0, tn2 = 0, fn2 = 0, abs2 = 0, count2 = 0;
  let totalCostUsd = 0;
  let totalLatencyMs = 0;

  for (const tc of suite) {
    try {
      const detFindings = await detectDeterministicIdor(tc.filesMap, false);
      const llmResult = await hunter.investigate(tc.filesMap);
      count2++;
      totalCostUsd += llmResult.metadata.costUsd;
      totalLatencyMs += llmResult.metadata.latencyMs;

      const combined = [...detFindings, ...llmResult.verifiedFindings];
      const hasIdor = combined.some(
        (f) => (f.ruleId === "idor.owner-column.v1" || f.origin === "llm") && f.confidenceTier !== "needs-review"
      );
      const hasNeedsReview = combined.some((f) => f.confidenceTier === "needs-review");

      if (tc.expectedVerdict === "vulnerable") {
        if (hasIdor) tp2++; else fn2++;
      } else if (tc.expectedVerdict === "safe") {
        if (hasIdor) fp2++; else tn2++;
      } else if (tc.expectedVerdict === "abstain") {
        if (hasNeedsReview || combined.length === 0) abs2++; else if (hasIdor) fp2++;
      }
    } catch {}
  }

  // --- Mode 3: Deterministic + LLM + Refutation Pass ---
  let tp3 = 0, fp3 = 0, tn3 = 0, fn3 = 0, abs3 = 0, count3 = 0;

  for (const tc of suite) {
    try {
      const detFindings = await detectDeterministicIdor(tc.filesMap, false);
      const llmResult = await hunter.investigate(tc.filesMap);
      count3++;

      const rawCombined = [...detFindings, ...llmResult.verifiedFindings];
      const unrefutedCombined = [];

      for (const finding of rawCombined) {
        const refRes = await refutationEngine.refuteFinding(finding, tc.filesMap);
        if (!refRes.isRefuted) {
          unrefutedCombined.push(finding);
        }
      }

      const hasIdor = unrefutedCombined.some(
        (f) => (f.ruleId === "idor.owner-column.v1" || f.origin === "llm") && f.confidenceTier !== "needs-review"
      );
      const hasNeedsReview = unrefutedCombined.some((f) => f.confidenceTier === "needs-review");

      if (tc.expectedVerdict === "vulnerable") {
        if (hasIdor) tp3++; else fn3++;
      } else if (tc.expectedVerdict === "safe") {
        if (hasIdor) fp3++; else tn3++;
      } else if (tc.expectedVerdict === "abstain") {
        if (hasNeedsReview || unrefutedCombined.length === 0) abs3++; else if (hasIdor) fp3++;
      }
    } catch {}
  }

  const vulnerableCases = suite.filter((c) => c.expectedVerdict === "vulnerable").length;
  const safeCases = suite.filter((c) => c.expectedVerdict === "safe").length;
  const abstainCases = suite.filter((c) => c.expectedVerdict === "abstain").length;

  const mode2Metrics = {
    totalCases: suite.length,
    vulnerableCases,
    safeCases,
    abstainCases,
    truePositives: tp2,
    falsePositives: fp2,
    trueNegatives: tn2,
    falseNegatives: fn2,
    abstentions: abs2,
    precision: tp2 + fp2 > 0 ? (tp2 / (tp2 + fp2)) * 100 : 100,
    recall: tp2 + fn2 > 0 ? (tp2 / (tp2 + fn2)) * 100 : 100,
    falsePositiveRate: fp2 + tn2 > 0 ? (fp2 / (fp2 + tn2)) * 100 : 0,
    falseNegativeRate: fn2 + tp2 > 0 ? (fn2 / (fn2 + tp2)) * 100 : 0,
    abstentionRate: (abs2 / suite.length) * 100,
    overallCoverage: (count2 / suite.length) * 100,
    totalCostUsd,
    totalLatencyMs,
  };

  const mode3Metrics = {
    totalCases: suite.length,
    vulnerableCases,
    safeCases,
    abstainCases,
    truePositives: tp3,
    falsePositives: fp3,
    trueNegatives: tn3,
    falseNegatives: fn3,
    abstentions: abs3,
    precision: tp3 + fp3 > 0 ? (tp3 / (tp3 + fp3)) * 100 : 100,
    recall: tp3 + fn3 > 0 ? (tp3 / (tp3 + fn3)) * 100 : 100,
    falsePositiveRate: fp3 + tn3 > 0 ? (fp3 / (fp3 + tn3)) * 100 : 0,
    falseNegativeRate: fn3 + tp3 > 0 ? (fn3 / (fn3 + tp3)) * 100 : 0,
    abstentionRate: (abs3 / suite.length) * 100,
    overallCoverage: (count3 / suite.length) * 100,
    totalCostUsd,
    totalLatencyMs,
  };

  return {
    deterministic: deterministicMetrics,
    deterministicPlusLlm: mode2Metrics,
    deterministicPlusLlmPlusRefutation: mode3Metrics,
  };
}
