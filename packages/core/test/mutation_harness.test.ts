import path from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";
import {
  renameVariablesInCode,
  wrapInHelperInCode,
  reformatCode,
  addUnrelatedSanitizerToCode,
  applyAutomatedMutations,
  runMutationHarness,
  PRECISION_THRESHOLD,
  RECALL_THRESHOLD,
} from "../src/mutation/harness.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");

describe("Mutation Harness & Automated AST Code Transformations", () => {
  it("should apply 5-stage automated mutations to source code files", () => {
    const originalCode = `
export async function POST(req: Request) {
  const { amount } = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { unit_amount: amount } }]
  });
  return Response.json({ url: session.url });
}
    `.trim();

    // 1. Rename variables
    const renamed = renameVariablesInCode(originalCode);
    expect(renamed).toContain("clientRequestPayload");
    expect(renamed).toContain("userSubmittedAmount");

    // 2. Wrap in helper
    const wrapped = wrapInHelperInCode(originalCode);
    expect(wrapped).toContain("__executeWithSecurityContext");

    // 3. Reformat code
    const reformatted = reformatCode(originalCode);
    expect(reformatted).toContain("\n\n");

    // 4. Add unrelated sanitizer
    const sanitized = addUnrelatedSanitizerToCode(originalCode);
    expect(sanitized).toContain("sanitizeUnrelatedHeader");

    // 5. Combined automated mutations map
    const filesMap = new Map<string, string>([["app/api/checkout/route.ts", originalCode]]);
    const mutatedMap = applyAutomatedMutations(filesMap);

    expect(mutatedMap.has("app/api/checkout/route.ts")).toBe(true);
    expect(mutatedMap.has("app/api/checkout/route.helper.ts")).toBe(true);

    const autoMutatedCode = mutatedMap.get("app/api/checkout/route.ts")!;
    expect(autoMutatedCode).toContain("clientRequestPayload");
    expect(autoMutatedCode).toContain("__executeWithSecurityContext");
    expect(autoMutatedCode).toContain("sanitizeUnrelatedHeader");
  });

  it("should run complete mutation harness, evaluate scoreboard, and pass threshold checks", async () => {
    const { scoreboard, exitCode } = await runMutationHarness({
      fixturesDir: FIXTURES_DIR,
      precisionThreshold: PRECISION_THRESHOLD,
      recallThreshold: RECALL_THRESHOLD,
    });

    expect(scoreboard.length).toBeGreaterThan(0);
    expect(exitCode).toBe(0);

    for (const entry of scoreboard) {
      expect(entry.precisionValue).toBeGreaterThanOrEqual(PRECISION_THRESHOLD);
      expect(entry.recallValue).toBeGreaterThanOrEqual(RECALL_THRESHOLD);
      expect(entry.status).toBe("PASS");
    }
  });

  it("should fail CI with exit code 1 when precision or recall drops below required thresholds", async () => {
    // Force impossible threshold (101%) to verify failure detection
    const { exitCode } = await runMutationHarness({
      fixturesDir: FIXTURES_DIR,
      precisionThreshold: 101.0,
      recallThreshold: 101.0,
    });

    expect(exitCode).toBe(1);
  });
});
