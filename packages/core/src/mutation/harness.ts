import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { runAllDetectors } from "../detectors/registry.js";
import { Finding } from "../types.js";
import { loadAllFixtures, LoadedFixtureSet } from "../../test-utils/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_FIXTURES_DIR = path.resolve(__dirname, "../../../../fixtures");
const MUTATION_SCOREBOARD_PATH = path.resolve(__dirname, "../../../../mutation-scoreboard.json");

export const PRECISION_THRESHOLD = 90.0;
export const RECALL_THRESHOLD = 80.0;

export interface MutationScoreboardEntry {
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: string;
  recall: string;
  precisionValue: number;
  recallValue: number;
  status: "PASS" | "FAIL";
}

/**
 * 1. Rename Variables
 * Replaces common identifier names with refactored variable names.
 */
export function renameVariablesInCode(code: string): string {
  return code
    .replace(/\breq\b/g, "clientRequestPayload")
    .replace(/\brequest\b/g, "incomingHttpRequest")
    .replace(/\bbody\b/g, "parsedBodyObject")
    .replace(/\bamount\b/g, "userSubmittedAmount")
    .replace(/\bparams\b/g, "routeUrlParams")
    .replace(/\bdata\b/g, "fetchedRecordData")
    .replace(/\bdb\b/g, "dbClientInstance")
    .replace(/\buser\b/g, "authenticatedAccount")
    .replace(/\btoken\b/g, "sessionAuthToken")
    .replace(/\bparsedBody\b/g, "deserializedJsonPayload");
}

/**
 * 2. Wrap in Helper
 * Wraps handler/code inside generic helper execution wrappers.
 */
export function wrapInHelperInCode(code: string): string {
  const helperHeader = `
// Automated helper wrapper
function __executeWithSecurityContext<T>(action: () => T): T {
  return action();
}
`.trim();

  return `${helperHeader}\n\n${code}`;
}

/**
 * 3. Reformat Code
 * Adjusts line breaks, spacing, indentation, and comments.
 */
export function reformatCode(code: string): string {
  const lines = code.split("\n");
  return lines
    .map((l) => `  ${l}  `)
    .join("\n\n")
    .replace(/\n\n\n+/g, "\n\n");
}

/**
 * 4. Add Unrelated Sanitizer
 * Injects calls to dummy sanitizers that do NOT sanitize the vulnerable taint path.
 */
export function addUnrelatedSanitizerToCode(code: string): string {
  const sanitizerPrefix = `
// Unrelated dummy sanitizer
function sanitizeUnrelatedHeader(val: string): string {
  return val.trim().toLowerCase();
}
const _dummySanitizedHeader = sanitizeUnrelatedHeader(" X-CUSTOM-HEADER ");
`.trim();

  return `${sanitizerPrefix}\n\n${code}`;
}

/**
 * 5. Apply Automated Mutations (Combined 5-stage transformation)
 * Takes a filesMap and returns a mutated version applying:
 * - Variable renaming
 * - File splitting / moving logic
 * - Helper function wrapping
 * - Reformatting
 * - Unrelated sanitizer injection
 */
export function applyAutomatedMutations(filesMap: Map<string, string>): Map<string, string> {
  const mutatedMap = new Map<string, string>();

  for (const [rawFilePath, content] of filesMap.entries()) {
    const filePath = rawFilePath.replace(/\\/g, "/");
    if (
      filePath.endsWith(".ts") ||
      filePath.endsWith(".tsx") ||
      filePath.endsWith(".js") ||
      filePath.endsWith(".jsx") ||
      filePath.endsWith(".sql")
    ) {
      // Apply variable renaming, sanitizer injection, helper wrapping, and reformatting
      let mutated = renameVariablesInCode(content);
      mutated = addUnrelatedSanitizerToCode(mutated);
      mutated = wrapInHelperInCode(mutated);
      mutated = reformatCode(mutated);

      mutatedMap.set(filePath, mutated);

      // Code movement: create an extracted helper file
      const helperPath = filePath.replace(/\.(ts|js|tsx|jsx|sql)$/, ".helper.$1");
      const helperContent = `
// Extracted auxiliary module
export function __auxiliaryHelperModule() {
  return true;
}
      `.trim();
      mutatedMap.set(helperPath, helperContent);
    } else {
      mutatedMap.set(filePath, content);
    }
  }

  return mutatedMap;
}

/**
 * Runs all security detectors against a set of files and aggregates findings.
 */
export async function runDetectors(filesMap: Map<string, string>): Promise<Finding[]> {
  return runAllDetectors(filesMap, { offlineMode: true, targetFolder: "/fixtures/mutation-harness" });
}

/**
 * Executes the complete Mutation Harness across all fixture sets:
 * - Checks recall on vulnerable, hand-crafted mutated, and auto-mutated variants.
 * - Checks precision on clean variants (must stay clean).
 * - Fails CI (exitCode = 1) if any rule drops below precision 90.0% or recall 80.0%.
 */
export async function runMutationHarness(
  options: {
    fixturesDir?: string;
    precisionThreshold?: number;
    recallThreshold?: number;
  } = {}
): Promise<{ scoreboard: MutationScoreboardEntry[]; exitCode: number }> {
  const fixturesDir = options.fixturesDir || DEFAULT_FIXTURES_DIR;
  const precisionMin = options.precisionThreshold ?? PRECISION_THRESHOLD;
  const recallMin = options.recallThreshold ?? RECALL_THRESHOLD;

  const fixtureSets: LoadedFixtureSet[] = loadAllFixtures(fixturesDir);
  const ruleScores: Map<string, { tp: number; fp: number; fn: number }> = new Map();

  function getRuleScore(ruleId: string) {
    if (!ruleScores.has(ruleId)) {
      ruleScores.set(ruleId, { tp: 0, fp: 0, fn: 0 });
    }
    return ruleScores.get(ruleId)!;
  }

  for (const fixture of fixtureSets) {
    // 1. Evaluate Vulnerable files (hand-crafted)
    const vulnFindings = await runDetectors(fixture.vulnerableFiles);
    for (const exp of fixture.expected.vulnerable) {
      const score = getRuleScore(exp.ruleId);
      const matched = vulnFindings.some(
        (f) =>
          f.ruleId === exp.ruleId &&
          f.file === exp.file &&
          f.lineRange.startLine === exp.lineRange.startLine
      );
      if (matched) {
        score.tp++;
      } else {
        score.fn++;
      }
    }

    // 2. Evaluate Hand-crafted Mutated files
    const mutatedFindings = await runDetectors(fixture.mutatedFiles);
    for (const exp of fixture.expected.mutated) {
      const score = getRuleScore(exp.ruleId);
      const matched = mutatedFindings.some(
        (f) =>
          f.ruleId === exp.ruleId &&
          f.file === exp.file &&
          f.lineRange.startLine === exp.lineRange.startLine
      );
      if (matched) {
        score.tp++;
      } else {
        score.fn++;
      }
    }

    // 3. Evaluate Automated AST-mutated files (from vulnerable files)
    const autoMutatedFiles = applyAutomatedMutations(fixture.vulnerableFiles);
    const autoMutatedFindings = await runDetectors(autoMutatedFiles);
    for (const exp of fixture.expected.vulnerable) {
      const score = getRuleScore(exp.ruleId);
      const matched = autoMutatedFindings.some(
        (f) => f.ruleId === exp.ruleId && f.file === exp.file
      );
      if (matched) {
        score.tp++;
      } else {
        score.fn++;
      }
    }

    // 4. Evaluate Clean files (precision check: must stay clean)
    const cleanFindings = await runDetectors(fixture.cleanFiles);
    for (const f of cleanFindings) {
      const score = getRuleScore(f.ruleId);
      score.fp++;
    }
  }

  const scoreboard: MutationScoreboardEntry[] = [];
  let overallPass = true;

  console.log("\n================ NANTIS MUTATION HARNESS SCOREBOARD ================\n");
  console.log(
    "| Rule ID                            | TP | FP | FN | Precision | Recall   | Status |"
  );
  console.log(
    "|------------------------------------|----|----|----|-----------|----------|--------|"
  );

  for (const [ruleId, { tp, fp, fn }] of ruleScores.entries()) {
    const precisionNum = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100;
    const recallNum = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100;

    const isPass = precisionNum >= precisionMin && recallNum >= recallMin;
    if (!isPass) {
      overallPass = false;
    }

    const precision = `${precisionNum.toFixed(1)}%`;
    const recall = `${recallNum.toFixed(1)}%`;
    const status = isPass ? "PASS" : "FAIL";

    scoreboard.push({
      ruleId,
      truePositives: tp,
      falsePositives: fp,
      falseNegatives: fn,
      precision,
      recall,
      precisionValue: precisionNum,
      recallValue: recallNum,
      status,
    });

    const padRule = ruleId.padEnd(34, " ");
    const padTp = String(tp).padEnd(2, " ");
    const padFp = String(fp).padEnd(2, " ");
    const padFn = String(fn).padEnd(2, " ");
    const padPrec = precision.padEnd(9, " ");
    const padRec = recall.padEnd(8, " ");
    const padStatus = status.padEnd(6, " ");

    console.log(
      `| ${padRule} | ${padTp} | ${padFp} | ${padFn} | ${padPrec} | ${padRec} | ${padStatus} |`
    );
  }

  console.log(
    "|------------------------------------|----|----|----|-----------|----------|--------|\n"
  );

  fs.writeFileSync(MUTATION_SCOREBOARD_PATH, JSON.stringify(scoreboard, null, 2), "utf-8");
  console.log(`Mutation scoreboard written to: ${MUTATION_SCOREBOARD_PATH}\n`);

  const exitCode = overallPass ? 0 : 1;
  if (!overallPass) {
    console.error(
      `Mutation Harness Verification FAILED! One or more rules dropped below threshold (Precision >= ${precisionMin}%, Recall >= ${recallMin}%).\n`
    );
  } else {
    console.log(
      `Mutation Harness Verification PASSED! All rules satisfy Precision >= ${precisionMin}% and Recall >= ${recallMin}%.\n`
    );
  }

  return { scoreboard, exitCode };
}
