import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { detectCiIssues } from "../detectors/ci-audit.js";
import { detectConfigIssues } from "../detectors/config.js";
import { detectDependencies } from "../detectors/dependencies.js";
import {
  detectApiRouteAuthIssues,
  detectServerActionAuthIssues,
  detectMiddlewareMatcherGaps,
  detectMissingOwnershipChecks,
  detectMassAssignmentIssues,
} from "../detectors/nextjs-rules.js";
import {
  detectMissingRlsInMigrations,
  detectPermissivePolicies,
  detectServiceRoleLeaks,
  detectStorageBucketIssues,
} from "../detectors/supabase.js";
import {
  detectStripeWebhookIssues,
  detectStripeWebhookParsedBody,
  detectStripeUserControlledPrice,
  detectStripeSecretKeyClientLeak,
} from "../detectors/stripe.js";
import { detectSecrets } from "../detectors/secrets.js";

import { loadAllFixtures } from "../../test-utils/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, "../../../../fixtures");
const ROOT_SCOREBOARD_PATH = path.resolve(__dirname, "../../../../scoreboard.json");

export interface RuleScoreboardEntry {
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: string;
  recall: string;
}

export async function runScoreboard(): Promise<{
  scoreboard: RuleScoreboardEntry[];
  exitCode: number;
}> {
  try {
    const fixtureSets = loadAllFixtures(FIXTURES_DIR);
    const ruleScores: Map<string, { tp: number; fp: number; fn: number }> = new Map();

    function getRuleScore(ruleId: string) {
      if (!ruleScores.has(ruleId)) {
        ruleScores.set(ruleId, { tp: 0, fp: 0, fn: 0 });
      }
      return ruleScores.get(ruleId)!;
    }

    for (const fixture of fixtureSets) {
      // 1. Evaluate Vulnerable files
      const vulnFindings = [
        ...(await detectSecrets(fixture.vulnerableFiles)),
        ...(await detectDependencies(fixture.vulnerableFiles, { offlineMode: true })),
        ...(await detectConfigIssues(fixture.vulnerableFiles)),
        ...(await detectCiIssues(fixture.vulnerableFiles)),
        ...(await detectApiRouteAuthIssues(fixture.vulnerableFiles)),
        ...(await detectMissingRlsInMigrations(fixture.vulnerableFiles)),
        ...(await detectStripeWebhookIssues(fixture.vulnerableFiles)),
        ...(await detectServerActionAuthIssues(fixture.vulnerableFiles)),
        ...(await detectMiddlewareMatcherGaps(fixture.vulnerableFiles)),
        ...(await detectMissingOwnershipChecks(fixture.vulnerableFiles)),
        ...(await detectMassAssignmentIssues(fixture.vulnerableFiles)),
        ...(await detectPermissivePolicies(fixture.vulnerableFiles)),
        ...(await detectServiceRoleLeaks(fixture.vulnerableFiles)),
        ...(await detectStorageBucketIssues(fixture.vulnerableFiles)),
        ...(await detectStripeWebhookParsedBody(fixture.vulnerableFiles)),
        ...(await detectStripeUserControlledPrice(fixture.vulnerableFiles)),
        ...(await detectStripeSecretKeyClientLeak(fixture.vulnerableFiles)),
      ];

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

      // 2. Evaluate Mutated files
      const mutatedFindings = [
        ...(await detectSecrets(fixture.mutatedFiles)),
        ...(await detectDependencies(fixture.mutatedFiles, { offlineMode: true })),
        ...(await detectConfigIssues(fixture.mutatedFiles)),
        ...(await detectCiIssues(fixture.mutatedFiles)),
        ...(await detectApiRouteAuthIssues(fixture.mutatedFiles)),
        ...(await detectMissingRlsInMigrations(fixture.mutatedFiles)),
        ...(await detectStripeWebhookIssues(fixture.mutatedFiles)),
        ...(await detectServerActionAuthIssues(fixture.mutatedFiles)),
        ...(await detectMiddlewareMatcherGaps(fixture.mutatedFiles)),
        ...(await detectMissingOwnershipChecks(fixture.mutatedFiles)),
        ...(await detectMassAssignmentIssues(fixture.mutatedFiles)),
        ...(await detectPermissivePolicies(fixture.mutatedFiles)),
        ...(await detectServiceRoleLeaks(fixture.mutatedFiles)),
        ...(await detectStorageBucketIssues(fixture.mutatedFiles)),
        ...(await detectStripeWebhookParsedBody(fixture.mutatedFiles)),
        ...(await detectStripeUserControlledPrice(fixture.mutatedFiles)),
        ...(await detectStripeSecretKeyClientLeak(fixture.mutatedFiles)),
      ];

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

      // 3. Evaluate Clean files
      const cleanFindings = [
        ...(await detectSecrets(fixture.cleanFiles)),
        ...(await detectDependencies(fixture.cleanFiles, { offlineMode: true })),
        ...(await detectConfigIssues(fixture.cleanFiles)),
        ...(await detectCiIssues(fixture.cleanFiles)),
        ...(await detectApiRouteAuthIssues(fixture.cleanFiles)),
        ...(await detectMissingRlsInMigrations(fixture.cleanFiles)),
        ...(await detectStripeWebhookIssues(fixture.cleanFiles)),
        ...(await detectServerActionAuthIssues(fixture.cleanFiles)),
        ...(await detectMiddlewareMatcherGaps(fixture.cleanFiles)),
        ...(await detectMissingOwnershipChecks(fixture.cleanFiles)),
        ...(await detectMassAssignmentIssues(fixture.cleanFiles)),
        ...(await detectPermissivePolicies(fixture.cleanFiles)),
        ...(await detectServiceRoleLeaks(fixture.cleanFiles)),
        ...(await detectStorageBucketIssues(fixture.cleanFiles)),
        ...(await detectStripeWebhookParsedBody(fixture.cleanFiles)),
        ...(await detectStripeUserControlledPrice(fixture.cleanFiles)),
        ...(await detectStripeSecretKeyClientLeak(fixture.cleanFiles)),
      ];

      for (const f of cleanFindings) {
        const score = getRuleScore(f.ruleId);
        score.fp++;
      }
    }

    const scoreboard: RuleScoreboardEntry[] = [];
    console.log("\n================ NANTIS RULE SCOREBOARD ================\n");
    console.log("| Rule ID                            | TP | FP | FN | Precision | Recall   |");
    console.log("|------------------------------------|----|----|----|-----------|----------|");

    for (const [ruleId, { tp, fp, fn }] of ruleScores.entries()) {
      const precisionNum = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100;
      const recallNum = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100;

      const precision = `${precisionNum.toFixed(1)}%`;
      const recall = `${recallNum.toFixed(1)}%`;

      scoreboard.push({
        ruleId,
        truePositives: tp,
        falsePositives: fp,
        falseNegatives: fn,
        precision,
        recall,
      });

      const padRule = ruleId.padEnd(34, " ");
      const padTp = String(tp).padEnd(2, " ");
      const padFp = String(fp).padEnd(2, " ");
      const padFn = String(fn).padEnd(2, " ");
      const padPrec = precision.padEnd(9, " ");
      const padRec = recall.padEnd(8, " ");

      console.log(`| ${padRule} | ${padTp} | ${padFp} | ${padFn} | ${padPrec} | ${padRec} |`);
    }

    console.log("|------------------------------------|----|----|----|-----------|----------|\n");

    fs.writeFileSync(ROOT_SCOREBOARD_PATH, JSON.stringify(scoreboard, null, 2), "utf-8");
    console.log(`Scoreboard written to: ${ROOT_SCOREBOARD_PATH}\n`);

    return { scoreboard, exitCode: 0 };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Tool Error during scoreboard execution: ${msg}`);
    return { scoreboard: [], exitCode: 2 };
  }
}

if (process.argv[1]?.includes("scoreboard.ts") || process.argv[1]?.includes("scoreboard.js")) {
  runScoreboard().then(({ exitCode }) => {
    process.exit(exitCode);
  });
}
