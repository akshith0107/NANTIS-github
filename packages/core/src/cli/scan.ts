import fs from "fs";
import path from "path";
import { NO_ISSUES_FOUND_MESSAGE } from "../constants.js";
import { runAllDetectors } from "../detectors/registry.js";
import {
  generateHumanReviewChecklist,
  renderHumanReviewChecklistText,
  HumanReviewChecklist,
} from "../human-review-checklist.js";
import { attachGitAttributionToFindings } from "../git/attribution.js";
import { Finding } from "../types.js";
import { walkDirectory } from "../walker.js";
import {
  compareScanResults,
  createBaseline,
  loadBaseline,
  saveBaseline,
  ComparisonResult,
} from "../baseline.js";
import { renderEvidenceChainAsStepsText } from "../evidence.js";

export async function runScan(
  targetFolder: string,
  options: {
    json?: boolean;
    baselinePath?: string;
    saveBaselinePath?: string;
    showUnchanged?: boolean;
    enableLlmHunter?: boolean;
  } = {}
): Promise<{
  findings: Finding[];
  exitCode: number;
  comparison?: ComparisonResult;
  checklist: HumanReviewChecklist;
}> {
  const normalizedPath = path.resolve(targetFolder);
  if (!fs.existsSync(normalizedPath)) {
    console.error(`Error: Target directory does not exist: ${targetFolder}`);
    return {
      findings: [],
      exitCode: 2,
      checklist: generateHumanReviewChecklist(new Map()),
    };
  }

  try {
    const scannedFiles = walkDirectory(normalizedPath);
    const filesMap = new Map<string, string>();
    for (const file of scannedFiles) {
      filesMap.set(file.relativePath, file.content);
    }

    const { findings: rawFindings, diagnostics } = await runAllDetectors(filesMap, {
      targetFolder: normalizedPath,
      offlineMode: true,
      enableLlmHunter: options.enableLlmHunter,
    });

    if (!options.json && diagnostics.length > 0) {
      console.warn("\n⚠️ [Analysis Warning] Some detectors encountered errors during scan:");
      for (const diag of diagnostics) {
        console.warn(`  - [${diag.detectorName || diag.detectorId}]: ${diag.message}`);
      }
    }

    const enrichedFindings = await attachGitAttributionToFindings(rawFindings, normalizedPath);

    let comparison: ComparisonResult | undefined;
    let exitCode = enrichedFindings.length > 0 ? 1 : 0;

    if (options.baselinePath) {
      const loaded = loadBaseline(options.baselinePath);
      comparison = compareScanResults(enrichedFindings, loaded);

      // In baseline comparison mode, CI fails only if NEW or REINTRODUCED findings exist
      exitCode = comparison.summary.newCount + comparison.summary.reintroducedCount > 0 ? 1 : 0;
    }

    if (options.saveBaselinePath) {
      const newBaseline = createBaseline(enrichedFindings);
      saveBaseline(options.saveBaselinePath, newBaseline);
      console.log(`Baseline recorded to: ${options.saveBaselinePath}`);
    }

    if (options.json) {
      if (comparison) {
        console.log(JSON.stringify(comparison, null, 2));
      } else {
        console.log(JSON.stringify(enrichedFindings, null, 2));
      }
    } else {
      if (comparison) {
        console.log("\n================ NANTIS SCAN-TO-SCAN COMPARISON ================\n");
        console.log(
          `Summary: ${comparison.summary.newCount} New, ${comparison.summary.reintroducedCount} Reintroduced, ${comparison.summary.fixedCount} Fixed, ${comparison.summary.unchangedCount} Unchanged (Total Scanned: ${comparison.summary.totalCurrent})\n`
        );

        if (comparison.newFindings.length > 0) {
          console.log(`--- NEW FINDINGS (${comparison.newFindings.length}) ---`);
          for (const f of comparison.newFindings) {
            console.log(
              `[NEW] [${f.severity.toUpperCase()}] ${f.title} in ${f.file}:${f.lineRange.startLine}`
            );
            console.log(renderEvidenceChainAsStepsText(f));
            console.log("");
          }
        }

        if (comparison.reintroducedFindings.length > 0) {
          console.log(`--- REINTRODUCED FINDINGS (${comparison.reintroducedFindings.length}) ---`);
          for (const f of comparison.reintroducedFindings) {
            console.log(
              `[REINTRODUCED] [${f.severity.toUpperCase()}] ${f.title} in ${f.file}:${f.lineRange.startLine}`
            );
            console.log(renderEvidenceChainAsStepsText(f));
            console.log("");
          }
        }

        if (comparison.fixedFindings.length > 0) {
          console.log(`--- FIXED FINDINGS (${comparison.fixedFindings.length}) ---`);
          for (const f of comparison.fixedFindings) {
            console.log(`[FIXED] ${f.title} in ${f.file}`);
          }
          console.log("");
        }

        if (comparison.summary.unchangedCount > 0) {
          if (options.showUnchanged) {
            console.log(`--- UNCHANGED FINDINGS (${comparison.summary.unchangedCount}) ---`);
            for (const f of comparison.unchangedFindings) {
              console.log(
                `[UNCHANGED] [${f.severity.toUpperCase()}] ${f.title} in ${f.file}:${f.lineRange.startLine}`
              );
            }
          } else {
            console.log(
              `📦 ${comparison.summary.unchangedCount} unchanged existing finding(s) collapsed into baseline count (hidden). Pass --show-unchanged to expand.\n`
            );
          }
        }

        if (comparison.summary.newCount === 0 && comparison.summary.reintroducedCount === 0) {
          console.log(`STATUS: Baseline check passed. ${NO_ISSUES_FOUND_MESSAGE}\n`);
        }
      } else {
        if (enrichedFindings.length === 0) {
          console.log(NO_ISSUES_FOUND_MESSAGE);
        } else {
          console.log(`Found ${enrichedFindings.length} issue(s):`);
          for (const finding of enrichedFindings) {
            console.log(
              `- [${finding.severity.toUpperCase()}] ${finding.title} in ${finding.file}:${finding.lineRange.startLine}`
            );
          }
        }
      }
    }

    const checklist = generateHumanReviewChecklist(filesMap);

    if (!options.json && process.argv.includes("--checklist")) {
      console.log(renderHumanReviewChecklistText(checklist));
    }

    return { findings: enrichedFindings, exitCode, comparison, checklist };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Tool Error during scan: ${msg}`);
    const emptyMap = new Map<string, string>();
    return {
      findings: [],
      exitCode: 2,
      checklist: generateHumanReviewChecklist(emptyMap),
    };
  }
}

// Execute directly if run as main CLI entrypoint
if (process.argv[1]?.includes("scan.ts") || process.argv[1]?.includes("scan.js")) {
  const args = process.argv.slice(2);
  const jsonFlag = args.includes("--json");
  const showUnchangedFlag = args.includes("--show-unchanged");

  let baselinePath: string | undefined;
  let saveBaselinePath: string | undefined;

  const baselineIdx = args.indexOf("--baseline");
  if (baselineIdx !== -1 && args[baselineIdx + 1]) {
    baselinePath = args[baselineIdx + 1];
  }

  const saveBaselineIdx = args.indexOf("--save-baseline");
  if (saveBaselineIdx !== -1 && args[saveBaselineIdx + 1]) {
    saveBaselinePath = args[saveBaselineIdx + 1];
  }

  const folderArg = args.find((a) => !a.startsWith("--")) || ".";

  runScan(folderArg, {
    json: jsonFlag,
    baselinePath,
    saveBaselinePath,
    showUnchanged: showUnchangedFlag,
  }).then(({ exitCode }) => {
    process.exit(exitCode);
  });
}
