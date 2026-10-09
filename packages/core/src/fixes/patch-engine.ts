import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { Finding } from "../types.js";
import { runScan } from "../cli/scan.js";
import { FixResult, FixSnapshot, StructuredEdit, VerificationReport } from "./types.js";
import { runSandboxVerification } from "./verification-runner.js";
import { evaluateProof } from "./proof/proof-engine.js";
import { fixDependencyBump } from "./rules/dependency-bump.js";
import { fixEnableRLS } from "./rules/enable-rls.js";
import { fixStripeWebhookVerification } from "./rules/stripe-webhook-verification.js";
import { fixIdorOwnerColumn } from "./rules/idor-owner-column.js";

/**
 * Validates that a patch does NOT delete code or insert rule suppression comments.
 */
export function validateAntiSuppressionAndDeletion(diff: string): {
  valid: boolean;
  reason?: string;
} {
  // Check suppression comments
  const suppressionPatterns = [
    /eslint-disable/i,
    /@ts-ignore/i,
    /@ts-nocheck/i,
    /@ts-expect-error/i,
    /nantis-disable/i,
    /\/\/\s*security-disable/i,
  ];

  for (const pattern of suppressionPatterns) {
    if (pattern.test(diff)) {
      return {
        valid: false,
        reason: `Patch rejected: contains rule suppression comment matching ${pattern}`,
      };
    }
  }

  // Check code deletion: count deleted non-empty code lines
  const lines = diff.split("\n");
  let deletedCodeLines = 0;

  for (const line of lines) {
    if (line.startsWith("-") && !line.startsWith("---")) {
      const lineText = line.substring(1).trim();
      // If deleted line contains executable code or statement
      if (lineText.length > 0 && !lineText.startsWith("//") && !lineText.startsWith("/*")) {
        deletedCodeLines++;
      }
    }
  }

  if (deletedCodeLines > 3) {
    return {
      valid: false,
      reason: `Patch rejected: attempts to fix issue by deleting ${deletedCodeLines} code lines`,
    };
  }

  return { valid: true };
}

/**
 * Applies structured edits to original file content.
 * Verifies that target text exists and matches before replacing.
 * Aborts with error if target text does not match.
 */
export function applyStructuredEdits(
  content: string,
  edits: StructuredEdit[]
): { success: boolean; updatedContent?: string; reason?: string } {
  let currentContent = content;

  for (const edit of edits) {
    if (!edit.targetContent) {
      return {
        success: false,
        reason: "Edit aborted: targetContent cannot be empty",
      };
    }

    if (!currentContent.includes(edit.targetContent)) {
      return {
        success: false,
        reason: `Edit aborted: target text mismatch for file ${edit.targetFile}. Target content not found in file.`,
      };
    }

    currentContent = currentContent.replace(edit.targetContent, edit.replacementContent);
  }

  return {
    success: true,
    updatedContent: currentContent,
  };
}

/**
 * Generates clean unified diff string by comparing before and after file contents.
 */
export function generateUnifiedDiff(
  filePath: string,
  beforeContent: string,
  afterContent: string
): string {
  const normPath = filePath.replace(/\\/g, "/");
  if (beforeContent === afterContent) {
    return `--- a/${normPath}\n+++ b/${normPath}`;
  }

  const beforeLines = beforeContent.length === 0 ? [] : beforeContent.split(/\r?\n/);
  const afterLines = afterContent.length === 0 ? [] : afterContent.split(/\r?\n/);

  // Compute LCS edit matrix
  const m = beforeLines.length;
  const n = afterLines.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (beforeLines[i] === afterLines[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  interface EditOp {
    type: "same" | "delete" | "add";
    line: string;
    origIdx: number;
    newIdx: number;
  }

  let i = m;
  let j = n;
  const ops: EditOp[] = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && beforeLines[i - 1] === afterLines[j - 1]) {
      ops.push({ type: "same", line: beforeLines[i - 1], origIdx: i, newIdx: j });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.push({ type: "add", line: afterLines[j - 1], origIdx: i + 1, newIdx: j });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      ops.push({ type: "delete", line: beforeLines[i - 1], origIdx: i, newIdx: j + 1 });
      i--;
    }
  }

  ops.reverse();

  const editIndices: number[] = [];
  for (let idx = 0; idx < ops.length; idx++) {
    if (ops[idx].type !== "same") {
      editIndices.push(idx);
    }
  }

  if (editIndices.length === 0) {
    return `--- a/${normPath}\n+++ b/${normPath}`;
  }

  const CONTEXT = 3;
  const hunkRanges: Array<{ startOpIdx: number; endOpIdx: number }> = [];

  let currentHunkStart = Math.max(0, editIndices[0] - CONTEXT);
  let currentHunkEnd = Math.min(ops.length - 1, editIndices[0] + CONTEXT);

  for (let k = 1; k < editIndices.length; k++) {
    const editIdx = editIndices[k];
    const candidateStart = Math.max(0, editIdx - CONTEXT);
    const candidateEnd = Math.min(ops.length - 1, editIdx + CONTEXT);

    if (candidateStart <= currentHunkEnd) {
      currentHunkEnd = candidateEnd;
    } else {
      hunkRanges.push({ startOpIdx: currentHunkStart, endOpIdx: currentHunkEnd });
      currentHunkStart = candidateStart;
      currentHunkEnd = candidateEnd;
    }
  }
  hunkRanges.push({ startOpIdx: currentHunkStart, endOpIdx: currentHunkEnd });

  const diffLines: string[] = [
    `--- a/${normPath}`,
    `+++ b/${normPath}`,
  ];

  const beforeEndsWithNewline = beforeContent.endsWith("\n") || beforeContent.endsWith("\r");
  const afterEndsWithNewline = afterContent.endsWith("\n") || afterContent.endsWith("\r");

  for (const range of hunkRanges) {
    const hunkOps = ops.slice(range.startOpIdx, range.endOpIdx + 1);

    const startBefore = hunkOps[0].origIdx;
    const startAfter = hunkOps[0].newIdx;

    const countBefore = hunkOps.filter((o) => o.type === "same" || o.type === "delete").length;
    const countAfter = hunkOps.filter((o) => o.type === "same" || o.type === "add").length;

    diffLines.push(`@@ -${startBefore},${countBefore} +${startAfter},${countAfter} @@`);

    for (const op of hunkOps) {
      const isLastBefore = op.origIdx === m;
      const isLastAfter = op.newIdx === n;

      if (op.type === "same") {
        diffLines.push(` ${op.line}`);
        if (isLastBefore && !beforeEndsWithNewline && isLastAfter && !afterEndsWithNewline) {
          diffLines.push("\\ No newline at end of file");
        }
      } else if (op.type === "delete") {
        diffLines.push(`-${op.line}`);
        if (isLastBefore && !beforeEndsWithNewline) {
          diffLines.push("\\ No newline at end of file");
        }
      } else if (op.type === "add") {
        diffLines.push(`+${op.line}`);
        if (isLastAfter && !afterEndsWithNewline) {
          diffLines.push("\\ No newline at end of file");
        }
      }
    }
  }

  return diffLines.join("\n") + "\n";
}

/**
 * Retrieves current git HEAD commit hash for branch change detection.
 */
export function getGitHeadHash(repoPath: string): string | null {
  try {
    const out = execSync("git rev-parse HEAD", {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim();
  } catch {
    return null;
  }
}

/**
 * Creates an in-memory snapshot of workspace files before fix application.
 */
export function createFixSnapshot(filesMap: Map<string, string>): FixSnapshot {
  const mapCopy = new Map<string, string>();
  for (const [k, v] of filesMap.entries()) {
    mapCopy.set(k, v);
  }
  return {
    timestamp: new Date().toISOString(),
    files: mapCopy,
  };
}

/**
 * Evaluates one of the 3 supported fix rules for a target finding.
 */
export function generateFixForRule(
  filesMap: Map<string, string>,
  finding: Finding,
  extra?: { pkgName?: string; fixedVersion?: string }
): FixResult {
  switch (finding.ruleId) {
    case "committed-env-file":
    case "dependency-bump":
      return fixDependencyBump(
        filesMap,
        finding.file,
        extra?.pkgName || "axios",
        extra?.fixedVersion || "1.7.4"
      );

    case "missing-rls-in-migration":
      return fixEnableRLS(filesMap, finding.file);

    case "stripe-webhook-no-signature":
      return fixStripeWebhookVerification(filesMap, finding.file);

    case "idor.owner-column.v1":
      return fixIdorOwnerColumn(filesMap, finding.file);

    default:
      return {
        kind: "suggested-manual",
        ruleId: finding.ruleId,
        targetFile: finding.file,
        reason: `No automated AST fix rule available for rule ID '${finding.ruleId}'`,
        suggestion: `Manually review ${finding.file} against security documentation.`,
      };
  }
}

/**
 * Executes full patch generation, temp workspace verification, snapshot/rollback, and approval preparation.
 */
export async function processFixInTempSandbox(
  repoPath: string,
  filesMap: Map<string, string>,
  finding: Finding,
  scanHeadHash?: string,
  extra?: { pkgName?: string; fixedVersion?: string; initialFindings?: Finding[] }
): Promise<{
  fixResult: FixResult;
  snapshot: FixSnapshot;
  branchChanged: boolean;
}> {
  // 1. Branch Staleness Check
  const currentHeadHash = getGitHeadHash(repoPath);
  const branchChanged = scanHeadHash !== undefined && currentHeadHash !== scanHeadHash;

  if (branchChanged) {
    // Branch changed since initial scan -> trigger rescan before applying fix
    await runScan(repoPath, { json: true });
  }

  // 2. Pre-apply Snapshot
  const snapshot = createFixSnapshot(filesMap);

  // 3. Generate Fix Rule candidate
  const fixCandidate = generateFixForRule(filesMap, finding, extra);

  if (fixCandidate.kind === "suggested-manual") {
    return { fixResult: fixCandidate, snapshot, branchChanged };
  }

  // 4. Create isolated temporary workspace copy
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-fix-sandbox-"));
  try {
    // Copy files to temp sandbox
    for (const [relPath, content] of filesMap.entries()) {
      const fullTempPath = path.join(tempDir, relPath);
      fs.mkdirSync(path.dirname(fullTempPath), { recursive: true });
      fs.writeFileSync(fullTempPath, content, "utf-8");
    }

    const targetTempFile = path.join(tempDir, fixCandidate.targetFile);
    let beforeContent = "";
    if (fs.existsSync(targetTempFile)) {
      beforeContent = fs.readFileSync(targetTempFile, "utf-8");
    }

    // 5. Apply structured edits to original file content
    const editResult = applyStructuredEdits(beforeContent, fixCandidate.edits);
    if (!editResult.success || !editResult.updatedContent) {
      return {
        fixResult: {
          kind: "suggested-manual",
          ruleId: finding.ruleId,
          targetFile: finding.file,
          reason: editResult.reason || "Structured edit application failed due to target text mismatch",
          suggestion: "Apply fix manually and verify local compilation.",
        },
        snapshot,
        branchChanged,
      };
    }

    const updatedContent = editResult.updatedContent;

    // 6. Compute clean unified diff comparing before and after content
    fixCandidate.diff = generateUnifiedDiff(fixCandidate.targetFile, beforeContent, updatedContent);

    // 7. Safety validation on generated diff
    const antiSuppression = validateAntiSuppressionAndDeletion(fixCandidate.diff);
    if (!antiSuppression.valid) {
      return {
        fixResult: {
          kind: "suggested-manual",
          ruleId: finding.ruleId,
          targetFile: finding.file,
          reason: antiSuppression.reason || "Patch rejected by safety validator",
          suggestion: "Manually resolve finding without suppressing rules or deleting code.",
        },
        snapshot,
        branchChanged,
      };
    }

    // Write updated content (valid code) to temp file
    fs.mkdirSync(path.dirname(targetTempFile), { recursive: true });
    fs.writeFileSync(targetTempFile, updatedContent, "utf-8");

    // 8. Run Sandbox Verification Runner
    const verificationReport: VerificationReport = await runSandboxVerification(
      tempDir,
      finding,
      { runTypecheck: true, initialFindings: extra?.initialFindings }
    );

    if (!verificationReport.passed) {
      // Automatic Rollback: discard temp changes and return suggested-manual fallback
      return {
        fixResult: {
          kind: "suggested-manual",
          ruleId: finding.ruleId,
          targetFile: finding.file,
          reason: verificationReport.dropReason || "Sandbox verification failed",
          suggestion: "Apply fix manually and verify local compilation.",
        },
        snapshot,
        branchChanged,
      };
    }

    // 9. Proof Engine Evaluation
    const afterContent = fs.readFileSync(targetTempFile, "utf-8");
    const proofResult = evaluateProof(tempDir, finding.ruleId, beforeContent, afterContent);

    fixCandidate.proofLabel = proofResult.label;
    fixCandidate.verificationReport = verificationReport;

    return { fixResult: fixCandidate, snapshot, branchChanged };
  } finally {
    // Clean up temporary workspace directory
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore temp cleanup errors
    }
  }
}
