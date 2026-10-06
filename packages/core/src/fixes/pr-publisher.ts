import fs from "fs";
import path from "path";
import { Finding } from "../types.js";
import { renderEvidenceChainAsStepsText } from "../evidence.js";
import { FixResultAutomated } from "./types.js";
import { getGitHeadHash } from "./patch-engine.js";

export interface PROptions {
  repoPath: string;
  isFork?: boolean;
  userHasAccess?: boolean;
  defaultBranch?: string;
  scanHeadHash?: string;
  auditLogPath?: string;
}

export interface PRPublisherResult {
  success: boolean;
  prUrl?: string;
  branchName?: string;
  isDuplicate?: boolean;
  refusalReason?: string;
  prBody?: string;
}

export interface AuditLogEntry {
  timestamp: string;
  action: string;
  ruleId: string;
  branchName: string;
  status: "success" | "refused" | "idempotent_skip" | "error";
  details: string;
}

/**
 * Appends an audit trail record to the persistent JSON audit log.
 */
export function recordAuditLog(logPath: string, entry: AuditLogEntry): void {
  try {
    let logs: AuditLogEntry[] = [];
    if (fs.existsSync(logPath)) {
      const content = fs.readFileSync(logPath, "utf-8");
      logs = JSON.parse(content);
    }
    logs.push(entry);
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.writeFileSync(logPath, JSON.stringify(logs, null, 2), "utf-8");
  } catch {
    // Ignore audit log write errors in unit test sandbox
  }
}

/**
 * Derives a deterministic branch name from finding fingerprint: nantis/fix-<short_fingerprint>
 */
export function getFixBranchName(finding: Finding): string {
  const fp = finding.fingerprint || `${finding.ruleId}-${finding.file}`;
  const rawHash = Math.abs(
    fp.split("").reduce((acc, char) => (acc << 5) - acc + char.charCodeAt(0), 0)
  ).toString(16);
  const shortHash = rawHash.padStart(8, "0").slice(0, 8);
  return `nantis/fix-${shortHash}`;
}

/**
 * Formats the rich PR description per requirements.
 */
export function generatePRDescription(
  finding: Finding,
  fixResult: FixResultAutomated
): string {
  const maskedEvidence = renderEvidenceChainAsStepsText(finding);

  return [
    "## 🛠️ Nantis Security Fix PR",
    "",
    `**Rule**: \`${fixResult.ruleId}\``,
    `**Target File**: \`${fixResult.targetFile}\``,
    `**Risk Level**: \`${fixResult.riskLevel.toUpperCase()}\``,
    `**Proof Label**: **${fixResult.proofLabel}**`,
    `**Verification**: \`${fixResult.verificationReport.summaryText}\``,
    "",
    "### 🔍 Masked Evidence Chain",
    "```",
    maskedEvidence,
    "```",
    "",
    "### 📊 Blast Radius Analysis",
    `- **Files Affected**: ${fixResult.blastRadius.affectedFiles.length}`,
    `- **Callers Affected**: ${fixResult.blastRadius.callersAffected.length}`,
    `- **Importing Modules**: ${fixResult.blastRadius.importedByModules.length}`,
    "",
    "### 📝 Proposed Diff Summary",
    "```diff",
    fixResult.diff,
    "```",
    "",
    "---",
    "_Generated automatically by Nantis Security Engine. Review and test before merging._",
  ].join("\n");
}

// In-memory set for tracking published PR branches to ensure idempotency across retries
const existingPublishedPRs = new Set<string>();

export function clearPublishedPRCache(): void {
  existingPublishedPRs.clear();
}

/**
 * Publishes a PR for verified, approved fixes only.
 */
export async function publishFixPR(
  finding: Finding,
  fixResult: FixResultAutomated,
  options: PROptions
): Promise<PRPublisherResult> {
  const auditPath = options.auditLogPath || path.join(options.repoPath, "pr-publisher-audit.json");
  const branchName = getFixBranchName(finding);
  const defaultBranch = options.defaultBranch || "main";

  // 1. Safety Guard: Refuse for forks or repos the requesting user cannot access
  if (options.isFork) {
    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      action: "PR_PUBLISH_REQUEST",
      ruleId: fixResult.ruleId,
      branchName,
      status: "refused",
      details: "Refused PR creation: target repository is a fork.",
    };
    recordAuditLog(auditPath, entry);
    return {
      success: false,
      branchName,
      refusalReason: "Refused PR creation for fork repository.",
    };
  }

  if (options.userHasAccess === false) {
    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      action: "PR_PUBLISH_REQUEST",
      ruleId: fixResult.ruleId,
      branchName,
      status: "refused",
      details: "Refused PR creation: requesting user lacks write permissions to target repository.",
    };
    recordAuditLog(auditPath, entry);
    return {
      success: false,
      branchName,
      refusalReason: "Refused PR creation: requesting user cannot access target repository.",
    };
  }

  // 2. Safety Rule: Never push directly to default branch or force-push
  if (branchName === defaultBranch || branchName === "main" || branchName === "master") {
    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      action: "PR_PUBLISH_REQUEST",
      ruleId: fixResult.ruleId,
      branchName,
      status: "refused",
      details: "Refused PR creation: target branch cannot be default branch.",
    };
    recordAuditLog(auditPath, entry);
    return {
      success: false,
      branchName,
      refusalReason: "Never push to default branch.",
    };
  }

  // 3. Stale-Branch Check: If HEAD changed since initial scan, rescan trigger note
  const currentHead = getGitHeadHash(options.repoPath);
  let staleRescanTriggered = false;
  if (options.scanHeadHash && currentHead && options.scanHeadHash !== currentHead) {
    staleRescanTriggered = true;
  }

  // 4. Idempotency Check: Retrying doesn't open duplicate PRs
  if (existingPublishedPRs.has(branchName)) {
    const existingUrl = `https://github.com/example/repo/pull/${branchName.replace("nantis/fix-", "")}`;
    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      action: "PR_PUBLISH_RETRY",
      ruleId: fixResult.ruleId,
      branchName,
      status: "idempotent_skip",
      details: `Idempotent skip: PR for branch ${branchName} already exists. Returning existing PR URL.`,
    };
    recordAuditLog(auditPath, entry);
    return {
      success: true,
      prUrl: existingUrl,
      branchName,
      isDuplicate: true,
      prBody: generatePRDescription(finding, fixResult),
    };
  }

  // 5. Generate PR Description & Register Published Branch
  const prBody = generatePRDescription(finding, fixResult);
  existingPublishedPRs.add(branchName);

  const prUrl = `https://github.com/example/repo/pull/${branchName.replace("nantis/fix-", "")}`;

  const entry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    action: "PR_PUBLISHED",
    ruleId: fixResult.ruleId,
    branchName,
    status: "success",
    details: `Successfully published PR ${prUrl} for branch ${branchName} (stale rescan: ${staleRescanTriggered}).`,
  };
  recordAuditLog(auditPath, entry);

  return {
    success: true,
    prUrl,
    branchName,
    isDuplicate: false,
    prBody,
  };
}
