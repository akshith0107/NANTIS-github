import { ApprovalFixCard, FixResultAutomated } from "./types.js";
import { PERMISSION_EXPLANATION } from "./permissions-opt-in.js";

/**
 * Creates an Approval UI card model from an automated fix result.
 */
export function createApprovalFixCard(
  findingId: string,
  fixResult: FixResultAutomated
): ApprovalFixCard {
  return {
    findingId,
    ruleId: fixResult.ruleId,
    targetFile: fixResult.targetFile,
    diff: fixResult.diff,
    riskLevel: fixResult.riskLevel,
    blastRadius: fixResult.blastRadius,
    proofLabel: fixResult.proofLabel,
    verificationText: fixResult.verificationReport.summaryText,
    selected: true,
  };
}

/**
 * Formats structured Approval UI text representation for CLI rendering.
 */
export function renderApprovalUIText(
  cards: ApprovalFixCard[],
  options?: {
    branchChanged?: boolean;
    permissionsOptedIn?: boolean;
  }
): string {
  const lines: string[] = [
    "================ NANTIS FIX APPROVAL UI ================",
    "",
  ];

  if (options?.branchChanged) {
    lines.push("⚠️  NOTICE: Git branch/HEAD changed since initial scan. Automatic rescan executed before patch generation.\n");
  }

  if (cards.length === 0) {
    lines.push("No automated fixes available for approval.");
    return lines.join("\n");
  }

  for (let i = 0; i < cards.length; i++) {
    const card = cards[i];
    const checkbox = card.selected ? "[x]" : "[ ]";
    lines.push(`FIX #${i + 1} ${checkbox} Rule: ${card.ruleId} (${card.targetFile})`);
    lines.push(`  • Risk Level:        [${card.riskLevel.toUpperCase()}]`);
    lines.push(`  • Blast Radius:      ${card.blastRadius.affectedFiles.length} file(s) affected (${card.blastRadius.callersAffected.length} caller(s))`);
    lines.push(`  • Proof Label:       ${card.proofLabel}`);
    lines.push(`  • Verification:      ${card.verificationText}`);
    lines.push("  • Diff:");
    for (const dLine of card.diff.split("\n")) {
      lines.push(`      ${dLine}`);
    }
    lines.push("");
  }

  if (options?.permissionsOptedIn) {
    lines.push("--- FIX PR PERMISSIONS ---");
    lines.push(`  • contents: write - ${PERMISSION_EXPLANATION["contents:write"]}`);
    lines.push(`  • pull-requests: write - ${PERMISSION_EXPLANATION["pull-requests:write"]}`);
    lines.push("");
  }

  lines.push("Pass selection choices to apply approved patches.");
  return lines.join("\n");
}
