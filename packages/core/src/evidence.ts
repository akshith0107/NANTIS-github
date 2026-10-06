import { Finding, ConfidenceTier } from "./types.js";

/**
 * Enforces consistency across confidence tiers:
 * - proven: Replayed / deterministic proof (must have no unresolved steps).
 * - likely: Full evidence chain from source to sink with no unresolved steps.
 * - needs-review: Any finding containing 1 or more unresolved steps/hops.
 * - hygiene: Best practice or security posture rule.
 *
 * CRITICAL RULE: A finding with an unresolved hop can NEVER be labelled "likely" or "proven".
 */
export function normalizeFindingConfidence(finding: Finding): Finding {
  const hasUnresolved = Boolean(finding.unresolvedSteps && finding.unresolvedSteps.length > 0);
  let normalizedTier: ConfidenceTier = finding.confidenceTier;

  if (hasUnresolved) {
    if (normalizedTier === "likely" || normalizedTier === "proven") {
      normalizedTier = "needs-review";
    }
  }

  return {
    ...finding,
    confidenceTier: normalizedTier,
  };
}

import { computeResilientFingerprint } from "./fingerprint.js";

/**
 * Creates a normalized Finding object ensuring confidence tier rules and resilient fingerprints are strictly enforced.
 */
export function createFinding(
  findingInput: Omit<Finding, "id" | "fingerprint"> & { id?: string; fingerprint?: string }
): Finding {
  const fullFinding: Finding = {
    ...findingInput,
    id: findingInput.id || crypto.randomUUID(),
    fingerprint: findingInput.fingerprint || "",
  };
  if (!fullFinding.fingerprint) {
    fullFinding.fingerprint = computeResilientFingerprint(fullFinding);
  }
  return normalizeFindingConfidence(fullFinding);
}

/**
 * Renders an evidence chain (with hops and unresolved steps) into structured HTML steps for Web UI display.
 */
export function renderEvidenceChainAsStepsHtml(finding: Finding): string {
  const hops = finding.evidenceChain || [];
  const unresolved = finding.unresolvedSteps || [];
  const totalSteps = hops.length + unresolved.length;

  if (totalSteps === 0) {
    return `<div class="evidence-chain-empty"><p>No evidence steps recorded.</p></div>`;
  }

  const stepsHtml: string[] = [];
  let stepIndex = 1;

  for (const hop of hops) {
    const kindClass = `badge-${hop.kind.toLowerCase()}`;
    const confidenceClass = `confidence-${hop.confidence}`;
    const snippetHtml = hop.maskedSnippet
      ? `<pre class="step-code"><code>${escapeHtml(hop.maskedSnippet)}</code></pre>`
      : "";

    stepsHtml.push(`
      <li class="evidence-step evidence-step-${hop.kind.toLowerCase()}">
        <div class="step-header">
          <span class="step-number">Step ${stepIndex}</span>
          <span class="step-badge ${kindClass}">[${hop.kind.toUpperCase()}]</span>
          <span class="step-location">${escapeHtml(hop.file)}:${hop.line}</span>
          <span class="step-confidence ${confidenceClass}">${hop.confidence} confidence</span>
        </div>
        <div class="step-note">${escapeHtml(hop.note)}</div>
        ${snippetHtml}
      </li>
    `);
    stepIndex++;
  }

  for (const unres of unresolved) {
    stepsHtml.push(`
      <li class="evidence-step evidence-step-unresolved">
        <div class="step-header">
          <span class="step-number">Step ${stepIndex}</span>
          <span class="step-badge badge-unresolved">[UNRESOLVED]</span>
          <span class="step-location">${escapeHtml(unres.location.file)}:${unres.location.line}</span>
          <span class="step-reason">Reason: ${escapeHtml(unres.reason)}</span>
        </div>
        <div class="step-note">${escapeHtml(unres.description)}</div>
      </li>
    `);
    stepIndex++;
  }

  return `
    <div class="evidence-chain-container">
      <h4 class="evidence-chain-title">Evidence Chain Steps (${totalSteps})</h4>
      <ol class="evidence-chain-steps">
        ${stepsHtml.join("\n")}
      </ol>
    </div>
  `.trim();
}

/**
 * Renders an evidence chain into readable plain text / CLI format.
 */
export function renderEvidenceChainAsStepsText(finding: Finding): string {
  const hops = finding.evidenceChain || [];
  const unresolved = finding.unresolvedSteps || [];
  const totalSteps = hops.length + unresolved.length;

  if (totalSteps === 0) {
    return "Evidence Chain: No steps recorded.";
  }

  const lines: string[] = [`Evidence Chain (${totalSteps} steps):`];
  let stepIndex = 1;

  for (const hop of hops) {
    lines.push(
      `  Step ${stepIndex} [${hop.kind.toUpperCase()}] ${hop.file}:${hop.line} (${hop.confidence} confidence)`
    );
    lines.push(`         Note: ${hop.note}`);
    if (hop.maskedSnippet) {
      lines.push(`         Code: ${hop.maskedSnippet.replace(/\n/g, "\n               ")}`);
    }
    stepIndex++;
  }

  for (const unres of unresolved) {
    lines.push(
      `  Step ${stepIndex} [UNRESOLVED] ${unres.location.file}:${unres.location.line} (${unres.reason})`
    );
    lines.push(`         Description: ${unres.description}`);
    stepIndex++;
  }

  return lines.join("\n");
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
