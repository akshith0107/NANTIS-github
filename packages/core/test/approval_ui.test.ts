import { describe, expect, it } from "vitest";
import {
  createApprovalFixCard,
  renderApprovalUIText,
  FixResultAutomated,
} from "../src/fixes/index.js";

describe("Approval UI & Branch Staleness Rescan", () => {
  const dummyAutomatedFix: FixResultAutomated = {
    kind: "automated",
    ruleId: "stripe-webhook-no-signature",
    targetFile: "apps/web/src/app/api/webhooks/stripe/route.ts",
    edits: [],
    diff: "--- route.ts\n+++ route.ts\n+ const signature = req.headers.get('stripe-signature');\n",
    riskLevel: "medium",
    blastRadius: {
      affectedFiles: ["apps/web/src/app/api/webhooks/stripe/route.ts"],
      callersAffected: ["handleStripeWebhook"],
      importedByModules: [],
      riskLevel: "medium",
    },
    proofLabel: "Proven by handler replay",
    verificationReport: {
      passed: true,
      checksRun: ["rescan", "tsc"],
      summaryText: "verified: rescan + tsc; no tests found",
    },
  };

  it("renders Approval UI card with diff, risk level, blast radius, proof label, and verification text", () => {
    const card = createApprovalFixCard("finding-123", dummyAutomatedFix);

    expect(card.ruleId).toBe("stripe-webhook-no-signature");
    expect(card.riskLevel).toBe("medium");
    expect(card.proofLabel).toBe("Proven by handler replay");
    expect(card.verificationText).toBe("verified: rescan + tsc; no tests found");

    const text = renderApprovalUIText([card]);

    expect(text).toContain("FIX #1");
    expect(text).toContain("stripe-webhook-no-signature");
    expect(text).toContain("[MEDIUM]");
    expect(text).toContain("Proven by handler replay");
    expect(text).toContain("verified: rescan + tsc; no tests found");
  });

  it("displays branch staleness rescan notice when branch changed since scan", () => {
    const card = createApprovalFixCard("finding-123", dummyAutomatedFix);
    const text = renderApprovalUIText([card], { branchChanged: true });

    expect(text).toContain("Git branch/HEAD changed since initial scan");
    expect(text).toContain("Automatic rescan executed before patch generation");
  });
});
