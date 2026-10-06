import { describe, expect, it } from "vitest";
import {
  RULE_EXPLANATIONS,
  getRuleExplanation,
} from "../src/rule-docs.js";
import {
  generateHumanReviewChecklist,
  renderHumanReviewChecklistText,
} from "../src/human-review-checklist.js";

describe("Rule Explanations & Human Review Checklist", () => {
  it("provides structured explanations for all registered rules", () => {
    const ruleIds = Object.keys(RULE_EXPLANATIONS);
    expect(ruleIds.length).toBeGreaterThan(15);

    for (const id of ruleIds) {
      const exp = RULE_EXPLANATIONS[id];
      expect(exp.ruleId).toBe(id);
      expect(exp.title).toBeTruthy();
      expect(exp.whatsWrong).toBeTruthy();
      expect(exp.howStrangerCouldAbuseIt).toBeTruthy();
      expect(exp.howToFixIt).toBeTruthy();
    }
  });

  it("returns fallback explanation for unknown rule IDs", () => {
    const unknown = getRuleExplanation("custom-rule-xyz");
    expect(unknown.ruleId).toBe("custom-rule-xyz");
    expect(unknown.whatsWrong).toContain("custom-rule-xyz");
    expect(unknown.howStrangerCouldAbuseIt).toBeTruthy();
    expect(unknown.howToFixIt).toBeTruthy();
  });

  it("generates human review checklist for payments, admin, and role code", () => {
    const filesMap = new Map<string, string>([
      ["apps/web/src/app/api/stripe/webhook/route.ts", "const sig = req.headers.get('stripe-signature');"],
      ["apps/web/src/app/admin/users/page.ts", "export function AdminUsers() {}"],
      ["apps/web/src/lib/auth/session.ts", "export function getSession() {}"],
    ]);

    const checklist = generateHumanReviewChecklist(filesMap);

    expect(checklist.payments.length).toBeGreaterThan(0);
    expect(checklist.admin.length).toBeGreaterThan(0);
    expect(checklist.roles.length).toBeGreaterThan(0);

    expect(checklist.payments[0].relevantFiles).toContain("apps/web/src/app/api/stripe/webhook/route.ts");
    expect(checklist.admin[0].relevantFiles).toContain("apps/web/src/app/admin/users/page.ts");
    expect(checklist.roles[0].relevantFiles).toContain("apps/web/src/lib/auth/session.ts");

    const text = renderHumanReviewChecklistText(checklist);
    expect(text).toContain("PAYMENTS (Stripe & Billing)");
    expect(text).toContain("ADMIN OPERATIONS & ENDPOINTS");
    expect(text).toContain("ROLE-BASED ACCESS CONTROL (RBAC)");
  });
});
