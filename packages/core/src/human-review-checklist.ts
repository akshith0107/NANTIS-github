export interface ChecklistItem {
  id: string;
  category: "payments" | "admin" | "roles";
  question: string;
  recommendation: string;
  relevantFiles?: string[];
}

export interface HumanReviewChecklist {
  payments: ChecklistItem[];
  admin: ChecklistItem[];
  roles: ChecklistItem[];
}

/**
 * Generates a human review checklist for payments, admin, and role-based access control (RBAC) code.
 */
export function generateHumanReviewChecklist(
  filesMap: Map<string, string>
): HumanReviewChecklist {
  const files = Array.from(filesMap.keys());

  const paymentFiles = files.filter((f) =>
    /stripe|payment|checkout|billing|invoice|webhook/i.test(f)
  );
  const adminFiles = files.filter((f) =>
    /admin|dashboard|management|internal/i.test(f)
  );
  const roleFiles = files.filter((f) =>
    /role|permission|rbac|access|grant|session|auth/i.test(f)
  );

  return {
    payments: [
      {
        id: "pay-1",
        category: "payments",
        question:
          "Does Stripe webhook signature verification receive raw unparsed body bytes?",
        recommendation:
          "Pass raw request body string/buffer (req.text()) to stripe.webhooks.constructEvent(). Re-serializing parsed JSON alters formatting and invalidates signatures.",
        relevantFiles: paymentFiles,
      },
      {
        id: "pay-2",
        category: "payments",
        question:
          "Are item prices and unit_amount values fetched directly from database rather than trusted client input?",
        recommendation:
          "Verify price values on the server (dbProduct.price) before initializing Checkout Session or PaymentIntent.",
        relevantFiles: paymentFiles,
      },
      {
        id: "pay-3",
        category: "payments",
        question:
          "Are webhook event handlers idempotent to handle duplicate delivery retries safely?",
        recommendation:
          "Record processed event IDs in database before applying fulfillments to prevent duplicate credit/order provisioning.",
        relevantFiles: paymentFiles,
      },
      {
        id: "pay-4",
        category: "payments",
        question:
          "Is STRIPE_SECRET_KEY strictly isolated from client-side bundles?",
        recommendation:
          "Ensure STRIPE_SECRET_KEY is referenced only in server-side API routes or Server Actions, never in 'use client' components.",
        relevantFiles: paymentFiles,
      },
    ],
    admin: [
      {
        id: "adm-1",
        category: "admin",
        question:
          "Do administrative endpoints verify user role (user.role === 'admin') on the server?",
        recommendation:
          "Perform explicit role assertions at the start of admin route handlers using authenticated session data.",
        relevantFiles: adminFiles,
      },
      {
        id: "adm-2",
        category: "admin",
        question:
          "Are sensitive administrative operations logged to an immutable audit log?",
        recommendation:
          "Record audit log entries for account deletions, tenant modifications, and role updates with user ID and timestamp.",
        relevantFiles: adminFiles,
      },
      {
        id: "adm-3",
        category: "admin",
        question:
          "Are admin route paths excluded from public middleware matcher rules?",
        recommendation:
          "Enforce strict middleware auth guards or local handler guards on all /api/admin/* endpoints.",
        relevantFiles: adminFiles,
      },
    ],
    roles: [
      {
        id: "rol-1",
        category: "roles",
        question:
          "Do database queries enforce tenant / user ownership filters (.eq('tenant_id', session.tenantId))?",
        recommendation:
          "Include user or tenant ID filters in every database SELECT, UPDATE, and DELETE query to prevent IDOR.",
        relevantFiles: roleFiles,
      },
      {
        id: "rol-2",
        category: "roles",
        question:
          "Do Server Actions validate caller permissions before mutating database state?",
        recommendation:
          "Call authorization assertion helpers at the top of exported Server Action functions.",
        relevantFiles: roleFiles,
      },
      {
        id: "rol-3",
        category: "roles",
        question:
          "Are user role escalations (e.g. member -> owner) restricted to authorized account owners?",
        recommendation:
          "Validate current user permissions before updating role fields in user management handlers.",
        relevantFiles: roleFiles,
      },
    ],
  };
}

/**
 * Renders the Human Review Checklist into plain text CLI format.
 */
export function renderHumanReviewChecklistText(
  checklist: HumanReviewChecklist
): string {
  const lines: string[] = [
    "================ NEEDS HUMAN REVIEW CHECKLIST ================",
    "",
    "PAYMENTS (Stripe & Billing):",
  ];

  for (const item of checklist.payments) {
    lines.push(`  [ ] ${item.question}`);
    lines.push(`      Recommendation: ${item.recommendation}`);
    if (item.relevantFiles && item.relevantFiles.length > 0) {
      lines.push(`      Files: ${item.relevantFiles.slice(0, 3).join(", ")}`);
    }
  }

  lines.push("");
  lines.push("ADMIN OPERATIONS & ENDPOINTS:");
  for (const item of checklist.admin) {
    lines.push(`  [ ] ${item.question}`);
    lines.push(`      Recommendation: ${item.recommendation}`);
    if (item.relevantFiles && item.relevantFiles.length > 0) {
      lines.push(`      Files: ${item.relevantFiles.slice(0, 3).join(", ")}`);
    }
  }

  lines.push("");
  lines.push("ROLE-BASED ACCESS CONTROL (RBAC):");
  for (const item of checklist.roles) {
    lines.push(`  [ ] ${item.question}`);
    lines.push(`      Recommendation: ${item.recommendation}`);
    if (item.relevantFiles && item.relevantFiles.length > 0) {
      lines.push(`      Files: ${item.relevantFiles.slice(0, 3).join(", ")}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}
