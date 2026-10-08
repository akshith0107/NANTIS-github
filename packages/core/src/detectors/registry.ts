import { detectCiIssues } from "./ci-audit.js";
import { detectConfigIssues } from "./config.js";
import { detectDependencies } from "./dependencies.js";
import { scanGitHistory } from "./git-history.js";
import {
  detectServerActionAuthIssues,
  detectMiddlewareMatcherGaps,
  detectMissingOwnershipChecks,
  detectMassAssignmentIssues,
  detectApiRouteAuthIssues,
} from "./nextjs-rules.js";
import { detectSecrets } from "./secrets.js";
import {
  detectStripeWebhookIssues,
  detectStripeWebhookParsedBody,
  detectStripeUserControlledPrice,
  detectStripeSecretKeyClientLeak,
} from "./stripe.js";
import {
  detectMissingRlsInMigrations,
  detectPermissivePolicies,
  detectServiceRoleLeaks,
  detectStorageBucketIssues,
} from "./supabase.js";
import { detectTestGaps } from "./test-gap.js";
import { maskSecrets } from "../masking.js";
import { DetectorRunResult, Finding, ScanDiagnostic } from "../types.js";

export interface DetectorContext {
  targetFolder?: string;
  offlineMode?: boolean;
}

export interface DetectorDefinition {
  id: string;
  name: string;
  file: string;
  run: (filesMap: Map<string, string>, context?: DetectorContext) => Promise<Finding[]>;
}

export const DETECTOR_REGISTRY: DetectorDefinition[] = [
  {
    id: "detectSecrets",
    name: "Detect Hardcoded Secrets",
    file: "secrets.ts",
    run: (filesMap) => detectSecrets(filesMap),
  },
  {
    id: "detectDependencies",
    name: "Detect Vulnerable & Loose Dependencies",
    file: "dependencies.ts",
    run: (filesMap, ctx) => detectDependencies(filesMap, { offlineMode: ctx?.offlineMode }),
  },
  {
    id: "detectConfigIssues",
    name: "Detect Configuration Security Issues",
    file: "config.ts",
    run: (filesMap) => detectConfigIssues(filesMap),
  },
  {
    id: "detectCiIssues",
    name: "Detect CI Workflow Security Issues",
    file: "ci-audit.ts",
    run: (filesMap) => detectCiIssues(filesMap),
  },
  {
    id: "detectApiRouteAuthIssues",
    name: "Detect Unprotected API Routes",
    file: "nextjs-rules.ts",
    run: (filesMap) => detectApiRouteAuthIssues(filesMap),
  },
  {
    id: "detectMissingRlsInMigrations",
    name: "Detect Missing RLS in Database Migrations",
    file: "supabase.ts",
    run: (filesMap) => detectMissingRlsInMigrations(filesMap),
  },
  {
    id: "detectStripeWebhookIssues",
    name: "Detect Unverified Stripe Webhooks",
    file: "stripe.ts",
    run: (filesMap) => detectStripeWebhookIssues(filesMap),
  },
  {
    id: "detectServerActionAuthIssues",
    name: "Detect Unprotected Next.js Server Actions",
    file: "nextjs-rules.ts",
    run: (filesMap) => detectServerActionAuthIssues(filesMap),
  },
  {
    id: "detectMiddlewareMatcherGaps",
    name: "Detect Next.js Middleware Matcher Gaps",
    file: "nextjs-rules.ts",
    run: (filesMap) => detectMiddlewareMatcherGaps(filesMap),
  },
  {
    id: "detectMissingOwnershipChecks",
    name: "Detect Missing Resource Ownership Checks",
    file: "nextjs-rules.ts",
    run: (filesMap) => detectMissingOwnershipChecks(filesMap),
  },
  {
    id: "detectMassAssignmentIssues",
    name: "Detect Supabase Mass Assignment Gaps",
    file: "nextjs-rules.ts",
    run: (filesMap) => detectMassAssignmentIssues(filesMap),
  },
  {
    id: "detectPermissivePolicies",
    name: "Detect Overly Permissive Supabase RLS Policies",
    file: "supabase.ts",
    run: (filesMap) => detectPermissivePolicies(filesMap),
  },
  {
    id: "detectServiceRoleLeaks",
    name: "Detect Supabase Service Role Key Leaks",
    file: "supabase.ts",
    run: (filesMap) => detectServiceRoleLeaks(filesMap),
  },
  {
    id: "detectStorageBucketIssues",
    name: "Detect Public Storage Bucket Data Exposure",
    file: "supabase.ts",
    run: (filesMap) => detectStorageBucketIssues(filesMap),
  },
  {
    id: "detectStripeWebhookParsedBody",
    name: "Detect Stripe Webhook Parsed Body Bypasses",
    file: "stripe.ts",
    run: (filesMap) => detectStripeWebhookParsedBody(filesMap),
  },
  {
    id: "detectStripeUserControlledPrice",
    name: "Detect User-Controlled Stripe Checkout Prices",
    file: "stripe.ts",
    run: (filesMap) => detectStripeUserControlledPrice(filesMap),
  },
  {
    id: "detectStripeSecretKeyClientLeak",
    name: "Detect Stripe Secret Key Client-Side Leaks",
    file: "stripe.ts",
    run: (filesMap) => detectStripeSecretKeyClientLeak(filesMap),
  },
  {
    id: "detectTestGaps",
    name: "Detect Untested Security-Sensitive Routes",
    file: "test-gap.ts",
    run: (filesMap, ctx) => detectTestGaps(filesMap, ctx?.targetFolder),
  },
  {
    id: "scanGitHistory",
    name: "Scan Git History for Exposed Secrets",
    file: "git-history.ts",
    run: async (_filesMap, ctx) => {
      if (!ctx?.targetFolder) return [];
      try {
        return await scanGitHistory(ctx.targetFolder);
      } catch {
        return [];
      }
    },
  },
];

export function sanitizeDiagnosticMessage(err: unknown): string {
  const rawMsg = err instanceof Error ? err.message : String(err);
  let sanitized = maskSecrets(rawMsg);
  sanitized = sanitized.split("\n")[0];
  sanitized = sanitized.replace(/[A-Za-z]:\\[^:\n\s]+/g, "[REDACTED_PATH]");
  sanitized = sanitized.replace(/\/[^:\n\s]+\//g, "[REDACTED_PATH]/");
  return sanitized.trim() || "Detector execution encountered an unexpected error";
}

export async function runAllDetectors(
  filesMap: Map<string, string>,
  context: DetectorContext = {}
): Promise<DetectorRunResult> {
  const allFindings: Finding[] = [];
  const diagnostics: ScanDiagnostic[] = [];

  for (const detector of DETECTOR_REGISTRY) {
    try {
      const findings = await detector.run(filesMap, context);
      allFindings.push(...findings);
    } catch (err: unknown) {
      const sanitizedMsg = sanitizeDiagnosticMessage(err);
      diagnostics.push({
        kind: "detector_error",
        detectorId: detector.id,
        detectorName: detector.name,
        message: `Detector '${detector.name}' failed during analysis: ${sanitizedMsg}`,
        fatal: false,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return { findings: allFindings, diagnostics };
}
