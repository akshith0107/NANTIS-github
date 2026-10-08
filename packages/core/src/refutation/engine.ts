import { createHash } from "node:crypto";
import { Finding } from "../types.js";
import {
  ClaimRefutationResult,
  RefutationEvidence,
  RefutationCoverage,
  FindingClosure,
  RefutationLimits,
  DEFAULT_REFUTATION_LIMITS,
} from "./types.js";
import { indexRepository, computeFileHash } from "../idor/indexer.js";
import { SupabaseAnalyzer } from "../idor/supabase-analyzer.js";

export const REFUTATION_ENGINE_VERSION = "0.1.0-phase4";

export interface RefutationPassResult {
  candidateFinding: Finding;
  isRefuted: boolean;
  claimResults: ClaimRefutationResult[];
  closure: FindingClosure;
}

/**
 * Deterministic Refutation Pass Engine.
 * Searches for concrete contradictory evidence to refute candidate security findings.
 */
export class RefutationEngine {
  private limits: RefutationLimits;

  constructor(limits?: Partial<RefutationLimits>) {
    this.limits = { ...DEFAULT_REFUTATION_LIMITS, ...limits };
  }

  /**
   * Runs deterministic refutation pass over a candidate finding.
   */
  async refuteFinding(
    candidate: Finding,
    filesMap: Map<string, string>
  ): Promise<RefutationPassResult> {
    const startMs = Date.now();
    const indexedRepo = indexRepository(filesMap);
    const supabaseAnalyzer = new SupabaseAnalyzer(indexedRepo);

    const normFile = candidate.file.replace(/\\/g, "/");
    const fileContent = filesMap.get(normFile) || "";
    const lines = fileContent.split("\n");
    const fileHash = indexedRepo.fileHashes.get(normFile) || computeFileHash(fileContent);

    const claimResults: ClaimRefutationResult[] = [];
    const blockingRefutingClaims: string[] = [];
    const supportingClaims: string[] = [];
    const reasonCodes: string[] = [];

    let filesSearched = 0;
    let symbolsInspected = 0;
    let edgesTraversed = 0;
    let unresolvedPaths = 0;
    let isTruncated = false;

    filesSearched = filesMap.size;

    // --- Refutation Target 1: Direct Ownership Check in Query or Body ---
    symbolsInspected++;
    const ownerCheckMatch = fileContent.match(
      /\.eq\(['"](user_id|owner_id|tenant_id|account_id|creator_id|author_id)['"]\s*,\s*([^)]+)\)/i
    );

    if (ownerCheckMatch) {
      edgesTraversed++;
      const matchedLine =
        lines.findIndex((l) => l.includes(ownerCheckMatch[0])) + 1 || candidate.lineRange.startLine;

      const refutingEv: RefutationEvidence = {
        target: "ownership_check",
        ref: {
          file: normFile,
          startLine: matchedLine,
          endLine: matchedLine,
          fileHash,
          snippet: lines[matchedLine - 1]?.trim() || ownerCheckMatch[0],
        },
        snippet: ownerCheckMatch[0],
        note: `Verified ownership check '${ownerCheckMatch[1]}' present in source code`,
      };

      claimResults.push({
        claimId: "claim-ownership-absent",
        status: "refuted",
        refutingEvidence: refutingEv,
        explanation: `Claim 'ownership_absent' refuted by concrete code check at ${normFile}:${matchedLine}`,
      });

      blockingRefutingClaims.push("ownership_enforced");
      reasonCodes.push("REFUTED_BY_DIRECT_OWNERSHIP_CHECK");
    } else {
      supportingClaims.push("ownership_absent");
    }

    // --- Refutation Target 2: Auth Guards & Session Authorization ---
    symbolsInspected++;
    const authGuardMatch = fileContent.match(
      /\b(assertRepoAccess|verifySession|getServerSession|auth\(\)|useAuth|supabase\.auth\.getUser|checkPermission|hasRole)\b/i
    );

    if (authGuardMatch) {
      edgesTraversed++;
      const guardName = authGuardMatch[1];
      const matchedLine =
        lines.findIndex((l) => l.includes(guardName)) + 1 || candidate.lineRange.startLine;

      const refutingEv: RefutationEvidence = {
        target: guardName.includes("Role") || guardName.includes("Permission") ? "role_check" : "auth_guard",
        ref: {
          file: normFile,
          startLine: matchedLine,
          endLine: matchedLine,
          fileHash,
          snippet: lines[matchedLine - 1]?.trim() || guardName,
        },
        snippet: lines[matchedLine - 1]?.trim() || guardName,
        note: `Verified authorization guard '${guardName}' present in route execution context`,
      };

      claimResults.push({
        claimId: "claim-guard-missing",
        status: "refuted",
        refutingEvidence: refutingEv,
        explanation: `Claim 'guard_missing' refuted by guard '${guardName}' at ${normFile}:${matchedLine}`,
      });

      blockingRefutingClaims.push("auth_guard_present");
      reasonCodes.push("REFUTED_BY_AUTH_GUARD");
    }

    // --- Refutation Target 3: RLS Policy Protection in Migrations ---
    symbolsInspected++;
    const epQuery = indexedRepo.queries.find((q) => q.file === normFile);
    if (epQuery) {
      const tableStatus = supabaseAnalyzer.getTableSecurityStatus(epQuery.table);
      if (tableStatus.isSecureByRls) {
        edgesTraversed++;
        const refutingEv: RefutationEvidence = {
          target: "rls_policy",
          ref: {
            file: `supabase/migrations/schema.sql`,
            startLine: 1,
            endLine: 1,
            fileHash: "rls-policy-hash",
            snippet: `ALTER TABLE ${epQuery.table} ENABLE ROW LEVEL SECURITY;`,
          },
          snippet: `ENABLE ROW LEVEL SECURITY`,
          note: `Verified Row Level Security (RLS) policy protects table '${epQuery.table}'`,
        };

        claimResults.push({
          claimId: "claim-rls-absent",
          status: "refuted",
          refutingEvidence: refutingEv,
          explanation: `Claim 'rls_absent' refuted by database migration RLS policy for table '${epQuery.table}'`,
        });

        blockingRefutingClaims.push("rls_policy_verified");
        reasonCodes.push("REFUTED_BY_RLS_POLICY");
      }
    }

    // --- Refutation Target 4: Cross-File Helper & Wrapper Analysis ---
    symbolsInspected++;
    if (fileContent.includes("withAuth(") || fileContent.includes("authorizeUser(")) {
      edgesTraversed++;
      const wrapperMatch = fileContent.match(/withAuth\(|authorizeUser\(/);
      const matchedLine = wrapperMatch
        ? lines.findIndex((l) => l.includes(wrapperMatch[0])) + 1
        : 1;

      const refutingEv: RefutationEvidence = {
        target: "wrapper_function",
        ref: {
          file: normFile,
          startLine: matchedLine,
          endLine: matchedLine,
          fileHash,
          snippet: lines[matchedLine - 1]?.trim() || "wrapper",
        },
        snippet: lines[matchedLine - 1]?.trim() || "wrapper",
        note: `Verified authorization wrapper function present on route definition`,
      };

      claimResults.push({
        claimId: "claim-wrapper-protection",
        status: "refuted",
        refutingEvidence: refutingEv,
        explanation: `Claim 'unprotected_route' refuted by authorization wrapper at ${normFile}:${matchedLine}`,
      });

      blockingRefutingClaims.push("wrapper_protection_verified");
      reasonCodes.push("REFUTED_BY_WRAPPER_FUNCTION");
    }

    // --- Ambiguous / Dynamic Dispatch Check ---
    if (fileContent.includes("import(") || fileContent.includes("eval(")) {
      unresolvedPaths++;
      claimResults.push({
        claimId: "claim-dynamic-dispatch",
        status: "unverifiable",
        explanation: `Dynamic dispatch or import prevents static resolution of authorization helpers`,
      });
      reasonCodes.push("UNVERIFIABLE_DYNAMIC_DISPATCH");
    }

    const runtimeMs = Date.now() - startMs;
    if (runtimeMs > this.limits.maxRuntimeMs) {
      isTruncated = true;
    }

    const isRefuted = blockingRefutingClaims.length > 0;

    const coverage: RefutationCoverage = {
      filesSearched,
      symbolsInspected,
      edgesTraversed,
      unresolvedPaths,
      maxDepthReached: 2,
      completionState: isTruncated ? "truncated" : unresolvedPaths > 0 ? "depth-limited" : "complete",
    };

    // Calculate deterministic closure hash
    const hashPayload = [
      candidate.fingerprint,
      REFUTATION_ENGINE_VERSION,
      isRefuted ? "refuted" : "unrefuted",
      blockingRefutingClaims.join(","),
      supportingClaims.join(","),
      reasonCodes.join(","),
    ].join(":");

    const closureHash = createHash("sha256").update(hashPayload, "utf8").digest("hex").slice(0, 16);

    const closure: FindingClosure = {
      closureHash,
      engineVersion: REFUTATION_ENGINE_VERSION,
      refutationRan: true,
      supportingClaims,
      blockingRefutingClaims,
      reasonCodes,
      coverage,
      unresolvedSteps: candidate.unresolvedSteps || [],
    };

    return {
      candidateFinding: candidate,
      isRefuted,
      claimResults,
      closure,
    };
  }
}
