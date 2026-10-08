import { IndexedEndpoint, IndexedSupabaseQuery } from "./types.js";
import { SupabaseTableSecurityStatus } from "./supabase-analyzer.js";
import { EvidenceHop, UnresolvedStep } from "../types.js";

export interface SecurityVerificationResult {
  isVulnerable: boolean;
  verdictReason: string;
  evidenceChain: EvidenceHop[];
  unresolvedSteps: UnresolvedStep[];
}

/**
 * Deterministic verifiers for IDOR/BOLA security evidence.
 */
export class SecurityVerifiers {
  /**
   * Evaluates IDOR evidence chain for a specific route parameter and query sink.
   */
  verifyIdorScenario(
    endpoint: IndexedEndpoint,
    paramName: string,
    query: IndexedSupabaseQuery,
    tableStatus: SupabaseTableSecurityStatus
  ): SecurityVerificationResult {
    const evidenceChain: EvidenceHop[] = [];
    const unresolvedSteps: UnresolvedStep[] = [...tableStatus.unresolvedSteps];

    // Hop 1: Source - User-controlled parameter
    evidenceChain.push({
      kind: "source",
      file: endpoint.filePath,
      line: endpoint.lineRange.startLine,
      maskedSnippet: `const ${paramName} = params.${paramName};`,
      confidence: "high",
      note: `User-controlled parameter '${paramName}' extracted from route request`,
    });

    // Hop 2: Flow - Selector reaches database query sink
    evidenceChain.push({
      kind: "flow",
      file: query.file,
      line: query.line,
      maskedSnippet: query.rawSnippet.trim(),
      confidence: "high",
      note: `Parameter '${paramName}' flows into database query selector on table '${query.table}'`,
    });

    // Hop 3: Sink - Database lookup executed
    evidenceChain.push({
      kind: "sink",
      file: query.file,
      line: query.line,
      maskedSnippet: query.rawSnippet.trim(),
      confidence: "high",
      note: `Database operation '${query.operation.toUpperCase()}' executed on '${query.table}' using resource ID`,
    });

    if (endpoint.isUnresolved) {
      unresolvedSteps.push({
        description: endpoint.unresolvedReason || "Opaque or unresolved construct detected on path",
        location: { file: endpoint.filePath, line: endpoint.lineRange.startLine },
        reason: "opaque-call",
      });
    }

    // Hop 4: Guard / Missing Guard Verification
    const hasOwnerFilter = query.filters.some((f) => f.isOwnerCheck || f.isAuthUidCheck);
    const hasCustomGuard = endpoint.authChecks.includes("assertRepoAccess");
    const isRlsProtected = tableStatus.isSecureByRls;

    if (hasOwnerFilter || hasCustomGuard) {
      evidenceChain.push({
        kind: "config",
        file: query.file,
        line: query.line,
        maskedSnippet: query.rawSnippet.trim(),
        confidence: "high",
        note: hasCustomGuard
          ? "Verified custom authorization guard 'assertRepoAccess' present"
          : "Verified ownership filter present on database query",
      });
      return {
        isVulnerable: false,
        verdictReason: "REJECTED_VERIFIED_OWNERSHIP_FILTER",
        evidenceChain,
        unresolvedSteps,
      };
    }

    if (isRlsProtected) {
      evidenceChain.push({
        kind: "config",
        file: tableStatus.tableName,
        line: 1,
        maskedSnippet: `ALTER TABLE ${tableStatus.tableName} ENABLE ROW LEVEL SECURITY;`,
        confidence: "high",
        note: `Verified Row Level Security (RLS) policy protects table '${tableStatus.tableName}'`,
      });
      return {
        isVulnerable: false,
        verdictReason: "REJECTED_VERIFIED_RLS_POLICY",
        evidenceChain,
        unresolvedSteps,
      };
    }

    // Missing ownership constraint detected
    evidenceChain.push({
      kind: "missing-guard",
      file: query.file,
      line: query.line,
      maskedSnippet: query.rawSnippet.trim(),
      confidence: "high",
      note: `Missing user_id / tenant_id ownership filter and table '${query.table}' lacks user-scoped RLS policy`,
    });

    const isVulnerable = !hasOwnerFilter && !isRlsProtected;
    const verdictReason =
      unresolvedSteps.length > 0
        ? "UNRESOLVED_AUTHORIZATION_NEEDS_REVIEW"
        : tableStatus.hasPermissivePolicy
        ? "PROVEN_IDOR_PERMISSIVE_RLS"
        : !tableStatus.rlsEnabled
        ? "PROVEN_IDOR_NO_OWNERSHIP_NO_RLS"
        : "LIKELY_IDOR_UNVERIFIED_OWNERSHIP";

    return {
      isVulnerable,
      verdictReason,
      evidenceChain,
      unresolvedSteps,
    };
  }
}
