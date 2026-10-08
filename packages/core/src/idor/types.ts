import { EvidenceHop, UnresolvedStep } from "../types.js";

/**
 * Concrete code location reference with hash and symbol.
 */
export interface Ref {
  file: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  fileHash?: string;
  symbol?: string;
  snippet?: string;
}

/**
 * Coverage metadata for repository security analysis.
 */
export interface Coverage {
  filesInspected: number;
  totalFiles: number;
  maxDepthReached: number;
  edgesResolved: number;
  edgesUnresolved: number;
  completionState: "complete" | "truncated" | "depth-limited";
}

/**
 * Standard tool execution result.
 */
export interface ToolResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  coverage?: Coverage;
  unresolved?: UnresolvedStep[];
}

/**
 * Security Verdict Tiers.
 */
export type VerdictResult = "proven" | "likely" | "needs_review" | "rejected";

/**
 * Deterministic Security Claim.
 */
export interface SecurityClaim {
  id: string;
  ruleId: string;
  origin: "engine";
  targetFile: string;
  targetSymbol?: string;
  claimType: "idor.owner-column.v1" | "missing-ownership" | "missing-rls";
  evidenceRefs: Ref[];
  unresolvedSteps: UnresolvedStep[];
}

/**
 * Deterministic verification result for a claim.
 */
export interface DeterministicVerification {
  claimId: string;
  verdict: VerdictResult;
  reasonCode: string;
  explanation: string;
  evidenceChain: EvidenceHop[];
  unresolvedSteps: UnresolvedStep[];
  coverage: Coverage;
}

/**
 * Dataflow limits for bounded analysis.
 */
export interface DataflowLimits {
  maxDepth: number;
  maxFiles: number;
  maxEdges: number;
  maxUnresolved: number;
}

export const DEFAULT_DATAFLOW_LIMITS: DataflowLimits = {
  maxDepth: 5,
  maxFiles: 50,
  maxEdges: 1000,
  maxUnresolved: 10,
};

/**
 * Indexed Supabase query operation details.
 */
export interface IndexedSupabaseQuery {
  file: string;
  line: number;
  table: string;
  operation: "select" | "update" | "delete" | "insert";
  filters: Array<{
    column: string;
    valueExpr: string;
    isUserControlled: boolean;
    isOwnerCheck: boolean;
    isAuthUidCheck: boolean;
  }>;
  hasOwnerColumnFilter: boolean;
  hasAuthUidFilter: boolean;
  rawSnippet: string;
}

/**
 * Indexed Route Parameter.
 */
export interface IndexedParam {
  name: string;
  source: "route-param" | "search-param" | "body-param";
  line: number;
}

/**
 * Indexed Endpoint in the repository.
 */
export interface IndexedEndpoint {
  id: string;
  filePath: string;
  name: string;
  kind: "route-handler" | "server-action" | "api-endpoint";
  httpMethod?: string;
  params: IndexedParam[];
  authChecks: string[];
  hasSessionAuth: boolean;
  queries: IndexedSupabaseQuery[];
  lineRange: { startLine: number; endLine: number };
  isUnresolved?: boolean;
  unresolvedReason?: string;
}

/**
 * Indexed RLS Policy in database migrations.
 */
export interface IndexedRlsPolicy {
  policyName: string;
  tableName: string;
  filePath: string;
  line: number;
  isPermissive: boolean; // USING (true) or WITH CHECK (true)
  hasAuthUid: boolean; // USING (auth.uid() = user_id)
  definitionSnippet: string;
}

/**
 * Indexed Table in database schema / migrations.
 */
export interface IndexedTable {
  tableName: string;
  filePath: string;
  line: number;
  hasRlsEnabled: boolean;
  ownerColumns: string[]; // e.g. ["user_id", "tenant_id", "owner_id", "account_id"]
  policies: IndexedRlsPolicy[];
}

/**
 * Complete Indexed Repository model.
 */
export interface IndexedRepository {
  fileHashes: Map<string, string>;
  endpoints: IndexedEndpoint[];
  tables: Map<string, IndexedTable>;
  queries: IndexedSupabaseQuery[];
  coverage: Coverage;
}
