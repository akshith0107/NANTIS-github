import { Ref } from "../idor/types.js";
import { UnresolvedStep } from "../types.js";

export type ClaimVerificationStatus = "verified" | "refuted" | "unverifiable";

export type RefutationTarget =
  | "ownership_check"
  | "auth_guard"
  | "role_check"
  | "rls_policy"
  | "wrapper_function"
  | "cross_file_helper";

export interface RefutationEvidence {
  target: RefutationTarget;
  ref: Ref;
  snippet: string;
  note: string;
}

export interface ClaimRefutationResult {
  claimId: string;
  status: ClaimVerificationStatus;
  supportingEvidence?: RefutationEvidence;
  refutingEvidence?: RefutationEvidence;
  explanation: string;
}

export interface RefutationLimits {
  maxRefutationDepth: number;
  maxClaims: number;
  maxFiles: number;
  maxVerifierCalls: number;
  maxRuntimeMs: number;
}

export const DEFAULT_REFUTATION_LIMITS: RefutationLimits = {
  maxRefutationDepth: 3,
  maxClaims: 20,
  maxFiles: 50,
  maxVerifierCalls: 100,
  maxRuntimeMs: 5000,
};

export interface RefutationCoverage {
  filesSearched: number;
  symbolsInspected: number;
  edgesTraversed: number;
  unresolvedPaths: number;
  maxDepthReached: number;
  completionState: "complete" | "truncated" | "depth-limited";
}

export interface FindingClosure {
  closureHash: string;
  engineVersion: string;
  refutationRan: boolean;
  supportingClaims: string[];
  blockingRefutingClaims: string[];
  reasonCodes: string[];
  coverage: RefutationCoverage;
  unresolvedSteps: UnresolvedStep[];
}
