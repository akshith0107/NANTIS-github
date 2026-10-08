import { VerdictResult, SecurityClaim, DeterministicVerification, Coverage } from "./types.js";
import { EvidenceHop, UnresolvedStep } from "../types.js";

/**
 * Pure, deterministic verdict engine mapping evidence to security confidence tiers.
 */
export class PureVerdictEngine {
  /**
   * Evaluates a security claim and evidence hops to determine a pure verdict.
   */
  static evaluate(
    claim: SecurityClaim,
    verdictReason: string,
    evidenceChain: EvidenceHop[],
    unresolvedSteps: UnresolvedStep[],
    coverage: Coverage
  ): DeterministicVerification {
    let verdict: VerdictResult = "needs_review";

    const hasUnresolved = unresolvedSteps.length > 0;

    switch (verdictReason) {
      case "REJECTED_VERIFIED_OWNERSHIP_FILTER":
      case "REJECTED_VERIFIED_RLS_POLICY":
        verdict = "rejected";
        break;

      case "PROVEN_IDOR_NO_OWNERSHIP_NO_RLS":
      case "PROVEN_IDOR_PERMISSIVE_RLS":
        verdict = hasUnresolved ? "needs_review" : "proven";
        break;

      case "LIKELY_IDOR_UNVERIFIED_OWNERSHIP":
        verdict = hasUnresolved ? "needs_review" : "likely";
        break;

      case "UNRESOLVED_AUTHORIZATION_NEEDS_REVIEW":
      default:
        verdict = "needs_review";
        break;
    }

    const explanation =
      verdict === "proven"
        ? `Proven IDOR vulnerability detected in '${claim.targetFile}'. Resource lookup using parameter lacks user ownership filter and database table lacks Row Level Security (RLS) protection.`
        : verdict === "likely"
        ? `Likely IDOR vulnerability detected in '${claim.targetFile}'. Query filters by resource ID without verifying user session ownership.`
        : verdict === "rejected"
        ? `No IDOR vulnerability. Route access in '${claim.targetFile}' is protected by verified ownership checks or RLS policy.`
        : `Potential IDOR in '${claim.targetFile}' requires manual security review due to unresolved authorization steps.`;

    return {
      claimId: claim.id,
      verdict,
      reasonCode: verdictReason,
      explanation,
      evidenceChain,
      unresolvedSteps,
      coverage,
    };
  }
}
