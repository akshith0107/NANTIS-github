import { z } from "zod";
import { Finding, Severity } from "../types.js";

/**
 * Concrete code reference proposed by LLM investigator.
 */
export interface CandidateRef {
  file: string;
  line: number;
  snippet?: string;
}

export const CandidateRefSchema = z.object({
  file: z.string().min(1),
  line: z.number().int().positive(),
  snippet: z.string().optional(),
});

/**
 * Structured security claim proposed by LLM.
 */
export type CandidateClaimType =
  | "input_user_controlled"
  | "flow_reaches_selector"
  | "ownership_absent"
  | "ownership_enforced"
  | "rls_protects"
  | "guard_semantics";

export interface CandidateClaim {
  claimType: CandidateClaimType;
  ref: CandidateRef;
  rationale: string;
}

export const CandidateClaimSchema = z.object({
  claimType: z.enum([
    "input_user_controlled",
    "flow_reaches_selector",
    "ownership_absent",
    "ownership_enforced",
    "rls_protects",
    "guard_semantics",
  ]),
  ref: CandidateRefSchema,
  rationale: z.string().min(1),
});

/**
 * Candidate finding proposed by LLM before deterministic verification.
 */
export interface CandidateFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  claims: CandidateClaim[];
  rationale: string;
}

export const CandidateFindingSchema = z.object({
  id: z.string().min(1),
  ruleId: z.string().min(1),
  title: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  file: z.string().min(1),
  line: z.number().int().positive(),
  claims: z.array(CandidateClaimSchema).min(1),
  rationale: z.string().min(1),
});

export const LlmInvestigationResponseSchema = z.object({
  candidateFindings: z.array(CandidateFindingSchema),
  investigatorRationale: z.string().optional(),
});

/**
 * Model & Execution Tracking Metadata.
 */
export interface ModelMetadata {
  modelId: string;
  promptVersion: string;
  investigatorVersion: string;
  contextFingerprint: string;
  costUsd: number;
  latencyMs: number;
  tokensUsed?: number;
}

/**
 * Result of LLM investigation pass.
 */
export interface LlmInvestigationResult {
  candidateFindings: CandidateFinding[];
  verifiedFindings: Finding[];
  metadata: ModelMetadata;
  diagnostics: string[];
}

/**
 * Config for LLM investigator.
 */
export interface LlmInvestigatorConfig {
  enabled?: boolean;
  provider?: "mock" | "openai" | "anthropic";
  apiKey?: string;
  modelId?: string;
  maxFiles?: number;
  maxTotalBytes?: number;
  timeoutMs?: number;
}
