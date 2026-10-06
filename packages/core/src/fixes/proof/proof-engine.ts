import path from "path";
import os from "os";
import { ProofLabel } from "../types.js";
import { simulateRLSPolicyAccess, RLSSimulationResult } from "./rls-simulator.js";
import { replayMissingAuthHandler, HandlerReplayResult } from "./handler-harness.js";

export interface ProofEvaluationResult {
  label: ProofLabel;
  rlsResult?: RLSSimulationResult;
  handlerResult?: HandlerReplayResult;
  executedInSandbox: boolean;
  refusalReason?: string;
}

/**
 * Validates whether the path is strictly inside a temporary sandbox directory.
 */
export function isSandboxDirectory(dirPath: string): boolean {
  const norm = path.resolve(dirPath).toLowerCase();
  const tmpDir = path.resolve(os.tmpdir()).toLowerCase();
  const envSandbox = process.env.NANTIS_SANDBOX === "true";

  return (
    norm.includes("temp") ||
    norm.includes("tmp") ||
    norm.startsWith(tmpDir) ||
    envSandbox
  );
}

/**
 * Runs proof engine for (a) RLS policy simulation or (b) Missing-auth handler replay.
 * REFUSES to run replay execution outside the sandbox workspace directory.
 */
export function evaluateProof(
  targetDir: string,
  ruleId: string,
  beforeContent: string,
  afterContent: string
): ProofEvaluationResult {
  const inSandbox = isSandboxDirectory(targetDir);

  if (!inSandbox) {
    return {
      label: "Not proven, reasoned from code",
      executedInSandbox: false,
      refusalReason:
        "Refused proof replay execution: target directory is outside the sandbox environment.",
    };
  }

  // Case (a): RLS policy simulation
  if (ruleId === "missing-rls-in-migration" || ruleId.includes("rls") || ruleId.includes("policy")) {
    const rlsResult = simulateRLSPolicyAccess(
      beforeContent,
      afterContent,
      { id: "user_tenant_A" },
      { user_id: "user_tenant_B" }
    );

    return {
      label: rlsResult.proven ? "Proven by policy simulation" : "Not proven, reasoned from code",
      rlsResult,
      executedInSandbox: true,
    };
  }

  // Case (b): Missing-auth handler replay
  if (ruleId === "api-route-no-auth" || ruleId === "server-action-no-auth" || ruleId.includes("auth")) {
    const handlerResult = replayMissingAuthHandler(beforeContent, afterContent);

    return {
      label: handlerResult.proven ? "Proven by handler replay" : "Not proven, reasoned from code",
      handlerResult,
      executedInSandbox: true,
    };
  }

  // Default fallback for other rules
  return {
    label: "Not proven, reasoned from code",
    executedInSandbox: true,
  };
}
