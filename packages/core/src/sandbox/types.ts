
export type VerificationLevel = "L0" | "L1" | "L2" | "L3" | "L4" | "L5";

export type VerificationLevelStatus = "passed" | "failed" | "unavailable";

export interface LevelDetail {
  status: VerificationLevelStatus;
  message: string;
  durationMs: number;
}

export interface VerificationLadderResult {
  L0_patchSafety: VerificationLevelStatus;
  L1_securityRescan: VerificationLevelStatus;
  L2_buildTypecheck: VerificationLevelStatus;
  L3_unitTests: VerificationLevelStatus;
  L4_regressionTest: VerificationLevelStatus;
  L5_exploitVerification: VerificationLevelStatus;
  overallResult: "passed" | "failed" | "partial";
  summaryMessage: string;
  expectedFiles: string[];
  actualFiles: string[];
  patchHash: string;
  generatorVersion: string;
  levelDetails: Record<VerificationLevel, LevelDetail>;
}

export interface SandboxExecutionConfig {
  cpuCount?: number;
  maxMemoryMb?: number;
  maxProcesses?: number;
  timeoutMs?: number;
  maxOutputBytes?: number;
  networkPhase?: "none" | "install_only" | "full";
}

export const DEFAULT_SANDBOX_CONFIG: SandboxExecutionConfig = {
  cpuCount: 1,
  maxMemoryMb: 512,
  maxProcesses: 20,
  timeoutMs: 10000,
  maxOutputBytes: 50000,
  networkPhase: "none",
};

export interface SandboxExecutionResult {
  success: boolean;
  exitCode: number;
  output: string;
  durationMs: number;
  timedOut: boolean;
  memoryExceeded: boolean;
  sanitized: boolean;
}
