import type { Finding } from "../types.js";

export type RiskLevel = "low" | "medium" | "high";

export interface BlastRadius {
  affectedFiles: string[];
  callersAffected: string[];
  importedByModules: string[];
  riskLevel: RiskLevel;
}

export type ProofLabel =
  | "Proven by policy simulation"
  | "Proven by handler replay"
  | "Not proven, reasoned from code";

export interface ContainerSandboxRunner {
  runCommand(
    tempCopyDir: string,
    command: string
  ): Promise<{ success: boolean; output: string; exitCode: number }>;
}

export interface VerificationReport {
  passed: boolean;
  checksRun: string[];
  summaryText: string;
  dropReason?: string;
  isWeak?: boolean;
}

export interface VerificationConfig {
  runTypecheck?: boolean;
  runLint?: boolean;
  runTests?: boolean;
  runBuild?: boolean;
  initialFindings?: Finding[];
  containerRunner?: ContainerSandboxRunner;
}

export interface FixSnapshot {
  timestamp: string;
  files: Map<string, string>;
}

export interface StructuredEdit {
  targetFile: string;
  targetContent: string;
  replacementContent: string;
  startLine?: number;
  endLine?: number;
}

export interface FixResultAutomated {
  kind: "automated";
  ruleId: string;
  targetFile: string;
  edits: StructuredEdit[];
  diff: string;
  riskLevel: RiskLevel;
  blastRadius: BlastRadius;
  proofLabel: ProofLabel;
  verificationReport: VerificationReport;
}

export interface FixResultManual {
  kind: "suggested-manual";
  ruleId: string;
  targetFile: string;
  reason: string;
  suggestion: string;
}

export type FixResult = FixResultAutomated | FixResultManual;

export interface FixPRPermissionsConfig {
  installationId: string;
  optedIn: boolean;
  contentsPermission: "read" | "write";
  pullRequestsPermission: "read" | "write";
  grantedAt?: string;
}

export interface ApprovalFixCard {
  findingId: string;
  ruleId: string;
  targetFile: string;
  diff: string;
  riskLevel: RiskLevel;
  blastRadius: BlastRadius;
  proofLabel: ProofLabel;
  verificationText: string;
  selected: boolean;
}
