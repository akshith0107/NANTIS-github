export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ConfidenceTier = "proven" | "likely" | "needs-review" | "hygiene";
export type FindingStatus = "new" | "fixed" | "unchanged" | "reintroduced";
export type EvidenceHopKind = "source" | "flow" | "sink" | "missing-guard" | "config";
export type HopConfidence = "high" | "medium" | "low";
export type UnresolvedReason =
  "dynamic-import" | "opaque-call" | "dynamic-property" | "external-library";

export interface LineRange {
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface GitCommitMeta {
  commit?: string;
  pr?: number;
  author?: string;
  date?: string;
  confidence?: HopConfidence;
  confidenceReason?: string;
}

export interface FindingFix {
  description: string;
  diff?: string;
}

export interface EvidenceHop {
  kind: EvidenceHopKind;
  file: string;
  line: number;
  maskedSnippet: string;
  confidence: HopConfidence;
  note: string;
}

export interface UnresolvedStep {
  description: string;
  location: {
    file: string;
    line: number;
  };
  reason: UnresolvedReason;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidenceTier: ConfidenceTier;
  file: string;
  lineRange: LineRange;
  evidenceChain: EvidenceHop[];
  unresolvedSteps: UnresolvedStep[];
  explanation: string;
  fix?: FindingFix;
  fingerprint: string;
  introducedIn?: GitCommitMeta;
  status?: FindingStatus;
}

export interface RuleFixture {
  vulnerable: string;
  clean: string;
  mutated: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  fixtures: RuleFixture;
  check(files: Map<string, string>): Promise<Finding[]>;
}

export interface ScanResult {
  findings: Finding[];
  summaryMessage: string;
  scannedFilesCount: number;
}
