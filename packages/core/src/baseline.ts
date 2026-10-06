import fs from "fs";
import path from "path";
import { Finding, FindingStatus, Severity } from "./types.js";
import { computeResilientFingerprint } from "./fingerprint.js";

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  title: string;
  severity: string;
  recordedAt: string;
  status: "active" | "fixed";
}

export interface BaselineFile {
  version: string;
  createdAt: string;
  updatedAt: string;
  findings: BaselineEntry[];
}

export interface ComparisonResult {
  findings: Finding[];
  summary: {
    newCount: number;
    fixedCount: number;
    unchangedCount: number;
    reintroducedCount: number;
    totalCurrent: number;
  };
  newFindings: Finding[];
  fixedFindings: Finding[];
  unchangedFindings: Finding[];
  reintroducedFindings: Finding[];
}

/**
 * Creates a BaselineFile structure from a set of findings.
 */
export function createBaseline(findings: Finding[]): BaselineFile {
  const now = new Date().toISOString();
  const entries: BaselineEntry[] = findings.map((f) => ({
    fingerprint: f.fingerprint || computeResilientFingerprint(f),
    ruleId: f.ruleId,
    file: f.file,
    title: f.title,
    severity: f.severity,
    recordedAt: now,
    status: "active",
  }));

  return {
    version: "1.0.0",
    createdAt: now,
    updatedAt: now,
    findings: entries,
  };
}

/**
 * Reads a baseline file from disk. Returns null if missing or invalid.
 */
export function loadBaseline(filePath: string): BaselineFile | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as BaselineFile;
  } catch {
    return null;
  }
}

/**
 * Saves a BaselineFile structure to disk.
 */
export function saveBaseline(filePath: string, baseline: BaselineFile): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), "utf-8");
}

/**
 * Compares current scan findings against a baseline record.
 * Categorizes each finding into:
 * - 'new': present in current scan, absent from baseline
 * - 'unchanged': present in both current scan and active baseline
 * - 'fixed': present as active in baseline, but missing from current scan
 * - 'reintroduced': present in current scan, but was previously marked 'fixed' in baseline
 */
export function compareScanResults(
  currentFindings: Finding[],
  baseline: BaselineFile | null
): ComparisonResult {
  if (!baseline || !baseline.findings || baseline.findings.length === 0) {
    const findingsWithStatus = currentFindings.map((f) => ({
      ...f,
      status: "new" as FindingStatus,
    }));
    return {
      findings: findingsWithStatus,
      summary: {
        newCount: findingsWithStatus.length,
        fixedCount: 0,
        unchangedCount: 0,
        reintroducedCount: 0,
        totalCurrent: currentFindings.length,
      },
      newFindings: findingsWithStatus,
      fixedFindings: [],
      unchangedFindings: [],
      reintroducedFindings: [],
    };
  }

  // Create baseline lookup map by fingerprint
  const baselineMap = new Map<string, BaselineEntry>();
  for (const entry of baseline.findings) {
    baselineMap.set(entry.fingerprint, entry);
  }

  const newFindings: Finding[] = [];
  const fixedFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];
  const reintroducedFindings: Finding[] = [];
  const processedFingerprints = new Set<string>();

  // Process current scan findings
  for (const finding of currentFindings) {
    const fp = finding.fingerprint || computeResilientFingerprint(finding);
    processedFingerprints.add(fp);

    const baselineEntry = baselineMap.get(fp);

    if (!baselineEntry) {
      const updatedFinding = { ...finding, fingerprint: fp, status: "new" as FindingStatus };
      newFindings.push(updatedFinding);
    } else if (baselineEntry.status === "fixed") {
      const updatedFinding = {
        ...finding,
        fingerprint: fp,
        status: "reintroduced" as FindingStatus,
      };
      reintroducedFindings.push(updatedFinding);
    } else {
      const updatedFinding = { ...finding, fingerprint: fp, status: "unchanged" as FindingStatus };
      unchangedFindings.push(updatedFinding);
    }
  }

  // Process baseline entries missing from current scan -> fixed findings
  for (const entry of baseline.findings) {
    if (entry.status === "active" && !processedFingerprints.has(entry.fingerprint)) {
      const syntheticFixedFinding: Finding = {
        id: `fixed-${entry.fingerprint}`,
        ruleId: entry.ruleId,
        title: `[FIXED] ${entry.title}`,
        severity: (entry.severity as Severity) || "info",
        confidenceTier: "proven",
        file: entry.file,
        lineRange: { startLine: 1, endLine: 1 },
        evidenceChain: [],
        unresolvedSteps: [],
        explanation: `Finding '${entry.title}' in '${entry.file}' was previously present in baseline but is now fixed.`,
        fingerprint: entry.fingerprint,
        status: "fixed",
      };
      fixedFindings.push(syntheticFixedFinding);
    }
  }

  const allFindings = [
    ...newFindings,
    ...reintroducedFindings,
    ...fixedFindings,
    ...unchangedFindings,
  ];

  return {
    findings: allFindings,
    summary: {
      newCount: newFindings.length,
      fixedCount: fixedFindings.length,
      unchangedCount: unchangedFindings.length,
      reintroducedCount: reintroducedFindings.length,
      totalCurrent: currentFindings.length,
    },
    newFindings,
    fixedFindings,
    unchangedFindings,
    reintroducedFindings,
  };
}

/**
 * Updates a baseline record with the latest scan comparison results.
 */
export function updateBaseline(
  currentBaseline: BaselineFile | null,
  comparisonResult: ComparisonResult
): BaselineFile {
  const now = new Date().toISOString();
  const entryMap = new Map<string, BaselineEntry>();

  if (currentBaseline) {
    for (const entry of currentBaseline.findings) {
      entryMap.set(entry.fingerprint, entry);
    }
  }

  for (const f of comparisonResult.newFindings) {
    entryMap.set(f.fingerprint, {
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      file: f.file,
      title: f.title,
      severity: f.severity,
      recordedAt: now,
      status: "active",
    });
  }

  for (const f of comparisonResult.unchangedFindings) {
    const existing = entryMap.get(f.fingerprint);
    if (existing) {
      existing.status = "active";
    }
  }

  for (const f of comparisonResult.reintroducedFindings) {
    entryMap.set(f.fingerprint, {
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      file: f.file,
      title: f.title,
      severity: f.severity,
      recordedAt: now,
      status: "active",
    });
  }

  for (const f of comparisonResult.fixedFindings) {
    const existing = entryMap.get(f.fingerprint);
    if (existing) {
      existing.status = "fixed";
    }
  }

  return {
    version: "1.0.0",
    createdAt: currentBaseline?.createdAt || now,
    updatedAt: now,
    findings: Array.from(entryMap.values()),
  };
}
