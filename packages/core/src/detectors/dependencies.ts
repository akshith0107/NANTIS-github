import crypto from "crypto";
import {
  ExactDependency,
  isLooseVersionRange,
  parsePackageLockJson,
  parsePnpmLockYaml,
  parseYarnLock,
} from "../parsers/lockfile.js";
import { FetchOSVClient, OSVClient, PackageQuery } from "../osv/client.js";
import { Finding, Severity } from "../types.js";

export interface DetectDependenciesOptions {
  osvClient?: OSVClient;
  offlineMode?: boolean;
}

function generateFindingId(): string {
  return crypto.randomUUID();
}

function generateFingerprint(
  ruleId: string,
  pkgName: string,
  version: string,
  advisoryId: string
): string {
  return crypto
    .createHash("sha256")
    .update(`${ruleId}:${pkgName}@${version}:${advisoryId}`)
    .digest("hex");
}

function extractFixedVersion(
  affectedList?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>
): string | undefined {
  if (!affectedList) return undefined;
  for (const aff of affectedList) {
    if (aff.ranges) {
      for (const range of aff.ranges) {
        if (range.events) {
          for (const ev of range.events) {
            if (ev.fixed) {
              return ev.fixed;
            }
          }
        }
      }
    }
  }
  return undefined;
}

export async function detectDependencies(
  files: Map<string, string>,
  options: DetectDependenciesOptions = {}
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const pkgJsonContent = files.get("package.json");
  const pkgLockContent = files.get("package-lock.json");
  const pnpmLockContent = files.get("pnpm-lock.yaml");
  const yarnLockContent = files.get("yarn.lock");

  // 1. Check missing lockfile
  if (pkgJsonContent && !pkgLockContent && !pnpmLockContent && !yarnLockContent) {
    findings.push({
      id: generateFindingId(),
      ruleId: "missing-lockfile",
      title: "Missing Lockfile in Repository",
      severity: "high",
      confidenceTier: "proven",
      file: "package.json",
      lineRange: { startLine: 1, endLine: 1 },
      evidenceChain: [
        {
          kind: "config",
          file: "package.json",
          line: 1,
          maskedSnippet: '{"name": "repository"}',
          confidence: "high",
          note: "No package-lock.json, pnpm-lock.yaml, or yarn.lock present",
        },
      ],
      unresolvedSteps: [],
      explanation:
        "No lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock) was found in the repository. " +
        "Without a lockfile, dependency builds are non-deterministic and vulnerability scanning cannot verify exact installed versions.",
      fingerprint: generateFingerprint("missing-lockfile", "repo", "0.0.0", "missing"),
    });
  }

  // 2. Check loose version ranges in package.json
  if (pkgJsonContent) {
    try {
      const parsedPkg = JSON.parse(pkgJsonContent) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const allDeps = { ...parsedPkg.dependencies, ...parsedPkg.devDependencies };
      for (const [depName, depSpec] of Object.entries(allDeps)) {
        if (isLooseVersionRange(depSpec)) {
          findings.push({
            id: generateFindingId(),
            ruleId: "loose-dependency-range",
            title: `Loose Version Range (${depName}: ${depSpec})`,
            severity: "medium",
            confidenceTier: "proven",
            file: "package.json",
            lineRange: { startLine: 1, endLine: 1 },
            evidenceChain: [
              {
                kind: "config",
                file: "package.json",
                line: 1,
                maskedSnippet: `"${depName}": "${depSpec}"`,
                confidence: "high",
                note: `Dependency ${depName} specifies loose version range ${depSpec}`,
              },
            ],
            unresolvedSteps: [],
            explanation:
              `Dependency ${depName} specifies a loose version range (${depSpec}). ` +
              `Wildcard or unbound version specs expose the project to unvetted upstream dependency updates.`,
            fingerprint: generateFingerprint("loose-dependency-range", depName, depSpec, "loose"),
          });
        }
      }
    } catch {
      // Ignore package.json parse error
    }
  }

  // 3. Extract exact dependencies from lockfiles
  let exactDeps: ExactDependency[] = [];
  let lockfilePath = "";

  if (pkgLockContent) {
    exactDeps = parsePackageLockJson(pkgLockContent);
    lockfilePath = "package-lock.json";
  } else if (pnpmLockContent) {
    exactDeps = parsePnpmLockYaml(pnpmLockContent);
    lockfilePath = "pnpm-lock.yaml";
  } else if (yarnLockContent) {
    exactDeps = parseYarnLock(yarnLockContent);
    lockfilePath = "yarn.lock";
  }

  if (exactDeps.length === 0) {
    return findings;
  }

  // 4. Query OSV.dev (or handle offline mode / network errors)
  if (options.offlineMode) {
    findings.push({
      id: generateFindingId(),
      ruleId: "dependency-data-unavailable",
      title: "Dependency Vulnerability Data Unavailable (Offline Mode)",
      severity: "info",
      confidenceTier: "hygiene",
      file: lockfilePath,
      lineRange: { startLine: 1, endLine: 1 },
      evidenceChain: [
        {
          kind: "config",
          file: lockfilePath,
          line: 1,
          maskedSnippet: `lockfile: ${lockfilePath}`,
          confidence: "low",
          note: "dependency check incomplete",
        },
      ],
      unresolvedSteps: [],
      explanation: "dependency check incomplete",
      fingerprint: generateFingerprint("dependency-data-unavailable", lockfilePath, "0", "offline"),
    });
    return findings;
  }

  const osvClient = options.osvClient || new FetchOSVClient();

  const queries: PackageQuery[] = exactDeps.map((d) => ({
    name: d.name,
    version: d.version,
    ecosystem: "npm",
  }));

  try {
    const queryResults = await osvClient.queryBatch(queries);

    for (const res of queryResults) {
      for (const vuln of res.vulnerabilities) {
        const advisoryId = vuln.id || "UNKNOWN-ADVISORY";
        const fixedVersion = extractFixedVersion(vuln.affected);
        const fixedMsg = fixedVersion ? ` Fixed in version ${fixedVersion}.` : "";

        let severity: Severity = "high";
        if (vuln.severity && vuln.severity.length > 0) {
          const cvss = vuln.severity[0].score;
          if (cvss.includes("/AV:N") && cvss.includes("/C:H")) {
            severity = "critical";
          }
        }

        findings.push({
          id: generateFindingId(),
          ruleId: "vulnerable-dependency",
          title: `Vulnerable Dependency: ${res.package.name}@${res.package.version}`,
          severity,
          confidenceTier: "proven",
          file: lockfilePath,
          lineRange: { startLine: 1, endLine: 1 },
          evidenceChain: [
            {
              kind: "sink",
              file: lockfilePath,
              line: 1,
              maskedSnippet: `${res.package.name}@${res.package.version} (${advisoryId})`,
              confidence: "high",
              note: vuln.summary || `Advisory ${advisoryId}`,
            },
          ],
          unresolvedSteps: [],
          explanation:
            `Package ${res.package.name}@${res.package.version} is affected by security advisory ${advisoryId}. ` +
            `${vuln.summary || ""}${fixedMsg}`,
          fingerprint: generateFingerprint(
            "vulnerable-dependency",
            res.package.name,
            res.package.version,
            advisoryId
          ),
        });
      }
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "OSV Query Error";
    findings.push({
      id: generateFindingId(),
      ruleId: "dependency-data-unavailable",
      title: "Dependency Vulnerability Data Unavailable",
      severity: "info",
      confidenceTier: "hygiene",
      file: lockfilePath,
      lineRange: { startLine: 1, endLine: 1 },
      evidenceChain: [
        {
          kind: "config",
          file: lockfilePath,
          line: 1,
          maskedSnippet: errorMsg,
          confidence: "low",
          note: "dependency check incomplete",
        },
      ],
      unresolvedSteps: [],
      explanation: `dependency check incomplete: ${errorMsg}`,
      fingerprint: generateFingerprint("dependency-data-unavailable", lockfilePath, "0", "error"),
    });
  }

  return findings;
}
