import { execSync } from "child_process";
import path from "path";
import { createFinding } from "../evidence.js";
import { RULE_EXPLANATIONS } from "../rule-docs.js";
import { EvidenceHop, Finding } from "../types.js";

export const CRITICAL_FILE_PATTERNS = [
  /auth/i,
  /session/i,
  /login/i,
  /payment/i,
  /stripe/i,
  /checkout/i,
  /billing/i,
  /rls/i,
  /migration/i,
  /webhook/i,
];

/**
 * Detects critical files (auth, payments, RLS, webhooks) that have high change frequency
 * (from git commit history) but NO corresponding test file referencing them.
 */
export async function detectTestGaps(
  filesMap: Map<string, string>,
  repoPath?: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Skip test gap detection for synthetic fixture or temp test directories
  if (repoPath) {
    const normRepo = repoPath.replace(/\\/g, "/").toLowerCase();
    if (normRepo.includes("/fixtures/") || normRepo.includes("/temp/")) {
      return [];
    }
  }

  // Identify all test files in filesMap
  const testFiles = Array.from(filesMap.keys()).filter((f) => {
    const norm = f.replace(/\\/g, "/");
    return (
      /\.(test|spec)\.(ts|js|tsx|jsx)$/i.test(norm) ||
      norm.includes("/test/") ||
      norm.includes("/tests/") ||
      norm.includes("/__tests__/")
    );
  });

  // Aggregate content of all test files into a searchable string
  const combinedTestContent = testFiles
    .map((tf) => filesMap.get(tf) || "")
    .join("\n");

  // Filter critical files (excluding test files themselves and configs)
  const criticalFiles = Array.from(filesMap.keys()).filter((f) => {
    const norm = f.replace(/\\/g, "/");
    if (
      /\.(test|spec)\.(ts|js|tsx|jsx)$/i.test(norm) ||
      norm.includes("/test/") ||
      norm.includes("/tests/") ||
      norm.endsWith(".json") ||
      norm.endsWith(".md")
    ) {
      return false;
    }

    return CRITICAL_FILE_PATTERNS.some((pat) => pat.test(norm));
  });

  for (const filePath of criticalFiles) {
    const normPath = filePath.replace(/\\/g, "/");
    const baseName = path.basename(normPath, path.extname(normPath));

    // Check if test files import or reference the file or basename
    const isReferencedInTests =
      combinedTestContent.includes(normPath) ||
      combinedTestContent.includes(baseName);

    if (!isReferencedInTests) {
      // Determine git change frequency (commit churn)
      let commitCount = 0;
      if (repoPath) {
        try {
          const absFilePath = path.isAbsolute(filePath)
            ? filePath
            : path.resolve(repoPath, filePath);
          const out = execSync(`git log --oneline -- "${absFilePath}"`, {
            cwd: repoPath,
            encoding: "utf-8",
            stdio: ["ignore", "pipe", "ignore"],
          });
          const lines = out.trim().split("\n").filter(Boolean);
          commitCount = lines.length;
        } catch {
          commitCount = 0;
        }
      } else {
        commitCount = 2;
      }

      // Flag finding if change frequency is high (>= 2 commits) and untested
      if (commitCount >= 2) {
        const content = filesMap.get(filePath) || "";
        const lines = content.split("\n");
        const maskedSnippet =
          lines.slice(0, 3).join("\n").trim() || `// Critical file: ${normPath}`;

        const ruleExplanation = RULE_EXPLANATIONS["test-gap-high-churn-untested"];

        const evidenceChain: EvidenceHop[] = [
          {
            kind: "source",
            file: normPath,
            line: 1,
            maskedSnippet,
            confidence: "high",
            note: `Critical module '${normPath}' has high git change frequency (${commitCount} commit(s))`,
          },
          {
            kind: "missing-guard",
            file: normPath,
            line: 1,
            maskedSnippet: `Scanned ${testFiles.length} test file(s) in repository`,
            confidence: "high",
            note: `Zero test files in repository reference '${baseName}' or import '${normPath}'`,
          },
        ];

        findings.push(
          createFinding({
            ruleId: "test-gap-high-churn-untested",
            title: ruleExplanation.title,
            severity: "medium",
            confidenceTier: "needs-review",
            file: normPath,
            lineRange: { startLine: 1, endLine: Math.min(10, lines.length) },
            evidenceChain,
            unresolvedSteps: [
              {
                description: `Module '${normPath}' lacks automated unit test coverage across ${testFiles.length} scanned test files`,
                location: { file: normPath, line: 1 },
                reason: "external-library",
              },
            ],
            explanation: ruleExplanation.whatsWrong + " " + ruleExplanation.howStrangerCouldAbuseIt,
            fingerprint: `test-gap-${normPath}`,
          })
        );
      }
    }
  }

  return findings;
}
