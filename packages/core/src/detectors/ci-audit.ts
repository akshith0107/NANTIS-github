import crypto from "crypto";
import { Finding } from "../types.js";

function generateFindingId(): string {
  return crypto.randomUUID();
}

function generateFingerprint(ruleId: string, filePath: string, line: number): string {
  return crypto
    .createHash("sha256")
    .update(`${ruleId}:${filePath.toLowerCase()}:${line}`)
    .digest("hex");
}

export async function detectCiIssues(files: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [relPath, content] of files.entries()) {
    const normalizedPath = relPath.replace(/\\/g, "/");

    // Only audit GitHub Actions workflows
    if (
      !normalizedPath.startsWith(".github/workflows/") ||
      (!normalizedPath.endsWith(".yml") && !normalizedPath.endsWith(".yaml"))
    ) {
      continue;
    }

    const lines = content.split(/\r?\n/);
    const isPullRequestTarget = content.includes("pull_request_target");

    // 1. Audit permissions block once per file/block
    let foundPermissionsWrite = false;
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;

      if (lineText.includes("permissions:")) {
        if (lineText.includes("write-all")) {
          foundPermissionsWrite = true;
          findings.push({
            id: generateFindingId(),
            ruleId: "ci-overbroad-permissions",
            title: "CI Over-broad Permissions (write-all)",
            severity: "high",
            confidenceTier: "proven",
            file: normalizedPath,
            lineRange: { startLine: lineNum, endLine: lineNum },
            evidenceChain: [
              {
                kind: "config",
                file: normalizedPath,
                line: lineNum,
                maskedSnippet: lineText.trim(),
                confidence: "high",
                note: "Over-broad write-all permissions assigned",
              },
            ],
            unresolvedSteps: [],
            explanation:
              "Over-broad GitHub Actions permissions grant unnecessary write privileges to the runner environment, " +
              "expanding the blast radius if a CI step is compromised.",
            fingerprint: generateFingerprint("ci-overbroad-permissions", normalizedPath, lineNum),
          });
        }
      }
    });

    if (!foundPermissionsWrite) {
      // Check multi-line permissions block for write grants
      let permStart = 0;
      let permEnd = 0;
      let hasWrite = false;

      lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;
        if (lineText.includes("permissions:")) {
          permStart = lineNum;
        }
        if (permStart > 0 && lineNum >= permStart && lineNum <= permStart + 5) {
          if (lineText.includes("contents: write") || lineText.includes("pull-requests: write")) {
            hasWrite = true;
            permEnd = lineNum;
          }
        }
      });

      if (hasWrite && permStart > 0) {
        findings.push({
          id: generateFindingId(),
          ruleId: "ci-overbroad-permissions",
          title: "CI Write Permissions Granted",
          severity: "medium",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: permStart, endLine: permEnd },
          evidenceChain: [
            {
              kind: "config",
              file: normalizedPath,
              line: permStart,
              maskedSnippet: lines
                .slice(permStart - 1, permEnd)
                .join("\n")
                .trim(),
              confidence: "high",
              note: "Write permissions assigned in workflow",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Over-broad GitHub Actions permissions grant unnecessary write privileges to the runner environment, " +
            "expanding the blast radius if a CI step is compromised.",
          fingerprint: generateFingerprint("ci-overbroad-permissions", normalizedPath, permStart),
        });
      }
    }

    // 2. Unpinned third-party actions (not a 40-char SHA)
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      if (lineText.includes("uses:")) {
        const actionMatch = /uses:\s*([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)@([^\s#]+)/.exec(lineText);
        if (actionMatch) {
          const actionRef = actionMatch[2];
          if (!/^[a-f0-9]{40}$/i.test(actionRef)) {
            findings.push({
              id: generateFindingId(),
              ruleId: "ci-unpinned-action",
              title: `Unpinned Third-Party CI Action (${actionMatch[1]}@${actionRef})`,
              severity: "medium",
              confidenceTier: "proven",
              file: normalizedPath,
              lineRange: { startLine: lineNum, endLine: lineNum },
              evidenceChain: [
                {
                  kind: "config",
                  file: normalizedPath,
                  line: lineNum,
                  maskedSnippet: lineText.trim(),
                  confidence: "high",
                  note: `Action ${actionMatch[1]} pinned to tag ${actionRef} instead of commit SHA`,
                },
              ],
              unresolvedSteps: [],
              explanation:
                "Mutable action tags (such as @v4 or @main) can be hijacked or modified upstream by attackers, " +
                "leading to automated execution of compromised action code inside CI pipelines.",
              fingerprint: generateFingerprint("ci-unpinned-action", normalizedPath, lineNum),
            });
          }
        }
      }

      // 3. Secrets echoed to logs
      if (/echo\s+.*?\$\{\{\s*secrets\./i.test(lineText)) {
        findings.push({
          id: generateFindingId(),
          ruleId: "ci-secrets-echoed",
          title: "CI Workflow Secret Echoed to Logs",
          severity: "high",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: lineNum, endLine: lineNum },
          evidenceChain: [
            {
              kind: "sink",
              file: normalizedPath,
              line: lineNum,
              maskedSnippet: lineText.trim(),
              confidence: "high",
              note: "Secret variable echoed in script step",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Printing secrets or environment variables directly to stdout in CI scripts writes raw credentials to public build log outputs.",
          fingerprint: generateFingerprint("ci-secrets-echoed", normalizedPath, lineNum),
        });
      }
    });

    // 4. pull_request_target with checkout of PR head code
    if (isPullRequestTarget) {
      lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;
        if (lineText.includes("actions/checkout")) {
          // Check if checkout step has ref set to PR head sha
          let endLine = lineNum;
          let hasPrHeadRef = false;
          for (let k = idx; k < Math.min(lines.length, idx + 5); k++) {
            if (lines[k].includes("pull_request.head")) {
              hasPrHeadRef = true;
              endLine = k + 1;
              break;
            }
          }

          if (hasPrHeadRef) {
            findings.push({
              id: generateFindingId(),
              ruleId: "ci-pull-request-target-checkout",
              title: "pull_request_target Workflow Checks Out Untrusted PR Code",
              severity: "critical",
              confidenceTier: "proven",
              file: normalizedPath,
              lineRange: { startLine: lineNum, endLine },
              evidenceChain: [
                {
                  kind: "sink",
                  file: normalizedPath,
                  line: lineNum,
                  maskedSnippet: lines.slice(idx, endLine).join("\n").trim(),
                  confidence: "high",
                  note: "pull_request_target checkout of PR head code",
                },
              ],
              unresolvedSteps: [],
              explanation:
                "Using pull_request_target grants workflow execution write tokens and secret access to untrusted pull requests " +
                "from fork repositories, allowing hostile PRs to execute arbitrary malicious code with repository privileges.",
              fingerprint: generateFingerprint(
                "ci-pull-request-target-checkout",
                normalizedPath,
                lineNum
              ),
            });
          }
        }
      });
    }
    // Sort findings by line order for deterministic finding lists
    findings.sort((a, b) => a.lineRange.startLine - b.lineRange.startLine);
  }

  return findings;
}
