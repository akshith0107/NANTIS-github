import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import readline from "readline";
import { maskSecrets } from "../masking.js";
import { Finding, Severity } from "../types.js";

const KNOWN_SECRET_REGEXES: Array<{ name: string; pattern: RegExp; defaultSeverity: Severity }> = [
  {
    name: "Stripe Secret Key",
    pattern: /\b(sk_live_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "critical",
  },
  { name: "Stripe Test Key", pattern: /\b(sk_test_[0-9a-zA-Z_]{16,})\b/g, defaultSeverity: "high" },
  {
    name: "Stripe Restricted Key",
    pattern: /\b(rk_live_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Stripe Restricted Test Key",
    pattern: /\b(rk_test_[0-9a-zA-Z_]{16,})\b/g,
    defaultSeverity: "high",
  },
  {
    name: "Supabase Service Role Key",
    pattern: /\b(sbp_[a-f0-9_]{32,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Supabase Postgres Connection",
    pattern: /postgres:\/\/[^:]+:[^@]+@[^\s"']+/g,
    defaultSeverity: "critical",
  },
  { name: "AWS Access Key", pattern: /\b(AKIA[0-9A-Z]{16})\b/g, defaultSeverity: "critical" },
  {
    name: "GitHub Personal Token",
    pattern: /\b(ghp_[a-zA-Z0-9_]{30,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "GitHub OAuth Token",
    pattern: /\b(gho_[a-zA-Z0-9_]{30,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "GitHub Fine-Grained Token",
    pattern: /\b(github_pat_[a-zA-Z0-9_]{20,})\b/g,
    defaultSeverity: "critical",
  },
  {
    name: "Private Key Block",
    pattern: /-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----/g,
    defaultSeverity: "critical",
  },
];

function generateFindingId(): string {
  return crypto.randomUUID();
}

function generateFingerprint(
  ruleId: string,
  commitHash: string,
  filePath: string,
  secretName: string
): string {
  return crypto
    .createHash("sha256")
    .update(`${ruleId}:${commitHash}:${filePath.toLowerCase()}:${secretName}`)
    .digest("hex");
}

export function scanGitHistory(repoDir: string): Promise<Finding[]> {
  const dotGitPath = path.join(repoDir, ".git");
  if (!fs.existsSync(dotGitPath)) {
    return Promise.resolve([]);
  }

  return new Promise((resolve) => {
    // Spawn git log with explicit args array (prevents shell command injection)
    const gitProcess = spawn("git", ["log", "-p", "-U0", "--all", "--date=iso"], {
      cwd: repoDir,
      env: { ...process.env },
    });

    const findings: Finding[] = [];
    const rl = readline.createInterface({
      input: gitProcess.stdout,
      crlfDelay: Infinity,
    });

    let currentCommit = "";
    let currentAuthor = "";
    let currentDate = "";
    let currentFile = "";
    let lineNumberInDiff = 0;

    rl.on("line", (line: string) => {
      if (line.startsWith("commit ")) {
        currentCommit = line.substring(7).trim();
      } else if (line.startsWith("Author: ")) {
        currentAuthor = line.substring(8).trim();
      } else if (line.startsWith("Date: ")) {
        currentDate = line.substring(6).trim();
      } else if (line.startsWith("+++ b/")) {
        currentFile = line.substring(6).trim();
        lineNumberInDiff = 0;
      } else if (line.startsWith("@@ ")) {
        // Parse @@ -a,b +c,d @@ to track target line number
        const match = /@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/.exec(line);
        if (match) {
          lineNumberInDiff = parseInt(match[1], 10) - 1;
        }
      } else if (line.startsWith("+") && !line.startsWith("+++")) {
        lineNumberInDiff++;
        const addedText = line.substring(1);

        // Scan added line for known secrets
        for (const { name, pattern, defaultSeverity } of KNOWN_SECRET_REGEXES) {
          pattern.lastIndex = 0;
          if (pattern.test(addedText)) {
            const maskedSnippet = maskSecrets(addedText);
            const lineNum = Math.max(1, lineNumberInDiff);

            findings.push({
              id: generateFindingId(),
              ruleId: "git-history-secret-leak",
              title: `Historical Secret Leaked in Git Commit (${name})`,
              severity: defaultSeverity,
              confidenceTier: "proven",
              file: currentFile || "unknown",
              lineRange: { startLine: lineNum, endLine: lineNum },
              evidenceChain: [
                {
                  kind: "sink",
                  file: currentFile || "unknown",
                  line: lineNum,
                  maskedSnippet,
                  confidence: "high",
                  note: `Secret added in commit ${currentCommit.substring(0, 8)}`,
                },
              ],
              unresolvedSteps: [],
              explanation:
                `Found secret ${name} added in historical commit ${currentCommit.substring(0, 8)} by ${currentAuthor} on ${currentDate}. ` +
                `Even if removed in subsequent commits, the key remains accessible in git history. ` +
                `ROTATE THIS KEY IMMEDIATELY. Removing from history is not enough as the key may already be compromised.`,
              fingerprint: generateFingerprint(
                "git-history-secret-leak",
                currentCommit,
                currentFile,
                name
              ),
              introducedIn: {
                commit: currentCommit,
                author: currentAuthor,
                date: currentDate,
              },
            });
          }
        }
      }
    });

    gitProcess.on("error", () => {
      // If git is not installed or repo is not a git repo, return empty array gracefully
      resolve([]);
    });

    gitProcess.on("close", () => {
      resolve(findings);
    });
  });
}
