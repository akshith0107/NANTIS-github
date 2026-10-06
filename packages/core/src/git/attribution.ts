import { spawn } from "child_process";
import { Finding, GitCommitMeta, HopConfidence } from "../types.js";

export function parsePrNumber(commitMessage: string): number | undefined {
  if (!commitMessage) return undefined;

  // Patterns like (#123), PR #123, Merge pull request #123
  const prPatterns = [
    /\(#(\d+)\)/,
    /\bPR\s*#?(\d+)\b/i,
    /Merge\s+pull\s+request\s+#(\d+)/i,
    /pull\s+request\s+#(\d+)/i,
  ];

  for (const pattern of prPatterns) {
    const match = pattern.exec(commitMessage);
    if (match) {
      return parseInt(match[1], 10);
    }
  }

  return undefined;
}

function runGitCommand(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve) => {
    const gitProc = spawn("git", args, {
      cwd,
      env: { ...process.env },
    });

    let output = "";
    gitProc.stdout.on("data", (data) => {
      output += data.toString();
    });

    gitProc.on("error", () => {
      resolve("");
    });

    gitProc.on("close", () => {
      resolve(output.trim());
    });
  });
}

export async function isShallowRepo(repoDir: string): Promise<boolean> {
  const result = await runGitCommand(["rev-parse", "--is-shallow-repository"], repoDir);
  return result === "true";
}

export async function getBlameForLine(
  repoDir: string,
  filePath: string,
  lineNumber: number
): Promise<{
  commit: string;
  author: string;
  date: string;
  summary: string;
} | null> {
  const lineStr = `${lineNumber},${lineNumber}`;
  const rawPorcelain = await runGitCommand(
    ["blame", "-L", lineStr, "--porcelain", "--", filePath],
    repoDir
  );

  if (!rawPorcelain) {
    return null;
  }

  const lines = rawPorcelain.split(/\r?\n/);
  const firstLine = lines[0] || "";
  const commitHash = firstLine.split(" ")[0] || "";

  let author = "";
  let authorTime = "";
  let summary = "";

  for (const l of lines) {
    if (l.startsWith("author ")) {
      author = l.substring(7).trim();
    } else if (l.startsWith("author-time ")) {
      authorTime = l.substring(12).trim();
    } else if (l.startsWith("summary ")) {
      summary = l.substring(8).trim();
    }
  }

  let dateStr = "";
  if (authorTime) {
    const timestampSec = parseInt(authorTime, 10);
    if (!isNaN(timestampSec)) {
      dateStr = new Date(timestampSec * 1000).toISOString();
    }
  }

  return {
    commit: commitHash,
    author: author || "Unknown",
    date: dateStr,
    summary,
  };
}

export async function attachGitAttribution(finding: Finding, repoDir: string): Promise<Finding> {
  // If already set by detector, maintain baseline
  if (finding.introducedIn?.commit && finding.introducedIn?.confidence) {
    return finding;
  }

  const isShallow = await isShallowRepo(repoDir);
  const startLine = finding.lineRange.startLine || 1;
  const blame = await getBlameForLine(repoDir, finding.file, startLine);

  if (!blame) {
    return {
      ...finding,
      introducedIn: {
        confidence: "low",
        confidenceReason: "Git blame information unavailable for file or line",
      },
    };
  }

  const isUncommitted = /^0+$/.test(blame.commit);
  const prNumber = parsePrNumber(blame.summary);

  let confidence: HopConfidence = "high";
  let confidenceReason: string | undefined = undefined;

  if (isShallow) {
    confidence = "low";
    confidenceReason = "Shallow clone depth may obscure introducing commit history";
  } else if (isUncommitted) {
    confidence = "medium";
    confidenceReason = "Uncommitted local working tree changes";
  } else if (!prNumber && blame.summary.toLowerCase().includes("squash")) {
    confidence = "medium";
    confidenceReason = "Squashed commit history without explicit PR metadata";
  }

  const commitMeta: GitCommitMeta = {
    commit: isUncommitted ? "working-tree-uncommitted" : blame.commit,
    author: blame.author,
    date: blame.date,
    pr: prNumber,
    confidence,
    confidenceReason,
  };

  return {
    ...finding,
    introducedIn: commitMeta,
  };
}

export async function attachGitAttributionToFindings(
  findings: Finding[],
  repoDir: string
): Promise<Finding[]> {
  const result: Finding[] = [];
  for (const f of findings) {
    result.push(await attachGitAttribution(f, repoDir));
  }
  return result;
}
