import { Finding, ScanDiagnostic } from "@nantis/core";
import { WebEnv } from "./env.js";
import { getInstallationAccessToken } from "./github-app.js";

export interface GitHubCheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "failure" | "warning" | "notice";
  message: string;
  title: string;
}

export interface CreateCheckRunOptions {
  owner: string;
  repo: string;
  headSha: string;
  installationId: number;
  env: WebEnv;
  fetchFn?: typeof fetch;
}

export interface UpdateCheckRunOptions {
  owner: string;
  repo: string;
  checkRunId: number;
  installationId: number;
  status: "queued" | "cloning" | "scanning" | "done" | "failed" | "pending" | "running" | "completed";
  scanId: string;
  findings?: Finding[];
  diagnostics?: ScanDiagnostic[];
  errorMessage?: string;
  env: WebEnv;
  fetchFn?: typeof fetch;
}

/**
 * Creates a GitHub Check Run in 'queued' status when a scan is initiated.
 * Failure isolated: Errors in GitHub API calls return null without breaking scan creation.
 */
export async function createGitHubCheckRun(options: CreateCheckRunOptions): Promise<number | null> {
  const { owner, repo, headSha, installationId, env, fetchFn = fetch } = options;

  try {
    const token = await getInstallationAccessToken(
      installationId,
      env.GITHUB_APP_ID,
      env.GITHUB_APP_PRIVATE_KEY,
      fetchFn
    );

    const res = await fetchFn(`https://api.github.com/repos/${owner}/${repo}/check-runs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "NANTIS-App",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "NANTIS Security Analysis",
        head_sha: headSha,
        status: "queued",
        started_at: new Date().toISOString(),
        output: {
          title: "NANTIS Security Analysis Queued",
          summary: "NANTIS static security analysis has been queued for processing.",
        },
      }),
    });

    if (!res.ok) {
      return null;
    }

    const data = (await res.json()) as { id?: number };
    return data.id || null;
  } catch {
    // Failure isolation: API errors must not crash scan creation
    return null;
  }
}

/**
 * Updates an existing GitHub Check Run as scan progresses (in_progress or completed).
 */
export async function updateGitHubCheckRun(options: UpdateCheckRunOptions): Promise<boolean> {
  const {
    owner,
    repo,
    checkRunId,
    installationId,
    status,
    scanId,
    findings = [],
    diagnostics = [],
    errorMessage,
    env,
    fetchFn = fetch,
  } = options;

  try {
    const token = await getInstallationAccessToken(
      installationId,
      env.GITHUB_APP_ID,
      env.GITHUB_APP_PRIVATE_KEY,
      fetchFn
    );

    let bodyPayload: Record<string, unknown>;

    if (status === "cloning" || status === "scanning" || status === "running" || status === "pending") {
      bodyPayload = {
        name: "NANTIS Security Analysis",
        status: "in_progress",
        output: {
          title: "NANTIS Security Analysis In Progress",
          summary: `NANTIS is analyzing repository source code (${status}).`,
        },
      };
    } else {
      // Completed status (done, completed, or failed)
      let conclusion: "success" | "failure" | "action_required" | "neutral" = "success";
      let title = "No issues found in checks performed";
      let summaryText = "NANTIS completed configured security checks. Zero findings detected across 19 deterministic security rules.";

      if (status === "failed") {
        conclusion = "failure";
        title = "NANTIS scan failed before completing checks";
        summaryText = `NANTIS scan failed before completing configured checks: ${errorMessage || "Scan execution error"}`;
      } else if (findings.length > 0) {
        conclusion = "action_required";
        title = `NANTIS found ${findings.length} issue(s) in checks performed`;

        const findingLines = findings.map(
          (f) => `- **[${f.ruleId}] ${f.title}** (${f.severity.toUpperCase()}): ${f.file}:${f.lineRange?.startLine || 1}`
        );
        summaryText = `NANTIS completed configured security checks and found **${findings.length} issue(s)**:\n\n${findingLines.join("\n")}\n\n[View Findings Dashboard](/scans/${scanId})`;
      } else if (diagnostics.some((d) => d.kind === "analysis_warning" || d.kind === "detector_error" || d.fatal)) {
        conclusion = "neutral";
        title = "No security issues found (completed with warnings)";
        summaryText = "NANTIS completed configured security checks. No vulnerabilities found, but 1 or more diagnostics warnings were emitted during analysis.";
      }

      const annotations: GitHubCheckAnnotation[] = findings
        .filter((f) => f.file)
        .map((f) => ({
          path: f.file,
          start_line: f.lineRange?.startLine || 1,
          end_line: f.lineRange?.endLine || f.lineRange?.startLine || 1,
          annotation_level: (f.severity === "high" || f.severity === "critical" ? "failure" : "warning") as "failure" | "warning",
          message: f.explanation || f.title,
          title: `[${f.ruleId}] ${f.title}`,
        }))
        .slice(0, 50); // Cap at max 50 annotations per GitHub API limits

      bodyPayload = {
        name: "NANTIS Security Analysis",
        status: "completed",
        completed_at: new Date().toISOString(),
        conclusion,
        output: {
          title,
          summary: summaryText,
          ...(annotations.length > 0 ? { annotations } : {}),
        },
      };
    }

    const res = await fetchFn(`https://api.github.com/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "NANTIS-App",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(bodyPayload),
    });

    return res.ok;
  } catch {
    // Failure isolation: API update failure does not crash scan
    return false;
  }
}
