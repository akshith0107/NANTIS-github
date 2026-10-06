import child_process from "child_process";
import fs from "fs";
import { walkDirectory } from "@nantis/core";

export interface CloneSandboxOptions {
  repoUrl: string;
  branch: string;
  targetDir: string;
  token?: string;
  maxRepoSizeBytes?: number;
}

/**
 * Sanitize error message to ensure tokens and internal file paths are never exposed.
 */
export function sanitizeGitErrorMessage(err: unknown, token?: string): string {
  let msg = err instanceof Error ? err.message : String(err);
  if (token) {
    msg = msg.replaceAll(token, "[REDACTED_TOKEN]");
  }
  if (
    msg.includes("cloning failed") ||
    msg.includes("fatal:") ||
    msg.includes("git clone failed")
  ) {
    return "Failed to clone repository source tree";
  }
  return msg;
}

/**
 * Perform a secure, sandboxed shallow git clone.
 * Disables git hooks, filter drivers (such as LFS smudge scripts), symlinks,
 * and system/global git configs to guarantee NO malicious repo script execution.
 */
export async function cloneRepositorySandboxed(options: CloneSandboxOptions): Promise<void> {
  const { repoUrl, branch, targetDir, token, maxRepoSizeBytes } = options;

  // Prepare clean target directory
  if (fs.existsSync(targetDir)) {
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
  fs.mkdirSync(targetDir, { recursive: true });

  // Format repository URL with token if provided (kept in memory only)
  let authenticatedUrl = repoUrl;
  if (token && repoUrl.startsWith("https://")) {
    authenticatedUrl = repoUrl.replace("https://", `https://x-access-token:${token}@`);
  }

  // Construct secure git clone command flags
  const gitArgs = [
    "clone",
    "--depth",
    "1",
    "--single-branch",
    "--branch",
    branch || "main",
    "-c",
    "core.hooksPath=",
    "-c",
    "core.symlinks=false",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.clean=",
    authenticatedUrl,
    targetDir,
  ];

  const env = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "",
    GIT_TERMINAL_PROMPT: "0",
  };

  try {
    await new Promise<void>((resolve, reject) => {
      child_process.execFile("git", gitArgs, { env, timeout: 30000 }, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  } catch (err: unknown) {
    const safeMsg = sanitizeGitErrorMessage(err, token);
    throw new Error(safeMsg);
  }

  // Check repository disk size limit
  if (maxRepoSizeBytes && maxRepoSizeBytes > 0 && fs.existsSync(targetDir)) {
    let totalSizeBytes = 0;
    const files = walkDirectory(targetDir);
    for (const f of files) {
      totalSizeBytes += Buffer.byteLength(f.content, "utf-8");
    }

    if (totalSizeBytes > maxRepoSizeBytes) {
      throw new Error(
        `Repository size (${totalSizeBytes} bytes) exceeds maximum allowed scan limit (${maxRepoSizeBytes} bytes)`
      );
    }
  }
}
