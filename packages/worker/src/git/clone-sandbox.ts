import child_process from "child_process";
import fs from "fs";
import path from "path";
import { walkDirectory } from "@nantis/core";

export interface CloneSandboxOptions {
  repoUrl: string;
  branch?: string;
  targetDir: string;
  token?: string;
  maxRepoSizeBytes?: number;
  maxFileCount?: number;
  timeoutMs?: number;
}

/**
 * Sanitize error message to ensure tokens and internal file paths are never exposed.
 */
export function sanitizeGitErrorMessage(err: unknown, token?: string): string {
  let msg = err instanceof Error ? err.message : String(err);
  if (token) {
    msg = msg.replaceAll(token, "[REDACTED_TOKEN]");
  }
  msg = msg.replace(/https?:\/\/[^@\s]+@/g, "https://");

  if (msg.includes("exceeds maximum")) {
    return msg;
  }

  if (
    msg.includes("cloning failed") ||
    msg.includes("fatal:") ||
    msg.includes("git clone failed") ||
    msg.includes("Git clone failed") ||
    msg.includes("timed out") ||
    msg.includes("ETIMEDOUT") ||
    msg.includes("REDACTED")
  ) {
    return "Failed to clone repository source tree";
  }
  return msg;
}

/**
 * Perform a secure, sandboxed shallow git clone.
 * Disables git hooks, filter drivers (such as LFS smudge scripts), symlinks,
 * submodules, and system/global git configs to guarantee NO malicious repo script execution.
 */
export async function cloneRepositorySandboxed(options: CloneSandboxOptions): Promise<void> {
  const { repoUrl, branch, targetDir, token, maxRepoSizeBytes, maxFileCount, timeoutMs } = options;

  // Prepare clean target directory parent
  if (fs.existsSync(targetDir)) {
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
  fs.mkdirSync(path.dirname(targetDir), { recursive: true });

  // Keep plain repository URL (no credentials in URL, zero token in .git/config)
  const plainUrl = repoUrl;

  // Construct secure git clone command flags
  const gitArgs: string[] = [
    "-c",
    "protocol.file.allow=always",
    "clone",
    "--depth",
    "1",
    "--single-branch",
    "--no-recurse-submodules",
  ];

  if (branch) {
    gitArgs.push("--branch", branch);
  }

  gitArgs.push(
    "-c",
    "core.hooksPath=",
    "-c",
    "core.symlinks=false",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.process=",
    plainUrl,
    targetDir
  );

  const env: Record<string, string | undefined> = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "",
    GIT_TERMINAL_PROMPT: "0",
  };

  // Pass token via GIT_CONFIG_COUNT / KEY / VALUE environment variables (zero process argv exposure)
  if (token) {
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_0 = `Authorization: Bearer ${token}`;
  }

  const actualTimeout = timeoutMs || 30000;

  try {
    await new Promise<void>((resolve, reject) => {
      child_process.execFile(
        "git",
        gitArgs,
        {
          env,
          timeout: actualTimeout,
          maxBuffer: 10 * 1024 * 1024,
        },
        (error, _stdout, stderr) => {
          if (error) {
            const sanitizedErr = sanitizeGitErrorMessage(stderr || error.message, token);
            reject(new Error(sanitizedErr));
          } else {
            resolve();
          }
        }
      );
    });
  } catch (err) {
    if (fs.existsSync(targetDir)) {
      fs.rmSync(targetDir, { recursive: true, force: true });
    }
    throw new Error(sanitizeGitErrorMessage(err, token));
  }

  // Post-clone size and file count enforcement
  if (maxRepoSizeBytes || maxFileCount) {
    const scannedFiles = walkDirectory(targetDir);
    if (maxFileCount && scannedFiles.length > maxFileCount) {
      if (fs.existsSync(targetDir)) {
        fs.rmSync(targetDir, { recursive: true, force: true });
      }
      throw new Error(`Repository exceeds maximum allowed file count limit of ${maxFileCount} files`);
    }

    const totalSize = scannedFiles.reduce((acc, f) => acc + (f.content ? f.content.length : 0), 0);
    if (maxRepoSizeBytes && totalSize > maxRepoSizeBytes) {
      if (fs.existsSync(targetDir)) {
        fs.rmSync(targetDir, { recursive: true, force: true });
      }
      throw new Error(
        `Repository size exceeds maximum allowed scan limit of ${Math.round(
          maxRepoSizeBytes / (1024 * 1024)
        )}MB`
      );
    }
  }
}
