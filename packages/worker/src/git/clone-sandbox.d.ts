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
export declare function sanitizeGitErrorMessage(err: unknown, token?: string): string;
/**
 * Perform a secure, sandboxed shallow git clone.
 * Disables git hooks, filter drivers (such as LFS smudge scripts), symlinks,
 * and system/global git configs to guarantee NO malicious repo script execution.
 */
export declare function cloneRepositorySandboxed(options: CloneSandboxOptions): Promise<void>;
//# sourceMappingURL=clone-sandbox.d.ts.map
