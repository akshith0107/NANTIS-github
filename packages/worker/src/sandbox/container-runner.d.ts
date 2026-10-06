export interface RunContainerSandboxOptions {
  workspaceDir: string;
  command: string[];
  env?: Record<string, string>;
  timeoutMs?: number;
  disableLifecycleScripts?: boolean;
}
export interface SandboxExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  contained: boolean;
  violationReason?: string;
}
/**
 * Filter environment variables to strictly prevent host secret leakage into sandbox process.
 */
export declare function sanitizeSandboxEnvironment(
  customEnv?: Record<string, string>
): Record<string, string>;
/**
 * Executes commands inside an isolated OCI Container Sandbox or sandbox process guard.
 * Enforces read-only root, non-root user, capability dropping, resource quotas,
 * network egress isolation, and lifecycle script suppression (--ignore-scripts).
 */
export declare function runInContainerSandbox(
  options: RunContainerSandboxOptions
): Promise<SandboxExecutionResult>;
//# sourceMappingURL=container-runner.d.ts.map
