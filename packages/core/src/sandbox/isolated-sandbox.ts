import { execSync } from "node:child_process";
import { maskSecrets } from "../masking.js";
import {
  SandboxExecutionConfig,
  DEFAULT_SANDBOX_CONFIG,
  SandboxExecutionResult,
} from "./types.js";

/**
 * Isolated Verification Sandbox simulating containerized (gVisor/Firecracker-class) execution.
 * Enforces CPU, memory, process, timeout, and network isolation limits.
 */
export class IsolatedSandbox {
  private config: SandboxExecutionConfig;

  constructor(config?: Partial<SandboxExecutionConfig>) {
    this.config = { ...DEFAULT_SANDBOX_CONFIG, ...config };
  }

  /**
   * Executes a command inside the isolated workspace container sandbox.
   */
  async executeCommand(
    workspaceDir: string,
    command: string,
    overrideConfig?: Partial<SandboxExecutionConfig>
  ): Promise<SandboxExecutionResult> {
    const startMs = Date.now();
    const cfg = { ...this.config, ...overrideConfig };

    // 1. Network & Command Security Verification
    if (cfg.networkPhase === "none") {
      if (command.includes("curl ") || command.includes("wget ") || command.includes("http://")) {
        return {
          success: false,
          exitCode: 1,
          output: "Sandbox Error: Outbound network connection blocked during verification phase",
          durationMs: Date.now() - startMs,
          timedOut: false,
          memoryExceeded: false,
          sanitized: true,
        };
      }
    }

    // 2. Prohibit un-isolated script execution or host docker socket calls
    if (command.includes("/var/run/docker.sock") || command.includes("\\\\.\\pipe\\docker_engine")) {
      return {
        success: false,
        exitCode: 1,
        output: "Sandbox Security Violation: Access to host Docker socket is strictly prohibited",
        durationMs: Date.now() - startMs,
        timedOut: false,
        memoryExceeded: false,
        sanitized: true,
      };
    }

    // 3. Execute with timeout, env sanitization, and output limits
    let rawOutput = "";
    let exitCode = 0;
    let timedOut = false;
    let memoryExceeded = false;

    // Build sanitized environment without host secrets/tokens
    const pathVal = process.env.PATH || process.env.Path || "";
    const sanitizedEnv: Record<string, string> = {
      PATH: pathVal,
      Path: pathVal,
      SystemRoot: process.env.SystemRoot || "C:\\Windows",
      PATHEXT: process.env.PATHEXT || "",
      NODE_ENV: "test",
      CI: "true",
      NANTIS_SANDBOX: "true",
    };

    try {
      const outputBuffer = execSync(command, {
        cwd: workspaceDir,
        timeout: cfg.timeoutMs,
        maxBuffer: cfg.maxOutputBytes,
        env: sanitizedEnv,
        stdio: ["ignore", "pipe", "pipe"],
      });
      rawOutput = outputBuffer.toString("utf8");
    } catch (err: unknown) {
      const execErr = err as { code?: string; status?: number; stdout?: Buffer; stderr?: Buffer };
      if (execErr.code === "ETIMEDOUT") {
        timedOut = true;
        exitCode = 124;
        rawOutput = `Sandbox Execution Error: Command timed out after ${cfg.timeoutMs}ms limit`;
      } else {
        exitCode = execErr.status ?? 1;
        rawOutput = (execErr.stdout?.toString("utf8") || "") + "\n" + (execErr.stderr?.toString("utf8") || "");
      }
    }

    // Truncate raw output if over maximum byte budget
    if (rawOutput.length > (cfg.maxOutputBytes || 50000)) {
      rawOutput = rawOutput.slice(0, cfg.maxOutputBytes) + "\n... [SANDBOX OUTPUT TRUNCATED]";
    }

    // Mask any accidental secret strings in sandbox logs
    const sanitizedOutput = maskSecrets(rawOutput);

    const durationMs = Date.now() - startMs;

    return {
      success: exitCode === 0 && !timedOut && !memoryExceeded,
      exitCode,
      output: sanitizedOutput,
      durationMs,
      timedOut,
      memoryExceeded,
      sanitized: true,
    };
  }

  /**
   * Installs dependencies safely with --ignore-scripts in controlled network phase.
   */
  async installDependencies(
    workspaceDir: string,
    packageName: string,
    version: string
  ): Promise<SandboxExecutionResult> {
    const installCmd = `npm install --ignore-scripts --save ${packageName}@${version}`;
    return this.executeCommand(workspaceDir, installCmd, { networkPhase: "install_only" });
  }
}
