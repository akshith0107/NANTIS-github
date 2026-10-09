import { execFileSync, execSync } from "node:child_process";
import { maskSecrets } from "../masking.js";
import {
  SandboxExecutionConfig,
  DEFAULT_SANDBOX_CONFIG,
  SandboxExecutionResult,
} from "./types.js";

/**
 * Checks whether Docker or Podman container daemon is active and responsive on the host.
 */
export function detectContainerEngine(): "docker" | "podman" | null {
  try {
    execSync("docker info", { stdio: "ignore", timeout: 1500 });
    return "docker";
  } catch {
    try {
      execSync("podman info", { stdio: "ignore", timeout: 1500 });
      return "podman";
    } catch {
      return null;
    }
  }
}

/**
 * Isolated Verification Sandbox executing untrusted commands strictly inside container runtimes (Docker/Podman/gVisor).
 * Enforces CPU, memory, process, timeout, network phase isolation, and strict fail-closed policy when container runtime is unavailable.
 */
export class IsolatedSandbox {
  private config: SandboxExecutionConfig;

  constructor(config?: Partial<SandboxExecutionConfig>) {
    this.config = { ...DEFAULT_SANDBOX_CONFIG, ...config };
  }

  /**
   * Executes a command inside the isolated container sandbox.
   * Fail-closed: If container runtime daemon is unavailable, host shell fallback is strictly prohibited.
   */
  async executeCommand(
    workspaceDir: string,
    command: string,
    overrideConfig?: Partial<SandboxExecutionConfig>
  ): Promise<SandboxExecutionResult> {
    const startMs = Date.now();
    const cfg = { ...this.config, ...overrideConfig };

    // 1. Determine Container Runtime Engine
    let engine: "docker" | "podman" | "mock" | null = null;
    if (cfg.runtimeEngine === "unavailable") {
      engine = null;
    } else if (cfg.runtimeEngine === "mock") {
      engine = "mock";
    } else if (cfg.runtimeEngine === "docker" || cfg.runtimeEngine === "podman") {
      engine = cfg.runtimeEngine;
    } else {
      engine = detectContainerEngine();
    }

    // 2. FAIL-CLOSED INVARIANT: If container runtime daemon is unavailable, DO NOT execute code on host shell!
    if (!engine) {
      return {
        success: false,
        exitCode: 127,
        output: "Sandbox Execution Error: Container runtime (Docker/Podman/gVisor) is unavailable or unhealthy. Fail-closed policy enforced; host execution prohibited.",
        durationMs: Date.now() - startMs,
        timedOut: false,
        memoryExceeded: false,
        sanitized: true,
        unavailable: true,
      };
    }

    // 3. Security Pre-Check: Prohibit Docker socket access or privilege escalation attempts
    if (
      command.includes("/var/run/docker.sock") ||
      command.includes("\\\\.\\pipe\\docker_engine") ||
      command.includes("docker run") ||
      command.includes("podman run") ||
      command.includes("--privileged")
    ) {
      return {
        success: false,
        exitCode: 1,
        output: "Sandbox Security Violation: Access to host Docker socket or container privilege escalation is strictly prohibited",
        durationMs: Date.now() - startMs,
        timedOut: false,
        memoryExceeded: false,
        sanitized: true,
      };
    }

    // 4. Security Pre-Check: Network Phase Isolation
    if (cfg.networkPhase === "none") {
      if (
        command.includes("curl ") ||
        command.includes("wget ") ||
        command.includes("http://") ||
        command.includes("https://") ||
        command.includes("fetch(") ||
        command.includes("urllib") ||
        command.includes("socket.") ||
        command.includes("require(\"net\")") ||
        command.includes("require('net')") ||
        command.includes("net.connect")
      ) {
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

    // 5. Execute via Mock Engine (for testing without Docker daemon)
    if (engine === "mock") {
      return this.executeMockContainer(command, cfg, startMs);
    }

    // 6. Execute via Real Container Daemon (Docker / Podman)
    return this.executeRealContainer(engine, workspaceDir, command, cfg, startMs);
  }

  private executeMockContainer(
    command: string,
    cfg: SandboxExecutionConfig,
    startMs: number
  ): SandboxExecutionResult {
    let rawOutput = "";
    let exitCode = 0;
    let timedOut = false;
    let memoryExceeded = false;

    if (command.includes("FORK_BOMB") || command.includes(":(){ :|:& };:")) {
      exitCode = 137;
      rawOutput = "Sandbox Execution Error: Process creation limit (20) exceeded in container";
    } else if (command.includes("MEMORY_EXHAUST")) {
      memoryExceeded = true;
      exitCode = 137;
      rawOutput = "Sandbox Execution Error: Memory limit (512MB) exceeded in container";
    } else if (command.includes("TIMEOUT_LOOP") || command.includes("while true")) {
      timedOut = true;
      exitCode = 124;
      rawOutput = `Sandbox Execution Error: Command timed out after ${cfg.timeoutMs}ms limit`;
    } else if (command.includes("HUGE_OUTPUT")) {
      rawOutput = "A".repeat(100000);
    } else if (command.includes("FAIL_CMD") || command.includes("exit 1")) {
      exitCode = 1;
      rawOutput = "Container command exited with code 1";
    } else if (command.includes("sk_live_")) {
      rawOutput = maskSecrets(command);
    } else {
      rawOutput = `Container execution succeeded: ${command}`;
    }

    if (rawOutput.length > (cfg.maxOutputBytes || 50000)) {
      rawOutput = rawOutput.slice(0, cfg.maxOutputBytes) + "\n... [SANDBOX OUTPUT TRUNCATED]";
    }

    const sanitizedOutput = maskSecrets(rawOutput);

    return {
      success: exitCode === 0 && !timedOut && !memoryExceeded,
      exitCode,
      output: sanitizedOutput,
      durationMs: Date.now() - startMs,
      timedOut,
      memoryExceeded,
      sanitized: true,
    };
  }

  private executeRealContainer(
    engine: "docker" | "podman",
    workspaceDir: string,
    command: string,
    cfg: SandboxExecutionConfig,
    startMs: number
  ): SandboxExecutionResult {
    const normalizedWorkspace = workspaceDir.replace(/\\/g, "/");
    const imageName = cfg.image || "node:20-alpine";
    const netMode = cfg.networkPhase === "install_only" ? "bridge" : "none";

    const containerArgs = [
      "run",
      "--rm",
      "--network", netMode,
      "--user", "1000:1000",
      "--cap-drop=ALL",
      "--security-opt", "no-new-privileges",
      "--cpus", String(cfg.cpuCount || 1),
      "--memory", `${cfg.maxMemoryMb || 512}m`,
      "--pids-limit", String(cfg.maxProcesses || 20),
      "-v", `${normalizedWorkspace}:/workspace:rw`,
      "-w", "/workspace",
      "-e", "NODE_ENV=test",
      "-e", "CI=true",
      "-e", "NANTIS_SANDBOX=true",
      "--entrypoint", "/bin/sh",
      imageName,
      "-c",
      command,
    ];

    let rawOutput = "";
    let exitCode = 0;
    let timedOut = false;
    let memoryExceeded = false;

    try {
      const outputBuffer = execFileSync(engine, containerArgs, {
        timeout: cfg.timeoutMs,
        maxBuffer: cfg.maxOutputBytes,
        stdio: ["ignore", "pipe", "pipe"],
      });
      rawOutput = outputBuffer.toString("utf8");
    } catch (err: unknown) {
      const execErr = err as { code?: string; status?: number; stdout?: Buffer; stderr?: Buffer };
      if (execErr.code === "ETIMEDOUT") {
        timedOut = true;
        exitCode = 124;
        rawOutput = `Sandbox Execution Error: Container command timed out after ${cfg.timeoutMs}ms limit`;
      } else {
        exitCode = execErr.status ?? 1;
        rawOutput = (execErr.stdout?.toString("utf8") || "") + "\n" + (execErr.stderr?.toString("utf8") || "");
      }
    }

    if (rawOutput.length > (cfg.maxOutputBytes || 50000)) {
      rawOutput = rawOutput.slice(0, cfg.maxOutputBytes) + "\n... [SANDBOX OUTPUT TRUNCATED]";
    }

    const sanitizedOutput = maskSecrets(rawOutput);

    return {
      success: exitCode === 0 && !timedOut && !memoryExceeded,
      exitCode,
      output: sanitizedOutput,
      durationMs: Date.now() - startMs,
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
