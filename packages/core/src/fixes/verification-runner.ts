import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { runScan } from "../cli/scan.js";
import { Finding } from "../types.js";
import { VerificationConfig, VerificationReport } from "./types.js";

/**
 * Executes verification checks inside the sandbox / temp copy directory.
 */
/**
 * Executes verification checks inside the sandbox / temp copy directory.
 * Host script execution (npm test, build scripts, lifecycle hooks) is strictly prohibited.
 */
export async function runSandboxVerification(
  tempCopyDir: string,
  originalFinding: Finding,
  config: VerificationConfig = { runTypecheck: true, runTests: false, runBuild: false }
): Promise<VerificationReport> {
  const checksRun: string[] = [];
  let isWeak = false;
  let testNote = "";

  // 1. Rescan verification (deterministic)
  checksRun.push("rescan");
  const scanResult = await runScan(tempCopyDir, { json: true });

  const originalStillExists = scanResult.findings.some(
    (f) => f.ruleId === originalFinding.ruleId && f.file === originalFinding.file
  );

  if (originalStillExists) {
    return {
      passed: false,
      checksRun,
      summaryText: "Verification FAILED: Target finding was not resolved by patch",
      dropReason: "Target finding persisted after fix applied",
    };
  }

  // Check for newly introduced findings (findings not present prior to patch application)
  const initialFingerprints = new Set(
    (config.initialFindings || [originalFinding]).map(
      (f) => f.fingerprint || `${f.ruleId}:${f.file}`
    )
  );

  const newFindings = scanResult.findings.filter(
    (f) => !initialFingerprints.has(f.fingerprint || `${f.ruleId}:${f.file}`)
  );

  if (newFindings.length > 0) {
    return {
      passed: false,
      checksRun,
      summaryText: `Verification FAILED: Patch introduced ${newFindings.length} new finding(s)`,
      dropReason: `Patch introduced new rule violation (${newFindings[0].ruleId})`,
    };
  }

  // 2. TypeScript typecheck (Safe static analysis: tsc does NOT execute package scripts)
  if (config.runTypecheck !== false && fs.existsSync(path.join(tempCopyDir, "tsconfig.json"))) {
    checksRun.push("tsc");
    try {
      execSync("npx tsc --noEmit", {
        cwd: tempCopyDir,
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf-8",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        passed: false,
        checksRun,
        summaryText: "Verification FAILED: tsc typecheck errors detected",
        dropReason: `TypeScript compiler failed: ${msg.slice(0, 100)}`,
      };
    }
  }

  // 3. Optional Unit tests check (Opt-in ONLY; requires container runner)
  if (config.runTests) {
    if (config.containerRunner) {
      checksRun.push("test");
      try {
        const result = await config.containerRunner.runCommand(tempCopyDir, "npm test");
        if (!result.success || result.exitCode !== 0) {
          return {
            passed: false,
            checksRun,
            summaryText: "Verification FAILED: Unit tests failed in container sandbox",
            dropReason: "Unit test suite failed inside isolated container runner",
          };
        }
      } catch {
        return {
          passed: false,
          checksRun,
          summaryText: "Verification FAILED: Container runner error during unit tests",
          dropReason: "Container runner failed to execute unit tests",
        };
      }
    } else {
      isWeak = true;
      testNote += "; tests not run: container runner unconfigured";
    }
  }

  // 4. Optional Build check (Opt-in ONLY; requires container runner)
  if (config.runBuild) {
    if (config.containerRunner) {
      checksRun.push("next build");
      try {
        const result = await config.containerRunner.runCommand(tempCopyDir, "npx next build");
        if (!result.success || result.exitCode !== 0) {
          return {
            passed: false,
            checksRun,
            summaryText: "Verification FAILED: Production build failed in container sandbox",
            dropReason: "Next.js build failed inside isolated container runner",
          };
        }
      } catch {
        return {
          passed: false,
          checksRun,
          summaryText: "Verification FAILED: Container runner error during build",
          dropReason: "Container runner failed to execute build",
        };
      }
    } else {
      isWeak = true;
      testNote += "; build not run: container runner unconfigured";
    }
  }

  const summaryText = `verified: ${checksRun.join(" + ")}${testNote}${isWeak ? " (WEAK verification)" : ""}`;

  return {
    passed: true,
    checksRun,
    summaryText,
    isWeak: isWeak ? true : undefined,
  };
}

/**
 * Installs dependencies strictly via container runner. Host execution is blocked.
 */
export function runSandboxInstall(
  tempCopyDir: string,
  pkgName: string,
  version: string,
  containerRunner?: VerificationConfig["containerRunner"]
): void {
  if (!containerRunner) {
    throw new Error(
      "Host dependency installation blocked: container runner unconfigured for sandboxed install"
    );
  }
  containerRunner.runCommand(
    tempCopyDir,
    `npm install --ignore-scripts --save ${pkgName}@${version}`
  );
}
