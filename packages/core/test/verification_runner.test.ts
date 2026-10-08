import fs from "fs";
import path from "path";
import os from "os";
import { describe, expect, it } from "vitest";
import { runSandboxVerification, runSandboxInstall } from "../src/fixes/verification-runner.js";
import { Finding } from "../src/types.js";
import { ContainerSandboxRunner } from "../src/fixes/types.js";

describe("Sandbox Verification Runner Security Hardening", () => {
  const dummyFinding: Finding = {
    id: "finding-123",
    ruleId: "hardcoded-secret",
    title: "Hardcoded API Key",
    severity: "high",
    confidenceTier: "proven",
    file: "src/config.ts",
    lineRange: { startLine: 1, endLine: 1 },
    evidenceChain: [],
    unresolvedSteps: [],
    explanation: "Test",
    fingerprint: "test-fp",
  };

  it("never executes malicious package.json scripts (test or postinstall) on the host machine by default", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-test-sec-1-"));
    const markerFile = path.join(tempDir, "MALICIOUS_HOST_EXECUTED.txt");

    try {
      fs.mkdirSync(path.join(tempDir, "src"), { recursive: true });
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "malicious-repo",
          scripts: {
            test: `node -e "require('fs').writeFileSync('${markerFile.replace(/\\/g, "/")}', 'HACKED')"`,
            postinstall: `node -e "require('fs').writeFileSync('${markerFile.replace(/\\/g, "/")}', 'HACKED')"`,
          },
        })
      );
      fs.writeFileSync(path.join(tempDir, "package-lock.json"), JSON.stringify({ name: "malicious-repo", lockfileVersion: 2 }));
      fs.writeFileSync(path.join(tempDir, "src/config.ts"), "export const safe = true;\n");

      const report = await runSandboxVerification(tempDir, dummyFinding);

      expect(report.passed).toBe(true);
      expect(report.checksRun).toEqual(["rescan"]);
      expect(report.isWeak).toBeUndefined();
      expect(fs.existsSync(markerFile), "SECURITY FAILURE: Malicious host script was executed! Marker file was created.").toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("marks result as WEAK and does NOT execute script on host when runTests is requested without container runner", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-test-sec-2-"));
    const markerFile = path.join(tempDir, "MALICIOUS_HOST_EXECUTED.txt");

    try {
      fs.mkdirSync(path.join(tempDir, "src"), { recursive: true });
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "malicious-repo",
          scripts: {
            test: `node -e "require('fs').writeFileSync('${markerFile.replace(/\\/g, "/")}', 'HACKED')"`,
          },
        })
      );
      fs.writeFileSync(path.join(tempDir, "package-lock.json"), JSON.stringify({ name: "malicious-repo", lockfileVersion: 2 }));
      fs.writeFileSync(path.join(tempDir, "src/config.ts"), "export const safe = true;\n");

      const report = await runSandboxVerification(tempDir, dummyFinding, { runTests: true });

      expect(report.passed).toBe(true);
      expect(report.isWeak).toBe(true);
      expect(report.summaryText).toBe("PARTIALLY VERIFIED (typecheck not run)");
      expect(fs.existsSync(markerFile), "SECURITY FAILURE: Malicious test script ran on host!").toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("delegates test execution to container runner when containerRunner is configured", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-test-sec-3-"));
    let containerCommandExecuted = "";

    const mockContainerRunner: ContainerSandboxRunner = {
      async runCommand(_dir, command) {
        containerCommandExecuted = command;
        return { success: true, output: "PASS", exitCode: 0 };
      },
    };

    try {
      fs.mkdirSync(path.join(tempDir, "src"), { recursive: true });
      fs.writeFileSync(path.join(tempDir, "package.json"), JSON.stringify({ name: "app" }));
      fs.writeFileSync(path.join(tempDir, "package-lock.json"), JSON.stringify({ name: "app", lockfileVersion: 2 }));
      fs.writeFileSync(path.join(tempDir, "src/config.ts"), "export const safe = true;\n");

      const report = await runSandboxVerification(tempDir, dummyFinding, {
        runTests: true,
        containerRunner: mockContainerRunner,
      });

      expect(report.passed).toBe(true);
      expect(report.checksRun).toContain("test");
      expect(containerCommandExecuted).toBe("npm test");
      expect(report.isWeak).toBeUndefined();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("blocks host dependency installation when no container runner is provided", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-test-sec-4-"));

    try {
      expect(() => runSandboxInstall(tempDir, "axios", "1.7.4")).toThrow(
        "Host dependency installation blocked: container runner unconfigured"
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
