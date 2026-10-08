import { describe, expect, it } from "vitest";
import {
  DETECTOR_REGISTRY,
  DetectorDefinition,
  Finding,
  runAllDetectors,
  sanitizeDiagnosticMessage,
} from "../src/index.js";
import { InMemoryDbAdapter, processScanJob, ScanJobQueue } from "../../worker/src/index.js";

describe("Phase 5B: Scan Diagnostics and Reliability", () => {
  it("A & E: Detector failure does not abort remaining detectors, and remaining detectors still execute after one throws", async () => {
    // Create mock detectors: detector 1 throws, detector 2 returns a finding
    const originalRegistry = [...DETECTOR_REGISTRY];
    try {
      const mockFailingDetector: DetectorDefinition = {
        id: "mockFailingDetector",
        name: "Mock Failing Detector",
        file: "mock-fail.ts",
        run: async () => {
          throw new Error("Simulated detector explosion! Path: C:\\Users\\secret\\repo and secret=sk_live_12345678901234567890");
        },
      };

      const mockSuccessDetector: DetectorDefinition = {
        id: "mockSuccessDetector",
        name: "Mock Success Detector",
        file: "mock-success.ts",
        run: async () => {
          const finding: Finding = {
            id: "finding-1",
            ruleId: "committed-env-file",
            title: "Mock Finding",
            severity: "high",
            confidenceTier: "proven",
            file: ".env",
            lineRange: { startLine: 1, endLine: 1 },
            explanation: "Mock finding from remaining detector",
            evidenceChain: [],
            unresolvedSteps: [],
            fingerprint: "mock-fingerprint-1",
          };
          return [finding];
        },
      };

      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(mockFailingDetector, mockSuccessDetector);

      const filesMap = new Map<string, string>([[".env", "FOO=bar"]]);
      const result = await runAllDetectors(filesMap, { offlineMode: true });

      // Remaining detector MUST execute despite previous detector throwing
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].ruleId).toBe("committed-env-file");

      // Diagnostic must be created
      expect(result.diagnostics.length).toBe(1);
      expect(result.diagnostics[0].detectorId).toBe("mockFailingDetector");
    } finally {
      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(...originalRegistry);
    }
  });

  it("B, C & G: Detector failure creates a diagnostic associated with the scan, producing FINDINGS_WITH_WARNINGS semantics", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const originalRegistry = [...DETECTOR_REGISTRY];

    try {
      const mockFailingDetector: DetectorDefinition = {
        id: "mockFailingDetector",
        name: "Mock Failing Detector",
        file: "mock-fail.ts",
        run: async () => {
          throw new Error("Syntax error parsing file foo.ts");
        },
      };

      const mockSuccessDetector: DetectorDefinition = {
        id: "mockSuccessDetector",
        name: "Mock Success Detector",
        file: "mock-success.ts",
        run: async () => {
          const finding: Finding = {
            id: "finding-1",
            ruleId: "committed-env-file",
            title: "Mock Finding",
            severity: "critical",
            confidenceTier: "proven",
            file: ".env",
            lineRange: { startLine: 1, endLine: 1 },
            explanation: "Found secret",
            evidenceChain: [],
            unresolvedSteps: [],
            fingerprint: "mock-fingerprint-2",
          };
          return [finding];
        },
      };

      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(mockFailingDetector, mockSuccessDetector);

      const scanId = "scan-test-123";
      const customFetcher = async (dir: string) => {
        // Create dummy file in directory
        const fs = await import("fs");
        const path = await import("path");
        fs.writeFileSync(path.join(dir, ".env"), "STRIPE_SECRET_KEY=sk_live_12345678901234567890");
      };

      const { state, findings } = await processScanJob(
        {
          scanId,
          repoId: "test/repo",
          installationId: 1,
          requestedByUserId: "user-1",
        },
        dbAdapter,
        { maxRepoSizeBytes: 10 * 1024 * 1024 },
        customFetcher
      );

      expect(state.status).toBe("done");
      expect(findings.length).toBe(1);

      // Verify diagnostics persisted to DB adapter and associated with scanId
      const diagnostics = await dbAdapter.getScanDiagnostics(scanId);
      expect(diagnostics.length).toBe(1);
      expect(diagnostics[0].detectorId).toBe("mockFailingDetector");
      expect(diagnostics[0].message).toContain("Syntax error");

      // Verify findings + warnings semantics (findings exist AND diagnostics exist)
      const storedFindings = await dbAdapter.getScanFindings(scanId);
      expect(storedFindings.length).toBe(1);
    } finally {
      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(...originalRegistry);
    }
  });

  it("D: Diagnostic does not contain secret material or sensitive file paths", () => {
    const rawErrorMsg = "Failed at C:\\Users\\Admin\\SecretDirectory\\file.ts with secret sk_live_99999999999999999999";
    const sanitized = sanitizeDiagnosticMessage(new Error(rawErrorMsg));

    expect(sanitized).not.toContain("sk_live_99999999999999999999");
    expect(sanitized).not.toContain("C:\\Users\\Admin\\SecretDirectory\\file.ts");
    expect(sanitized).toContain("[REDACTED_SECRET]");
    expect(sanitized).toContain("[REDACTED_PATH]");
  });

  it("F: Successful scan with no detector failures produces no warnings", async () => {
    const filesMap = new Map<string, string>([
      ["app.ts", "console.log('clean code');"],
    ]);
    const result = await runAllDetectors(filesMap, { offlineMode: true });

    expect(result.diagnostics.length).toBe(0);
  });

  it("TASK 6 (FAILURE SEMANTICS): Detector exception MUST NOT produce clean scan without warnings", async () => {
    const originalRegistry = [...DETECTOR_REGISTRY];
    try {
      const mockCrashDetector: DetectorDefinition = {
        id: "mockCrashDetector",
        name: "Mock Crash Detector",
        file: "crash.ts",
        run: async () => {
          throw new Error("Internal detector failure");
        },
      };

      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(mockCrashDetector);

      const filesMap = new Map<string, string>([["app.ts", "const x = 1;"]]);
      const result = await runAllDetectors(filesMap, { offlineMode: true });

      // Findings is empty, but diagnostics MUST be present to signal INCOMPLETE analysis
      expect(result.findings.length).toBe(0);
      expect(result.diagnostics.length).toBe(1);
      expect(result.diagnostics[0].detectorId).toBe("mockCrashDetector");

      // Crucial Invariant: result is NOT clean (must have diagnostics)
      const isCleanWithoutWarnings = result.findings.length === 0 && result.diagnostics.length === 0;
      expect(isCleanWithoutWarnings).toBe(false);
    } finally {
      DETECTOR_REGISTRY.length = 0;
      DETECTOR_REGISTRY.push(...originalRegistry);
    }
  });

  it("H, I, K & L: Public repo scanning enqueues a job, executes via worker queue, and updates status", async () => {
    const dbAdapter = new InMemoryDbAdapter();
    const queue = new ScanJobQueue(dbAdapter);

    const scanId = "scan-public-123";
    const payload = {
      scanId,
      repoId: "facebook/react",
      installationId: 1,
      requestedByUserId: "user-public",
    };

    let fetcherExecuted = false;
    const customFetcher = async (dir: string) => {
      fetcherExecuted = true;
      const fs = await import("fs");
      const path = await import("path");
      fs.writeFileSync(path.join(dir, "package.json"), '{"name": "react"}');
    };

    // Enqueue job into worker ScanJobQueue
    const initialState = await queue.enqueueJob(payload, {}, customFetcher);
    expect(initialState.status).toBe("queued");

    const statusImmediately = await dbAdapter.getScanStatus(scanId);
    expect(statusImmediately.status).toBe("queued");

    // Wait for queue to process job
    const completedState = await queue.waitForJobCompletion(scanId, 5000);

    expect(fetcherExecuted).toBe(true);
    expect(completedState.status).toBe("done");

    const finalStatus = await dbAdapter.getScanStatus(scanId);
    expect(finalStatus.status).toBe("done");
  });
});
