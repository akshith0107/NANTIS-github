import fs from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import { DETECTOR_REGISTRY, runAllDetectors } from "../src/detectors/registry.js";

describe("Centralized Detector Registry", () => {
  it("should include every detector file in packages/core/src/detectors/", () => {
    const detectorsDir = path.resolve(__dirname, "../src/detectors");
    const allFiles = fs.readdirSync(detectorsDir);

    // Filter for source .ts files (excluding registry.ts, type definitions, or maps)
    const detectorFiles = allFiles.filter(
      (file) =>
        file.endsWith(".ts") &&
        !file.endsWith(".d.ts") &&
        file !== "registry.ts"
    );

    const registeredFiles = new Set(DETECTOR_REGISTRY.map((d) => d.file));

    // Ensure every detector file in the directory has at least one entry in DETECTOR_REGISTRY
    for (const detectorFile of detectorFiles) {
      expect(
        registeredFiles.has(detectorFile),
        `Detector file '${detectorFile}' exists in src/detectors/ but is missing from DETECTOR_REGISTRY!`
      ).toBe(true);
    }
  });

  it("should contain exactly 19 registered detectors", () => {
    expect(DETECTOR_REGISTRY.length).toBe(19);
  });

  it("should execute all detectors via runAllDetectors and aggregate findings", async () => {
    const sampleFiles = new Map<string, string>([
      [".env", "STRIPE_SECRET_KEY=sk_live_12345678901234567890"],
      ["package.json", '{"name": "test-repo", "dependencies": {"express": "*"}}'],
    ]);

    const findings = await runAllDetectors(sampleFiles, { offlineMode: true });
    expect(Array.isArray(findings)).toBe(true);

    // Verify secret detector fired via registry
    const secretFinding = findings.find((f) => f.ruleId === "committed-env-file");
    expect(secretFinding).toBeDefined();

    // Verify loose dependency range detector fired via registry
    const looseDepFinding = findings.find((f) => f.ruleId === "loose-dependency-range");
    expect(looseDepFinding).toBeDefined();
  });
});
