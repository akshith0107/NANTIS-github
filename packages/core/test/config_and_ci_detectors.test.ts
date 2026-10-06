import path from "path";
import { describe, expect, it } from "vitest";
import { detectCiIssues } from "../src/detectors/ci-audit.js";
import { detectConfigIssues } from "../src/detectors/config.js";
import { loadFixture } from "../test-utils/index.js";

const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");

describe("Config Audit Detector (packages/core/src/detectors/config.ts)", () => {
  const fixture = loadFixture(FIXTURES_DIR, "config-audit");

  it("should detect expected findings in vulnerable config-audit fixture", async () => {
    const findings = await detectConfigIssues(fixture.vulnerableFiles);
    expect(findings.length).toBe(fixture.expected.vulnerable.length);

    for (let i = 0; i < findings.length; i++) {
      const expected = fixture.expected.vulnerable[i];
      expect(findings[i].ruleId).toBe(expected.ruleId);
      expect(findings[i].file).toBe(expected.file);
      expect(findings[i].lineRange.startLine).toBe(expected.lineRange.startLine);
    }
  });

  it("should detect expected findings in mutated config-audit fixture", async () => {
    const findings = await detectConfigIssues(fixture.mutatedFiles);
    expect(findings.length).toBe(fixture.expected.mutated.length);

    for (let i = 0; i < findings.length; i++) {
      const expected = fixture.expected.mutated[i];
      expect(findings[i].ruleId).toBe(expected.ruleId);
      expect(findings[i].file).toBe(expected.file);
      expect(findings[i].lineRange.startLine).toBe(expected.lineRange.startLine);
    }
  });

  it("should return 0 findings for clean config-audit fixture", async () => {
    const findings = await detectConfigIssues(fixture.cleanFiles);
    expect(findings.length).toBe(0);
  });
});

describe("CI Audit Detector (packages/core/src/detectors/ci-audit.ts)", () => {
  const fixture = loadFixture(FIXTURES_DIR, "ci-audit");

  it("should detect expected findings in vulnerable ci-audit fixture", async () => {
    const findings = await detectCiIssues(fixture.vulnerableFiles);
    expect(findings.length).toBe(fixture.expected.vulnerable.length);

    for (let i = 0; i < findings.length; i++) {
      const expected = fixture.expected.vulnerable[i];
      expect(findings[i].ruleId).toBe(expected.ruleId);
      expect(findings[i].file).toBe(expected.file);
      expect(findings[i].lineRange.startLine).toBe(expected.lineRange.startLine);
    }
  });

  it("should detect expected findings in mutated ci-audit fixture", async () => {
    const findings = await detectCiIssues(fixture.mutatedFiles);
    expect(findings.length).toBe(fixture.expected.mutated.length);

    for (let i = 0; i < findings.length; i++) {
      const expected = fixture.expected.mutated[i];
      expect(findings[i].ruleId).toBe(expected.ruleId);
      expect(findings[i].file).toBe(expected.file);
      expect(findings[i].lineRange.startLine).toBe(expected.lineRange.startLine);
    }
  });

  it("should return 0 findings for clean ci-audit fixture", async () => {
    const findings = await detectCiIssues(fixture.cleanFiles);
    expect(findings.length).toBe(0);
  });
});
