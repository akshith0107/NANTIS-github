import path from "path";
import { describe, expect, it } from "vitest";
import { loadAllFixtures, loadFixture } from "../test-utils/index.js";

const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");

describe("Fixture Loader in packages/core/test-utils", () => {
  const targetChecks = [
    "hardcoded-secret",
    "committed-env-file",
    "missing-rls-in-migration",
    "api-route-no-auth",
    "stripe-webhook-no-signature",
  ];

  it("should load all 5 requested check fixtures", () => {
    const all = loadAllFixtures(FIXTURES_DIR);
    expect(all.length).toBeGreaterThanOrEqual(5);

    for (const checkId of targetChecks) {
      const loaded = loadFixture(FIXTURES_DIR, checkId);
      expect(loaded.checkId).toBe(checkId);
      expect(loaded.vulnerableFiles.size).toBeGreaterThan(0);
      expect(loaded.cleanFiles.size).toBeGreaterThan(0);
      expect(loaded.mutatedFiles.size).toBeGreaterThan(0);
      expect(Array.isArray(loaded.expected.vulnerable)).toBe(true);
      expect(Array.isArray(loaded.expected.mutated)).toBe(true);
      expect(Array.isArray(loaded.expected.clean)).toBe(true);
      expect(loaded.expected.clean.length).toBe(0);
    }
  });

  it("should ensure all fixtures contain only obvious fake secrets per Rule 9", () => {
    for (const checkId of targetChecks) {
      const fixture = loadFixture(FIXTURES_DIR, checkId);
      for (const filesMap of [fixture.vulnerableFiles, fixture.cleanFiles, fixture.mutatedFiles]) {
        for (const [, content] of filesMap.entries()) {
          // Verify no real-looking secrets are present without FAKE prefix or zero padding
          if (content.includes("sk_live_") || content.includes("sk_test_")) {
            expect(content).toContain("FAKE");
          }
        }
      }
    }
  });
});
