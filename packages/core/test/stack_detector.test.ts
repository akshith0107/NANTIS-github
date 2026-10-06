import path from "path";
import { describe, expect, it } from "vitest";
import { detectStack } from "../src/stack-detector.js";
import { loadFixture } from "../test-utils/index.js";

const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");

describe("Stack Detector (packages/core/src/stack-detector.ts)", () => {
  it("should detect Stripe and Next.js App Router from api-route-no-auth fixture", () => {
    const fixture = loadFixture(FIXTURES_DIR, "api-route-no-auth");
    const result = detectStack(fixture.vulnerableFiles);

    expect(result.hasNextAppRouter).toBe(true);
    expect(result.hasSupabase).toBe(true);
  });

  it("should detect Supabase migrations from missing-rls-in-migration fixture", () => {
    const fixture = loadFixture(FIXTURES_DIR, "missing-rls-in-migration");
    const result = detectStack(fixture.vulnerableFiles);

    expect(result.hasSupabase).toBe(true);
    expect(result.details.supabaseMigrationsCount).toBeGreaterThan(0);
  });

  it("should detect Stripe SDK usage from hardcoded-secret fixture", () => {
    const fixture = loadFixture(FIXTURES_DIR, "hardcoded-secret");
    const result = detectStack(fixture.vulnerableFiles);

    expect(result.hasStripe).toBe(true);
    expect(result.details.stripeSdkDetected).toBe(true);
  });
});
