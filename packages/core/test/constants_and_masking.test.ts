import { describe, expect, it } from "vitest";
import { NO_ISSUES_FOUND_MESSAGE } from "../src/constants.js";
import { maskSecrets } from "../src/masking.js";

describe("Rule 6 Compliance: Fixed wording", () => {
  it("should have exact required wording for no issues found", () => {
    expect(NO_ISSUES_FOUND_MESSAGE).toBe("no issues found in the checks we run");
  });

  it("should never contain forbidden words like secure, safe, or production ready", () => {
    const forbidden = ["secure", "safe", "production ready"];
    for (const word of forbidden) {
      expect(NO_ISSUES_FOUND_MESSAGE.toLowerCase()).not.toContain(word);
    }
  });
});

describe("Rule 3 Compliance: Secret Masking", () => {
  it("should mask Stripe test and live keys", () => {
    const fakeStripeLive = "sk_live_" + "1".repeat(24);
    const fakeStripeTest = "sk_test_" + "2".repeat(24);
    const input = `const stripeKey = "${fakeStripeLive}"; const testKey = "${fakeStripeTest}";`;
    const masked = maskSecrets(input);

    expect(masked).not.toContain(fakeStripeLive);
    expect(masked).not.toContain(fakeStripeTest);
    expect(masked).toContain("[REDACTED_SECRET]");
  });

  it("should mask Supabase service role key patterns and Postgres URLs", () => {
    const fakeSbpKey = "sbp_" + "a".repeat(40);
    const fakePgUrl = "postgres://postgres:mysecretpassword123@db.supabase.co:5432/postgres";
    const input = `SUPABASE_KEY=${fakeSbpKey}\nDATABASE_URL=${fakePgUrl}`;
    const masked = maskSecrets(input);

    expect(masked).not.toContain(fakeSbpKey);
    expect(masked).not.toContain("mysecretpassword123");
    expect(masked).toContain("postgres://[REDACTED]:[REDACTED]@[REDACTED]");
  });

  it("should mask GitHub personal access tokens", () => {
    const fakeGhp = "ghp_" + "x".repeat(36);
    const input = `GITHUB_TOKEN=${fakeGhp}`;
    const masked = maskSecrets(input);

    expect(masked).not.toContain(fakeGhp);
    expect(masked).toContain("[REDACTED_SECRET]");
  });
});
