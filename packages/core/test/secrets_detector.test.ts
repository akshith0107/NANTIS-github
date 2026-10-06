import path from "path";
import { describe, expect, it } from "vitest";
import { detectSecrets } from "../src/detectors/secrets.js";
import { loadFixture } from "../test-utils/index.js";

const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");

describe("Secrets Detector (packages/core/src/detectors/secrets.ts)", () => {
  const secretChecks = ["hardcoded-secret", "committed-env-file", "use-client-secret-leak"];

  for (const checkId of secretChecks) {
    describe(`Fixture tests for ${checkId}`, () => {
      const fixture = loadFixture(FIXTURES_DIR, checkId);

      it(`should detect expected findings in vulnerable fixture for ${checkId}`, async () => {
        const findings = await detectSecrets(fixture.vulnerableFiles);
        const filtered = findings.filter((f) => f.ruleId === checkId);

        expect(filtered.length).toBe(fixture.expected.vulnerable.length);
        for (let i = 0; i < filtered.length; i++) {
          const expected = fixture.expected.vulnerable[i];
          expect(filtered[i].ruleId).toBe(expected.ruleId);
          expect(filtered[i].file).toBe(expected.file);
          expect(filtered[i].lineRange.startLine).toBe(expected.lineRange.startLine);
        }
      });

      it(`should detect expected findings in mutated fixture for ${checkId}`, async () => {
        const findings = await detectSecrets(fixture.mutatedFiles);
        const filtered = findings.filter((f) => f.ruleId === checkId);

        expect(filtered.length).toBe(fixture.expected.mutated.length);
        for (let i = 0; i < filtered.length; i++) {
          const expected = fixture.expected.mutated[i];
          expect(filtered[i].ruleId).toBe(expected.ruleId);
          expect(filtered[i].file).toBe(expected.file);
          expect(filtered[i].lineRange.startLine).toBe(expected.lineRange.startLine);
        }
      });

      it(`should return 0 findings for clean fixture for ${checkId}`, async () => {
        const findings = await detectSecrets(fixture.cleanFiles);
        const filtered = findings.filter((f) => f.ruleId === checkId);

        expect(filtered.length).toBe(0);
      });
    });
  }

  it("SECURITY TEST: should never leak more than 4 characters of any raw secret in findings JSON or output", async () => {
    // Synthetic raw secret tokens
    const rawSecrets = [
      "sk_live_99887766554433221100aabbccdd",
      "sk_test_11223344556677889900aabbccdd",
      "sbp_1122334455667788990011223344556677889900",
      "ghp_112233445566778899001122334455667788",
    ];

    const codeWithSecrets = new Map<string, string>([
      [
        "src/config.ts",
        `const stripe = "${rawSecrets[0]}";
const testStripe = "${rawSecrets[1]}";
const supabase = "${rawSecrets[2]}";
const github = "${rawSecrets[3]}";`,
      ],
    ]);

    const findings = await detectSecrets(codeWithSecrets);
    const jsonOutput = JSON.stringify(findings);

    for (const secret of rawSecrets) {
      // Check that the full raw secret is NOT present
      expect(jsonOutput).not.toContain(secret);

      // Extract the random payload body after standard prefix
      const secretBody = secret.replace(/^(sk_live_|sk_test_|sbp_|ghp_)/, "");
      // Check that no payload substring of 5 or more characters is present in the output
      for (let len = 5; len <= secretBody.length; len++) {
        for (let i = 0; i <= secretBody.length - len; i++) {
          const sub = secretBody.substring(i, i + len);
          expect(jsonOutput).not.toContain(sub);
        }
      }
    }
  });
});
