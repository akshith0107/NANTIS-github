import { describe, expect, it } from "vitest";
import {
  createFixSnapshot,
  validateAntiSuppressionAndDeletion,
  calculateBlastRadius,
} from "../src/fixes/index.js";

describe("Fixes Framework Core & Safety Rules", () => {
  it("creates immutable in-memory snapshot before applying fixes", () => {
    const filesMap = new Map<string, string>([
      ["package.json", '{"name": "test"}'],
      ["src/index.ts", "console.log('hello');"],
    ]);

    const snapshot = createFixSnapshot(filesMap);

    expect(snapshot.files.get("package.json")).toBe('{"name": "test"}');

    // Mutate original map
    filesMap.set("package.json", '{"name": "mutated"}');

    // Snapshot remains untouched
    expect(snapshot.files.get("package.json")).toBe('{"name": "test"}');
  });

  it("calculates blast radius metrics and assigns risk level via ts-morph", () => {
    const filesMap = new Map<string, string>([
      ["src/utils/auth.ts", "export function checkAuth() { return true; }"],
      ["src/routes/user.ts", 'import { checkAuth } from "../utils/auth";\ncheckAuth();'],
      ["src/routes/admin.ts", 'import { checkAuth } from "../utils/auth";\ncheckAuth();'],
    ]);

    const radius = calculateBlastRadius(filesMap, "src/utils/auth.ts");

    expect(radius.affectedFiles).toContain("src/utils/auth.ts");
    expect(radius.affectedFiles).toContain("src/routes/user.ts");
    expect(radius.importedByModules.length).toBe(2);
    expect(radius.riskLevel).toBe("medium");
  });

  it("rejects patches that attempt to fix issues by suppressing rules", () => {
    const eslintDiff = `--- src/app.ts\n+++ src/app.ts\n+ // eslint-disable-next-line\n+ const secret = "123";\n`;
    const tsIgnoreDiff = `--- src/app.ts\n+++ src/app.ts\n+ // @ts-ignore\n+ const auth = null;\n`;
    const nantisDisableDiff = `--- src/app.ts\n+++ src/app.ts\n+ // nantis-disable-rule\n`;

    expect(validateAntiSuppressionAndDeletion(eslintDiff).valid).toBe(false);
    expect(validateAntiSuppressionAndDeletion(tsIgnoreDiff).valid).toBe(false);
    expect(validateAntiSuppressionAndDeletion(nantisDisableDiff).valid).toBe(false);
  });

  it("rejects patches that fix issues by deleting code lines", () => {
    const deletingDiff = [
      "--- src/routes/user.ts",
      "+++ src/routes/user.ts",
      "- const user = getUser();",
      "- const session = getSession();",
      "- if (!session) return 401;",
      "- doSensitiveWrite();",
      "+ // Fix by deletion",
    ].join("\n");

    const result = validateAntiSuppressionAndDeletion(deletingDiff);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("deleting");
  });

  it("accepts valid constructive patches with no suppression comments", () => {
    const validDiff = [
      "--- package.json",
      "+++ package.json",
      '-  "axios": "0.21.1"',
      '+  "axios": "^1.7.4"',
    ].join("\n");

    const result = validateAntiSuppressionAndDeletion(validDiff);
    expect(result.valid).toBe(true);
  });
});
