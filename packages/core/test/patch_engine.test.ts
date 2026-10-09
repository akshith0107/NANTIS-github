import fs from "fs";
import path from "path";
import os from "os";
import { describe, expect, it } from "vitest";
import {
  applyStructuredEdits,
  generateUnifiedDiff,
} from "../src/fixes/patch-engine.js";
import { fixIdorOwnerColumn } from "../src/fixes/rules/idor-owner-column.js";
import { StructuredEdit } from "../src/fixes/types.js";

describe("Patch Engine & Structured Edits", () => {
  it("should apply structured edits to original content producing valid patched code", () => {
    const original = '{\n  "dependencies": {\n    "axios": "0.21.1"\n  }\n}';
    const edits: StructuredEdit[] = [
      {
        targetFile: "package.json",
        targetContent: '"axios": "0.21.1"',
        replacementContent: '"axios": "^1.7.4"',
      },
    ];

    const result = applyStructuredEdits(original, edits);
    expect(result.success).toBe(true);
    expect(result.updatedContent).toContain('"axios": "^1.7.4"');
    expect(result.updatedContent).not.toContain("--- package.json");
    expect(() => JSON.parse(result.updatedContent!)).not.toThrow();
  });

  it("should generate clean unified diff with line numbers and context lines for 3 line insertion in a 10 line file", () => {
    const before = Array.from({ length: 10 }, (_, i) => `line ${i + 1}`).join("\n");
    const after = [
      ...Array.from({ length: 5 }, (_, i) => `line ${i + 1}`),
      "inserted line 1",
      "inserted line 2",
      "inserted line 3",
      ...Array.from({ length: 5 }, (_, i) => `line ${i + 6}`),
    ].join("\n");

    const diff = generateUnifiedDiff("app/api/route.ts", before, after);
    expect(diff).toContain("--- a/app/api/route.ts");
    expect(diff).toContain("+++ b/app/api/route.ts");
    expect(diff).toContain("@@ -3,6 +3,9 @@");
    expect(diff).toContain(" line 3");
    expect(diff).toContain("+inserted line 1");
    expect(diff).toContain("+inserted line 2");
    expect(diff).toContain("+inserted line 3");
    expect(diff).toContain(" line 6");
  });

  it("should generate and apply diff for an edit at the START of a file", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-start-"));
    try {
      const before = Array.from({ length: 10 }, (_, i) => `line ${i + 1}`).join("\n");
      const after = ["MODIFIED START LINE", ...Array.from({ length: 9 }, (_, i) => `line ${i + 2}`)].join("\n");

      const diff = generateUnifiedDiff("file.txt", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.txt"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.txt"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      expect(diff).toContain("@@ -1,4 +1,4 @@");
      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should generate and apply diff for an edit in the MIDDLE of a file", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-middle-"));
    try {
      const before = Array.from({ length: 10 }, (_, i) => `line ${i + 1}`).join("\n");
      const after = [
        ...Array.from({ length: 4 }, (_, i) => `line ${i + 1}`),
        "MODIFIED MIDDLE LINE",
        ...Array.from({ length: 5 }, (_, i) => `line ${i + 6}`),
      ].join("\n");

      const diff = generateUnifiedDiff("file.txt", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.txt"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.txt"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      expect(diff).toContain("@@ -2,7 +2,7 @@");
      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should generate and apply diff for an edit at the END of a file", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-end-"));
    try {
      const before = Array.from({ length: 10 }, (_, i) => `line ${i + 1}`).join("\n");
      const after = [...Array.from({ length: 9 }, (_, i) => `line ${i + 1}`), "MODIFIED END LINE"].join("\n");

      const diff = generateUnifiedDiff("file.txt", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.txt"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.txt"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      expect(diff).toContain("@@ -7,4 +7,4 @@");
      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should generate and apply diff for a file with TWO SEPARATE edits into separate hunks", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-two-edits-"));
    try {
      const beforeLines = Array.from({ length: 25 }, (_, i) => `line ${i + 1}`);
      const afterLines = [...beforeLines];
      afterLines[1] = "EDIT 1 NEAR START"; // Line 2
      afterLines[23] = "EDIT 2 NEAR END";   // Line 24

      const before = beforeLines.join("\n");
      const after = afterLines.join("\n");

      const diff = generateUnifiedDiff("file.txt", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.txt"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.txt"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      // Verify two distinct @@ hunks were generated
      const hunkMatches = diff.match(/@@ -/g);
      expect(hunkMatches?.length).toBe(2);
      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should merge nearby hunks separated by 6 or fewer unmodified lines into a single hunk", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-merged-hunks-"));
    try {
      const beforeLines = Array.from({ length: 15 }, (_, i) => `line ${i + 1}`);
      const afterLines = [...beforeLines];
      afterLines[1] = "NEARBY EDIT 1"; // Line 2
      afterLines[5] = "NEARBY EDIT 2"; // Line 6 (3 unmodified lines between them)

      const before = beforeLines.join("\n");
      const after = afterLines.join("\n");

      const diff = generateUnifiedDiff("file.txt", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.txt"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.txt"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      const hunkMatches = diff.match(/@@ -/g);
      expect(hunkMatches?.length).toBe(1);
      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should correctly handle files without trailing newlines", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-test-no-trailing-"));
    try {
      const before = "const a = 1;\nconst b = 2;\nconst c = 3;"; // No trailing newline
      const after = "const a = 1;\nconst b = 99;\nconst c = 3;";

      const diff = generateUnifiedDiff("file.js", before, after);
      fs.writeFileSync(path.join(tempDir, "patch.diff"), diff, "utf-8");
      fs.writeFileSync(path.join(tempDir, "file.js"), before, "utf-8");

      const savedDiff = fs.readFileSync(path.join(tempDir, "patch.diff"), "utf-8");
      const savedBefore = fs.readFileSync(path.join(tempDir, "file.js"), "utf-8");
      const applied = applyUnifiedDiff(savedBefore, savedDiff);

      expect(applied).toBe(after);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should generate automated AST fix for idor.owner-column.v1", () => {
    const filesMap = new Map<string, string>([
      [
        "app/api/orders/route.ts",
        `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  const { data } = await supabase.from("orders").select("*").eq("id", params.id);
  return Response.json(data);
}
        `.trim(),
      ],
    ]);

    const res = fixIdorOwnerColumn(filesMap, "app/api/orders/route.ts");
    expect(res.kind).toBe("automated");
    expect(res.edits[0].replacementContent).toContain('.eq("id", params.id).eq("user_id", session.user.id)');
  });
});

import { execSync } from "child_process";

/**
 * Native git apply patch applicator helper for testing unified diff outputs.
 * Uses system git apply in a temporary git repository to verify real git compatibility.
 */
function applyUnifiedDiff(beforeContent: string, diffText: string): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "git-apply-test-"));
  try {
    const fileMatch = diffText.match(/^---\s+(?:a\/)?([^\s\r\n]+)/m);
    const targetFile = fileMatch ? fileMatch[1] : "file.txt";
    const filePath = path.join(tempDir, targetFile);
    const patchPath = path.join(tempDir, "patch.diff");

    const normalizedBefore = beforeContent.replace(/\r\n/g, "\n");
    const normalizedDiff = diffText.replace(/\r\n/g, "\n");

    execSync("git init", { cwd: tempDir, stdio: "ignore" });
    execSync("git config core.autocrlf false", { cwd: tempDir, stdio: "ignore" });
    execSync('git config user.name "Test"', { cwd: tempDir, stdio: "ignore" });
    execSync('git config user.email "test@test.com"', { cwd: tempDir, stdio: "ignore" });

    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, normalizedBefore, "utf-8");
    execSync("git add .", { cwd: tempDir, stdio: "ignore" });
    execSync('git commit -m "initial"', { cwd: tempDir, stdio: "ignore" });

    fs.writeFileSync(patchPath, normalizedDiff, "utf-8");
    execSync("git apply --whitespace=nowarn patch.diff", { cwd: tempDir, stdio: ["ignore", "pipe", "pipe"] });

    return fs.readFileSync(filePath, "utf-8");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}
