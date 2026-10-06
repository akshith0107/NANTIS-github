import fs from "fs";
import path from "path";
import os from "os";
import { describe, expect, it } from "vitest";
import {
  applyStructuredEdits,
  generateUnifiedDiff,
} from "../src/fixes/patch-engine.js";
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
    expect(diff).toContain("--- app/api/route.ts");
    expect(diff).toContain("+++ app/api/route.ts");
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
});

/**
 * Independent patch applicator helper for testing unified diff outputs without external dependencies.
 */
function applyUnifiedDiff(originalContent: string, diffText: string): string {
  const originalLines = originalContent.length === 0 ? [] : originalContent.split(/\r?\n/);
  const diffLines = diffText.split(/\r?\n/);

  const resultLines: string[] = [];
  let origIdx = 0;

  for (let l = 0; l < diffLines.length; l++) {
    const line = diffLines[l];
    if (line.startsWith("---") || line.startsWith("+++")) {
      continue;
    }

    if (line.startsWith("@@")) {
      const match = line.match(/@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
      if (match) {
        const hunkStartOrig = parseInt(match[1], 10);
        const targetIdx = Math.max(0, hunkStartOrig - 1);
        while (origIdx < targetIdx && origIdx < originalLines.length) {
          resultLines.push(originalLines[origIdx]);
          origIdx++;
        }
      }
      continue;
    }

    if (line.startsWith(" ")) {
      const contextLine = line.substring(1);
      resultLines.push(contextLine);
      origIdx++;
    } else if (line.startsWith("-")) {
      origIdx++;
    } else if (line.startsWith("+")) {
      resultLines.push(line.substring(1));
    }
  }

  while (origIdx < originalLines.length) {
    resultLines.push(originalLines[origIdx]);
    origIdx++;
  }

  return resultLines.join("\n");
}
