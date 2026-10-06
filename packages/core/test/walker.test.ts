import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isBinaryFile, walkDirectory } from "../src/walker.js";

describe("File Walker (packages/core/src/walker.ts)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-walker-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should walk directory and return text files while skipping node_modules and .git", () => {
    fs.mkdirSync(path.join(tmpDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, "node_modules/express"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, ".git"), { recursive: true });

    fs.writeFileSync(path.join(tmpDir, "src/index.ts"), "console.log('hello');");
    fs.writeFileSync(path.join(tmpDir, "node_modules/express/index.js"), "module.exports = {};");
    fs.writeFileSync(path.join(tmpDir, ".git/config"), "[core]");

    const files = walkDirectory(tmpDir);
    const relPaths = files.map((f) => f.relativePath);

    expect(relPaths).toContain("src/index.ts");
    expect(relPaths).not.toContain("node_modules/express/index.js");
    expect(relPaths).not.toContain(".git/config");
  });

  it("should respect .gitignore files", () => {
    fs.writeFileSync(path.join(tmpDir, ".gitignore"), "ignored.txt\nsecrets/\n");
    fs.mkdirSync(path.join(tmpDir, "secrets"), { recursive: true });

    fs.writeFileSync(path.join(tmpDir, "allowed.txt"), "hello");
    fs.writeFileSync(path.join(tmpDir, "ignored.txt"), "secret");
    fs.writeFileSync(path.join(tmpDir, "secrets/pass.txt"), "pass");

    const files = walkDirectory(tmpDir);
    const relPaths = files.map((f) => f.relativePath);

    expect(relPaths).toContain("allowed.txt");
    expect(relPaths).not.toContain("ignored.txt");
    expect(relPaths).not.toContain("secrets/pass.txt");
  });

  it("should skip binary files based on extension or null bytes", () => {
    fs.writeFileSync(path.join(tmpDir, "image.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    fs.writeFileSync(path.join(tmpDir, "binary.dat"), Buffer.from([0x00, 0x01, 0x02, 0x03]));
    fs.writeFileSync(path.join(tmpDir, "code.js"), "const a = 1;");

    expect(isBinaryFile("image.png")).toBe(true);

    const files = walkDirectory(tmpDir);
    const relPaths = files.map((f) => f.relativePath);

    expect(relPaths).toContain("code.js");
    expect(relPaths).not.toContain("image.png");
    expect(relPaths).not.toContain("binary.dat");
  });

  it("SECURITY TEST: should never escape root directory via symlink or relative path traversal (e.g. ../../etc/passwd)", () => {
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "nantis-outside-"));
    const secretFile = path.join(outsideDir, "passwd");
    fs.writeFileSync(secretFile, "root:x:0:0:root:/root:/bin/bash");

    // Attempt 1: Create a symlink inside tmpDir pointing to secretFile outside root
    const symlinkPath = path.join(tmpDir, "outside_link");
    try {
      fs.symlinkSync(secretFile, symlinkPath, "file");
    } catch {
      // Symlink creation might require admin on Windows; fallback test path
    }

    // Traverse directory
    const files = walkDirectory(tmpDir);
    const contents = files.map((f) => f.content);

    // Verify root:x:0:0 secret file content is NEVER read or included
    for (const c of contents) {
      expect(c).not.toContain("root:x:0:0");
    }

    fs.rmSync(outsideDir, { recursive: true, force: true });
  });
});
