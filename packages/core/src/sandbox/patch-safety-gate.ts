import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { StructuredEdit } from "../fixes/types.js";

export const PATCH_GATE_GENERATOR_VERSION = "0.1.0-phase6b";

export interface PatchSafetyValidationResult {
  valid: boolean;
  reason?: string;
  expectedFiles: string[];
  actualFiles: string[];
  patchHash: string;
  generatorVersion: string;
}

/**
 * Patch Safety Gate validating file path containment, canonical paths, symlinks, anti-suppression, and file bounds.
 */
export class PatchSafetyGate {
  /**
   * Validates a set of structured edits and unified diff before application.
   */
  static validatePatch(
    edits: StructuredEdit[],
    diff: string,
    expectedFiles: string[],
    workspaceRoot: string = process.cwd()
  ): PatchSafetyValidationResult {
    const actualFilesSet = new Set<string>();

    const rootResolved = path.resolve(workspaceRoot);
    let canonicalRoot = rootResolved;
    if (fs.existsSync(rootResolved)) {
      try {
        canonicalRoot = fs.realpathSync(rootResolved);
      } catch {
        canonicalRoot = rootResolved;
      }
    }
    const normCanonicalRoot = canonicalRoot.replace(/\\/g, "/");

    for (const edit of edits) {
      const rawPath = edit.targetFile;
      let decodedPath = rawPath;
      try {
        decodedPath = decodeURIComponent(rawPath);
      } catch {
        decodedPath = rawPath;
      }
      const normPath = decodedPath.replace(/\\/g, "/");

      // 1. Path Containment & Traversal Verification
      if (
        normPath.startsWith("/") ||
        /^[a-zA-Z]:[\\/]/i.test(normPath) ||
        normPath.includes("../") ||
        normPath.includes("..\\") ||
        normPath.includes("%2e%2e") ||
        normPath.includes("\0")
      ) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Absolute path or traversal detected in target file '${edit.targetFile}'`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }

      // 2. Protect .git, Infrastructure & Configuration Files
      if (
        normPath.startsWith(".git/") ||
        normPath.includes("/.git/") ||
        normPath === ".git" ||
        normPath.startsWith(".git\\") ||
        normPath.endsWith(".env") ||
        normPath.includes(".ssh")
      ) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Attempted modification of forbidden .git directory or protected file '${edit.targetFile}'`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }

      // 3. Canonical Path Resolution & Symlink Escape Detection
      const targetResolved = path.resolve(rootResolved, normPath);
      const normTargetResolved = targetResolved.replace(/\\/g, "/");

      if (!normTargetResolved.startsWith(normCanonicalRoot) && !normTargetResolved.startsWith(rootResolved.replace(/\\/g, "/"))) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Target path '${edit.targetFile}' resolves outside workspace root`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }

      // Check filesystem stat & symlinks if file or parent exists on disk
      if (fs.existsSync(targetResolved)) {
        try {
          const lstat = fs.lstatSync(targetResolved);

          // Reject symlinks, FIFOs, Sockets, Devices
          if (lstat.isSymbolicLink() || lstat.isFIFO() || lstat.isSocket() || lstat.isCharacterDevice() || lstat.isBlockDevice()) {
            return {
              valid: false,
              reason: `Patch Safety Gate REJECTED: Target file '${edit.targetFile}' is a symlink, socket, FIFO, or special device`,
              expectedFiles,
              actualFiles: Array.from(actualFilesSet),
              patchHash: "",
              generatorVersion: PATCH_GATE_GENERATOR_VERSION,
            };
          }

          // Check hard links
          if (lstat.nlink > 1) {
            return {
              valid: false,
              reason: `Patch Safety Gate REJECTED: Target file '${edit.targetFile}' is a hard link with multiple references`,
              expectedFiles,
              actualFiles: Array.from(actualFilesSet),
              patchHash: "",
              generatorVersion: PATCH_GATE_GENERATOR_VERSION,
            };
          }

          // Check canonical realpath
          const realTarget = fs.realpathSync(targetResolved);
          const normRealTarget = realTarget.replace(/\\/g, "/");
          if (!normRealTarget.startsWith(normCanonicalRoot)) {
            return {
              valid: false,
              reason: `Patch Safety Gate REJECTED: Symlink or junction in target '${edit.targetFile}' resolves outside canonical workspace root`,
              expectedFiles,
              actualFiles: Array.from(actualFilesSet),
              patchHash: "",
              generatorVersion: PATCH_GATE_GENERATOR_VERSION,
            };
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          return {
            valid: false,
            reason: `Patch Safety Gate REJECTED: Filesystem safety check error for target '${edit.targetFile}': ${msg}`,
            expectedFiles,
            actualFiles: Array.from(actualFilesSet),
            patchHash: "",
            generatorVersion: PATCH_GATE_GENERATOR_VERSION,
          };
        }
      }

      // Walk parent directories up to workspace root checking for symlinks escaping root
      let parentDir = path.dirname(targetResolved);
      while (parentDir.length >= rootResolved.length && parentDir !== path.dirname(parentDir)) {
        if (fs.existsSync(parentDir)) {
          try {
            const pLstat = fs.lstatSync(parentDir);
            if (pLstat.isSymbolicLink()) {
              const pReal = fs.realpathSync(parentDir).replace(/\\/g, "/");
              if (!pReal.startsWith(normCanonicalRoot)) {
                return {
                  valid: false,
                  reason: `Patch Safety Gate REJECTED: Parent directory '${parentDir}' is a symlink resolving outside workspace root`,
                  expectedFiles,
                  actualFiles: Array.from(actualFilesSet),
                  patchHash: "",
                  generatorVersion: PATCH_GATE_GENERATOR_VERSION,
                };
              }
            }
          } catch {
            // Ignore error if parent directory stat fails
          }
        }
        if (parentDir === rootResolved || parentDir.replace(/\\/g, "/") === normCanonicalRoot) break;
        parentDir = path.dirname(parentDir);
      }

      // 4. Expected File Whitelist Enforcement
      const normExpected = expectedFiles.map((f) => f.replace(/\\/g, "/"));
      if (normExpected.length > 0 && !normExpected.includes(normPath)) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Target file '${edit.targetFile}' is outside expected file whitelist [${expectedFiles.join(", ")}]`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }

      actualFilesSet.add(normPath);
    }

    // 5. Anti-Suppression Comments & Excessive Deletion Verification
    const suppressionPatterns = [
      /eslint-disable/i,
      /@ts-ignore/i,
      /@ts-nocheck/i,
      /@ts-expect-error/i,
      /nantis-disable/i,
      /\/\/\s*security-disable/i,
    ];

    for (const pattern of suppressionPatterns) {
      if (pattern.test(diff)) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Patch contains rule suppression comment matching ${pattern}`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }
    }

    // Count deleted non-empty code lines
    const diffLines = diff.split("\n");
    let deletedCodeLines = 0;
    for (const line of diffLines) {
      if (line.startsWith("-") && !line.startsWith("---")) {
        const lineText = line.substring(1).trim();
        if (lineText.length > 0 && !lineText.startsWith("//") && !lineText.startsWith("/*")) {
          deletedCodeLines++;
        }
      }
    }

    if (deletedCodeLines > 3) {
      return {
        valid: false,
        reason: `Patch Safety Gate REJECTED: Attempts to fix issue by deleting ${deletedCodeLines} code lines`,
        expectedFiles,
        actualFiles: Array.from(actualFilesSet),
        patchHash: "",
        generatorVersion: PATCH_GATE_GENERATOR_VERSION,
      };
    }

    // Compute SHA-256 Patch Hash
    const patchHash = createHash("sha256")
      .update(`${diff}:${PATCH_GATE_GENERATOR_VERSION}`, "utf8")
      .digest("hex")
      .slice(0, 16);

    return {
      valid: true,
      expectedFiles,
      actualFiles: Array.from(actualFilesSet),
      patchHash,
      generatorVersion: PATCH_GATE_GENERATOR_VERSION,
    };
  }
}
