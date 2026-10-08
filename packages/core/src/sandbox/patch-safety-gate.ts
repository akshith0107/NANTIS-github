import { createHash } from "node:crypto";
import { StructuredEdit } from "../fixes/types.js";

export const PATCH_GATE_GENERATOR_VERSION = "0.1.0-phase5";

export interface PatchSafetyValidationResult {
  valid: boolean;
  reason?: string;
  expectedFiles: string[];
  actualFiles: string[];
  patchHash: string;
  generatorVersion: string;
}

/**
 * Patch Safety Gate validating file path containment, anti-suppression, and file bounds.
 */
export class PatchSafetyGate {
  /**
   * Validates a set of structured edits and unified diff before application.
   */
  static validatePatch(
    edits: StructuredEdit[],
    diff: string,
    expectedFiles: string[]
  ): PatchSafetyValidationResult {
    const actualFilesSet = new Set<string>();

    for (const edit of edits) {
      const normPath = edit.targetFile.replace(/\\/g, "/");

      // 1. Path Containment & Traversal Verification
      if (
        normPath.startsWith("/") ||
        /^[a-zA-Z]:[\\/]/i.test(normPath) ||
        normPath.includes("../") ||
        normPath.includes("..\\")
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

      // 2. Protect .git Directory and Hooks
      if (
        normPath.startsWith(".git/") ||
        normPath.includes("/.git/") ||
        normPath === ".git" ||
        normPath.startsWith(".git\\")
      ) {
        return {
          valid: false,
          reason: `Patch Safety Gate REJECTED: Attempted modification of forbidden .git directory '${edit.targetFile}'`,
          expectedFiles,
          actualFiles: Array.from(actualFilesSet),
          patchHash: "",
          generatorVersion: PATCH_GATE_GENERATOR_VERSION,
        };
      }

      // 3. Expected File Whitelist Enforcement
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

    // 4. Anti-Suppression Comments & Excessive Deletion Verification
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
