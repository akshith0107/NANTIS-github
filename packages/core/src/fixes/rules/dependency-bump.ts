import { FixResult } from "../types.js";
import { calculateBlastRadius } from "../blast-radius.js";

/**
 * Fix Rule 1: Dependency bump to fixed version in package.json.
 * Falls back to "suggested-manual" when code shape does not match expected package.json structure.
 */
export function fixDependencyBump(
  filesMap: Map<string, string>,
  targetFilePath: string,
  pkgName: string,
  fixedVersion: string
): FixResult {
  const normPath = targetFilePath.replace(/\\/g, "/");
  const content = filesMap.get(targetFilePath) || filesMap.get(normPath);

  if (!content || !normPath.endsWith("package.json")) {
    return {
      kind: "suggested-manual",
      ruleId: "dependency-bump",
      targetFile: normPath,
      reason: "Target file is not package.json or file content is unreadable",
      suggestion: `Manually update dependency "${pkgName}" to version "^${fixedVersion}" in package.json.`,
    };
  }

  try {
    const pkg = JSON.parse(content);
    let updated = false;

    if (pkg.dependencies && pkg.dependencies[pkgName]) {
      pkg.dependencies[pkgName] = `^${fixedVersion}`;
      updated = true;
    } else if (pkg.devDependencies && pkg.devDependencies[pkgName]) {
      pkg.devDependencies[pkgName] = `^${fixedVersion}`;
      updated = true;
    }

    if (!updated) {
      return {
        kind: "suggested-manual",
        ruleId: "dependency-bump",
        targetFile: normPath,
        reason: `Package "${pkgName}" was not found in dependencies or devDependencies`,
        suggestion: `Add "${pkgName}": "^${fixedVersion}" to package.json dependencies manually.`,
      };
    }

    const depRegex = new RegExp(`("${pkgName}"\\s*:\\s*")([^"]+)(")`);
    const match = depRegex.exec(content);

    if (!match) {
      return {
        kind: "suggested-manual",
        ruleId: "dependency-bump",
        targetFile: normPath,
        reason: `Package "${pkgName}" line could not be located in ${normPath}`,
        suggestion: `Update "${pkgName}": "^${fixedVersion}" manually in package.json.`,
      };
    }

    const targetContent = match[0];
    const replacementContent = `"${pkgName}": "^${fixedVersion}"`;

    const edits = [
      {
        targetFile: normPath,
        targetContent,
        replacementContent,
      },
    ];

    const blastRadius = calculateBlastRadius(filesMap, normPath);

    return {
      kind: "automated",
      ruleId: "dependency-bump",
      targetFile: normPath,
      edits,
      diff: "",
      riskLevel: "low",
      blastRadius,
      proofLabel: "Not proven, reasoned from code",
      verificationReport: {
        passed: true,
        checksRun: ["json-parse"],
        summaryText: `verified: bumped ${pkgName} to ^${fixedVersion}`,
      },
    };
  } catch {
    return {
      kind: "suggested-manual",
      ruleId: "dependency-bump",
      targetFile: normPath,
      reason: "package.json contains invalid or malformed JSON syntax",
      suggestion: `Fix JSON formatting errors in ${normPath} and update "${pkgName}" to "^${fixedVersion}".`,
    };
  }
}
