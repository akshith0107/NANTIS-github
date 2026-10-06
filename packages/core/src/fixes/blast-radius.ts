import path from "path";
import { Project } from "ts-morph";
import { BlastRadius, RiskLevel } from "./types.js";

/**
 * Calculates blast radius and risk level using ts-morph AST analysis.
 */
export function calculateBlastRadius(
  filesMap: Map<string, string>,
  targetFilePath: string
): BlastRadius {
  const normTarget = targetFilePath.replace(/\\/g, "/");
  const targetBaseName = path.basename(normTarget, path.extname(normTarget));

  const importedByModules: string[] = [];
  const callersAffected: string[] = [];

  const project = new Project({ useInMemoryFileSystem: true });

  for (const [filePath, content] of filesMap.entries()) {
    const norm = filePath.replace(/\\/g, "/");
    project.createSourceFile(norm, content, { overwrite: true });
  }

  for (const [filePath, content] of filesMap.entries()) {
    const norm = filePath.replace(/\\/g, "/");
    if (norm === normTarget) continue;

    if (content.includes(targetBaseName) || content.includes(normTarget)) {
      importedByModules.push(norm);

      // Simple regex/AST caller detection for symbols exported from target
      const matchCall = content.match(new RegExp(`\\b${targetBaseName}\\w*\\(`, "g"));
      if (matchCall) {
        callersAffected.push(...matchCall.map((c) => c.replace("(", "")));
      }
    }
  }

  const affectedFiles = Array.from(new Set([normTarget, ...importedByModules]));
  const uniqueCallers = Array.from(new Set(callersAffected));

  let riskLevel: RiskLevel = "low";
  if (affectedFiles.length > 5 || uniqueCallers.length > 5) {
    riskLevel = "high";
  } else if (affectedFiles.length > 2 || uniqueCallers.length > 1) {
    riskLevel = "medium";
  }

  return {
    affectedFiles,
    callersAffected: uniqueCallers,
    importedByModules,
    riskLevel,
  };
}
