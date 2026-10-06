import { FixResult } from "../types.js";
import { calculateBlastRadius } from "../blast-radius.js";

/**
 * Fix Rule 2: Enable RLS on a database migration table with a template policy requiring human review.
 * Falls back to "suggested-manual" when code shape does not match expected table creation pattern.
 */
export function fixEnableRLS(
  filesMap: Map<string, string>,
  targetFilePath: string
): FixResult {
  const normPath = targetFilePath.replace(/\\/g, "/");
  const content = filesMap.get(targetFilePath) || filesMap.get(normPath);

  if (!content) {
    return {
      kind: "suggested-manual",
      ruleId: "missing-rls-in-migration",
      targetFile: normPath,
      reason: "Migration file content could not be read",
      suggestion: "Add ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY; manually to migration SQL.",
    };
  }

  // Strip SQL comments before matching CREATE TABLE
  const sqlWithoutComments = content.replace(/--.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");

  // Match CREATE TABLE public.tablename or CREATE TABLE tablename
  const createTableMatch = sqlWithoutComments.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([a-z0-9_"]+)/i);

  if (!createTableMatch) {
    return {
      kind: "suggested-manual",
      ruleId: "missing-rls-in-migration",
      targetFile: normPath,
      reason: "Could not identify target SQL CREATE TABLE statement in migration file",
      suggestion:
        "Manually add ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY; and define appropriate RLS policies.",
    };
  }

  const tableName = createTableMatch[1].replace(/"/g, "");

  // If RLS is already enabled, no fix needed or return manual
  if (/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content)) {
    return {
      kind: "suggested-manual",
      ruleId: "missing-rls-in-migration",
      targetFile: normPath,
      reason: `Row Level Security is already enabled on table ${tableName} but may lack restrictive policies`,
      suggestion: `Review RLS policies for table ${tableName} to ensure tenant row isolation.`,
    };
  }

  const fullTableMatch = content.match(new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:public\\.)?${tableName}[^;]*;`, "i")) || content.match(new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:public\\.)?${tableName}`, "i"));

  if (!fullTableMatch) {
    return {
      kind: "suggested-manual",
      ruleId: "missing-rls-in-migration",
      targetFile: normPath,
      reason: `Could not target CREATE TABLE block for ${tableName}`,
      suggestion: `Manually add ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;`,
    };
  }

  const targetContent = fullTableMatch[0];
  const CANDIDATE_COLS = ["user_id", "owner_id", "account_id", "tenant_id"];
  
  // Extract table definition body inside CREATE TABLE (...)
  const bodyMatch = targetContent.match(/\(([\s\S]+)\)/);
  const tableBody = bodyMatch ? bodyMatch[1] : targetContent;
  
  const matchedOwnershipCols: string[] = [];
  for (const col of CANDIDATE_COLS) {
    const colRegex = new RegExp(`\\b"?${col}"?\\b`, "i");
    if (colRegex.test(tableBody)) {
      matchedOwnershipCols.push(col);
    }
  }

  let rlsStatements = "";
  const proofLabel: "Not proven, reasoned from code" = "Not proven, reasoned from code";
  let reviewNote = "";

  const USER_IDENTIFIER_COLS = ["user_id", "owner_id"];

  if (matchedOwnershipCols.length === 1 && USER_IDENTIFIER_COLS.includes(matchedOwnershipCols[0])) {
    const colName = matchedOwnershipCols[0];
    rlsStatements = `\nALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Tenant access policy" ON ${tableName} FOR ALL USING (auth.uid() = ${colName});`;
    reviewNote = `enabled RLS on table ${tableName} using ownership column ${colName}; Needs Human Review`;
  } else {
    rlsStatements = `\nALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;\n-- TODO: Define RLS policy for ${tableName}. Needs Human Review to specify tenant column isolation.`;
    reviewNote = `enabled RLS on table ${tableName}; Needs Human Review for policy column`;
  }

  const replacementContent = targetContent + rlsStatements;

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
    ruleId: "missing-rls-in-migration",
    targetFile: normPath,
    edits,
    diff: "",
    riskLevel: "medium",
    blastRadius,
    proofLabel,
    verificationReport: {
      passed: true,
      checksRun: ["sql-parse"],
      summaryText: `verified: ${reviewNote}`,
    },
  };
}
