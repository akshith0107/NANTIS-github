import { createHash } from "node:crypto";
import { Project, SourceFile } from "ts-morph";
import { parse } from "pgsql-ast-parser";
import {
  Coverage,
  IndexedRepository,
  IndexedEndpoint,
  IndexedParam,
  IndexedSupabaseQuery,
  IndexedTable,
  IndexedRlsPolicy,
} from "./types.js";

/**
 * Computes a deterministic SHA-256 hash of file contents.
 */
export function computeFileHash(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex").slice(0, 16);
}

/**
 * Known ownership column names in database schemas.
 */
export const KNOWN_OWNER_COLUMNS = [
  "user_id",
  "owner_id",
  "tenant_id",
  "account_id",
  "creator_id",
  "author_id",
];

/**
 * Builds a deterministic index of a repository's entrypoints, DB schemas, queries, and RLS policies.
 */
export function indexRepository(filesMap: Map<string, string>): IndexedRepository {
  const fileHashes = new Map<string, string>();
  for (const [path, content] of filesMap.entries()) {
    const norm = path.replace(/\\/g, "/");
    fileHashes.set(norm, computeFileHash(content));
  }

  const project = new Project({
    useInMemoryFileSystem: true,
    skipAddingFilesFromTsConfig: true,
  });

  const sourceFilesMap = new Map<string, SourceFile>();
  for (const [filePath, content] of filesMap.entries()) {
    const norm = filePath.replace(/\\/g, "/");
    if (
      norm.endsWith(".ts") ||
      norm.endsWith(".tsx") ||
      norm.endsWith(".js") ||
      norm.endsWith(".jsx")
    ) {
      const sf = project.createSourceFile(norm, content, { overwrite: true });
      sourceFilesMap.set(norm, sf);
    }
  }

  const endpoints: IndexedEndpoint[] = [];
  const tables = new Map<string, IndexedTable>();
  const queries: IndexedSupabaseQuery[] = [];
  let totalEdgesResolved = 0;
  let totalEdgesUnresolved = 0;

  // --- Step 1: Index SQL Migrations (Tables & RLS Policies) ---
  for (const [filePath, content] of filesMap.entries()) {
    const norm = filePath.replace(/\\/g, "/");
    if (!norm.endsWith(".sql")) continue;

    try {
      parse(content);
    } catch {
      totalEdgesUnresolved++;
    }

    // Index CREATE TABLE statements
    const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)\s*\(([^;]+)\);?/gi;
    let match: RegExpExecArray | null;

    while ((match = createTableRegex.exec(content)) !== null) {
      const rawName = match[1].replace(/["`]/g, "");
      const tableName = rawName.includes(".") ? rawName.split(".")[1] : rawName;
      const body = match[2];
      const startLine = content.slice(0, match.index).split("\n").length;

      const ownerCols: string[] = [];
      for (const col of KNOWN_OWNER_COLUMNS) {
        if (new RegExp(`\\b${col}\\b`, "i").test(body)) {
          ownerCols.push(col);
        }
      }

      const hasRls = new RegExp(
        `ALTER\\s+TABLE\\s+${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
        "i"
      ).test(content);

      if (!tables.has(tableName)) {
        tables.set(tableName, {
          tableName,
          filePath: norm,
          line: startLine,
          hasRlsEnabled: hasRls,
          ownerColumns: ownerCols,
          policies: [],
        });
      } else {
        const existing = tables.get(tableName)!;
        if (hasRls) existing.hasRlsEnabled = true;
        for (const col of ownerCols) {
          if (!existing.ownerColumns.includes(col)) existing.ownerColumns.push(col);
        }
      }
    }

    // Index ALTER TABLE ... ENABLE ROW LEVEL SECURITY
    const enableRlsRegex = /ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
    while ((match = enableRlsRegex.exec(content)) !== null) {
      const rawName = match[1].replace(/["`]/g, "");
      const tableName = rawName.includes(".") ? rawName.split(".")[1] : rawName;
      if (tables.has(tableName)) {
        tables.get(tableName)!.hasRlsEnabled = true;
      } else {
        tables.set(tableName, {
          tableName,
          filePath: norm,
          line: content.slice(0, match.index).split("\n").length,
          hasRlsEnabled: true,
          ownerColumns: [],
          policies: [],
        });
      }
    }

    // Index CREATE POLICY statements
    const policyRegex =
      /CREATE\s+POLICY\s+(?:"([^"]+)"|'([^']+)'|([^\s]+))\s+ON\s+([^\s]+)([^;]+);?/gi;
    while ((match = policyRegex.exec(content)) !== null) {
      const policyName = match[1] || match[2] || match[3] || "policy";
      const rawTable = match[4].replace(/["`]/g, "");
      const tableName = rawTable.includes(".") ? rawTable.split(".")[1] : rawTable;
      const body = match[5] || "";
      const startLine = content.slice(0, match.index).split("\n").length;

      const isPermissive = /\bUSING\s*\(\s*true\s*\)|\bWITH\s+CHECK\s*\(\s*true\s*\)/i.test(body);
      const hasAuthUid = /auth\.uid\(\)/i.test(body);

      const policyObj: IndexedRlsPolicy = {
        policyName,
        tableName,
        filePath: norm,
        line: startLine,
        isPermissive,
        hasAuthUid,
        definitionSnippet: match[0],
      };

      if (!tables.has(tableName)) {
        tables.set(tableName, {
          tableName,
          filePath: norm,
          line: startLine,
          hasRlsEnabled: false,
          ownerColumns: [],
          policies: [policyObj],
        });
      } else {
        tables.get(tableName)!.policies.push(policyObj);
      }
      totalEdgesResolved++;
    }
  }

  // --- Step 2: Index Endpoints, Queries, and Auth Guards ---
  for (const [normPath, sf] of sourceFilesMap.entries()) {
    const text = sf.getFullText();
    const lines = text.split("\n");

    const isRouteHandler = /(?:^|\/)app\/.*\/route\.(?:ts|js|tsx|jsx)$/i.test(normPath) || normPath.includes("pages/api/");
    const isServerAction = /^\s*['"]use server['"]/m.test(text);

    // Detect parameters
    const params: IndexedParam[] = [];

    // 1. Explicit parameter access (params.id, searchParams.get('id'), req.json(), body.id)
    const paramMatches = [
      ...text.matchAll(
        /(?:params\.([a-zA-Z0-9_]+)|searchParams\.get\(['"]([a-zA-Z0-9_]+)['"]\)|req\.json\(\)(?:\.([a-zA-Z0-9_]+))?|body\.([a-zA-Z0-9_]+)|formData\.get\(['"]([a-zA-Z0-9_]+)['"]\))/gi
      ),
    ];

    for (const pm of paramMatches) {
      const name = pm[1] || pm[2] || pm[3] || pm[4] || pm[5] || "id";
      const line = text.slice(0, pm.index).split("\n").length;
      if (!params.some((p) => p.name === name)) {
        params.push({
          name,
          source: pm[1] ? "route-param" : pm[2] ? "search-param" : "body-param",
          line,
        });
      }
    }

    // 2. Exported Function signature arguments (e.g., export async function deleteComment(commentId: string))
    const fnDeclMatches = [...text.matchAll(/export\s+(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/gi)];
    for (const fnM of fnDeclMatches) {
      const rawParams = fnM[2];
      const line = text.slice(0, fnM.index).split("\n").length;

      const argMatches = [...rawParams.matchAll(/\b([a-zA-Z0-9_]+)\b/g)];
      for (const arg of argMatches) {
        const argName = arg[1];
        if (
          argName !== "req" &&
          argName !== "Request" &&
          argName !== "params" &&
          argName !== "string" &&
          argName !== "any" &&
          argName !== "Promise" &&
          argName !== "Response"
        ) {
          if (!params.some((p) => p.name === argName)) {
            params.push({ name: argName, source: "route-param", line });
          }
        }
      }
    }

    if (params.length === 0) {
      const genericParamMatch = text.match(/\bparams\s*:\s*\{?\s*([a-zA-Z0-9_]+)\b/i);
      if (genericParamMatch) {
        params.push({
          name: genericParamMatch[1],
          source: "route-param",
          line: text.slice(0, genericParamMatch.index).split("\n").length,
        });
      }
    }

    // Detect session auth checks
    const authChecks: string[] = [];
    if (/\bgetServerSession\b/.test(text)) authChecks.push("getServerSession");
    if (/supabase\.auth\.getUser/.test(text)) authChecks.push("supabase.auth.getUser");
    if (/supabase\.auth\.getSession/.test(text)) authChecks.push("supabase.auth.getSession");
    if (/\bassertRepoAccess\b/.test(text)) authChecks.push("assertRepoAccess");
    if (/\bauth\s*\(/.test(text)) authChecks.push("auth()");
    if (/\bverifySession\b/.test(text)) authChecks.push("verifySession");

    const hasSessionAuth = authChecks.length > 0;

    // Detect Supabase database queries
    const queryMatches: IndexedSupabaseQuery[] = [];
    const fromRegex = /\.from\(['"]([a-zA-Z0-9_]+)['"]\)\s*\.([a-zA-Z0-9_]+)\([^)]*\)/gi;
    let qMatch: RegExpExecArray | null;

    while ((qMatch = fromRegex.exec(text)) !== null) {
      const table = qMatch[1];
      const opRaw = qMatch[2].toLowerCase();
      const operation: IndexedSupabaseQuery["operation"] =
        opRaw === "update" ? "update" : opRaw === "delete" ? "delete" : opRaw === "insert" ? "insert" : "select";
      const line = text.slice(0, qMatch.index).split("\n").length;

      // Extract statement block around query to analyze .eq() filters
      const snippetEnd = Math.min(text.length, qMatch.index + 300);
      const snippet = text.slice(qMatch.index, snippetEnd);

      const filters: IndexedSupabaseQuery["filters"] = [];
      const eqMatches = [...snippet.matchAll(/\.eq\(['"]([a-zA-Z0-9_]+)['"]\s*,\s*([^)]+)\)/gi)];

      let hasOwnerColumnFilter = false;
      let hasAuthUidFilter = false;

      for (const eq of eqMatches) {
        const col = eq[1];
        const valExpr = eq[2].trim();
        const isUserControlled = params.some((p) => valExpr.includes(p.name)) || valExpr.includes("id");
        const isOwnerCheck = KNOWN_OWNER_COLUMNS.includes(col);
        const isAuthUidCheck =
          /session|user\.id|userId|auth\.uid/i.test(valExpr) && isOwnerCheck;

        if (isOwnerCheck) hasOwnerColumnFilter = true;
        if (isAuthUidCheck) hasAuthUidFilter = true;

        filters.push({
          column: col,
          valueExpr: valExpr,
          isUserControlled,
          isOwnerCheck,
          isAuthUidCheck,
        });
      }

      const indexedQ: IndexedSupabaseQuery = {
        file: normPath,
        line,
        table,
        operation,
        filters,
        hasOwnerColumnFilter,
        hasAuthUidFilter,
        rawSnippet: lines.slice(line - 1, line + 3).join("\n"),
      };

      queryMatches.push(indexedQ);
      queries.push(indexedQ);
      totalEdgesResolved++;
    }

    const hasDynamicImport = /\bimport\s*\(/.test(text);
    const hasEval = /\beval\s*\(|new\s+Function\s*\(/.test(text);
    const hasDynamicProperty = /\.eq\(\s*([a-zA-Z0-9_]+)\s*,/i.test(text) && !/\.eq\(['"]/.test(text);
    const isUnresolved = hasDynamicImport || hasEval || hasDynamicProperty;
    const unresolvedReason = hasDynamicImport
      ? "Dynamic import 'import(...)' detected on path"
      : hasEval
      ? "Dynamic code execution (eval / new Function) detected on path"
      : hasDynamicProperty
      ? "Dynamic property lookup in database query filter detected on path"
      : undefined;

    if (isRouteHandler || isServerAction || params.length > 0) {
      endpoints.push({
        id: `${normPath}:${isRouteHandler ? "route" : isServerAction ? "action" : "helper"}`,
        filePath: normPath,
        name: normPath.split("/").pop() || "endpoint",
        kind: isRouteHandler ? "route-handler" : "server-action",
        params,
        authChecks,
        hasSessionAuth,
        queries: queryMatches,
        lineRange: { startLine: 1, endLine: lines.length },
        isUnresolved,
        unresolvedReason,
      });
    }
  }

  const totalFiles = filesMap.size;
  const coverage: Coverage = {
    filesInspected: totalFiles,
    totalFiles,
    maxDepthReached: 3,
    edgesResolved: totalEdgesResolved,
    edgesUnresolved: totalEdgesUnresolved,
    completionState: totalEdgesUnresolved > 0 ? "truncated" : "complete",
  };

  return {
    fileHashes,
    endpoints,
    tables,
    queries,
    coverage,
  };
}
