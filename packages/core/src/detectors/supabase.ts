import { parse, Statement } from "pgsql-ast-parser";
import { Finding, EvidenceHop, UnresolvedStep } from "../types.js";
import { createFinding } from "../evidence.js";

/**
 * Safely extracts table name and schema from a QName AST node or string.
 */
function extractQName(node: unknown): { name: string; schema?: string } {
  if (!node) return { name: "" };
  if (typeof node === "string") return { name: node };
  if (typeof node === "object" && node !== null) {
    const obj = node as Record<string, unknown>;
    if (typeof obj.name === "string")
      return { name: obj.name, schema: typeof obj.schema === "string" ? obj.schema : undefined };
    if (typeof obj.table === "string")
      return { name: obj.table, schema: typeof obj.schema === "string" ? obj.schema : undefined };
  }
  return { name: String(node) };
}

/**
 * 1. detectMissingRlsInMigrations (missing-rls-in-migration)
 * Parses SQL migrations using pgsql-ast-parser to find tables lacking ENABLE ROW LEVEL SECURITY.
 */
export async function detectMissingRlsInMigrations(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (!normPath.endsWith(".sql")) continue;

    const lines = content.split("\n");
    let statements: Statement[] = [];
    let parseErrorReason: string | undefined = undefined;

    try {
      statements = parse(content);
    } catch (err: unknown) {
      parseErrorReason = err instanceof Error ? err.message : String(err);
    }

    const createdTables: Array<{ tableName: string; line: number }> = [];
    const tablesWithRls = new Set<string>();

    if (statements.length > 0) {
      for (const stmt of statements) {
        // Table creation in AST
        if (stmt.type === "create table") {
          const qname = extractQName(stmt.name);
          const line = lines.findIndex((l) => l.toLowerCase().includes("create table")) + 1 || 1;
          createdTables.push({ tableName: qname.name, line });
        }

        // Alter table enable RLS in AST
        if (stmt.type === "alter table") {
          const qname = extractQName(stmt.table);
          const stmtObj = stmt as unknown as Record<string, unknown>;
          const changes = stmtObj.changes || stmtObj.change;
          if (Array.isArray(changes)) {
            for (const change of changes) {
              if (
                typeof change === "object" &&
                change !== null &&
                (change as Record<string, unknown>).type === "enable rls"
              ) {
                tablesWithRls.add(qname.name);
              }
            }
          }
        }
      }
    } else {
      // Fallback regex if SQL statement uses unparsed vendor extensions
      const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)/gi;
      let match: RegExpExecArray | null;
      while ((match = createTableRegex.exec(content)) !== null) {
        const rawName = match[1].replace(/["`]/g, "");
        const tableName = rawName.includes(".") ? rawName.split(".")[1] : rawName;
        const startLine = content.slice(0, match.index).split("\n").length;
        createdTables.push({ tableName, line: startLine });
      }

      if (/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content)) {
        for (const t of createdTables) {
          tablesWithRls.add(t.tableName);
        }
      }
    }

    for (const { tableName, line } of createdTables) {
      if (!tablesWithRls.has(tableName)) {
        const maskedSnippet = lines
          .slice(line - 1, Math.min(lines.length, line + 4))
          .join("\n")
          .trim();

        const evidenceChain: EvidenceHop[] = [
          {
            kind: "source",
            file: normPath,
            line,
            maskedSnippet: lines[line - 1]?.trim() || `CREATE TABLE ${tableName}`,
            confidence: "high",
            note: `PostgreSQL table '${tableName}' created in SQL migration AST`,
          },
          {
            kind: "missing-guard",
            file: normPath,
            line,
            maskedSnippet,
            confidence: "high",
            note: `Missing 'ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;' AST statement`,
          },
          {
            kind: "sink",
            file: normPath,
            line,
            maskedSnippet,
            confidence: "high",
            note: "Table exposed over Supabase Data API without Row Level Security protection",
          },
        ];

        const unresolvedSteps: UnresolvedStep[] = [];
        if (parseErrorReason) {
          unresolvedSteps.push({
            description: `SQL parser fallback: ${parseErrorReason}`,
            location: { file: normPath, line },
            reason: "external-library",
          });
        }

        findings.push(
          createFinding({
            ruleId: "missing-rls-in-migration",
            title: "Missing Row Level Security (RLS) in Migration",
            severity: "high",
            confidenceTier: "proven",
            file: normPath,
            lineRange: { startLine: line, endLine: Math.min(lines.length, line + 3) },
            evidenceChain,
            unresolvedSteps,
            explanation: `Table '${tableName}' is created without enabling Row Level Security. According to Supabase RLS Documentation (https://supabase.com/docs/guides/auth/row-level-security), every table must execute 'ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;' to prevent unauthorized public access over the Data API.`,
            fingerprint: `missing-rls-${normPath}-${tableName}`,
          })
        );
      }
    }
  }

  return findings;
}

/**
 * 2. detectPermissivePolicies (supabase-permissive-policy)
 * Parses SQL migrations using pgsql-ast-parser to detect overly permissive USING (true) or WITH CHECK (true) policies.
 */
export async function detectPermissivePolicies(filesMap: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (!normPath.endsWith(".sql")) continue;

    const lines = content.split("\n");
    let statements: Statement[] = [];
    try {
      statements = parse(content);
    } catch {}

    const policyMatches: Array<{ policyName: string; line: number; text: string }> = [];

    if (statements.length > 0) {
      for (const stmt of statements) {
        const stmtObj = stmt as unknown as Record<string, unknown>;
        if (stmtObj.type === "create policy") {
          const policyName = extractQName(stmtObj.name).name;
          const usingStr = JSON.stringify(stmtObj.using || {}).toLowerCase();
          const checkStr = JSON.stringify(stmtObj.withCheck || {}).toLowerCase();

          const isPermissiveUsing = usingStr.includes("true");
          const isPermissiveCheck = checkStr.includes("true");

          if (isPermissiveUsing || isPermissiveCheck) {
            const line = lines.findIndex((l) => l.toLowerCase().includes("create policy")) + 1 || 1;
            policyMatches.push({ policyName, line, text: lines[line - 1] || "" });
          }
        }
      }
    }

    // Regex fallback for quotes with spaces or dynamic syntax
    if (policyMatches.length === 0) {
      const policyRegex =
        /CREATE\s+POLICY\s+(?:"([^"]+)"|'([^']+)'|([^\s]+))\s+ON\s+[^\s]+\s+(?:FOR\s+[^\s]+\s+)?(?:USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\))/gi;
      let match: RegExpExecArray | null;
      while ((match = policyRegex.exec(content)) !== null) {
        const policyName = match[1] || match[2] || match[3] || "PermissivePolicy";
        const line = content.slice(0, match.index).split("\n").length;
        policyMatches.push({ policyName, line, text: match[0] });
      }
    }

    for (const { policyName, line, text } of policyMatches) {
      const maskedSnippet = lines[line - 1]?.trim() || text;

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: `RLS policy '${policyName}' defined on table in SQL migration`,
        },
        {
          kind: "flow",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Policy uses 'USING (true)' or 'WITH CHECK (true)' expression in AST",
        },
        {
          kind: "sink",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Grants unrestricted access to all table rows for anon/authenticated callers",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Missing tenant scoping filter (e.g. auth.uid() = user_id)",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "supabase-permissive-policy",
          title: "Overly Permissive RLS Policy USING (true)",
          severity: "high",
          confidenceTier: "likely",
          file: normPath,
          lineRange: { startLine: line, endLine: line },
          evidenceChain,
          unresolvedSteps: [],
          explanation: `RLS policy '${policyName}' uses 'USING (true)' or 'WITH CHECK (true)'. According to Supabase Row Level Security Policies Documentation (https://supabase.com/docs/guides/auth/row-level-security#policies), policies using unrestricted true conditions allow callers to access/modify all rows across tenants.`,
          fingerprint: `permissive-policy-${normPath}-${policyName}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 3. detectServiceRoleLeaks (supabase-service-role-leak)
 * Detects SUPABASE_SERVICE_ROLE_KEY used in client components or unauthenticated routes.
 */
export async function detectServiceRoleLeaks(filesMap: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (
      !normPath.endsWith(".ts") &&
      !normPath.endsWith(".tsx") &&
      !normPath.endsWith(".js") &&
      !normPath.endsWith(".jsx")
    ) {
      continue;
    }

    if (!content.includes("SUPABASE_SERVICE_ROLE_KEY")) continue;

    const isClientComponent = /^\s*['"]use client['"]/m.test(content);
    const isPublicRoute =
      normPath.includes("app/api/") &&
      !content.includes("assertRepoAccess") &&
      !content.includes("getServerSession");

    if (isClientComponent || isPublicRoute) {
      const lines = content.split("\n");
      const line = lines.findIndex((l) => l.includes("SUPABASE_SERVICE_ROLE_KEY")) + 1 || 1;
      const endLine = Math.min(lines.length, line + 3);

      const maskedSnippet = lines
        .slice(Math.max(0, line - 2), endLine)
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line,
          maskedSnippet: lines[line - 1]?.trim() || "SUPABASE_SERVICE_ROLE_KEY",
          confidence: "high",
          note: "Reference to SUPABASE_SERVICE_ROLE_KEY administrative key",
        },
        {
          kind: "flow",
          file: normPath,
          line,
          maskedSnippet: lines[line - 1]?.trim() || "createClient(..., SUPABASE_SERVICE_ROLE_KEY)",
          confidence: "high",
          note: "Service role key instantiated in client component or unauthenticated endpoint",
        },
        {
          kind: "sink",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Service role client bypasses all Row Level Security (RLS) policies",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Exposes administrative database bypass rights to untrusted callers",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "supabase-service-role-leak",
          title: "Supabase Service-Role Key Exposed in Client/Public Code",
          severity: "critical",
          confidenceTier: "proven",
          file: normPath,
          lineRange: { startLine: line, endLine },
          evidenceChain,
          unresolvedSteps: [],
          explanation: `SUPABASE_SERVICE_ROLE_KEY is referenced in '${normPath}'. According to Supabase API Keys Security Documentation (https://supabase.com/docs/guides/api/api-keys#the-servicerole-key), the service_role key has BYPASSRLS admin privileges and must NEVER be exposed in client code or public endpoints.`,
          fingerprint: `service-role-leak-${normPath}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 4. detectStorageBucketIssues (supabase-storage-public-or-unprotected)
 * Parses SQL migrations to detect storage buckets created with public = true or missing RLS policy on storage.objects.
 */
export async function detectStorageBucketIssues(filesMap: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (!normPath.endsWith(".sql")) continue;

    const lines = content.split("\n");
    let statements: Statement[] = [];
    try {
      statements = parse(content);
    } catch {}

    let isPublicBucket = false;
    let isBucketCreated = false;
    let bucketLine = 1;

    if (statements.length > 0) {
      for (const stmt of statements) {
        if (stmt.type === "insert") {
          const stmtObj = stmt as unknown as Record<string, unknown>;
          const qname = extractQName(stmtObj.table);
          if (qname.name === "buckets" || qname.name === "storage.buckets") {
            isBucketCreated = true;
            bucketLine =
              lines.findIndex((l) => l.toLowerCase().includes("storage.buckets")) + 1 || 1;

            const insertBody = stmtObj.insert as Record<string, unknown> | undefined;
            if (insertBody && insertBody.type === "values" && Array.isArray(insertBody.values)) {
              for (const valRow of insertBody.values) {
                if (Array.isArray(valRow)) {
                  for (const val of valRow) {
                    if (
                      val &&
                      typeof val === "object" &&
                      (val as Record<string, unknown>).type === "boolean" &&
                      (val as Record<string, unknown>).value === true
                    ) {
                      isPublicBucket = true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    if (!isBucketCreated && /storage\.buckets/i.test(content)) {
      isBucketCreated = true;
      bucketLine = lines.findIndex((l) => l.toLowerCase().includes("storage.buckets")) + 1 || 1;
      if (/public.*true|true.*public|true\)/i.test(content)) {
        isPublicBucket = true;
      }
    }

    const hasStorageObjectsPolicy =
      /CREATE\s+POLICY.*ON\s+storage\.objects/i.test(content) ||
      statements.some((s: Statement) => {
        const sObj = s as unknown as Record<string, unknown>;
        return sObj.type === "create policy" && extractQName(sObj.on).name === "objects";
      });

    if (isBucketCreated && (isPublicBucket || !hasStorageObjectsPolicy)) {
      const maskedSnippet = lines[bucketLine - 1]?.trim() || "INSERT INTO storage.buckets ...";

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line: bucketLine,
          maskedSnippet,
          confidence: "high",
          note: "Supabase storage bucket creation in SQL migration AST",
        },
        {
          kind: "config",
          file: normPath,
          line: bucketLine,
          maskedSnippet,
          confidence: "high",
          note: isPublicBucket
            ? "Bucket configured with 'public = true'"
            : "Bucket created without corresponding RLS policy on 'storage.objects'",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line: bucketLine,
          maskedSnippet,
          confidence: "high",
          note: "Lacks object-level storage authorization policies (CREATE POLICY ON storage.objects)",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "supabase-storage-public-or-unprotected",
          title: "Supabase Storage Bucket Public or Lacks RLS Policy",
          severity: "high",
          confidenceTier: "proven",
          file: normPath,
          lineRange: { startLine: bucketLine, endLine: bucketLine },
          evidenceChain,
          unresolvedSteps: [],
          explanation: `Storage bucket created in '${normPath}' is public or missing RLS policy on storage.objects. According to Supabase Storage Access Control Documentation (https://supabase.com/docs/guides/storage/security/access-control), public buckets serve files without access checks. Private buckets require RLS policies on storage.objects.`,
          fingerprint: `storage-issue-${normPath}`,
        })
      );
    }
  }

  return findings;
}
