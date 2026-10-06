import { Finding, EvidenceHop, UnresolvedStep } from "../types.js";
import { createFinding } from "../evidence.js";
import {
  analyzeNextjsAppRouter,
  convertFilePathToRouteUrl,
  isPathMatchedByMiddleware,
} from "../adapters/nextjs-app-router.js";

/**
 * 1. detectApiRouteAuthIssues (api-route-no-auth)
 */
export async function detectApiRouteAuthIssues(filesMap: Map<string, string>): Promise<Finding[]> {
  const result = analyzeNextjsAppRouter(filesMap);
  const findings: Finding[] = [];

  for (const entry of result.entryPoints) {
    if (entry.kind === "route-handler" && entry.authGuardStatus === "unguarded") {
      // Skip webhooks or stripe routes which rely on signature verification
      if (entry.filePath.includes("webhook") || entry.filePath.includes("stripe")) {
        continue;
      }

      const content = filesMap.get(entry.filePath) || "";
      const lines = content.split("\n");
      const startLine = entry.lineRange?.startLine || 1;
      const endLine = entry.lineRange?.endLine || lines.length;

      const maskedSnippet = lines
        .slice(startLine - 1, Math.min(endLine, startLine + 4))
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: entry.filePath,
          line: startLine,
          maskedSnippet: lines[startLine - 1]?.trim() || `export async function ${entry.name}()`,
          confidence: "high",
          note: `Route handler entry point '${entry.name}' exposed at ${convertFilePathToRouteUrl(entry.filePath)}`,
        },
        {
          kind: "missing-guard",
          file: entry.filePath,
          line: startLine,
          maskedSnippet,
          confidence: "high",
          note: "No authentication session check (getServerSession, assertRepoAccess, supabase.auth.getUser) found in handler or middleware",
        },
        {
          kind: "sink",
          file: entry.filePath,
          line: Math.min(endLine, startLine + 2),
          maskedSnippet,
          confidence: "high",
          note: "Endpoint returns response data or executes database operations without user session check",
        },
      ];

      const unresolvedSteps: UnresolvedStep[] = [];
      if (entry.isUnresolved && entry.unresolvedReason) {
        unresolvedSteps.push({
          description: entry.unresolvedReason,
          location: { file: entry.filePath, line: startLine },
          reason: entry.unresolvedReason.includes("Dynamic import")
            ? "dynamic-import"
            : "opaque-call",
        });
      }

      findings.push(
        createFinding({
          ruleId: "api-route-no-auth",
          title: "API Route Missing Authentication Check",
          severity: "high",
          confidenceTier: "likely",
          file: entry.filePath,
          lineRange: { startLine, endLine },
          evidenceChain,
          unresolvedSteps,
          explanation: `API route handler '${entry.name}' exposed at '${convertFilePathToRouteUrl(entry.filePath)}' performs operations without verifying user authentication.`,
          fingerprint: `api-route-no-auth-${entry.filePath}-${entry.name}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 2. detectServerActionAuthIssues (server-action-no-auth)
 */
export async function detectServerActionAuthIssues(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const result = analyzeNextjsAppRouter(filesMap);
  const findings: Finding[] = [];

  for (const entry of result.entryPoints) {
    if (entry.kind === "server-action" && entry.authGuardStatus === "unguarded") {
      const content = filesMap.get(entry.filePath) || "";
      const lines = content.split("\n");
      const startLine = entry.lineRange?.startLine || 1;
      const endLine = entry.lineRange?.endLine || lines.length;

      const maskedSnippet = lines
        .slice(startLine - 1, Math.min(endLine, startLine + 4))
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: entry.filePath,
          line: startLine,
          maskedSnippet: lines[startLine - 1]?.trim() || `"use server"`,
          confidence: "high",
          note: `Server Action entry point '${entry.name}' defined with 'use server' directive`,
        },
        {
          kind: "missing-guard",
          file: entry.filePath,
          line: startLine,
          maskedSnippet,
          confidence: "high",
          note: "Missing user session authentication check (assertRepoAccess, getServerSession, supabase.auth.getUser) in server action body",
        },
        {
          kind: "sink",
          file: entry.filePath,
          line: Math.min(endLine, startLine + 2),
          maskedSnippet,
          confidence: "high",
          note: "Server Action executes database writes or mutations without user session authorization",
        },
      ];

      const unresolvedSteps: UnresolvedStep[] = [];
      if (entry.isUnresolved && entry.unresolvedReason) {
        unresolvedSteps.push({
          description: entry.unresolvedReason,
          location: { file: entry.filePath, line: startLine },
          reason: "opaque-call",
        });
      }

      findings.push(
        createFinding({
          ruleId: "server-action-no-auth",
          title: "Server Action Missing Authentication Check",
          severity: "high",
          confidenceTier: "likely",
          file: entry.filePath,
          lineRange: { startLine, endLine },
          evidenceChain,
          unresolvedSteps,
          explanation: `Server action '${entry.name}' in '${entry.filePath}' executes sensitive state mutations without validating user session authentication.`,
          fingerprint: `server-action-no-auth-${entry.filePath}-${entry.name}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 3. detectMiddlewareMatcherGaps (middleware-matcher-gap)
 */
export async function detectMiddlewareMatcherGaps(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const result = analyzeNextjsAppRouter(filesMap);
  const findings: Finding[] = [];

  const middlewareInfo = result.middlewareInfo;
  if (!middlewareInfo) return findings;

  for (const entry of result.entryPoints) {
    if (entry.kind === "route-handler") {
      const routeUrl = convertFilePathToRouteUrl(entry.filePath);
      const isMatched = isPathMatchedByMiddleware(routeUrl, middlewareInfo.matcher);

      // Gap exists if route is NOT matched by middleware AND has no local in-route auth guard
      if (!isMatched && entry.authGuardStatus !== "guarded") {
        const content = filesMap.get(entry.filePath) || "";
        const lines = content.split("\n");
        const startLine = entry.lineRange?.startLine || 1;
        const endLine = entry.lineRange?.endLine || lines.length;

        const maskedSnippet = lines
          .slice(startLine - 1, Math.min(endLine, startLine + 3))
          .join("\n")
          .trim();

        const evidenceChain: EvidenceHop[] = [
          {
            kind: "source",
            file: entry.filePath,
            line: startLine,
            maskedSnippet,
            confidence: "high",
            note: `Sensitive route handler '${entry.name}' exposed at '${routeUrl}'`,
          },
          {
            kind: "config",
            file: middlewareInfo.filePath,
            line: 1,
            maskedSnippet: `matcher: ${JSON.stringify(middlewareInfo.matcher || [])}`,
            confidence: "high",
            note: `Middleware config.matcher does not include pattern covering '${routeUrl}'`,
          },
          {
            kind: "missing-guard",
            file: entry.filePath,
            line: startLine,
            maskedSnippet,
            confidence: "high",
            note: "Route handler relies on middleware for protection but is excluded by matcher rules",
          },
        ];

        findings.push(
          createFinding({
            ruleId: "middleware-matcher-gap",
            title: "Middleware Matcher Gap Exposes Route Handler",
            severity: "high",
            confidenceTier: "likely",
            file: entry.filePath,
            lineRange: { startLine, endLine },
            evidenceChain,
            unresolvedSteps: [],
            explanation: `Route handler at '${routeUrl}' is not matched by middleware matcher rules '${JSON.stringify(middlewareInfo.matcher)}' and lacks an in-route auth guard.`,
            fingerprint: `middleware-matcher-gap-${entry.filePath}`,
          })
        );
      }
    }
  }

  return findings;
}

/**
 * 4. detectMissingOwnershipChecks (missing-ownership-check)
 */
export async function detectMissingOwnershipChecks(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (!normPath.includes("app/api/") && !normPath.includes("actions/")) {
      continue;
    }

    const lines = content.split("\n");

    // Search for ID parameters extracted from request
    const paramMatches = [
      ...content.matchAll(
        /(?:params\.([a-zA-Z0-9_]*id)|searchParams\.get\(['"]([a-zA-Z0-9_]*id)['"]\)|req\.json\(\)\.([a-zA-Z0-9_]*id))/gi
      ),
    ];

    if (paramMatches.length > 0) {
      // Check if DB query is executed filtering by ID
      const hasIdQuery =
        /\.eq\(['"]id['"]|\bWHERE\s+id\s*=/i.test(content) ||
        /getOrderById|getRecordById|query/i.test(content);

      // Check if ownership filter (user_id / tenant_id / owner_id / assertRepoAccess) is present
      const hasOwnershipFilter =
        /\.eq\(['"](?:user_id|tenant_id|owner_id|account_id)['"]/i.test(content) ||
        /\bWHERE\s+.*(?:user_id|tenant_id|owner_id)\s*=/i.test(content) ||
        /assertRepoAccess/i.test(content);

      if (hasIdQuery && !hasOwnershipFilter) {
        let fnStartLine = 1;
        let queryLine = 1;

        for (let i = 0; i < lines.length; i++) {
          if (/export\s+async\s+function/i.test(lines[i])) {
            fnStartLine = i + 1;
          }
          if (
            lines[i].includes(".eq(") ||
            lines[i].includes("WHERE") ||
            lines[i].includes("getOrderById")
          ) {
            queryLine = i + 1;
          }
        }
        const startLine = fnStartLine;
        const endLine = Math.max(startLine, queryLine);

        const paramName = paramMatches[0][1] || paramMatches[0][2] || paramMatches[0][3] || "id";
        const maskedSnippet = lines
          .slice(startLine - 1, endLine)
          .join("\n")
          .trim();

        const evidenceChain: EvidenceHop[] = [
          {
            kind: "source",
            file: normPath,
            line: startLine,
            maskedSnippet: lines[startLine - 1]?.trim() || `params.${paramName}`,
            confidence: "high",
            note: `Request parameter '${paramName}' extracted from client request`,
          },
          {
            kind: "flow",
            file: normPath,
            line: startLine + 1,
            maskedSnippet: lines[startLine]?.trim() || `const id = params.${paramName}`,
            confidence: "high",
            note: `Parameter '${paramName}' flows into database lookup variable`,
          },
          {
            kind: "sink",
            file: normPath,
            line: queryLine,
            maskedSnippet: lines[queryLine - 1]?.trim() || `.eq("id", ${paramName})`,
            confidence: "high",
            note: "Database query filters strictly by document/resource ID",
          },
          {
            kind: "missing-guard",
            file: normPath,
            line: queryLine,
            maskedSnippet,
            confidence: "high",
            note: "No user_id / tenant_id ownership filter present on database query",
          },
        ];

        const unresolvedSteps: UnresolvedStep[] = [];
        if (/getOrderById|updateRecordInDb/i.test(content)) {
          unresolvedSteps.push({
            description: "Database call delegated to external helper function",
            location: { file: normPath, line: queryLine },
            reason: "opaque-call",
          });
        }

        findings.push(
          createFinding({
            ruleId: "missing-ownership-check",
            title: "Database Query Missing User Ownership Filter",
            severity: "high",
            confidenceTier: "likely",
            file: normPath,
            lineRange: { startLine, endLine },
            evidenceChain,
            unresolvedSteps,
            explanation: `Handler queries database by parameter '${paramName}' without filtering by the authenticated user's ID (user_id / tenant_id), allowing unauthorized access to arbitrary records.`,
            fingerprint: `missing-ownership-check-${normPath}-${paramName}`,
          })
        );
      }
    }
  }

  return findings;
}

/**
 * 5. detectMassAssignmentIssues (mass-assignment)
 */
export async function detectMassAssignmentIssues(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (!normPath.includes("app/api/") && !normPath.includes("actions/")) {
      continue;
    }

    const lines = content.split("\n");

    // Trace body parsing
    const hasReqJson = /await\s+[a-zA-Z0-9_.]+\.json\(\)|\.json\(\)/i.test(content);
    const hasDbWrite = /\.insert\(|\.update\(|updateRecordInDb|db\..*\.insert/i.test(content);

    // Check if schema validation (zod.parse, schema.parse) or field picking exists
    const hasSchemaValidation = /\.parse\(/i.test(content) || /z\.object/i.test(content);

    if (hasReqJson && hasDbWrite && !hasSchemaValidation) {
      let fnStartLine = 1;
      let bodyLine = 1;
      let writeLine = 1;

      for (let i = 0; i < lines.length; i++) {
        if (/export\s+async\s+function/i.test(lines[i])) {
          fnStartLine = i + 1;
        }
        if (lines[i].includes(".json()")) {
          bodyLine = i + 1;
        }
        if (
          lines[i].includes(".insert(") ||
          lines[i].includes(".update(") ||
          lines[i].includes("updateRecordInDb")
        ) {
          writeLine = i + 1;
        }
      }

      const startLine = fnStartLine;
      const endLine = Math.max(bodyLine, writeLine);
      const maskedSnippet = lines
        .slice(startLine - 1, endLine)
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line: bodyLine,
          maskedSnippet: lines[bodyLine - 1]?.trim() || "const body = await req.json();",
          confidence: "high",
          note: "Raw unvalidated request body parsed from HTTP request",
        },
        {
          kind: "flow",
          file: normPath,
          line: bodyLine,
          maskedSnippet: lines[bodyLine - 1]?.trim() || "body",
          confidence: "high",
          note: "Whole request payload passed directly into database write operation",
        },
        {
          kind: "sink",
          file: normPath,
          line: writeLine,
          maskedSnippet: lines[writeLine - 1]?.trim() || ".insert(body)",
          confidence: "high",
          note: "Database write mutation accepts unsanitized object payload",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line: writeLine,
          maskedSnippet,
          confidence: "high",
          note: "Missing Zod schema validation or explicit field whitelist",
        },
      ];

      const unresolvedSteps: UnresolvedStep[] = [];
      if (/updateRecordInDb/i.test(content)) {
        unresolvedSteps.push({
          description: "Opaque database helper 'updateRecordInDb' accepts entire payload",
          location: { file: normPath, line: writeLine },
          reason: "opaque-call",
        });
      }

      findings.push(
        createFinding({
          ruleId: "mass-assignment",
          title: "Mass Assignment Vulnerability in DB Write",
          severity: "high",
          confidenceTier: "likely",
          file: normPath,
          lineRange: { startLine, endLine },
          evidenceChain,
          unresolvedSteps,
          explanation:
            "Entire unvalidated request body is passed directly to database write/insert operation without Zod schema parsing or field whitelisting.",
          fingerprint: `mass-assignment-${normPath}`,
        })
      );
    }
  }

  return findings;
}
