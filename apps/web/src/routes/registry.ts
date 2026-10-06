import {
  handleCreateScan,
  handleGetFinding,
  handleGetRepo,
  handleGetReport,
  handleGetScan,
  handleGetScanReport,
  handleListFindings,
  handleListScans,
} from "./api-routes.js";
import { handleReportFalsePositive } from "./false-positive-route.js";

export interface RouteDefinition {
  name: string;
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  targetResource: "repo" | "scan" | "finding" | "report";
  accessCheck: "assertRepoAccess";
  handler: Function;
}

export const API_ROUTE_REGISTRY: RouteDefinition[] = [
  {
    name: "Get Repository",
    method: "GET",
    path: "/api/repos/:repoId",
    targetResource: "repo",
    accessCheck: "assertRepoAccess",
    handler: handleGetRepo,
  },
  {
    name: "List Scans",
    method: "GET",
    path: "/api/repos/:repoId/scans",
    targetResource: "scan",
    accessCheck: "assertRepoAccess",
    handler: handleListScans,
  },
  {
    name: "Create Scan",
    method: "POST",
    path: "/api/repos/:repoId/scans",
    targetResource: "scan",
    accessCheck: "assertRepoAccess",
    handler: handleCreateScan,
  },
  {
    name: "Get Scan Details",
    method: "GET",
    path: "/api/scans/:scanId",
    targetResource: "scan",
    accessCheck: "assertRepoAccess",
    handler: handleGetScan,
  },
  {
    name: "List Scan Findings",
    method: "GET",
    path: "/api/scans/:scanId/findings",
    targetResource: "finding",
    accessCheck: "assertRepoAccess",
    handler: handleListFindings,
  },
  {
    name: "Get Finding Details",
    method: "GET",
    path: "/api/findings/:findingId",
    targetResource: "finding",
    accessCheck: "assertRepoAccess",
    handler: handleGetFinding,
  },
  {
    name: "Get Repository Report",
    method: "GET",
    path: "/api/repos/:repoId/report",
    targetResource: "report",
    accessCheck: "assertRepoAccess",
    handler: handleGetReport,
  },
  {
    name: "Get Scan Report",
    method: "GET",
    path: "/api/scans/:scanId/report",
    targetResource: "report",
    accessCheck: "assertRepoAccess",
    handler: handleGetScanReport,
  },
  {
    name: "Report False Positive",
    method: "POST",
    path: "/api/findings/false-positive",
    targetResource: "finding",
    accessCheck: "assertRepoAccess",
    handler: handleReportFalsePositive,
  },
];

/**
 * Format route access control registry as a markdown table for reporting and auditing.
 */
export function formatRouteRegistryTable(): string {
  const lines: string[] = [];
  lines.push("| Route Name | Method | Path | Resource | Access Check |");
  lines.push("|------------|--------|------|----------|--------------|");
  for (const r of API_ROUTE_REGISTRY) {
    const padName = r.name.padEnd(20, " ");
    const padMethod = r.method.padEnd(6, " ");
    const padPath = r.path.padEnd(28, " ");
    const padRes = r.targetResource.padEnd(8, " ");
    const padCheck = r.accessCheck.padEnd(16, " ");
    lines.push(`| ${padName} | ${padMethod} | ${padPath} | ${padRes} | ${padCheck} |`);
  }
  return lines.join("\n");
}

/**
 * Audits all API routes in the registry.
 * Fails fast if any route touching repos/scans/findings/reports lacks `assertRepoAccess`.
 */
export function auditRouteRegistry(): { passed: boolean; totalRoutes: number; errors: string[] } {
  const errors: string[] = [];
  for (const route of API_ROUTE_REGISTRY) {
    if (route.accessCheck !== "assertRepoAccess") {
      errors.push(
        `Route ${route.method} ${route.path} (${route.name}) is missing required assertRepoAccess check! Found: '${route.accessCheck}'`
      );
    }
  }

  return {
    passed: errors.length === 0,
    totalRoutes: API_ROUTE_REGISTRY.length,
    errors,
  };
}
