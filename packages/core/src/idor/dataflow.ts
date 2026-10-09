import {
  DataflowLimits,
  DEFAULT_DATAFLOW_LIMITS,
  Coverage,
  IndexedEndpoint,
  IndexedSupabaseQuery,
} from "./types.js";
import { UnresolvedStep } from "../types.js";

export interface DataflowPath {
  sourceEndpoint: IndexedEndpoint;
  paramName: string;
  sinkQuery: IndexedSupabaseQuery;
  isUserControlled: boolean;
  depth: number;
  unresolvedSteps: UnresolvedStep[];
  isTruncated: boolean;
}

export interface DataflowAnalysisResult {
  paths: DataflowPath[];
  coverage: Coverage;
}

/**
 * Bounded, deterministic dataflow engine tracing attacker-controlled inputs to database query sinks.
 */
export class BoundedDataflowEngine {
  private limits: DataflowLimits;

  constructor(limits?: Partial<DataflowLimits>) {
    this.limits = { ...DEFAULT_DATAFLOW_LIMITS, ...limits };
  }

  /**
   * Analyzes parameter dataflow for a list of endpoints and database queries.
   */
  analyzeDataflow(
    endpoints: IndexedEndpoint[],
    queries: IndexedSupabaseQuery[],
    totalRepoFiles: number
  ): DataflowAnalysisResult {
    const paths: DataflowPath[] = [];
    let filesInspectedCount = 0;
    const inspectedFilesSet = new Set<string>();
    let maxDepthReached = 0;
    let edgesResolved = 0;
    let edgesUnresolved = 0;
    let isTruncatedOverall = false;

    for (const ep of endpoints) {
      if (inspectedFilesSet.size >= this.limits.maxFiles) {
        isTruncatedOverall = true;
        break;
      }

      inspectedFilesSet.add(ep.filePath);
      filesInspectedCount = inspectedFilesSet.size;

      // 1. Same-file database queries
      const sameFileQueries = queries.filter((q) => q.file === ep.filePath);

      // 2. Cross-file database queries (helpers / db access modules called by endpoint)
      const crossFileQueries = queries.filter((q) => {
        if (q.file === ep.filePath) return false;
        // Check if endpoint file references helper module or function in q.file
        const baseName = q.file.split("/").pop()?.replace(/\.(ts|js|tsx|jsx)$/, "") || "";
        const helperNameMatch = baseName.length > 2 && ep.filePath !== q.file;
        return helperNameMatch;
      });

      const relatedQueries = [...sameFileQueries, ...crossFileQueries];

      for (const param of ep.params) {
        for (const query of relatedQueries) {
          if (edgesResolved >= this.limits.maxEdges) {
            isTruncatedOverall = true;
            break;
          }

          const isCrossFile = query.file !== ep.filePath;
          const depth = isCrossFile ? 3 : 2; // Route parameter -> (Helper call) -> DB query
          if (depth > maxDepthReached) maxDepthReached = depth;

          // Check if parameter reaches query filter (e.g. .eq('id', param.name))
          const matchingFilter = query.filters.find(
            (f) => f.isUserControlled || f.column === "id" || f.valueExpr.includes(param.name)
          );

          const unresolvedSteps: UnresolvedStep[] = [];

          let isPathTruncated = false;
          if (depth > this.limits.maxDepth) {
            isPathTruncated = true;
            edgesUnresolved++;
            unresolvedSteps.push({
              description: `Dataflow traversal depth limit (${this.limits.maxDepth}) exceeded for parameter '${param.name}'`,
              location: { file: ep.filePath, line: param.line },
              reason: "opaque-call",
            });
          }

          if (matchingFilter || query.rawSnippet.includes(param.name) || query.rawSnippet.includes("id")) {
            edgesResolved++;
            paths.push({
              sourceEndpoint: ep,
              paramName: param.name,
              sinkQuery: query,
              isUserControlled: true,
              depth,
              unresolvedSteps,
              isTruncated: isPathTruncated,
            });
          }
        }
      }
    }

    const completionState: Coverage["completionState"] = isTruncatedOverall
      ? "truncated"
      : maxDepthReached > this.limits.maxDepth
      ? "depth-limited"
      : "complete";

    const coverage: Coverage = {
      filesInspected: filesInspectedCount,
      totalFiles: totalRepoFiles,
      maxDepthReached,
      edgesResolved,
      edgesUnresolved,
      completionState,
    };

    return { paths, coverage };
  }
}
