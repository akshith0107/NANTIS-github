/**
 * Janitor process: Scans the scan workspace directory and deletes any stale,
 * orphaned temporary folders that exceed maxAgeMs (default: 10 minutes).
 * Guarantees zero disk exhaustion over time from crashed or aborted jobs.
 */
export declare function cleanStaleWorkspaces(
  baseTempDir: string,
  maxAgeMs?: number
): Promise<number>;
//# sourceMappingURL=stale-cleanup.d.ts.map
