import { Finding } from "@nantis/core";
import { DatabaseStateAdapter, ScanJobOptions, ScanJobPayload, ScanJobState } from "../types.js";
export declare const DEFAULT_JOB_OPTIONS: ScanJobOptions;
/**
 * Sanitize error messages to ensure NO stack traces, internal file system paths,
 * or secret strings are ever leaked to end users in UI scan status responses.
 */
export declare function sanitizeUserFacingErrorMessage(err: unknown): string;
export declare function processScanJob(
  payload: ScanJobPayload,
  dbAdapter: DatabaseStateAdapter,
  options?: Partial<ScanJobOptions>,
  customSourceFetcher?: (targetDir: string) => Promise<void>
): Promise<{
  state: ScanJobState;
  findings: Finding[];
}>;
//# sourceMappingURL=scan-processor.d.ts.map
