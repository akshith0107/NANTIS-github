import { Finding } from "@nantis/core";
import {
  AuditLogPayload,
  DatabaseStateAdapter,
  JobStatus,
  ScanJobOptions,
  ScanJobPayload,
  ScanJobState,
} from "../types.js";
export declare class InMemoryDbAdapter implements DatabaseStateAdapter {
  private scanStatuses;
  private scanFindings;
  private auditLogs;
  updateScanStatus(scanId: string, status: JobStatus, errorMessage?: string): Promise<void>;
  getScanStatus(scanId: string): Promise<{
    status: JobStatus;
    errorMessage?: string;
  }>;
  saveScanFindings(scanId: string, findings: Finding[]): Promise<void>;
  getScanFindings(scanId: string): Promise<Finding[]>;
  createAuditLog(payload: AuditLogPayload): Promise<void>;
  getAuditLogs(): Promise<AuditLogPayload[]>;
  clear(): void;
}
export declare class ScanJobQueue {
  private options;
  private dbAdapter;
  private jobStates;
  private activeConcurrency;
  private queue;
  constructor(dbAdapter?: DatabaseStateAdapter, options?: Partial<ScanJobOptions>);
  enqueueJob(
    payload: ScanJobPayload,
    optionsOverride?: Partial<ScanJobOptions>,
    customFetcher?: (dir: string) => Promise<void>
  ): Promise<ScanJobState>;
  private processNextQueueItem;
  getJobStatus(scanId: string): Promise<{
    status: JobStatus;
    errorMessage?: string;
  } | null>;
  getJobState(scanId: string): ScanJobState | undefined;
  waitForJobCompletion(scanId: string, timeoutMs?: number): Promise<ScanJobState>;
  getActiveConcurrencyCount(): number;
  getPendingQueueLength(): number;
}
//# sourceMappingURL=job-queue.d.ts.map
