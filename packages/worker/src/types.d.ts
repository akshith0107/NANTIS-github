import { Finding } from "@nantis/core";
export type JobStatus = "queued" | "cloning" | "scanning" | "done" | "failed";
export interface ScanJobPayload {
  scanId: string;
  repoId: string;
  installationId: number;
  requestedByUserId: string;
}
export interface ScanJobOptions {
  maxRepoSizeBytes: number;
  maxJobTimeMs: number;
  maxRetries: number;
  retryBackoffSeconds: number;
  maxConcurrency: number;
}
export interface ScanJobState {
  scanId: string;
  repoId: string;
  installationId: number;
  requestedByUserId: string;
  status: JobStatus;
  currentRetry: number;
  errorMessage?: string;
  startedAt: string;
  updatedAt: string;
  tempPath?: string;
}
export interface AuditLogPayload {
  userId: string;
  repoId: string;
  action: string;
  tokenId: string;
  timestamp: string;
}
export interface DatabaseStateAdapter {
  updateScanStatus(scanId: string, status: JobStatus, errorMessage?: string): Promise<void>;
  getScanStatus(scanId: string): Promise<{
    status: JobStatus;
    errorMessage?: string;
  }>;
  saveScanFindings?(scanId: string, findings: Finding[]): Promise<void>;
  createAuditLog?(payload: AuditLogPayload): Promise<unknown>;
}
//# sourceMappingURL=types.d.ts.map
