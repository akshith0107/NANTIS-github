import { Finding, ScanDiagnostic } from "@nantis/core";

export type JobStatus = "queued" | "cloning" | "scanning" | "done" | "failed";

export interface ScanJobPayload {
  scanId: string;
  repoId: string;
  installationId: number;
  requestedByUserId: string;
}

export interface ScanJobOptions {
  maxRepoSizeBytes: number; // Max allowed repository size in bytes
  maxJobTimeMs: number; // Max job execution time in milliseconds (timeout)
  maxRetries: number; // Max retry attempts for transient failures
  retryBackoffSeconds: number; // Base exponential backoff delay in seconds
  maxConcurrency: number; // Max concurrent jobs running on worker
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
  tokenId: string; // Token ID / reference, NEVER secret token string
  timestamp: string;
}

export interface DatabaseStateAdapter {
  updateScanStatus(scanId: string, status: JobStatus, errorMessage?: string): Promise<void>;
  getScanStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string }>;
  saveScanFindings?(scanId: string, findings: Finding[]): Promise<void>;
  saveScanDiagnostics?(scanId: string, diagnostics: ScanDiagnostic[]): Promise<void>;
  getScanDiagnostics?(scanId: string): Promise<ScanDiagnostic[]>;
  createAuditLog?(payload: AuditLogPayload): Promise<unknown>;
}
