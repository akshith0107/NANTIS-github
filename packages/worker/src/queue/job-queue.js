import { DEFAULT_JOB_OPTIONS, processScanJob } from "../processor/scan-processor.js";
export class InMemoryDbAdapter {
  scanStatuses = new Map();
  scanFindings = new Map();
  auditLogs = [];
  async updateScanStatus(scanId, status, errorMessage) {
    this.scanStatuses.set(scanId, { status, errorMessage });
  }
  async getScanStatus(scanId) {
    return (
      this.scanStatuses.get(scanId) || {
        status: "queued",
      }
    );
  }
  async saveScanFindings(scanId, findings) {
    this.scanFindings.set(scanId, findings);
  }
  async getScanFindings(scanId) {
    return this.scanFindings.get(scanId) || [];
  }
  async createAuditLog(payload) {
    this.auditLogs.push(payload);
  }
  async getAuditLogs() {
    return [...this.auditLogs];
  }
  clear() {
    this.scanStatuses.clear();
    this.scanFindings.clear();
    this.auditLogs = [];
  }
}
export class ScanJobQueue {
  options;
  dbAdapter;
  jobStates = new Map();
  activeConcurrency = 0;
  queue = [];
  constructor(dbAdapter = new InMemoryDbAdapter(), options = {}) {
    this.dbAdapter = dbAdapter;
    this.options = { ...DEFAULT_JOB_OPTIONS, ...options };
  }
  async enqueueJob(payload, optionsOverride = {}, customFetcher) {
    const now = new Date().toISOString();
    const initialState = {
      scanId: payload.scanId,
      repoId: payload.repoId,
      installationId: payload.installationId,
      requestedByUserId: payload.requestedByUserId,
      status: "queued",
      currentRetry: 0,
      startedAt: now,
      updatedAt: now,
    };
    this.jobStates.set(payload.scanId, initialState);
    await this.dbAdapter.updateScanStatus(payload.scanId, "queued");
    this.queue.push({ payload, optionsOverride, customFetcher });
    setImmediate(() => this.processNextQueueItem());
    return initialState;
  }
  async processNextQueueItem() {
    if (this.activeConcurrency >= this.options.maxConcurrency || this.queue.length === 0) {
      return;
    }
    const item = this.queue.shift();
    if (!item) return;
    this.activeConcurrency++;
    const mergedOpts = { ...this.options, ...item.optionsOverride };
    let attempt = 0;
    const executeAttempt = async () => {
      attempt++;
      const result = await processScanJob(
        item.payload,
        this.dbAdapter,
        mergedOpts,
        item.customFetcher
      );
      result.state.currentRetry = attempt;
      this.jobStates.set(item.payload.scanId, result.state);
      if (
        result.state.status === "failed" &&
        attempt <= mergedOpts.maxRetries &&
        result.state.errorMessage !== "Repository size exceeds maximum allowed scan limit"
      ) {
        // Retry with backoff
        const backoffMs = mergedOpts.retryBackoffSeconds * 1000 * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
        return executeAttempt();
      }
    };
    try {
      await executeAttempt();
    } finally {
      this.activeConcurrency--;
      setImmediate(() => this.processNextQueueItem());
    }
  }
  async getJobStatus(scanId) {
    return this.dbAdapter.getScanStatus(scanId);
  }
  getJobState(scanId) {
    return this.jobStates.get(scanId);
  }
  async waitForJobCompletion(scanId, timeoutMs = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const state = this.getJobState(scanId);
      const dbStatus = await this.getJobStatus(scanId);
      if (
        state &&
        (state.status === "done" ||
          (state.status === "failed" && state.currentRetry > this.options.maxRetries))
      ) {
        if (dbStatus && (dbStatus.status === "done" || dbStatus.status === "failed")) {
          return state;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`waitForJobCompletion timed out for scan ${scanId}`);
  }
  getActiveConcurrencyCount() {
    return this.activeConcurrency;
  }
  getPendingQueueLength() {
    return this.queue.length;
  }
}
//# sourceMappingURL=job-queue.js.map
