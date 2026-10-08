import { PgBoss } from "pg-boss";
import { DEFAULT_JOB_OPTIONS, processScanJob } from "../processor/scan-processor.js";
import {
  DatabaseStateAdapter,
  JobStatus,
  ScanJobOptions,
  ScanJobPayload,
  ScanJobState,
} from "../types.js";

export const QUEUE_NAME = "nantis_scan_jobs";

export class PgBossScanJobQueue {
  private boss: PgBoss;
  private dbAdapter: DatabaseStateAdapter;
  private options: ScanJobOptions;
  private isStarted = false;
  private activeConcurrency = 0;
  private jobStates = new Map<string, ScanJobState>();
  private customFetchers = new Map<string, (dir: string) => Promise<void>>();

  constructor(
    dbAdapter: DatabaseStateAdapter,
    connectionStringOrConfig?: string | object,
    options: Partial<ScanJobOptions> = {}
  ) {
    this.dbAdapter = dbAdapter;
    this.options = { ...DEFAULT_JOB_OPTIONS, ...options };

    const dbConfig =
      connectionStringOrConfig ||
      process.env.DATABASE_URL ||
      "postgres://postgres:postgres@localhost:5432/nantis";

    if (typeof dbConfig === "string") {
      this.boss = new PgBoss(dbConfig);
    } else {
      this.boss = new PgBoss(dbConfig as Record<string, unknown>);
    }

    this.setupProcessListeners();
  }

  async start(): Promise<void> {
    if (this.isStarted) return;
    await this.boss.start();
    this.isStarted = true;

    // Register worker handler with pg-boss
    await this.boss.work(
      QUEUE_NAME,
      { localConcurrency: this.options.maxConcurrency },
      async (jobs) => {
        const job = jobs[0];
        if (!job) return;
        this.activeConcurrency++;
        const payload = job.data as ScanJobPayload;
        const customFetcher = this.customFetchers.get(payload.scanId);

        console.log(`[Worker Log] [Job Enqueued/Started] scanId=${payload.scanId} repoId=${payload.repoId} jobId=${job.id}`);

        try {
          const result = await processScanJob(
            payload,
            this.dbAdapter,
            this.options,
            customFetcher
          );

          this.jobStates.set(payload.scanId, result.state);

          if (result.state.status === "failed") {
            console.warn(`[Worker Log] [Job Failed] scanId=${payload.scanId} repoId=${payload.repoId} reason="${result.state.errorMessage}"`);
          } else {
            console.log(`[Worker Log] [Job Completed] scanId=${payload.scanId} repoId=${payload.repoId} status=${result.state.status}`);
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`[Worker Log] [Job Error] scanId=${payload.scanId} error=${msg}`);
          throw err;
        } finally {
          this.activeConcurrency--;
          this.customFetchers.delete(payload.scanId);
        }
      }
    );
  }

  async enqueueJob(
    payload: ScanJobPayload,
    optionsOverride: Partial<ScanJobOptions> = {},
    customFetcher?: (dir: string) => Promise<void>
  ): Promise<ScanJobState> {
    if (!this.isStarted) {
      await this.start();
    }

    const mergedOptions = { ...this.options, ...optionsOverride };
    const now = new Date().toISOString();
    const initialState: ScanJobState = {
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

    if (customFetcher) {
      this.customFetchers.set(payload.scanId, customFetcher);
    }

    const bossJobOptions = {
      retryLimit: mergedOptions.maxRetries,
      retryDelay: mergedOptions.retryBackoffSeconds,
      retryBackoff: true,
      expireInSeconds: Math.ceil(mergedOptions.maxJobTimeMs / 1000) + 240, // 5 minutes (well above 60s execution window)
      singletonKey: payload.scanId, // Enforce job idempotency via pg-boss singleton key
    };

    const jobId = await this.boss.send(QUEUE_NAME, payload, bossJobOptions);
    console.log(`[Worker Log] [Job Enqueued] scanId=${payload.scanId} repoId=${payload.repoId} pgBossJobId=${jobId}`);

    return initialState;
  }

  async getJobStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string } | null> {
    return this.dbAdapter.getScanStatus(scanId);
  }

  getJobState(scanId: string): ScanJobState | undefined {
    return this.jobStates.get(scanId);
  }

  async waitForJobCompletion(scanId: string, timeoutMs = 10000): Promise<ScanJobState> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const state = this.getJobState(scanId);
      const dbStatus = await this.getJobStatus(scanId);
      if (
        (state && (state.status === "done" || state.status === "failed")) ||
        (dbStatus && (dbStatus.status === "done" || dbStatus.status === "failed"))
      ) {
        return (
          state || {
            scanId,
            repoId: "",
            installationId: 1,
            requestedByUserId: "",
            status: dbStatus?.status || "done",
            currentRetry: 0,
            errorMessage: dbStatus?.errorMessage,
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          }
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`waitForJobCompletion timed out for scan ${scanId}`);
  }

  getActiveConcurrencyCount(): number {
    return this.activeConcurrency;
  }

  getPendingQueueLength(): number {
    return 0; // Managed persistently inside PostgreSQL pg-boss queue tables
  }

  async stop(): Promise<void> {
    if (!this.isStarted) return;
    await this.boss.stop();
    this.isStarted = false;
    console.log("[Worker Log] PgBoss queue stopped gracefully.");
  }

  private setupProcessListeners() {
    const shutdown = async () => {
      if (this.isStarted) {
        console.log("[Worker Log] Shutdown signal received. Stopping PgBoss scan queue...");
        await this.stop().catch(() => {});
      }
    };

    process.once("SIGTERM", shutdown);
    process.once("SIGINT", shutdown);
  }
}
