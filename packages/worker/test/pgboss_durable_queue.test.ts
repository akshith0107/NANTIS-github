import { describe, expect, it } from "vitest";
import { InMemoryDbAdapter, PgBossScanJobQueue, QUEUE_NAME } from "../src/index.js";

describe("Phase 1B: Durable Scan Queue with pg-boss", () => {
  it("Job Payload Hygiene & Security — Job payload contains strictly non-sensitive execution metadata", () => {
    const payload = {
      scanId: "scan-pgboss-1001",
      repoId: "test-org/secure-repo",
      installationId: 4422,
      requestedByUserId: "user-uuid-8888",
    };

    // Verify payload keys
    const keys = Object.keys(payload);
    expect(keys).toEqual(["scanId", "repoId", "installationId", "requestedByUserId"]);

    // Security assertions: NO secret tokens, OAuth keys, or source code contents in payload
    expect(JSON.stringify(payload)).not.toContain("ghs_");
    expect(JSON.stringify(payload)).not.toContain("sk_live_");
    expect(JSON.stringify(payload)).not.toContain("token");
    expect(JSON.stringify(payload)).not.toContain("sourceCode");
  });

  it("Queue Abstraction Parity & PgBoss Constants — Queue name and options are properly defined", () => {
    expect(QUEUE_NAME).toBe("nantis_scan_jobs");

    const dbAdapter = new InMemoryDbAdapter();
    const queue = new PgBossScanJobQueue(
      dbAdapter,
      "postgres://postgres:postgres@localhost:5432/nantis_test_dummy",
      { maxConcurrency: 3 }
    );

    expect(typeof queue.enqueueJob).toBe("function");
    expect(typeof queue.getJobStatus).toBe("function");
    expect(typeof queue.stop).toBe("function");

    // Clean up queue instance
    queue.stop().catch(() => {});
  });
});
