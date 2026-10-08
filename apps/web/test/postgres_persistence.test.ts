import { describe, expect, it } from "vitest";
import { createDatabaseClient, DatabaseClient, PostgresDatabaseClient } from "../src/db/client.js";

describe("Phase 1A: PostgreSQL Persistence Foundation", () => {
  it("Explicit Production Invariant — Fails explicitly when DATABASE_URL is missing in production mode", () => {
    const origEnv = process.env.NODE_ENV;
    const origUrl = process.env.DATABASE_URL;

    try {
      process.env.NODE_ENV = "production";
      delete process.env.DATABASE_URL;

      expect(() => createDatabaseClient()).toThrowError(
        "CRITICAL DATABASE CONFIGURATION ERROR: Production mode requires DATABASE_URL to be set"
      );
    } finally {
      process.env.NODE_ENV = origEnv;
      process.env.DATABASE_URL = origUrl;
    }
  });

  it("Database Interface Parity — DatabaseClient and PostgresDatabaseClient share identical domain contracts", () => {
    const memoryClient = new DatabaseClient();
    const pgClient = new PostgresDatabaseClient({
      connectionString: "postgres://postgres:postgres@localhost:5432/nantis_test_dummy",
    });

    // Verify key domain methods exist on both instances
    const domainMethods = [
      "upsertUser",
      "getUserById",
      "upsertRepository",
      "createScan",
      "updateScanStatus",
      "saveScanFindings",
      "saveScanDiagnostics",
      "getScanDiagnostics",
      "grantRepoAccess",
      "checkUserRepoAccess",
      "createAuditLog",
      "setFindingLabel",
      "saveUserRepoSnapshot",
      "checkAnonymousRateLimit",
    ] as const;

    for (const method of domainMethods) {
      expect(typeof (memoryClient as unknown as Record<string, unknown>)[method]).toBe("function");
      expect(typeof (pgClient as unknown as Record<string, unknown>)[method]).toBe("function");
    }

    // Clean up dummy pg pool instance
    pgClient.close().catch(() => {});
  });

  it("Domain State Isolation & Snapshot Behavior — Memory client preserves domain invariants", async () => {
    const client = new DatabaseClient();

    const user = await client.upsertUser({
      github_user_id: 1001,
      github_login: "test-dev-user",
      avatar_url: "https://avatar.com/1",
    });

    const repo = await client.upsertRepository({
      installation_id: "inst-1",
      github_repo_id: 2002,
      name: "test-repo",
      full_name: "test-dev-user/test-repo",
      private: true,
      default_branch: "main",
    });

    await client.grantRepoAccess(user.id, repo.id);
    const hasAccess = await client.checkUserRepoAccess(user.id, repo.id);
    expect(hasAccess).toBe(true);

    const scan = await client.createScan({
      repository_id: repo.id,
      status: "queued",
      trigger_type: "manual",
      commit_sha: "abc1234",
      branch: "main",
      triggered_by_user_id: user.id,
    });

    await client.updateScanStatus(scan.id, "done");
    const updated = await client.getScanById(scan.id);
    expect(updated?.status).toBe("done");

    // Add diagnostics
    await client.saveScanDiagnostics(scan.id, [
      {
        kind: "detector_error",
        detectorId: "detectSecrets",
        detectorName: "Secrets Detector",
        message: "Analysis completed with warnings: [REDACTED_PATH]",
        fatal: false,
        timestamp: new Date().toISOString(),
      },
    ]);

    const diagnostics = await client.getScanDiagnostics(scan.id);
    expect(diagnostics.length).toBe(1);
    expect(diagnostics[0].detectorId).toBe("detectSecrets");
  });
});
