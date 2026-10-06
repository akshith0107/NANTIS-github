import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { handleReportFalsePositive } from "../src/routes/false-positive-route.js";
import { RequestContext } from "../src/routes/api-routes.js";
import { renderRulesCatalogPage } from "../src/routes/rules-catalog-page.js";
import { renderPrivacyPage } from "../src/routes/privacy-page.js";
import { encodeSession } from "../src/lib/session.js";
import { WebEnv } from "../src/lib/env.js";

const mockEnv: WebEnv = {
  NODE_ENV: "test",
  SESSION_SECRET: "test-secret-32-chars-long-123456",
  GITHUB_CLIENT_ID: "client_id",
  GITHUB_CLIENT_SECRET: "client_secret",
  GITHUB_WEBHOOK_SECRET: "webhook_secret",
  GITHUB_APP_ID: "123456",
  GITHUB_APP_PRIVATE_KEY: "fake_private_key",
  DATABASE_URL: "file:mem",
};

describe("Report False Positive, Rules Catalog & Privacy Pages", () => {
  beforeEach(() => {
    db.resetInMemoryData();
  });

  describe("Report False Positive Feature", () => {
    it("saves false positive report with ruleId, fingerprint, and userNote while storing ZERO source code", async () => {
      const user = await db.upsertUser({ github_user_id: 123, github_login: "testuser", avatar_url: "url" });
      const repo = await db.upsertRepository({ installation_id: "inst-1", github_repo_id: 456, name: "testrepo", full_name: "test/testrepo", private: false, default_branch: "main" });
      db.grantRepoAccess(user.id, repo.id);

      const validToken = encodeSession({ userId: user.id, githubUserId: user.github_user_id, githubLogin: user.github_login, createdAt: Date.now() }, mockEnv.SESSION_SECRET);

      const payload = {
        ruleId: "stripe-webhook-no-signature",
        fingerprint: "stripe-sig-fp-100",
        userNote: "Verified in custom middleware guard before handler execution.",
        // Extra source code attempt should NOT be stored or retained
        sourceCode: "function dangerousCode() { ... }",
      };

      const res = await handleReportFalsePositive(
        {
          sessionToken: validToken,
          cookies: { nantis_session: validToken },
          body: JSON.stringify(payload),
          headers: { "content-type": "application/json" },
        } as RequestContext,
        repo.id,
        mockEnv
      );

      expect(res.status).toBe(201);
      const resData = JSON.parse(res.body || "{}");
      expect(resData.ok).toBe(true);
      expect(resData.message).toContain("No source code was stored");

      const storedReports = await db.getFalsePositiveReports();
      expect(storedReports.length).toBe(1);
      const report = storedReports[0];

      expect(report.rule_id).toBe("stripe-webhook-no-signature");
      expect(report.fingerprint).toBe("stripe-sig-fp-100");
      expect(report.user_note).toBe("Verified in custom middleware guard before handler execution.");

      // Verify ZERO source code stored
      const reportJson = JSON.stringify(report);
      expect(reportJson).not.toContain("dangerousCode");
      expect(reportJson).not.toContain("sourceCode");
    });

    it("rejects false positive report when ruleId or fingerprint is missing", async () => {
      const user = await db.upsertUser({ github_user_id: 123, github_login: "testuser", avatar_url: "url" });
      const repo = await db.upsertRepository({ installation_id: "inst-1", github_repo_id: 456, name: "testrepo", full_name: "test/testrepo", private: false, default_branch: "main" });
      db.grantRepoAccess(user.id, repo.id);

      const validToken = encodeSession({ userId: user.id, githubUserId: user.github_user_id, githubLogin: user.github_login, createdAt: Date.now() }, mockEnv.SESSION_SECRET);

      const res = await handleReportFalsePositive(
        {
          sessionToken: validToken,
          body: JSON.stringify({ userNote: "Missing ruleId and fingerprint" }),
          headers: { "content-type": "application/json" },
        } as RequestContext,
        repo.id,
        mockEnv
      );

      expect(res.status).toBe(400);
      expect(res.body).toContain("Missing required fields");
    });

    it("NEGATIVE TEST: unauthenticated request to report false positive returns 404 and creates ZERO records", async () => {
      const repo = await db.upsertRepository({ installation_id: "inst-1", github_repo_id: 456, name: "testrepo", full_name: "test/testrepo", private: false, default_branch: "main" });

      const res = await handleReportFalsePositive(
        {
          body: JSON.stringify({ ruleId: "r1", fingerprint: "fp1", userNote: "Unauth" }),
          headers: { "content-type": "application/json" },
        } as RequestContext,
        repo.id,
        mockEnv
      );

      expect(res.status).toBe(404);

      const storedReports = await db.getFalsePositiveReports();
      expect(storedReports.length).toBe(0);
    });
  });

  describe("Public Rules Catalog Page", () => {
    it("renders public rules catalog with rule ID, title, whatsWrong, howStrangerCouldAbuseIt, and howToFixIt", async () => {
      const res = await renderRulesCatalogPage();

      expect(res.status).toBe(200);
      expect(res.headers?.["Content-Type"]).toContain("text/html");

      expect(res.body).toContain("Nantis Rules Catalog");
      expect(res.body).toContain("stripe-webhook-no-signature");
      expect(res.body).toContain("What's Wrong");
      expect(res.body).toContain("How a Stranger Could Abuse It");
      expect(res.body).toContain("How to Fix It");
    });
  });

  describe("Public Privacy Page", () => {
    it("renders plain-language privacy page listing stored items vs. never-stored items", async () => {
      const res = await renderPrivacyPage();

      expect(res.status).toBe(200);
      expect(res.headers?.["Content-Type"]).toContain("text/html");

      expect(res.body).toContain("Privacy Policy & Plain-English Data Guarantees");
      expect(res.body).toContain("What IS Stored in Nantis Databases");
      expect(res.body).toContain("What is NEVER Stored or Retained");

      // Verify explicit privacy statements
      expect(res.body).toContain("Source Code Files & Contents");
      expect(res.body).toContain("Secret Credentials & API Keys");
      expect(res.body).toContain("zero source code snippets are attached or retained");
    });
  });
});
