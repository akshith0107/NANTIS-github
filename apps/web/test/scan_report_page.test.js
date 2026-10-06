import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { encodeSession } from "../src/lib/session.js";
import { handleGetScanReport } from "../src/routes/api-routes.js";
import { renderScanReportPage } from "../src/routes/scan-report-page.js";
const TEST_ENV = {
    GITHUB_CLIENT_ID: "fake_client_id_123",
    GITHUB_CLIENT_SECRET: "fake_client_secret_abc",
    GITHUB_APP_ID: "99999",
    GITHUB_APP_PRIVATE_KEY: "fake_private_key",
    GITHUB_WEBHOOK_SECRET: "fake_webhook_secret_xyz",
    SESSION_SECRET: "super_secret_32_characters_key_here",
    DATABASE_URL: "postgresql://localhost:5432/test",
    NODE_ENV: "test",
};
describe("Plain Scan Report Page & Access Control (apps/web)", () => {
    beforeEach(async () => {
        db.resetInMemoryData();
    });
    it("should render scan report page with findings grouped by confidence tier and introduced-in info", async () => {
        // Setup User & Repo
        const alice = await db.upsertUser({
            github_user_id: 101,
            github_login: "alice",
            avatar_url: "https://github.com/alice.png",
        });
        const inst = await db.upsertInstallation({
            installation_id: 301,
            target_type: "User",
            target_id: 101,
            account_name: "alice",
        });
        const repo = await db.upsertRepository({
            installation_id: inst.id,
            github_repo_id: 801,
            name: "alice-service",
            full_name: "alice/alice-service",
            private: true,
            default_branch: "main",
        });
        db.grantRepoAccess(alice.id, repo.id);
        const aliceToken = encodeSession({ userId: alice.id, githubUserId: 101, githubLogin: "alice", createdAt: Date.now() }, TEST_ENV.SESSION_SECRET);
        const scan = await db.createScan({
            repository_id: repo.id,
            status: "completed",
            trigger_type: "manual",
            commit_sha: "a1b2c3d4",
            branch: "main",
            triggered_by_user_id: alice.id,
        });
        // Add Proven finding with introducedIn git commit metadata
        await db.createFinding({
            id: crypto.randomUUID(),
            scan_id: scan.id,
            ruleId: "hardcoded-secret",
            title: "Hardcoded Stripe Test Key",
            severity: "high",
            confidenceTier: "proven",
            file: "src/stripe.ts",
            lineRange: { startLine: 5, endLine: 5 },
            explanation: "Found hardcoded Stripe test key in source file.",
            evidenceChain: [
                {
                    kind: "sink",
                    file: "src/stripe.ts",
                    line: 5,
                    maskedSnippet: 'export const key = "[REDACTED_SECRET]";',
                    confidence: "high",
                    note: "Stripe test key detected",
                },
            ],
            unresolvedSteps: [],
            fingerprint: "fp_proven_1",
            introducedIn: {
                commit: "a1b2c3d4",
                pr: 42,
                author: "Alice Developer <alice@example.com>",
                date: "2026-10-04T12:00:00Z",
                confidence: "high",
                confidenceReason: "Exact git blame match",
            },
        });
        // Add Hygiene finding
        await db.createFinding({
            id: crypto.randomUUID(),
            scan_id: scan.id,
            ruleId: "cookie-missing-flags",
            title: "Session Cookie Missing Secure Flag",
            severity: "low",
            confidenceTier: "hygiene",
            file: "src/auth.ts",
            lineRange: { startLine: 12, endLine: 12 },
            explanation: "Session cookie set without Secure flag.",
            evidenceChain: [
                {
                    kind: "config",
                    file: "src/auth.ts",
                    line: 12,
                    maskedSnippet: 'res.setHeader("Set-Cookie", "session=xyz");',
                    confidence: "medium",
                    note: "Missing Secure flag",
                },
            ],
            unresolvedSteps: [],
            fingerprint: "fp_hygiene_1",
            introducedIn: {
                confidence: "medium",
                confidenceReason: "Uncommitted working tree changes",
            },
        });
        // Render report page
        const res = await renderScanReportPage({ sessionToken: aliceToken }, scan.id, TEST_ENV);
        expect(res.status).toBe(200);
        expect(res.body).toContain("Scan Security Report for alice/alice-service");
        // Grouping by confidence tier headers
        expect(res.body).toContain("Proven Confidence (1)");
        expect(res.body).toContain("Hygiene (1)");
        // Details: severity, explanation, evidence chain, introduced-in
        expect(res.body).toContain("[HIGH] Hardcoded Stripe Test Key");
        expect(res.body).toContain("Found hardcoded Stripe test key in source file.");
        expect(res.body).toContain("[SINK]");
        expect(res.body).toContain("[REDACTED_SECRET]");
        expect(res.body).toContain("Commit: a1b2c3d4");
        expect(res.body).toContain("PR #42");
        expect(res.body).toContain("Alice Developer <alice@example.com>");
        // Check no fix buttons exist
        expect(res.body).not.toContain("<button>Fix</button>");
        expect(res.body).not.toContain('type="submit"');
        // Also test API route handleGetScanReport
        const apiRes = await handleGetScanReport({ sessionToken: aliceToken }, scan.id, TEST_ENV);
        expect(apiRes.status).toBe(200);
        const apiJson = JSON.parse(apiRes.body);
        expect(apiJson.report.findingsByConfidenceTier.proven.length).toBe(1);
        expect(apiJson.report.findingsByConfidenceTier.hygiene.length).toBe(1);
    });
    it("should render compliant zero-findings message when scan detects no issues", async () => {
        const bob = await db.upsertUser({ github_user_id: 202, github_login: "bob", avatar_url: "b" });
        const inst = await db.upsertInstallation({
            installation_id: 302,
            target_type: "User",
            target_id: 202,
            account_name: "bob",
        });
        const repo = await db.upsertRepository({
            installation_id: inst.id,
            github_repo_id: 802,
            name: "bob-clean",
            full_name: "bob/bob-clean",
            private: false,
            default_branch: "main",
        });
        db.grantRepoAccess(bob.id, repo.id);
        const bobToken = encodeSession({ userId: bob.id, githubUserId: 202, githubLogin: "bob", createdAt: Date.now() }, TEST_ENV.SESSION_SECRET);
        const scan = await db.createScan({
            repository_id: repo.id,
            status: "completed",
            trigger_type: "manual",
            commit_sha: "clean123",
            branch: "main",
            triggered_by_user_id: bob.id,
        });
        const res = await renderScanReportPage({ sessionToken: bobToken }, scan.id, TEST_ENV);
        expect(res.status).toBe(200);
        // MANDATORY WORDING CHECK: Must contain "no issues found in the checks we run"
        expect(res.body).toContain("no issues found in the checks we run");
        // ABSOLUTE FORBIDDEN WORDS CHECK: Must NEVER contain "secure", "safe", or "production ready"
        const lowerBody = (res.body || "").toLowerCase();
        expect(lowerBody).not.toContain("secure");
        expect(lowerBody).not.toContain("safe");
        expect(lowerBody).not.toContain("production ready");
    });
    it("should enforce tenant isolation and deny unauthorized access to scan report page (404)", async () => {
        const alice = await db.upsertUser({
            github_user_id: 101,
            github_login: "alice",
            avatar_url: "a",
        });
        const bob = await db.upsertUser({ github_user_id: 202, github_login: "bob", avatar_url: "b" });
        const inst = await db.upsertInstallation({
            installation_id: 301,
            target_type: "User",
            target_id: 101,
            account_name: "alice",
        });
        const repo = await db.upsertRepository({
            installation_id: inst.id,
            github_repo_id: 801,
            name: "alice-app",
            full_name: "alice/alice-app",
            private: true,
            default_branch: "main",
        });
        db.grantRepoAccess(alice.id, repo.id);
        const scan = await db.createScan({
            repository_id: repo.id,
            status: "completed",
            trigger_type: "manual",
            commit_sha: "sha123",
            branch: "main",
            triggered_by_user_id: alice.id,
        });
        const bobToken = encodeSession({ userId: bob.id, githubUserId: 202, githubLogin: "bob", createdAt: Date.now() }, TEST_ENV.SESSION_SECRET);
        const res = await renderScanReportPage({ sessionToken: bobToken }, scan.id, TEST_ENV);
        // Default DENY access check: returns 404 for unauthorized user
        expect(res.status).toBe(404);
        expect(res.body).toContain("404 Not Found");
    });
});
//# sourceMappingURL=scan_report_page.test.js.map