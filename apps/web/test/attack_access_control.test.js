import { describe, expect, it, beforeEach } from "vitest";
import { db } from "../src/db/client.js";
import { encodeSession } from "../src/lib/session.js";
import { handleCreateScan, handleGetFinding, handleGetRepo, handleGetReport, handleGetScan, handleListFindings, handleListScans, } from "../src/routes/api-routes.js";
import { API_ROUTE_REGISTRY, auditRouteRegistry, formatRouteRegistryTable, } from "../src/routes/registry.js";
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
describe("Tenant Isolation & Access Control Attack Suite (apps/web)", () => {
    let userA;
    let userB;
    let repoA;
    let repoB;
    let scanB;
    let findingB;
    beforeEach(async () => {
        db.resetInMemoryData();
        // Setup User A & Repo A
        const uA = await db.upsertUser({
            github_user_id: 1001,
            github_login: "user_a",
            avatar_url: "https://github.com/user_a.png",
        });
        userA = {
            id: uA.id,
            token: encodeSession({ userId: uA.id, githubUserId: 1001, githubLogin: "user_a", createdAt: Date.now() }, TEST_ENV.SESSION_SECRET),
        };
        const instA = await db.upsertInstallation({
            installation_id: 5001,
            target_type: "User",
            target_id: 1001,
            account_name: "user_a",
        });
        const rA = await db.upsertRepository({
            installation_id: instA.id,
            github_repo_id: 9001,
            name: "repo-a-private",
            full_name: "user_a/repo-a-private",
            private: true,
            default_branch: "main",
        });
        repoA = { id: rA.id };
        db.grantRepoAccess(userA.id, repoA.id);
        // Setup User B & Repo B, Scan B, Finding B
        const uB = await db.upsertUser({
            github_user_id: 2002,
            github_login: "user_b",
            avatar_url: "https://github.com/user_b.png",
        });
        userB = {
            id: uB.id,
            token: encodeSession({ userId: uB.id, githubUserId: 2002, githubLogin: "user_b", createdAt: Date.now() }, TEST_ENV.SESSION_SECRET),
        };
        const instB = await db.upsertInstallation({
            installation_id: 5002,
            target_type: "User",
            target_id: 2002,
            account_name: "user_b",
        });
        const rB = await db.upsertRepository({
            installation_id: instB.id,
            github_repo_id: 9002,
            name: "repo-b-secret",
            full_name: "user_b/repo-b-secret",
            private: true,
            default_branch: "main",
        });
        repoB = { id: rB.id };
        db.grantRepoAccess(userB.id, repoB.id);
        const sB = await db.createScan({
            repository_id: repoB.id,
            status: "completed",
            trigger_type: "manual",
            commit_sha: "abc123def456",
            branch: "main",
            triggered_by_user_id: userB.id,
        });
        scanB = { id: sB.id };
        const fB = await db.createFinding({
            id: crypto.randomUUID(),
            scan_id: scanB.id,
            ruleId: "hardcoded-secret",
            title: "Hardcoded Stripe Secret",
            severity: "high",
            confidenceTier: "proven",
            file: "src/secret.ts",
            lineRange: { startLine: 10, endLine: 10 },
            evidenceChain: [],
            unresolvedSteps: [],
            explanation: "Secret key exposed",
            fingerprint: "fingerprint_b_123",
        });
        findingB = { db_id: fB.db_id };
    });
    it("ATTACK SCENARIO 1: User A guesses User B's resource IDs (repo, scan, finding, report) -> All denied with 404", async () => {
        const reqA = { sessionToken: userA.token };
        const resRepo = await handleGetRepo(reqA, repoB.id, TEST_ENV);
        expect(resRepo.status).toBe(404);
        expect(resRepo.body).toBe('{"error":"Not found"}');
        const resListScans = await handleListScans(reqA, repoB.id, TEST_ENV);
        expect(resListScans.status).toBe(404);
        expect(resListScans.body).toBe('{"error":"Not found"}');
        const resCreateScan = await handleCreateScan(reqA, repoB.id, TEST_ENV);
        expect(resCreateScan.status).toBe(404);
        expect(resCreateScan.body).toBe('{"error":"Not found"}');
        const resGetScan = await handleGetScan(reqA, scanB.id, TEST_ENV);
        expect(resGetScan.status).toBe(404);
        expect(resGetScan.body).toBe('{"error":"Not found"}');
        const resListFindings = await handleListFindings(reqA, scanB.id, TEST_ENV);
        expect(resListFindings.status).toBe(404);
        expect(resListFindings.body).toBe('{"error":"Not found"}');
        const resGetFinding = await handleGetFinding(reqA, findingB.db_id, TEST_ENV);
        expect(resGetFinding.status).toBe(404);
        expect(resGetFinding.body).toBe('{"error":"Not found"}');
        const resGetReport = await handleGetReport(reqA, repoB.id, TEST_ENV);
        expect(resGetReport.status).toBe(404);
        expect(resGetReport.body).toBe('{"error":"Not found"}');
    });
    it("ATTACK SCENARIO 2: Unauthenticated requests to every protected API route -> All denied with 404", async () => {
        const reqUnauth = {}; // No session token or cookie
        for (const route of API_ROUTE_REGISTRY) {
            let targetId = repoA.id;
            if (route.targetResource === "scan")
                targetId = scanB.id;
            if (route.targetResource === "finding")
                targetId = findingB.db_id;
            const res = await route.handler(reqUnauth, targetId, TEST_ENV);
            expect(res.status).toBe(404);
            expect(res.body).toBe('{"error":"Not found"}');
        }
    });
    it("ATTACK SCENARIO 3: User removed from installation loses repo access immediately", async () => {
        const reqA = { sessionToken: userA.token };
        // 1. Initial access confirmed
        const resInitial = await handleGetRepo(reqA, repoA.id, TEST_ENV);
        expect(resInitial.status).toBe(200);
        // 2. Revoke access (simulate GitHub membership removal webhook / access revocation)
        db.revokeRepoAccess(userA.id, repoA.id);
        // 3. Immediate re-check must fail with 404
        const resRevoked = await handleGetRepo(reqA, repoA.id, TEST_ENV);
        expect(resRevoked.status).toBe(404);
        expect(resRevoked.body).toBe('{"error":"Not found"}');
    });
    it("ATTACK SCENARIO 4: ID-enumeration protection: responses for 'not yours' and 'does not exist' are identical", async () => {
        const reqA = { sessionToken: userA.token };
        const nonExistentRepoId = "00000000-0000-0000-0000-000000000000";
        // Request existing repo owned by User B ("not yours")
        const resNotYours = await handleGetRepo(reqA, repoB.id, TEST_ENV);
        // Request non-existent repo ("does not exist")
        const resDoesNotExist = await handleGetRepo(reqA, nonExistentRepoId, TEST_ENV);
        // Assert responses are bit-for-bit identical to prevent enumeration attacks
        expect(resNotYours.status).toBe(resDoesNotExist.status);
        expect(resNotYours.status).toBe(404);
        expect(resNotYours.headers["Content-Type"]).toBe(resDoesNotExist.headers["Content-Type"]);
        expect(resNotYours.headers["Content-Type"]).toBe("application/json");
        expect(resNotYours.body).toBe(resDoesNotExist.body);
        expect(resNotYours.body).toBe('{"error":"Not found"}');
    });
    it("AUDIT CHECK: Every API route is registered and uses assertRepoAccess (Fails suite if any route lacks it)", () => {
        const tableOutput = formatRouteRegistryTable();
        console.log("\n================ API ROUTE ACCESS CONTROL MATRIX ================\n");
        console.log(tableOutput);
        console.log("\n=================================================================\n");
        const auditResult = auditRouteRegistry();
        if (!auditResult.passed) {
            console.error("AUDIT FAILED: Missing access checks:", auditResult.errors);
        }
        expect(auditResult.passed).toBe(true);
        expect(auditResult.totalRoutes).toBeGreaterThan(0);
        expect(auditResult.errors.length).toBe(0);
    });
});
//# sourceMappingURL=attack_access_control.test.js.map