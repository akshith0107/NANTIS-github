import { describe, expect, it, beforeEach } from "vitest";
import { validateWebEnv } from "../src/lib/env.js";
import { buildSessionCookieOptions, encodeSession, generateCsrfStateToken, serializeCookie, } from "../src/lib/session.js";
import { handleAuthLogin } from "../src/routes/auth-login.js";
import { handleAuthCallback } from "../src/routes/auth-callback.js";
import { db } from "../src/db/client.js";
const TEST_ENV = {
    GITHUB_CLIENT_ID: "fake_client_id_123",
    GITHUB_CLIENT_SECRET: "fake_client_secret_abc",
    GITHUB_APP_ID: "99999",
    GITHUB_APP_PRIVATE_KEY: "fake_private_key",
    GITHUB_WEBHOOK_SECRET: "fake_webhook_secret_xyz",
    SESSION_SECRET: "super_secret_32_characters_key_here",
    DATABASE_URL: "postgresql://localhost:5432/test",
    NODE_ENV: "production",
};
describe("Authentication & Session Security (apps/web)", () => {
    beforeEach(() => {
        db.resetInMemoryData();
    });
    it("should fail fast during startup check if required environment variables are missing", () => {
        expect(() => validateWebEnv({})).toThrow(/Missing required environment variable/);
        expect(() => validateWebEnv({ GITHUB_CLIENT_ID: "123" })).toThrow(/Missing required environment variable/);
    });
    it("should configure session cookie with HttpOnly, Secure, and SameSite=Lax flags", () => {
        const sessionToken = encodeSession({
            userId: "user_123",
            githubUserId: 45678,
            githubLogin: "octocat",
            createdAt: Date.now(),
        }, TEST_ENV.SESSION_SECRET);
        const cookieOpts = buildSessionCookieOptions(sessionToken, true);
        expect(cookieOpts.httpOnly).toBe(true);
        expect(cookieOpts.secure).toBe(true);
        expect(cookieOpts.sameSite).toBe("Lax");
        expect(cookieOpts.path).toBe("/");
        const cookieHeader = serializeCookie(cookieOpts);
        expect(cookieHeader).toContain("HttpOnly");
        expect(cookieHeader).toContain("Secure");
        expect(cookieHeader).toContain("SameSite=Lax");
    });
    it("should initiate OAuth login with CSRF state token and HttpOnly CSRF cookie", () => {
        const res = handleAuthLogin(TEST_ENV);
        expect(res.status).toBe(302);
        expect(res.headers.Location).toContain("https://github.com/login/oauth/authorize");
        expect(res.headers.Location).toContain("state=");
        expect(res.headers["Set-Cookie"]).toContain("HttpOnly");
        expect(res.headers["Set-Cookie"]).toContain("nantis_csrf_state=");
    });
    it("should reject OAuth callback with HTTP 400 when CSRF state token is missing or mismatched", async () => {
        const res = await handleAuthCallback({
            code: "fake_oauth_code",
            state: "invalid_state_token",
            cookies: { nantis_csrf_state: "expected_state_token" },
        }, TEST_ENV);
        expect(res.status).toBe(400);
        expect(res.body).toContain("Invalid CSRF state token");
        const logs = await db.getAuditLogs();
        expect(logs.some((l) => l.action === "user.login_failed")).toBe(true);
    });
    it("should complete OAuth flow, set secure session cookie, and NEVER store user access token", async () => {
        const csrfState = generateCsrfStateToken();
        // Mock fetch for GitHub API endpoints
        const fakeFetch = async (url) => {
            if (String(url).includes("/access_token")) {
                return new Response(JSON.stringify({ access_token: "gho_FAKE_USER_ACCESS_TOKEN_999" }), {
                    status: 200,
                    headers: { "Content-Type": "application/json" },
                });
            }
            if (String(url).includes("/user")) {
                return new Response(JSON.stringify({
                    id: 12345,
                    login: "testuser",
                    avatar_url: "https://github.com/images/error/octocat_happy.gif",
                }), { status: 200, headers: { "Content-Type": "application/json" } });
            }
            return new Response(null, { status: 404 });
        };
        const res = await handleAuthCallback({
            code: "valid_oauth_code",
            state: csrfState,
            cookies: { nantis_csrf_state: csrfState },
        }, TEST_ENV, fakeFetch);
        expect(res.status).toBe(302);
        expect(res.headers.Location).toBe("/");
        expect(res.headers["Set-Cookie"]).toContain("nantis_session=");
        expect(res.headers["Set-Cookie"]).toContain("HttpOnly");
        expect(res.headers["Set-Cookie"]).toContain("Secure");
        // Verify user in database
        const dbUser = await db.getUserByGithubId(12345);
        expect(dbUser).not.toBeNull();
        expect(dbUser?.github_login).toBe("testuser");
        // Verify user access token was NEVER stored in DB or session
        const jsonStr = JSON.stringify(dbUser);
        expect(jsonStr).not.toContain("gho_FAKE_USER_ACCESS_TOKEN_999");
    });
});
//# sourceMappingURL=auth_and_session.test.js.map