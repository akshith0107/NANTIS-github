import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { exchangeCodeForUserIdentity } from "../lib/github-oauth.js";
import { buildSessionCookieOptions, encodeSession, serializeCookie } from "../lib/session.js";
import { HttpResponse } from "./auth-login.js";

export async function handleAuthCallback(
  request: {
    code?: string;
    state?: string;
    cookies: Record<string, string>;
    ip?: string;
    userAgent?: string;
  },
  env: WebEnv,
  fetchFn: typeof fetch = fetch
): Promise<HttpResponse> {
  const { code, state, cookies, ip = "127.0.0.1", userAgent = "Unknown" } = request;
  const expectedState = cookies["nantis_csrf_state"];

  // 1. CSRF State Verification
  if (!state || !expectedState || state !== expectedState) {
    await db.createAuditLog({
      action: "user.login_failed",
      target_resource: "oauth:callback",
      ip_address: ip,
      user_agent: userAgent,
      details: { reason: "CSRF state token mismatch or missing" },
    });
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid CSRF state token" }),
    };
  }

  if (!code) {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing authorization code" }),
    };
  }

  try {
    // 2. Exchange OAuth code for user identity (user token discarded immediately)
    const githubUser = await exchangeCodeForUserIdentity(
      code,
      env.GITHUB_CLIENT_ID,
      env.GITHUB_CLIENT_SECRET,
      fetchFn
    );

    // 3. Upsert user in database
    const user = await db.upsertUser({
      github_user_id: githubUser.id,
      github_login: githubUser.login,
      avatar_url: githubUser.avatar_url,
    });

    // 4. Create signed session
    const sessionToken = encodeSession(
      {
        userId: user.id,
        githubUserId: user.github_user_id,
        githubLogin: user.github_login,
        createdAt: Date.now(),
      },
      env.SESSION_SECRET
    );

    const isProd = env.NODE_ENV === "production";
    const sessionCookieOptions = buildSessionCookieOptions(sessionToken, isProd);
    const sessionCookieHeader = serializeCookie(sessionCookieOptions);

    // Clear CSRF cookie
    const clearCsrfCookie = serializeCookie({
      name: "nantis_csrf_state",
      value: "",
      httpOnly: true,
      secure: isProd,
      sameSite: "Lax",
      path: "/",
      maxAge: 0,
    });

    // 5. Audit Log
    await db.createAuditLog({
      user_id: user.id,
      action: "user.login",
      target_resource: `user:${user.id}`,
      ip_address: ip,
      user_agent: userAgent,
      details: { github_login: user.github_login },
    });

    return {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": `${sessionCookieHeader}, ${clearCsrfCookie}`,
      },
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    await db.createAuditLog({
      action: "user.login_error",
      target_resource: "oauth:callback",
      ip_address: ip,
      user_agent: userAgent,
      details: { error: errorMsg },
    });

    return {
      status: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: `Authentication failed: ${errorMsg}` }),
    };
  }
}
