import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { fetchUserRepoSnapshotFromGitHub, verifyAndConsumeOAuthState, verifyUserInstallationAccess } from "../lib/github-oauth.js";
import { buildSessionCookieOptions, encodeSession, serializeCookie } from "../lib/session.js";
import { HttpResponse } from "./auth-login.js";

export async function handleAuthCallback(
  request: {
    code?: string;
    state?: string;
    installation_id?: string;
    cookies: Record<string, string>;
    ip?: string;
    userAgent?: string;
  },
  env: WebEnv,
  fetchFn: typeof fetch = fetch
): Promise<HttpResponse> {
  const { code, state, installation_id, cookies, ip = "127.0.0.1", userAgent = "Unknown" } = request;
  const expectedState = cookies["nantis_csrf_state"];

  const isProd = env.NODE_ENV === "production";
  const clearCsrfCookie = serializeCookie({
    name: "nantis_csrf_state",
    value: "",
    httpOnly: true,
    secure: isProd,
    sameSite: "Lax",
    path: "/",
    maxAge: 0,
  });

  // 1. Single-use CSRF state token verification + 10-minute expiry check
  const stateCheck = state ? verifyAndConsumeOAuthState(state) : { valid: false };
  if (!state || !expectedState || state !== expectedState || !stateCheck.valid) {
    await db.createAuditLog({
      action: "user.login_failed",
      target_resource: "oauth:callback",
      ip_address: ip,
      user_agent: userAgent,
      details: { reason: "CSRF state token mismatch, expired, or reused" },
    });
    return {
      status: 400,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": clearCsrfCookie,
      },
      body: `<!DOCTYPE html><html><body><h1>400 Bad Request</h1><p>Invalid CSRF state token. <a href="/auth/login">Try signing in again</a>.</p></body></html>`,
    };
  }

  if (!code) {
    return {
      status: 400,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": clearCsrfCookie,
      },
      body: `<!DOCTYPE html><html><body><h1>400 Bad Request</h1><p>Missing authorization code from GitHub.</p></body></html>`,
    };
  }

  try {
    // 2. Exchange OAuth code for user token & identity
    const tokenResponse = await fetchFn("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(`OAuth code exchange failed with status ${tokenResponse.status}`);
    }

    const tokenData = (await tokenResponse.json()) as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      throw new Error(`OAuth token exchange returned error: ${tokenData.error || "No access token"}`);
    }

    const userOAuthToken = tokenData.access_token;

    try {
      // Fetch User Identity
      const userResponse = await fetchFn("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${userOAuthToken}`,
          "User-Agent": "NANTIS-Web-Auth",
          Accept: "application/json",
        },
      });

      if (!userResponse.ok) {
        throw new Error(`GitHub user identity lookup failed with status ${userResponse.status}`);
      }

      const githubUser = (await userResponse.json()) as { id: number; login: string; avatar_url: string };

      // 3. Upsert user in database
      const user = await db.upsertUser({
        github_user_id: githubUser.id,
        github_login: githubUser.login,
        avatar_url: githubUser.avatar_url,
      });

      // 4. Fetch per-user, per-repo access snapshot from GitHub using user token
      const { repos, installations } = await fetchUserRepoSnapshotFromGitHub(userOAuthToken, fetchFn);

      // Link installations to user in DB
      for (const inst of installations) {
        await db.linkUserInstallation(user.id, inst.id, inst.html_url);
        await db.upsertInstallation({
          installation_id: inst.id,
          target_type: "User",
          target_id: githubUser.id,
          account_name: githubUser.login,
        });
      }

      // Upsert repos in DB and grant access snapshot with TTL
      for (const r of repos) {
        const repoRow = await db.upsertRepository({
          installation_id: String(r.installation_id),
          github_repo_id: r.github_repo_id,
          name: r.repo_name,
          full_name: r.full_name,
          private: r.private,
          default_branch: "main",
        });
        await db.grantRepoAccess(user.id, repoRow.id);
      }

      // Save user repo snapshot with configurable TTL (default 1 hr)
      await db.saveUserRepoSnapshot(user.id, repos, env.USER_REPO_SNAPSHOT_TTL_MS);

      // 5. Setup callback installation_id ownership check (Confused Deputy defense)
      if (installation_id) {
        const parsedInstId = parseInt(installation_id, 10);
        if (!Number.isNaN(parsedInstId)) {
          const isUserAuthorized = await verifyUserInstallationAccess(userOAuthToken, parsedInstId, fetchFn);
          if (!isUserAuthorized) {
            await db.createAuditLog({
              user_id: user.id,
              action: "installation.attach_rejected",
              target_resource: `installation:${parsedInstId}`,
              ip_address: ip,
              user_agent: userAgent,
              details: { reason: "Confused deputy: User lacks confirmed access to installation_id" },
            });
            return {
              status: 403,
              headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": clearCsrfCookie },
              body: `<!DOCTYPE html><html><body><h1>403 Forbidden</h1><p>Access denied: You do not have permission to attach this GitHub repository access to your account.</p></body></html>`,
            };
          }
          await db.linkUserInstallation(user.id, parsedInstId);
        }
      }

      // 6. Rotate session (HttpOnly, SameSite=Lax, Secure in production)
      const sessionToken = encodeSession(
        {
          userId: user.id,
          githubUserId: user.github_user_id,
          githubLogin: user.github_login,
          createdAt: Date.now(),
        },
        env.SESSION_SECRET
      );

      const sessionCookieOptions = buildSessionCookieOptions(sessionToken, isProd);
      const sessionCookieHeader = serializeCookie(sessionCookieOptions);

      // 7. Audit Log
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
    } finally {
      // User OAuth token reference is discarded immediately
    }
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
      headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": clearCsrfCookie },
      body: `<!DOCTYPE html><html><body><h1>Authentication Failed</h1><p>${errorMsg}</p><p><a href="/auth/login">Try signing in again</a></p></body></html>`,
    };
  }
}
