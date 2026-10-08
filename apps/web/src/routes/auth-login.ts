import { WebEnv } from "../lib/env.js";
import { buildGitHubAuthorizeUrl, generateOAuthState } from "../lib/github-oauth.js";
import { serializeCookie } from "../lib/session.js";

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body?: string;
}

export function handleAuthLogin(env: WebEnv, redirectUri?: string, userId?: string): HttpResponse {
  const csrfState = generateOAuthState(userId);
  const authorizeUrl = buildGitHubAuthorizeUrl(env.GITHUB_CLIENT_ID, csrfState, redirectUri);

  const isProd = env.NODE_ENV === "production";

  const csrfCookie = serializeCookie({
    name: "nantis_csrf_state",
    value: csrfState,
    httpOnly: true,
    secure: isProd,
    sameSite: "Lax",
    path: "/",
    maxAge: 60 * 10, // 10 minutes
  });

  return {
    status: 302,
    headers: {
      Location: authorizeUrl,
      "Set-Cookie": csrfCookie,
    },
  };
}
