import { WebEnv } from "../lib/env.js";
import { decodeSession, serializeCookie } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import { db } from "../db/client.js";

export async function handleAuthLogout(
  req: RequestContext,
  env: WebEnv
): Promise<HttpResponse> {
  const isProd = env.NODE_ENV === "production";
  const token = req.sessionToken || req.cookies?.["nantis_session"];

  if (token) {
    const session = decodeSession(token, env.SESSION_SECRET);
    if (session?.userId) {
      await db.createAuditLog({
        user_id: session.userId,
        action: "user.logout",
        target_resource: `user:${session.userId}`,
        ip_address: req.clientIp || "127.0.0.1",
        user_agent: req.headers?.["user-agent"] || "Unknown",
        details: { github_login: session.githubLogin },
      });
    }
  }

  const clearSessionCookie = serializeCookie({
    name: "nantis_session",
    value: "",
    httpOnly: true,
    secure: isProd,
    sameSite: "Lax",
    path: "/",
    maxAge: 0,
  });

  return {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": clearSessionCookie,
    },
  };
}
