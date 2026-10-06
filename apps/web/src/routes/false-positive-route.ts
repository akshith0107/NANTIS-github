import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";

import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

export async function handleReportFalsePositive(
  req: RequestContext,
  targetId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);

  try {
    // Assert repo access first
    if (!userId) {
      return {
        status: 404,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Not found" }),
      };
    }

    try {
      await assertRepoAccess(userId, targetId);
    } catch (err) {
      if (err instanceof NotFoundError) {
        return {
          status: 404,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ error: "Not found" }),
        };
      }
      throw err;
    }

    let bodyData: Record<string, unknown> | undefined;
    if (typeof req.body === "string") {
      try {
        bodyData = JSON.parse(req.body) as Record<string, unknown>;
      } catch {
        bodyData = undefined;
      }
    } else if (typeof req.body === "object" && req.body !== null) {
      bodyData = req.body as Record<string, unknown>;
    }

    const { ruleId, fingerprint, userNote } = bodyData || {};

    if (!ruleId || !fingerprint) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Missing required fields: ruleId and fingerprint" }),
      };
    }

    // Save false positive feedback record (strictly ruleId, fingerprint, userNote only — NO source code)
    const report = await db.createFalsePositiveReport({
      rule_id: String(ruleId),
      fingerprint: String(fingerprint),
      user_note: String(userNote || ""),
      user_id: userId || null,
    });

    return {
      status: 201,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ok: true,
        reportId: report.id,
        message: "False positive report recorded. No source code was stored.",
      }),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: `Invalid request payload: ${msg}` }),
    };
  }
}
