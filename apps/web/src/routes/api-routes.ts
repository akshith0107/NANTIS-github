import { ScanJobQueue } from "@nantis/worker";
import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { HttpResponse } from "./auth-login.js";

export const scanJobQueue = new ScanJobQueue(db);

export interface RequestContext {
  cookies?: Record<string, string>;
  sessionToken?: string;
  body?: Record<string, unknown> | string | unknown;
  ip?: string;
  userAgent?: string;
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  clientIp?: string;
  query?: Record<string, string>;
}

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

function createNotFoundResponse(): HttpResponse {
  return {
    status: 404,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ error: "Not found" }),
  };
}

/**
 * GET /api/repos/:repoId
 */
export async function handleGetRepo(
  req: RequestContext,
  repoId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  try {
    const { repository } = await assertRepoAccess(userId, repoId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repository }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/repos/:repoId/scans
 */
export async function handleListScans(
  req: RequestContext,
  repoId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  try {
    await assertRepoAccess(userId, repoId);
    const scans = await db.getScansForRepository(repoId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scans }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * POST /api/repos/:repoId/scans
 */
export async function handleCreateScan(
  req: RequestContext,
  repoId: string,
  env: WebEnv,
  customFetcher?: (dir: string) => Promise<void>
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  try {
    const { repository } = await assertRepoAccess(userId, repoId);
    let bodyObj: Record<string, unknown> = {};
    if (typeof req.body === "string") {
      try {
        bodyObj = JSON.parse(req.body) as Record<string, unknown>;
      } catch {
        bodyObj = {};
      }
    } else if (typeof req.body === "object" && req.body !== null) {
      bodyObj = req.body as Record<string, unknown>;
    }

    const scan = await db.createScan({
      repository_id: repoId,
      status: "queued",
      trigger_type: "manual",
      commit_sha: (bodyObj.commit_sha as string) || "HEAD",
      branch: (bodyObj.branch as string) || "main",
      triggered_by_user_id: userId,
    });

    const inst = await db.getInstallation(repository.installation_id);
    if (!inst) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          error: `Repository ${repoId} has no valid GitHub installation configured`,
        }),
      };
    }

    await scanJobQueue.enqueueJob(
      {
        scanId: scan.id,
        repoId: repository.id,
        installationId: inst.installation_id,
        requestedByUserId: userId || "anonymous",
      },
      {},
      customFetcher
    );

    return {
      status: 201,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/scans/:scanId
 */
export async function handleGetScan(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);

  // If scan does not exist, pass a non-existent repoId to assertRepoAccess to trigger standard 404
  const targetRepoId = scan ? scan.repository_id : `non_existent_${scanId}`;

  try {
    await assertRepoAccess(userId, targetRepoId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/scans/:scanId/findings
 */
export async function handleListFindings(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);
  const targetRepoId = scan ? scan.repository_id : `non_existent_${scanId}`;

  try {
    await assertRepoAccess(userId, targetRepoId);
    const findings = await db.getFindingsForScan(scanId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/findings/:findingId
 */
export async function handleGetFinding(
  req: RequestContext,
  findingId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const finding = await db.getFindingById(findingId);
  const scan = finding ? await db.getScanById(finding.scan_id) : null;
  const targetRepoId = scan ? scan.repository_id : `non_existent_${findingId}`;

  try {
    await assertRepoAccess(userId, targetRepoId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/repos/:repoId/report
 */
export async function handleGetReport(
  req: RequestContext,
  repoId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  try {
    const { repository } = await assertRepoAccess(userId, repoId);
    const scans = await db.getScansForRepository(repoId);
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        report: {
          repository: repository.full_name,
          scansCount: scans.length,
          generatedAt: new Date().toISOString(),
        },
      }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}

/**
 * GET /api/scans/:scanId/report
 */
export async function handleGetScanReport(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);
  const targetRepoId = scan ? scan.repository_id : `non_existent_${scanId}`;

  try {
    const { repository } = await assertRepoAccess(userId, targetRepoId);
    if (!scan) return createNotFoundResponse();

    const findings = await db.getFindingsForScan(scanId);
    const grouped: Record<string, typeof findings> = {
      proven: [],
      likely: [],
      "needs-review": [],
      hygiene: [],
    };

    for (const f of findings) {
      const tier = f.confidenceTier || "proven";
      if (!grouped[tier]) grouped[tier] = [];
      grouped[tier].push(f);
    }

    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        report: {
          scanId: scan.id,
          repository: repository.full_name,
          status: scan.status,
          commitSha: scan.commit_sha,
          branch: scan.branch,
          totalFindings: findings.length,
          findingsByConfidenceTier: grouped,
          generatedAt: new Date().toISOString(),
        },
      }),
    };
  } catch (err: unknown) {
    if (err instanceof NotFoundError) return createNotFoundResponse();
    throw err;
  }
}
