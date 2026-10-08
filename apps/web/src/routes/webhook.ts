import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { verifyGitHubWebhookSignature } from "../lib/webhook-signature.js";
import { HttpResponse } from "./auth-login.js";
import { scanJobQueue } from "./api-routes.js";

export interface GitHubWebhookPayload {
  action?: string;
  ref?: string;
  before?: string;
  after?: string;
  installation?: {
    id: number;
    account?: {
      id: number;
      login: string;
      type: "User" | "Organization";
    };
  };
  repository?: {
    id: number;
    name: string;
    full_name: string;
    private?: boolean;
    default_branch?: string;
  };
  head_commit?: {
    id: string;
    message: string;
    timestamp: string;
    author?: { name: string; email: string };
  };
  repositories?: { id: number; name: string; full_name: string; private: boolean }[];
  repositories_removed?: { id: number; name?: string; full_name?: string; private?: boolean }[];
}

const pushDeduplicationMap = new Map<
  string,
  { timestamp: number; scanId: string; commitSha: string }
>();
const DEDUPLICATION_WINDOW_MS = 10000;
const MAX_QUEUE_LIMIT = 50;

/**
 * Resets the in-memory push deduplication map (used in tests)
 */
export function resetPushDeduplicationMap(): void {
  pushDeduplicationMap.clear();
}

export async function handleGitHubWebhook(
  request: {
    rawBody: string | Buffer;
    headers: Record<string, string | string[] | undefined>;
    ip?: string;
    userAgent?: string;
  },
  env: WebEnv
): Promise<HttpResponse> {
  const { rawBody, headers, ip = "127.0.0.1", userAgent = "GitHub-Hookshot" } = request;

  // Extract signature header (supports case-insensitive header keys)
  const signatureHeader =
    (headers["x-hub-signature-256"] as string | undefined) ||
    (headers["X-Hub-Signature-256"] as string | undefined);

  // 1. Mandatory HMAC Signature Verification BEFORE parsing payload
  const isValidSignature = verifyGitHubWebhookSignature(
    rawBody,
    signatureHeader,
    env.GITHUB_WEBHOOK_SECRET
  );

  if (!isValidSignature) {
    await db.createAuditLog({
      action: "webhook.rejected_bad_signature",
      target_resource: "webhook:github",
      ip_address: ip,
      user_agent: userAgent,
      details: { reason: "HMAC signature verification failed" },
    });

    return {
      status: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid or missing webhook signature" }),
    };
  }

  // 2. Safe to parse payload after signature is verified
  let payload: GitHubWebhookPayload;
  try {
    const bodyString = typeof rawBody === "string" ? rawBody : rawBody.toString("utf-8");
    payload = JSON.parse(bodyString) as GitHubWebhookPayload;
  } catch {
    return {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Malformed JSON payload" }),
    };
  }

  const eventType =
    (headers["x-github-event"] as string | undefined) ||
    (headers["X-GitHub-Event"] as string | undefined);

  const action = payload.action;

  // 3. Handle Installation Events
  if (eventType === "installation" && payload.installation) {
    const inst = payload.installation;
    const account = inst.account;

    if (action === "created" && account) {
      await db.upsertInstallation({
        installation_id: inst.id,
        target_type: account.type,
        target_id: account.id,
        account_name: account.login,
      });

      await db.createAuditLog({
        action: "installation.created",
        target_resource: `installation:${inst.id}`,
        ip_address: ip,
        user_agent: userAgent,
        details: { account_name: account.login, target_type: account.type },
      });
    } else if (action === "deleted" || action === "suspend") {
      await db.deleteSnapshotsForInstallation(inst.id);

      await db.createAuditLog({
        action: `installation.${action}`,
        target_resource: `installation:${inst.id}`,
        ip_address: ip,
        user_agent: userAgent,
        details: { installation_id: inst.id },
      });
    }
  }

  // 3b. Handle Installation Repositories Events
  if (eventType === "installation_repositories" && payload.repositories_removed) {
    const removedList = payload.repositories_removed as { id: number; full_name?: string }[];
    for (const r of removedList) {
      await db.deleteSnapshotsForRepo(r.id);
    }
  }

  // 4. Handle Push Webhook Events (Rescan Queueing, Default Branch Filtering, Deduplication & Job Limit Rules)
  if (eventType === "push") {
    const repoInfo = payload.repository;
    if (!repoInfo) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Missing repository in push payload" }),
      };
    }

    // Lookup repository in database by GitHub Repo ID, Full Name, or internal ID
    const repo =
      (await db.getRepositoryByGithubId(repoInfo.id)) ||
      (await db.getRepositoryByFullName(repoInfo.full_name)) ||
      (await db.getRepositoryById(String(repoInfo.id)));

    if (!repo) {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, ignored: "unconnected_repository" }),
      };
    }

    // Extract branch name and compare against default branch
    const refBranch = (payload.ref || "").replace(/^refs\/heads\//, "");
    const defaultBranch = repo.default_branch || repoInfo.default_branch || "main";

    if (refBranch !== defaultBranch) {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ok: true,
          ignored: "non_default_branch",
          branch: refBranch,
          defaultBranch,
        }),
      };
    }

    const commitSha = payload.head_commit?.id || payload.after || "head";
    const dedupKey = `${repo.id}:${refBranch}`;
    const now = Date.now();
    const existing = pushDeduplicationMap.get(dedupKey);

    // Rapid push deduplication check
    if (
      existing &&
      (existing.commitSha === commitSha || now - existing.timestamp < DEDUPLICATION_WINDOW_MS)
    ) {
      await db.createAuditLog({
        action: "webhook.push_deduplicated",
        target_resource: `repo:${repo.id}`,
        ip_address: ip,
        user_agent: userAgent,
        details: { commitSha, branch: refBranch, scanId: existing.scanId },
      });

      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, deduplicated: true, scanId: existing.scanId }),
      };
    }

    // Job limit enforcement
    if (scanJobQueue.getPendingQueueLength() >= MAX_QUEUE_LIMIT) {
      await db.createAuditLog({
        action: "webhook.rejected_job_limit",
        target_resource: `repo:${repo.id}`,
        ip_address: ip,
        user_agent: userAgent,
        details: { pendingQueueLength: scanJobQueue.getPendingQueueLength() },
      });

      return {
        status: 429,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Job limits exceeded, please retry later" }),
      };
    }

    // Create scan record & enqueue job
    const scan = await db.createScan({
      repository_id: repo.id,
      status: "queued",
      trigger_type: "webhook_push",
      commit_sha: commitSha,
      branch: refBranch,
    });

    pushDeduplicationMap.set(dedupKey, {
      timestamp: now,
      scanId: scan.id,
      commitSha,
    });

    await scanJobQueue.enqueueJob({
      scanId: scan.id,
      repoId: repo.id,
      installationId: Number(repo.installation_id) || 1,
      requestedByUserId: "github_webhook_push",
    });

    await db.createAuditLog({
      action: "webhook.push_scan_queued",
      target_resource: `scan:${scan.id}`,
      ip_address: ip,
      user_agent: userAgent,
      details: { repoId: repo.id, commitSha, branch: refBranch },
    });

    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: true, queued: true, scanId: scan.id }),
    };
  }

  return {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ok: true, event: eventType, action }),
  };
}
