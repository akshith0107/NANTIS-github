import { db } from "../db/client.js";
import { WebEnv } from "../lib/env.js";
import { verifyGitHubWebhookSignature } from "../lib/webhook-signature.js";
import { createGitHubCheckRun } from "../lib/github-checks.js";
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
  pull_request?: {
    number: number;
    state?: string;
    head?: {
      sha: string;
      ref: string;
      label?: string;
    };
    base?: {
      sha: string;
      ref: string;
      label?: string;
    };
  };
  repositories?: { id: number; name: string; full_name: string; private: boolean }[];
  repositories_added?: { id: number; name: string; full_name: string; private: boolean }[];
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

  const deliveryId =
    (headers["x-github-delivery"] as string | undefined) ||
    (headers["X-GitHub-Delivery"] as string | undefined);

  const action = payload.action;

  // 3. Persistent Delivery Deduplication (Step 8)
  if (deliveryId) {
    const isNewDelivery = await db.recordWebhookDelivery(deliveryId, eventType || "unknown", action);
    if (!isNewDelivery) {
      await db.createAuditLog({
        action: "webhook.duplicate_delivery_ignored",
        target_resource: `delivery:${deliveryId}`,
        ip_address: ip,
        user_agent: userAgent,
        details: { deliveryId, eventType, action },
      });

      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, duplicate: true, deliveryId }),
      };
    }
  }

  // 4. Handle Installation Lifecycle Events
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

  // 4b. Handle Installation Repositories Lifecycle Events
  if (eventType === "installation_repositories" && payload.repositories_removed) {
    const removedList = payload.repositories_removed as { id: number; full_name?: string }[];
    for (const r of removedList) {
      await db.deleteSnapshotsForRepo(r.id);
    }
  }

  // Helper for checking Repository & Installation Authorization (Step 10)
  const verifyRepoAndInstallation = async (repoInfo: { id: number; full_name: string }) => {
    const repo =
      (await db.getRepositoryByGithubId(repoInfo.id)) ||
      (await db.getRepositoryByFullName(repoInfo.full_name)) ||
      (await db.getRepositoryById(String(repoInfo.id)));

    if (!repo) {
      return { repo: null, authorized: false, reason: "unconnected_repository" };
    }

    if (payload.installation) {
      const payloadInstId = payload.installation.id;
      const dbInstId = Number(repo.installation_id);
      if (!Number.isNaN(dbInstId) && dbInstId !== payloadInstId) {
        // Installation mismatch
        return { repo, authorized: false, reason: "unauthorized_installation" };
      }
    }

    return { repo, authorized: true, reason: null };
  };

  // 5. Handle Push Webhook Events
  if (eventType === "push") {
    const repoInfo = payload.repository;
    if (!repoInfo) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Missing repository in push payload" }),
      };
    }

    const { repo, authorized, reason } = await verifyRepoAndInstallation(repoInfo);
    if (!repo || !authorized) {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, ignored: reason || "unconnected_repository" }),
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

    // Create scan record
    const parts = repo.full_name.split("/");
    let checkRunId: number | null = null;
    if (parts.length === 2) {
      const [owner, name] = parts;
      checkRunId = await createGitHubCheckRun({
        owner,
        repo: name,
        headSha: commitSha,
        installationId: Number(repo.installation_id) || 1,
        env,
      });
    }

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "queued",
      trigger_type: "webhook_push",
      commit_sha: commitSha,
      branch: refBranch,
      github_check_run_id: checkRunId,
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
      details: { repoId: repo.id, commitSha, branch: refBranch, checkRunId },
    });

    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: true, queued: true, scanId: scan.id, checkRunId }),
    };
  }

  // 6. Handle Pull Request Webhook Events (Step 7)
  if (eventType === "pull_request") {
    const repoInfo = payload.repository;
    const prInfo = payload.pull_request;

    if (!repoInfo || !prInfo) {
      return {
        status: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Missing repository or pull_request in payload" }),
      };
    }

    // Filter PR actions: opened, synchronize, reopened trigger scans; closed is ignored safely
    const prAction = action || "opened";
    if (prAction === "closed") {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, ignored: "pr_closed" }),
      };
    }

    if (prAction !== "opened" && prAction !== "synchronize" && prAction !== "reopened") {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, ignored: `unsupported_pr_action:${prAction}` }),
      };
    }

    const { repo, authorized, reason } = await verifyRepoAndInstallation(repoInfo);
    if (!repo || !authorized) {
      return {
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, ignored: reason || "unconnected_repository" }),
      };
    }

    const headSha = prInfo.head?.sha || "head";
    const headRef = prInfo.head?.ref || repo.default_branch || "main";

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

    // Create scan record & GitHub Check Run
    const prParts = repo.full_name.split("/");
    let prCheckRunId: number | null = null;
    if (prParts.length === 2) {
      const [owner, name] = prParts;
      prCheckRunId = await createGitHubCheckRun({
        owner,
        repo: name,
        headSha,
        installationId: Number(repo.installation_id) || 1,
        env,
      });
    }

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "queued",
      trigger_type: "webhook_pr",
      commit_sha: headSha,
      branch: headRef,
      github_check_run_id: prCheckRunId,
    });

    await scanJobQueue.enqueueJob({
      scanId: scan.id,
      repoId: repo.id,
      installationId: Number(repo.installation_id) || 1,
      requestedByUserId: "github_webhook_pr",
    });

    await db.createAuditLog({
      action: "webhook.pr_scan_queued",
      target_resource: `scan:${scan.id}`,
      ip_address: ip,
      user_agent: userAgent,
      details: { repoId: repo.id, commitSha: headSha, branch: headRef, prNumber: prInfo.number, action: prAction, checkRunId: prCheckRunId },
    });

    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: true, queued: true, scanId: scan.id, prNumber: prInfo.number, checkRunId: prCheckRunId }),
    };
  }

  return {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ok: true, event: eventType, action }),
  };
}

