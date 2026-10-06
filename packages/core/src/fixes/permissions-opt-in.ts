import { FixPRPermissionsConfig } from "./types.js";

export const PERMISSION_EXPLANATION = {
  "contents:write":
    "Allows creating dedicated fix feature branches (e.g. nantis/fix-...) and pushing verified fix commits to the repository.",
  "pull-requests:write":
    "Allows opening pull requests for approved fixes and updating pull request descriptions and comments.",
};

export const GITHUB_APP_ADMIN_APPROVAL_DOCS =
  "Per GitHub App documentation, requesting scope upgrades (from read to write) triggers an email notification to organization and repository administrators. Elevated write permissions take effect only after an administrator explicitly approves the updated permission request.";

/**
 * Gets default read-only permissions configuration for an installation.
 */
export function getDefaultPermissionsConfig(installationId: string): FixPRPermissionsConfig {
  return {
    installationId,
    optedIn: false,
    contentsPermission: "read",
    pullRequestsPermission: "read",
  };
}

/**
 * Generates permission opt-in payload for enabling Fix PRs.
 */
export function createFixPROptInRequest(installationId: string): {
  config: FixPRPermissionsConfig;
  requestedPermissions: { contents: string; pull_requests: string };
  explanationText: string;
  adminApprovalNote: string;
} {
  const config: FixPRPermissionsConfig = {
    installationId,
    optedIn: true,
    contentsPermission: "write",
    pullRequestsPermission: "write",
    grantedAt: new Date().toISOString(),
  };

  const explanationText = [
    "--- FIX PR PERMISSIONS REQUESTED ---",
    `• contents: write - ${PERMISSION_EXPLANATION["contents:write"]}`,
    `• pull-requests: write - ${PERMISSION_EXPLANATION["pull-requests:write"]}`,
  ].join("\n");

  return {
    config,
    requestedPermissions: {
      contents: "write",
      pull_requests: "write",
    },
    explanationText,
    adminApprovalNote: GITHUB_APP_ADMIN_APPROVAL_DOCS,
  };
}
