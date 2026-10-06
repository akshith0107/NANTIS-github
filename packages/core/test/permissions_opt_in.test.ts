import { describe, expect, it } from "vitest";
import {
  getDefaultPermissionsConfig,
  createFixPROptInRequest,
  PERMISSION_EXPLANATION,
  GITHUB_APP_ADMIN_APPROVAL_DOCS,
} from "../src/fixes/index.js";

describe("Fix PR Permissions Opt-in Manager", () => {
  it("defaults installation permission config to read-only", () => {
    const config = getDefaultPermissionsConfig("inst-12345");

    expect(config.installationId).toBe("inst-12345");
    expect(config.optedIn).toBe(false);
    expect(config.contentsPermission).toBe("read");
    expect(config.pullRequestsPermission).toBe("read");
  });

  it("requires explicit opt-in to request contents: write and pull-requests: write", () => {
    const optIn = createFixPROptInRequest("inst-12345");

    expect(optIn.config.optedIn).toBe(true);
    expect(optIn.requestedPermissions.contents).toBe("write");
    expect(optIn.requestedPermissions.pull_requests).toBe("write");

    expect(optIn.explanationText).toContain("contents: write");
    expect(optIn.explanationText).toContain(PERMISSION_EXPLANATION["contents:write"]);
    expect(optIn.explanationText).toContain("pull-requests: write");
    expect(optIn.explanationText).toContain(PERMISSION_EXPLANATION["pull-requests:write"]);
  });

  it("documents GitHub App admin approval requirements for elevated permissions", () => {
    expect(GITHUB_APP_ADMIN_APPROVAL_DOCS).toContain("organization and repository administrators");
    expect(GITHUB_APP_ADMIN_APPROVAL_DOCS).toContain("explicitly approves the updated permission request");
  });
});
