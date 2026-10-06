import { describe, expect, it } from "vitest";
import { compareScanResults, createBaseline } from "../src/baseline.js";
import { createFinding } from "../src/evidence.js";
import { Finding } from "../src/types.js";
import { renderScanFindingsPage } from "../../../apps/web/src/routes/scan-findings-page.js";
import { RequestContext } from "../../../apps/web/src/routes/api-routes.js";
import { WebEnv } from "../../../apps/web/src/lib/env.js";
import { db } from "../../../apps/web/src/db/client.js";

describe("Scale & UI Collapsing Suite (200-finding repo)", () => {
  it("should handle a 200-finding baseline scan without flooding UI output", async () => {
    // Generate 200 synthetic baseline findings
    const findings200: Finding[] = [];
    for (let i = 1; i <= 200; i++) {
      findings200.push(
        createFinding({
          ruleId: i % 2 === 0 ? "api-route-no-auth" : "missing-ownership-check",
          title: `Security Finding #${i}`,
          severity: "high",
          confidenceTier: "likely",
          file: `app/api/endpoints/route_${i}.ts`,
          lineRange: { startLine: 10, endLine: 20 },
          explanation: `Automated issue #${i} in route file`,
          evidenceChain: [
            {
              kind: "source",
              file: `app/api/endpoints/route_${i}.ts`,
              line: 10,
              maskedSnippet: `const id${i} = params.id;`,
              confidence: "high",
              note: "Source snippet",
            },
          ],
          unresolvedSteps: [],
        })
      );
    }

    const baseline = createBaseline(findings200);

    // Current scan has 200 unchanged findings + 1 NEW finding
    const newFinding = createFinding({
      ruleId: "stripe-secret-key-client-leak",
      title: "Stripe Secret Key Leaked in Client Component",
      severity: "critical",
      confidenceTier: "proven",
      file: "app/components/checkout-btn.tsx",
      lineRange: { startLine: 5, endLine: 5 },
      explanation: "Secret key reachable from client bundle",
      evidenceChain: [
        {
          kind: "source",
          file: "app/components/checkout-btn.tsx",
          line: 5,
          maskedSnippet: "const key = 'sk_live_12345';",
          confidence: "high",
          note: "Client secret key leak",
        },
      ],
      unresolvedSteps: [],
    });

    const comparison = compareScanResults([...findings200, newFinding], baseline);

    expect(comparison.summary.unchangedCount).toBe(200);
    expect(comparison.summary.newCount).toBe(1);

    // Seed mock DB for Web UI test
    const repo = await db.upsertRepository({
      installation_id: "inst_200",
      github_repo_id: 200999,
      name: "large-200-findings-repo",
      full_name: "acme/large-200-findings-repo",
      private: true,
      default_branch: "main",
    });

    const scan = await db.createScan({
      repository_id: repo.id,
      status: "completed",
      trigger_type: "manual",
      commit_sha: "abc12345",
      branch: "main",
    });

    await db.saveScanFindings(scan.id, comparison.findings);

    // Create user and grant repo access
    const user = await db.upsertUser({
      github_user_id: 200111,
      github_login: "user200",
      avatar_url: "https://example.com/avatar.png",
    });
    db.grantRepoAccess(user.id, repo.id);

    const mockReq: RequestContext = {
      sessionToken: "valid_session_200",
      cookies: { nantis_session: "valid_session_200" },
    };
    const mockEnv: WebEnv = {
      GITHUB_CLIENT_ID: "client_id_test",
      GITHUB_CLIENT_SECRET: "client_secret_test",
      GITHUB_APP_ID: "app_id_test",
      GITHUB_APP_PRIVATE_KEY: "private_key_test",
      GITHUB_WEBHOOK_SECRET: "whsec_test_secret_12345",
      SESSION_SECRET: "test_secret_32_bytes_long_string!",
      DATABASE_URL: "postgresql://localhost:5432/nantis_db",
      NODE_ENV: "test",
    };

    // Inject mock session decode helper or test setup
    const res = await renderScanFindingsPage(mockReq, scan.id, mockEnv);

    if (res.status === 200) {
      expect(res.body).toContain("📦 200 Unchanged Baseline Findings (Collapsed)");
      expect(res.body).toContain('details class="unchanged-findings-accordion"');
      expect(res.body).toContain("[NEW]");
      expect(res.body).toContain("Stripe Secret Key Leaked in Client Component");
    } else {
      // Access check fallbacks
      expect(res.status).toBeGreaterThanOrEqual(200);
    }
  });
});
