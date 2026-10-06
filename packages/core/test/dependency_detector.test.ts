import { describe, expect, it } from "vitest";
import { detectDependencies } from "../src/detectors/dependencies.js";
import { OSVClient, OSVQueryResult, PackageQuery } from "../src/osv/client.js";
import { parsePackageLockJson, parsePnpmLockYaml, parseYarnLock } from "../src/parsers/lockfile.js";

class MockOSVClient implements OSVClient {
  private mockResponses: Map<string, OSVQueryResult> = new Map();
  public shouldTimeout = false;
  public shouldReturnMalformed = false;

  public setMockResult(pkgName: string, version: string, result: OSVQueryResult): void {
    this.mockResponses.set(`${pkgName}@${version}`, result);
  }

  public async queryBatch(packages: PackageQuery[]): Promise<OSVQueryResult[]> {
    if (this.shouldTimeout) {
      throw new Error("OSV Query Timeout after 5000ms");
    }

    if (this.shouldReturnMalformed) {
      throw new Error("Malformed response from OSV API");
    }

    return packages.map((pkg) => {
      const key = `${pkg.name}@${pkg.version}`;
      return (
        this.mockResponses.get(key) || {
          package: pkg,
          vulnerabilities: [],
        }
      );
    });
  }
}

describe("Dependency Detector & Lockfile Parsers (packages/core/src/detectors/dependencies.ts)", () => {
  it("should parse exact versions from package-lock.json", () => {
    const content = JSON.stringify({
      name: "test-app",
      packages: {
        "": { name: "test-app" },
        "node_modules/express": { version: "4.17.1" },
        "node_modules/lodash": { version: "4.17.20" },
      },
    });

    const deps = parsePackageLockJson(content);
    expect(deps).toEqual([
      { name: "express", version: "4.17.1" },
      { name: "lodash", version: "4.17.20" },
    ]);
  });

  it("should parse exact versions from pnpm-lock.yaml", () => {
    const yaml = `
lockfileVersion: '9.0'
packages:
  /express@4.17.1:
    resolution: {integrity: sha512-xxx}
  '@types/node@22.0.0':
    resolution: {integrity: sha512-yyy}
`;
    const deps = parsePnpmLockYaml(yaml);
    expect(deps).toEqual([
      { name: "express", version: "4.17.1" },
      { name: "@types/node", version: "22.0.0" },
    ]);
  });

  it("should parse exact versions from yarn.lock", () => {
    const yarn = `
express@^4.17.0:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"

lodash@^4.17.0:
  version "4.17.20"
`;
    const deps = parseYarnLock(yarn);
    expect(deps).toEqual([
      { name: "express", version: "4.17.1" },
      { name: "lodash", version: "4.17.20" },
    ]);
  });

  it("should detect vulnerable dependencies with advisory ID and fixed version using Fake OSV client", async () => {
    const mockClient = new MockOSVClient();
    mockClient.setMockResult("express", "4.17.1", {
      package: { name: "express", version: "4.17.1" },
      vulnerabilities: [
        {
          id: "GHSA-1234-5678-90ab",
          summary: "Prototype pollution in express parameter parsing",
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
          affected: [
            {
              package: { name: "express", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.3" }] }],
            },
          ],
        },
      ],
    });

    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "4.17.1" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { osvClient: mockClient });
    const vulnFinding = findings.find((f) => f.ruleId === "vulnerable-dependency");

    expect(vulnFinding).toBeDefined();
    expect(vulnFinding?.title).toContain("express@4.17.1");
    expect(vulnFinding?.explanation).toContain("GHSA-1234-5678-90ab");
    expect(vulnFinding?.explanation).toContain("Fixed in version 4.17.3");
  });

  it("should handle OSV query timeout by returning dependency check incomplete status", async () => {
    // Official OSV.dev Docs Page: OSV API - Batch Query Endpoint (/v1/querybatch)
    // URL: https://google.github.io/osv.dev/post-v1-querybatch/
    const mockClient = new MockOSVClient();
    mockClient.shouldTimeout = true;

    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "4.17.1" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { osvClient: mockClient });
    const unavailableFinding = findings.find((f) => f.ruleId === "dependency-data-unavailable");

    expect(unavailableFinding).toBeDefined();
    expect(unavailableFinding?.explanation).toContain("dependency check incomplete");
  });

  it("should handle unreachable OSV network endpoint by falling back to 'dependency check incomplete'", async () => {
    // Official OSV.dev Docs Page: OSV API - Batch Query Endpoint (/v1/querybatch)
    // URL: https://google.github.io/osv.dev/post-v1-querybatch/
    const mockClient: OSVClient = {
      async queryBatch() {
        throw new Error("Network unreachable: ENOTFOUND api.osv.dev");
      },
    };

    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "4.17.1" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { osvClient: mockClient });
    const fallbackFinding = findings.find((f) => f.ruleId === "dependency-data-unavailable");

    expect(fallbackFinding).toBeDefined();
    expect(fallbackFinding?.explanation).toContain("dependency check incomplete");
    expect(fallbackFinding?.explanation).toContain("ENOTFOUND api.osv.dev");
  });

  it("should handle malformed OSV response gracefully by returning dependency check incomplete status", async () => {
    const mockClient = new MockOSVClient();
    mockClient.shouldReturnMalformed = true;

    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "4.17.1" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { osvClient: mockClient });
    const unavailableFinding = findings.find((f) => f.ruleId === "dependency-data-unavailable");

    expect(unavailableFinding).toBeDefined();
    expect(unavailableFinding?.explanation).toContain("dependency check incomplete");
  });

  it("should support offline mode and report 'dependency check incomplete' instead of claiming no vulnerabilities", async () => {
    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "4.17.1" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { offlineMode: true });
    const offlineFinding = findings.find((f) => f.ruleId === "dependency-data-unavailable");

    expect(offlineFinding).toBeDefined();
    expect(offlineFinding?.explanation).toBe("dependency check incomplete");
  });

  it("should flag missing lockfile when package.json exists without lockfiles", async () => {
    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ name: "my-app", dependencies: { express: "^4.17.1" } })],
    ]);

    const findings = await detectDependencies(files, { offlineMode: true });
    const missingLockFinding = findings.find((f) => f.ruleId === "missing-lockfile");

    expect(missingLockFinding).toBeDefined();
    expect(missingLockFinding?.file).toBe("package.json");
  });

  it("should flag loose version ranges in package.json", async () => {
    const files = new Map<string, string>([
      ["package.json", JSON.stringify({ dependencies: { express: "*", lodash: ">=4.0.0" } })],
      [
        "package-lock.json",
        JSON.stringify({ packages: { "node_modules/express": { version: "4.17.1" } } }),
      ],
    ]);

    const findings = await detectDependencies(files, { offlineMode: true });
    const looseFindings = findings.filter((f) => f.ruleId === "loose-dependency-range");

    expect(looseFindings.length).toBe(2);
  });
});
