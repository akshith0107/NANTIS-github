export interface PackageQuery {
  name: string;
  version: string;
  ecosystem?: string;
}

export interface OSVEvent {
  introduced?: string;
  fixed?: string;
}

export interface OSVRange {
  type: string;
  events: OSVEvent[];
}

export interface OSVAffected {
  package: {
    name: string;
    ecosystem: string;
  };
  ranges?: OSVRange[];
}

export interface OSVSeverityItem {
  type: string;
  score: string;
}

export interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: OSVSeverityItem[];
  affected?: OSVAffected[];
}

export interface OSVQueryResult {
  package: PackageQuery;
  vulnerabilities: OSVVulnerability[];
}

/**
 * Interface for OSV.dev lookup.
 * Enforces Rule 1: No direct network calls in tests or deterministic core logic without interface abstraction.
 */
export interface OSVClient {
  queryBatch(packages: PackageQuery[]): Promise<OSVQueryResult[]>;
}

export class FetchOSVClient implements OSVClient {
  private endpoint: string;
  private timeoutMs: number;

  constructor(endpoint = "https://api.osv.dev/v1/querybatch", timeoutMs = 5000) {
    this.endpoint = endpoint;
    this.timeoutMs = timeoutMs;
  }

  public async queryBatch(packages: PackageQuery[]): Promise<OSVQueryResult[]> {
    if (packages.length === 0) return [];

    const queries = packages.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: pkg.ecosystem || "npm",
      },
      version: pkg.version,
    }));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`OSV API HTTP Error ${response.status}: ${response.statusText}`);
      }

      const data = (await response.json()) as { results?: Array<{ vulns?: OSVVulnerability[] }> };

      if (!data || !Array.isArray(data.results)) {
        throw new Error("Malformed response from OSV API");
      }

      return packages.map((pkg, i) => ({
        package: pkg,
        vulnerabilities: data.results?.[i]?.vulns || [],
      }));
    } catch (err: unknown) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : "OSV query failed";
      throw new Error(`OSV lookup error: ${msg}`);
    }
  }
}
