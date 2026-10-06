import { Finding } from "@nantis/core";
import { JobStatus } from "@nantis/worker";
import {
  AuditLogRow,
  FalsePositiveReportRow,
  FindingLabelRow,
  FindingRow,
  GithubInstallationRow,
  RepositoryRow,
  ScanRow,
  UserRow,
} from "./schema.js";

export class DatabaseClient {
  private users = new Map<string, UserRow>();
  private installations = new Map<number, GithubInstallationRow>();
  private repositories = new Map<string, RepositoryRow>();
  private scans = new Map<string, ScanRow>();
  private findings = new Map<string, FindingRow>();
  private falsePositiveReports = new Map<string, FalsePositiveReportRow>();
  private findingLabels = new Map<string, FindingLabelRow>();
  private auditLogs: AuditLogRow[] = [];

  // User Repository Permissions (represents GitHub confirmed access)
  private userRepoAccess = new Set<string>(); // key: `${userId}:${repoId}`

  // Users Operations
  async upsertUser(data: {
    github_user_id: number;
    github_login: string;
    avatar_url: string;
  }): Promise<UserRow> {
    const existing = Array.from(this.users.values()).find(
      (u) => u.github_user_id === data.github_user_id
    );

    const now = new Date().toISOString();
    if (existing) {
      existing.github_login = data.github_login;
      existing.avatar_url = data.avatar_url;
      existing.updated_at = now;
      return existing;
    }

    const newUser: UserRow = {
      id: crypto.randomUUID(),
      github_user_id: data.github_user_id,
      github_login: data.github_login,
      avatar_url: data.avatar_url,
      created_at: now,
      updated_at: now,
    };
    this.users.set(newUser.id, newUser);
    return newUser;
  }

  async getUserById(id: string): Promise<UserRow | null> {
    return this.users.get(id) || null;
  }

  async getUserByGithubId(githubUserId: number): Promise<UserRow | null> {
    return Array.from(this.users.values()).find((u) => u.github_user_id === githubUserId) || null;
  }

  // GitHub Installations Operations
  async upsertInstallation(data: {
    installation_id: number;
    target_type: "User" | "Organization";
    target_id: number;
    account_name: string;
  }): Promise<GithubInstallationRow> {
    const existing = this.installations.get(data.installation_id);
    const now = new Date().toISOString();

    if (existing) {
      existing.account_name = data.account_name;
      existing.updated_at = now;
      return existing;
    }

    const newInstallation: GithubInstallationRow = {
      id: crypto.randomUUID(),
      installation_id: data.installation_id,
      target_type: data.target_type,
      target_id: data.target_id,
      account_name: data.account_name,
      created_at: now,
      updated_at: now,
    };
    this.installations.set(data.installation_id, newInstallation);
    return newInstallation;
  }

  async deleteInstallation(installationId: number): Promise<boolean> {
    return this.installations.delete(installationId);
  }

  async getInstallationByGithubId(installationId: number): Promise<GithubInstallationRow | null> {
    return this.installations.get(installationId) || null;
  }

  async getInstallation(ref: string | number): Promise<GithubInstallationRow | null> {
    if (typeof ref === "number") {
      return this.installations.get(ref) || null;
    }
    const parsedNum = Number(ref);
    if (!Number.isNaN(parsedNum) && this.installations.has(parsedNum)) {
      return this.installations.get(parsedNum)!;
    }
    return Array.from(this.installations.values()).find((i) => i.id === ref) || null;
  }

  // Repositories Operations
  async upsertRepository(data: {
    id?: string;
    installation_id: string;
    github_repo_id: number;
    name: string;
    full_name: string;
    private: boolean;
    default_branch: string;
  }): Promise<RepositoryRow> {
    const existing = Array.from(this.repositories.values()).find(
      (r) => r.github_repo_id === data.github_repo_id
    );
    const now = new Date().toISOString();

    if (existing) {
      existing.name = data.name;
      existing.full_name = data.full_name;
      existing.private = data.private;
      existing.default_branch = data.default_branch;
      existing.updated_at = now;
      return existing;
    }

    const newRepo: RepositoryRow = {
      id: data.id || crypto.randomUUID(),
      installation_id: data.installation_id,
      github_repo_id: data.github_repo_id,
      name: data.name,
      full_name: data.full_name,
      private: data.private,
      default_branch: data.default_branch,
      created_at: now,
      updated_at: now,
    };
    this.repositories.set(newRepo.id, newRepo);
    return newRepo;
  }

  async getRepositoryById(id: string): Promise<RepositoryRow | null> {
    return this.repositories.get(id) || null;
  }

  async getRepositoryByGithubId(githubRepoId: number): Promise<RepositoryRow | null> {
    return Array.from(this.repositories.values()).find((r) => r.github_repo_id === githubRepoId) || null;
  }

  async getRepositoryByFullName(fullName: string): Promise<RepositoryRow | null> {
    return Array.from(this.repositories.values()).find((r) => r.full_name === fullName) || null;
  }

  // Scans Operations
  async createScan(data: {
    id?: string;
    repository_id: string;
    status: ScanRow["status"];
    trigger_type: "manual" | "webhook_push" | "webhook_pr";
    commit_sha: string;
    branch: string;
    triggered_by_user_id?: string | null;
  }): Promise<ScanRow> {
    const newScan: ScanRow = {
      id: data.id || crypto.randomUUID(),
      repository_id: data.repository_id,
      status: data.status,
      trigger_type: data.trigger_type,
      commit_sha: data.commit_sha,
      branch: data.branch,
      triggered_by_user_id: data.triggered_by_user_id,
      started_at: new Date().toISOString(),
    };
    this.scans.set(newScan.id, newScan);
    return newScan;
  }

  async getScanById(id: string): Promise<ScanRow | null> {
    return this.scans.get(id) || null;
  }

  async getScansForRepository(repositoryId: string): Promise<ScanRow[]> {
    return Array.from(this.scans.values()).filter((s) => s.repository_id === repositoryId);
  }

  async updateScanStatus(
    scanId: string,
    status: ScanRow["status"],
    errorMessage?: string
  ): Promise<void> {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.status = status;
      if (status === "done" || status === "completed" || status === "failed") {
        scan.completed_at = new Date().toISOString();
      }
      if (errorMessage !== undefined) {
        scan.error_message = errorMessage;
      }
    }
  }

  async getScanStatus(scanId: string): Promise<{ status: JobStatus; errorMessage?: string }> {
    const scan = this.scans.get(scanId);
    if (!scan) return { status: "queued" };
    return {
      status: scan.status as JobStatus,
      errorMessage: scan.error_message || undefined,
    };
  }

  async saveScanFindings(scanId: string, findings: Finding[]): Promise<void> {
    for (const f of findings) {
      await this.createFinding({
        ...f,
        scan_id: scanId,
      });
    }
  }

  // Findings Operations
  async createFinding(data: Omit<FindingRow, "db_id"> & { db_id?: string }): Promise<FindingRow> {
    const newFinding: FindingRow = {
      ...data,
      db_id: data.db_id || crypto.randomUUID(),
    };
    this.findings.set(newFinding.db_id, newFinding);
    return newFinding;
  }

  async getFindingById(id: string): Promise<FindingRow | null> {
    return (
      this.findings.get(id) ||
      Array.from(this.findings.values()).find((f) => f.db_id === id || f.id === id) ||
      null
    );
  }

  async getFindingsForScan(scanId: string): Promise<FindingRow[]> {
    return Array.from(this.findings.values()).filter((f) => f.scan_id === scanId);
  }

  // Access Control Operations
  grantRepoAccess(userId: string, repoId: string): void {
    this.userRepoAccess.add(`${userId}:${repoId}`);
  }

  revokeRepoAccess(userId: string, repoId: string): void {
    this.userRepoAccess.delete(`${userId}:${repoId}`);
  }

  revokeAllAccessForUser(userId: string): void {
    for (const key of Array.from(this.userRepoAccess.keys())) {
      if (key.startsWith(`${userId}:`)) {
        this.userRepoAccess.delete(key);
      }
    }
  }

  async checkUserRepoAccess(userId: string, repoId: string): Promise<boolean> {
    return this.userRepoAccess.has(`${userId}:${repoId}`);
  }

  async getUserAccessibleRepositories(userId: string): Promise<RepositoryRow[]> {
    const accessible: RepositoryRow[] = [];
    for (const repo of this.repositories.values()) {
      if (this.userRepoAccess.has(`${userId}:${repo.id}`)) {
        accessible.push(repo);
      }
    }
    return accessible;
  }

  // Audit Log Operations
  async createAuditLog(
    entry:
      | Omit<AuditLogRow, "id" | "timestamp">
      | { userId: string; repoId: string; action: string; tokenId: string; timestamp?: string }
  ): Promise<AuditLogRow> {
    if ("userId" in entry) {
      const newEntry: AuditLogRow = {
        id: crypto.randomUUID(),
        user_id: entry.userId,
        action: entry.action,
        target_resource: entry.repoId,
        ip_address: "127.0.0.1",
        user_agent: "nantis-worker",
        timestamp: entry.timestamp || new Date().toISOString(),
        details: { tokenId: entry.tokenId },
      };
      this.auditLogs.push(newEntry);
      return newEntry;
    }

    const newEntry: AuditLogRow = {
      ...entry,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.push(newEntry);
    return newEntry;
  }

  async getAuditLogs(): Promise<AuditLogRow[]> {
    return [...this.auditLogs];
  }

  // False Positive Report Operations
  async createFalsePositiveReport(data: {
    rule_id: string;
    fingerprint: string;
    user_note: string;
    user_id?: string | null;
  }): Promise<FalsePositiveReportRow> {
    const report: FalsePositiveReportRow = {
      id: crypto.randomUUID(),
      rule_id: data.rule_id,
      fingerprint: data.fingerprint,
      user_note: data.user_note,
      user_id: data.user_id || null,
      created_at: new Date().toISOString(),
    };
    this.falsePositiveReports.set(report.id, report);
    return report;
  }

  async getFalsePositiveReports(): Promise<FalsePositiveReportRow[]> {
    return Array.from(this.falsePositiveReports.values());
  }

  // Finding Labels Operations
  async setFindingLabel(data: {
    user_id: string;
    finding_id: string;
    repo_full_name: string;
    rule_id: string;
    file: string;
    line: number;
    label: "real_issue" | "false_positive" | "not_sure";
  }): Promise<FindingLabelRow> {
    const key = `${data.user_id}:${data.finding_id}`;
    const existing = this.findingLabels.get(key);
    const now = new Date().toISOString();

    if (existing) {
      existing.label = data.label;
      existing.created_at = now;
      return existing;
    }

    const row: FindingLabelRow = {
      id: crypto.randomUUID(),
      user_id: data.user_id,
      finding_id: data.finding_id,
      repo_full_name: data.repo_full_name,
      rule_id: data.rule_id,
      file: data.file,
      line: data.line,
      label: data.label,
      created_at: now,
    };
    this.findingLabels.set(key, row);
    return row;
  }

  async getFindingLabel(userId: string, findingId: string): Promise<FindingLabelRow | null> {
    return this.findingLabels.get(`${userId}:${findingId}`) || null;
  }

  async getFindingLabelsForRepo(userId: string, repoFullName: string): Promise<FindingLabelRow[]> {
    return Array.from(this.findingLabels.values()).filter(
      (l) => l.user_id === userId && l.repo_full_name.toLowerCase() === repoFullName.toLowerCase()
    );
  }

  async exportFindingLabelsJson(userId: string, repoFullName?: string): Promise<string> {
    const labels = Array.from(this.findingLabels.values()).filter(
      (l) => l.user_id === userId && (!repoFullName || l.repo_full_name.toLowerCase() === repoFullName.toLowerCase())
    );
    return JSON.stringify(labels, null, 2);
  }

  // Utility reset for testing
  resetInMemoryData() {
    this.users.clear();
    this.installations.clear();
    this.repositories.clear();
    this.scans.clear();
    this.findings.clear();
    this.falsePositiveReports.clear();
    this.findingLabels.clear();
    this.userRepoAccess.clear();
    this.auditLogs = [];
  }
}

export const db = new DatabaseClient();
