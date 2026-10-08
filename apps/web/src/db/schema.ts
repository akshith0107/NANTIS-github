import { Finding } from "@nantis/core";

export interface UserRow {
  id: string; // UUID
  github_user_id: number;
  github_login: string;
  avatar_url: string;
  created_at: string;
  updated_at: string;
}

export interface GithubInstallationRow {
  id: string; // UUID
  installation_id: number;
  target_type: "User" | "Organization";
  target_id: number;
  account_name: string;
  created_at: string;
  updated_at: string;
}

export interface RepositoryRow {
  id: string; // UUID
  installation_id: string;
  github_repo_id: number;
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  created_at: string;
  updated_at: string;
}

export interface ScanRow {
  id: string; // UUID
  repository_id: string;
  status:
    "queued" | "cloning" | "scanning" | "done" | "failed" | "pending" | "running" | "completed";
  trigger_type: "manual" | "webhook_push" | "webhook_pr";
  commit_sha: string;
  branch: string;
  triggered_by_user_id?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
}

export interface FindingRow extends Finding {
  db_id: string;
  scan_id: string;
}

export interface AuditLogRow {
  id: string; // UUID
  user_id?: string | null;
  action: string;
  target_resource: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  details: Record<string, unknown>;
}

export interface FalsePositiveReportRow {
  id: string; // UUID
  rule_id: string;
  fingerprint: string;
  user_note: string;
  user_id?: string | null;
  created_at: string;
}

export interface FindingLabelRow {
  id: string;
  user_id: string;
  finding_id: string;
  repo_full_name: string;
  rule_id: string;
  file: string;
  line: number;
  label: "real_issue" | "false_positive" | "not_sure";
  created_at: string;
}

export interface UserRepoSnapshotRow {
  id: string;
  user_id: string;
  github_repo_id: number;
  repo_name: string;
  full_name: string;
  installation_id: number;
  private: boolean;
  html_url?: string;
  fetched_at: string;
  expires_at: string;
}

export interface UserInstallationRow {
  id: string;
  user_id: string;
  installation_id: number;
  html_url?: string;
  created_at: string;
}
