-- Migration 001: Initial NANTIS PostgreSQL Schema
-- Canonical database foundation for production persistence

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INT PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 1. Users
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_user_id BIGINT UNIQUE NOT NULL,
  github_login TEXT NOT NULL,
  avatar_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_github_user_id ON users(github_user_id);

-- 2. GitHub Installations
CREATE TABLE IF NOT EXISTS github_installations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT UNIQUE NOT NULL,
  target_type VARCHAR(32) NOT NULL,
  target_id BIGINT NOT NULL,
  account_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_installations_id ON github_installations(installation_id);

-- 3. Repositories
CREATE TABLE IF NOT EXISTS repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id VARCHAR(64) NOT NULL,
  github_repo_id BIGINT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  full_name TEXT UNIQUE NOT NULL,
  private BOOLEAN NOT NULL DEFAULT false,
  default_branch TEXT NOT NULL DEFAULT 'main',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_repositories_github_repo_id ON repositories(github_repo_id);
CREATE INDEX IF NOT EXISTS idx_repositories_full_name ON repositories(full_name);

-- 4. Scans
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  status VARCHAR(32) NOT NULL,
  trigger_type VARCHAR(32) NOT NULL,
  commit_sha TEXT NOT NULL,
  branch TEXT NOT NULL,
  triggered_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_repository_id ON scans(repository_id);

-- 5. Findings
CREATE TABLE IF NOT EXISTS findings (
  db_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity VARCHAR(32) NOT NULL,
  confidence_tier VARCHAR(32) NOT NULL DEFAULT 'needs-review',
  file TEXT NOT NULL,
  start_line INT NOT NULL,
  end_line INT NOT NULL,
  explanation TEXT NOT NULL,
  evidence_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
  unresolved_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
  fingerprint TEXT NOT NULL,
  code_snippet TEXT,
  remediation_patch JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);

-- 6. Scan Diagnostics
CREATE TABLE IF NOT EXISTS scan_diagnostics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind VARCHAR(32) NOT NULL,
  detector_id TEXT,
  detector_name TEXT,
  rule_ids JSONB DEFAULT '[]'::jsonb,
  message TEXT NOT NULL,
  fatal BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_diagnostics_scan_id ON scan_diagnostics(scan_id);

-- 7. User Repository Access
CREATE TABLE IF NOT EXISTS user_repo_access (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_user_repo UNIQUE(user_id, repository_id)
);

CREATE INDEX IF NOT EXISTS idx_user_repo_access_user_id ON user_repo_access(user_id);

-- 8. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT,
  action TEXT NOT NULL,
  target_resource TEXT NOT NULL,
  ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
  user_agent TEXT NOT NULL DEFAULT 'nantis',
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- 9. False Positive Reports
CREATE TABLE IF NOT EXISTS false_positive_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  user_note TEXT NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 10. Finding Labels
CREATE TABLE IF NOT EXISTS finding_labels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  repo_full_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  file TEXT NOT NULL,
  line INT NOT NULL,
  label VARCHAR(32) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_user_finding_label UNIQUE(user_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_labels_user ON finding_labels(user_id);

-- 11. User Repo Access Snapshots
CREATE TABLE IF NOT EXISTS user_repo_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  github_repo_id BIGINT NOT NULL,
  repo_name TEXT NOT NULL,
  full_name TEXT NOT NULL,
  installation_id BIGINT NOT NULL,
  private BOOLEAN NOT NULL DEFAULT false,
  html_url TEXT,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT unique_user_github_repo_snapshot UNIQUE(user_id, github_repo_id)
);

CREATE INDEX IF NOT EXISTS idx_user_repo_snapshots_user ON user_repo_snapshots(user_id);

-- 12. User Installations
CREATE TABLE IF NOT EXISTS user_installations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL,
  html_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_user_installation UNIQUE(user_id, installation_id)
);

-- 13. Anonymous Rate Limits
CREATE TABLE IF NOT EXISTS anonymous_rate_limits (
  key TEXT PRIMARY KEY,
  count INT NOT NULL DEFAULT 1,
  day_start_ms BIGINT NOT NULL
);
