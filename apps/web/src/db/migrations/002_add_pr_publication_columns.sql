-- Migration 002: Add PR publication columns to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_pr_number INT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_pr_url TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_branch TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS publication_status VARCHAR(32);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS publication_error TEXT;
