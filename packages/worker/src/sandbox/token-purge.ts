import fs from "fs";
import path from "path";

/**
 * Purge any installation tokens or embedded authentication credentials from
 * `.git/config` and temporary credential files inside the target repository workspace.
 * Ensures the token is strictly available ONLY during the initial git clone step.
 */
export function purgeTokenFromWorkspace(targetDir: string): void {
  if (!fs.existsSync(targetDir)) return;

  const gitConfigPath = path.join(targetDir, ".git", "config");
  if (fs.existsSync(gitConfigPath)) {
    try {
      let content = fs.readFileSync(gitConfigPath, "utf-8");

      // Replace x-access-token:<token> or ghs_<token> credentials in remote URLs
      content = content.replace(/https:\/\/(x-access-token:[^@]+|ghs_[^@]+)@/g, "https://");

      fs.writeFileSync(gitConfigPath, content, "utf-8");
    } catch {
      // Ignore git config write errors if directory is read-only
    }
  }

  // Remove any leftover git credential helper files inside workspace
  const gitCredentialsPath = path.join(targetDir, ".git", "credentials");
  if (fs.existsSync(gitCredentialsPath)) {
    try {
      fs.unlinkSync(gitCredentialsPath);
    } catch {
      // Ignore cleanup error
    }
  }
}
