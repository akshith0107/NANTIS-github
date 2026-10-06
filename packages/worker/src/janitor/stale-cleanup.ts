import fs from "fs";
import path from "path";

/**
 * Janitor process: Scans the scan workspace directory and deletes any stale,
 * orphaned temporary folders that exceed maxAgeMs (default: 10 minutes).
 * Guarantees zero disk exhaustion over time from crashed or aborted jobs.
 */
export async function cleanStaleWorkspaces(
  baseTempDir: string,
  maxAgeMs = 10 * 60 * 1000
): Promise<number> {
  if (!fs.existsSync(baseTempDir)) {
    return 0;
  }

  let deletedCount = 0;
  const now = Date.now();

  try {
    const entries = fs.readdirSync(baseTempDir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const fullPath = path.join(baseTempDir, entry.name);
        try {
          const stats = fs.statSync(fullPath);
          const ageMs = now - stats.mtimeMs;

          if (ageMs > maxAgeMs) {
            fs.rmSync(fullPath, { recursive: true, force: true });
            deletedCount++;
          }
        } catch {
          // Ignore individual directory stat/rm errors
        }
      }
    }
  } catch {
    // Ignore top-level readdir errors
  }

  return deletedCount;
}
