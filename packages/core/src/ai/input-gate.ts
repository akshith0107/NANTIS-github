import { createHash } from "node:crypto";
import { maskSecrets } from "../masking.js";

export interface PreparedLlmContext {
  files: Map<string, string>;
  totalBytes: number;
  truncated: boolean;
  contextFingerprint: string;
}

export interface InputGateLimits {
  maxFiles: number;
  maxBytesPerFile: number;
  maxTotalBytes: number;
}

export const DEFAULT_INPUT_GATE_LIMITS: InputGateLimits = {
  maxFiles: 20,
  maxBytesPerFile: 10000,
  maxTotalBytes: 100000,
};

/**
 * Sanitizes and bounds repository context before sending to LLM.
 */
export class LlmInputGate {
  private limits: InputGateLimits;

  constructor(limits?: Partial<InputGateLimits>) {
    this.limits = { ...DEFAULT_INPUT_GATE_LIMITS, ...limits };
  }

  /**
   * Filters, bounds, and masks repository files for safe LLM ingestion.
   */
  prepareContext(filesMap: Map<string, string>): PreparedLlmContext {
    const preparedFiles = new Map<string, string>();
    let totalBytes = 0;
    let truncated = false;

    // Filter relevant files (API routes, server actions, TS/JS files, SQL migrations)
    const sortedEntries = Array.from(filesMap.entries())
      .map(([path, content]) => ({ path: path.replace(/\\/g, "/"), content }))
      .filter(({ path }) => {
        return (
          path.endsWith(".ts") ||
          path.endsWith(".tsx") ||
          path.endsWith(".js") ||
          path.endsWith(".jsx") ||
          path.endsWith(".sql")
        );
      })
      .sort((a, b) => {
        // Prioritize API routes, server actions, and migrations first
        const scoreA = a.path.includes("route.") || a.path.includes("action") || a.path.endsWith(".sql") ? 0 : 1;
        const scoreB = b.path.includes("route.") || b.path.includes("action") || b.path.endsWith(".sql") ? 0 : 1;
        return scoreA - scoreB;
      });

    for (const { path, content } of sortedEntries) {
      if (preparedFiles.size >= this.limits.maxFiles) {
        truncated = true;
        break;
      }

      // Mask hardcoded secrets/tokens
      let sanitizedContent = maskSecrets(content);

      // Truncate file if over per-file byte limit
      if (sanitizedContent.length > this.limits.maxBytesPerFile) {
        sanitizedContent = sanitizedContent.slice(0, this.limits.maxBytesPerFile) + "\n... [TRUNCATED]";
        truncated = true;
      }

      if (totalBytes + sanitizedContent.length > this.limits.maxTotalBytes) {
        truncated = true;
        break;
      }

      preparedFiles.set(path, sanitizedContent);
      totalBytes += sanitizedContent.length;
    }

    // Hash context deterministically
    const hash = createHash("sha256");
    for (const [p, c] of preparedFiles.entries()) {
      hash.update(`${p}:${c}`, "utf8");
    }
    const contextFingerprint = hash.digest("hex").slice(0, 16);

    return {
      files: preparedFiles,
      totalBytes,
      truncated,
      contextFingerprint,
    };
  }
}
