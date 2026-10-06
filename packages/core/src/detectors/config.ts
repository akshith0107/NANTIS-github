import crypto from "crypto";
import { Finding } from "../types.js";

function generateFindingId(): string {
  return crypto.randomUUID();
}

function generateFingerprint(ruleId: string, filePath: string, line: number): string {
  return crypto
    .createHash("sha256")
    .update(`${ruleId}:${filePath.toLowerCase()}:${line}`)
    .digest("hex");
}

export async function detectConfigIssues(files: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [relPath, content] of files.entries()) {
    const normalizedPath = relPath.replace(/\\/g, "/");

    // 1. Check committed source map files
    if (normalizedPath.endsWith(".map")) {
      findings.push({
        id: generateFindingId(),
        ruleId: "committed-source-maps",
        title: "Committed Source Map File",
        severity: "medium",
        confidenceTier: "proven",
        file: normalizedPath,
        lineRange: { startLine: 1, endLine: 1 },
        evidenceChain: [
          {
            kind: "config",
            file: normalizedPath,
            line: 1,
            maskedSnippet: `Source map file: ${normalizedPath}`,
            confidence: "high",
            note: "Source map file committed in repository",
          },
        ],
        unresolvedSteps: [],
        explanation:
          "Source map file (.map) is committed to source control. " +
          "Shipping unminified source maps in production allows attackers to inspect original uncompiled source code and internal comments.",
        fingerprint: generateFingerprint("committed-source-maps", normalizedPath, 1),
      });
    }

    // 2. Cookie missing HttpOnly / Secure / SameSite (parsing complete set statement blocks)
    const cookieSetMatches = Array.from(content.matchAll(/cookies?\.set\s*\([\s\S]*?\)/g));
    for (const match of cookieSetMatches) {
      const statementText = match[0];
      const startIndex = match.index || 0;
      const lineNum = content.substring(0, startIndex).split(/\r?\n/).length;

      const hasHttpOnlyFalse = /httpOnly\s*:\s*false/i.test(statementText);
      const missingHttpOnly = !/httpOnly\s*:\s*true/i.test(statementText);
      const missingSecure = !/secure\s*:\s*true/i.test(statementText);

      if (hasHttpOnlyFalse || missingHttpOnly || missingSecure) {
        findings.push({
          id: generateFindingId(),
          ruleId: "cookie-missing-flags",
          title: "Cookie Set Without HttpOnly/Secure Security Flags",
          severity: "high",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: lineNum, endLine: lineNum },
          evidenceChain: [
            {
              kind: "sink",
              file: normalizedPath,
              line: lineNum,
              maskedSnippet: statementText.replace(/\s+/g, " ").trim(),
              confidence: "high",
              note: "Cookie configured without required security flags",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Missing httpOnly allows client-side JavaScript (e.g. via XSS) to read session cookies, " +
            "while missing secure transmits cookies over unencrypted HTTP, and missing sameSite leaves session cookies exposed to CSRF attacks.",
          fingerprint: generateFingerprint("cookie-missing-flags", normalizedPath, lineNum),
        });
      }
    }

    const lines = content.split(/\r?\n/);
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;

      // 3. Permissive CORS (wildcard or reflected origin)
      if (
        lineText.includes("Access-Control-Allow-Origin") &&
        (lineText.includes("*") ||
          lineText.includes("req.headers") ||
          lineText.includes("request.headers"))
      ) {
        findings.push({
          id: generateFindingId(),
          ruleId: "permissive-cors",
          title: "Permissive CORS Policy (Wildcard or Reflected Origin)",
          severity: "high",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: lineNum, endLine: lineNum },
          evidenceChain: [
            {
              kind: "config",
              file: normalizedPath,
              line: lineNum,
              maskedSnippet: lineText.trim(),
              confidence: "high",
              note: "Permissive CORS header configuration",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Wildcard or reflected origins allow untrusted third-party websites to make authenticated cross-origin requests " +
            "and read sensitive API responses from users' browsers.",
          fingerprint: generateFingerprint("permissive-cors", normalizedPath, lineNum),
        });
      }

      // 4. Debug mode / verbose errors in production config
      if (
        (/debug\s*:\s*true/i.test(lineText) ||
          /NODE_ENV\s*:\s*["']development["']/i.test(lineText)) &&
        !lineText.includes("//")
      ) {
        findings.push({
          id: generateFindingId(),
          ruleId: "debug-mode-production",
          title: "Debug Mode or Development Config Enabled",
          severity: "medium",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: lineNum, endLine: lineNum },
          evidenceChain: [
            {
              kind: "config",
              file: normalizedPath,
              line: lineNum,
              maskedSnippet: lineText.trim(),
              confidence: "high",
              note: "Development or debug mode enabled in configuration",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Enabling debug mode or verbose error reporting in production exposes sensitive internal stack traces, " +
            "database schema details, and environment state to external callers.",
          fingerprint: generateFingerprint("debug-mode-production", normalizedPath, lineNum),
        });
      }

      // 5. Next.js productionBrowserSourceMaps: true
      if (lineText.includes("productionBrowserSourceMaps") && lineText.includes("true")) {
        findings.push({
          id: generateFindingId(),
          ruleId: "committed-source-maps",
          title: "Next.js Production Browser Source Maps Enabled",
          severity: "medium",
          confidenceTier: "proven",
          file: normalizedPath,
          lineRange: { startLine: lineNum, endLine: lineNum },
          evidenceChain: [
            {
              kind: "config",
              file: normalizedPath,
              line: lineNum,
              maskedSnippet: lineText.trim(),
              confidence: "high",
              note: "productionBrowserSourceMaps set to true",
            },
          ],
          unresolvedSteps: [],
          explanation:
            "Shipping unminified source maps in production allows attackers to reverse-engineer server component business logic, " +
            "internal comments, and uncompiled source code.",
          fingerprint: generateFingerprint("committed-source-maps", normalizedPath, lineNum),
        });
      }
    });
  }

  return findings;
}
