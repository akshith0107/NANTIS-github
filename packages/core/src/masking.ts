/**
 * Secret masking utilities to prevent secret leakage in findings, logs, outputs, and PR text.
 * Enforces Rule 3: Mask secrets everywhere.
 */

const MASK_REPLACEMENT = "[REDACTED_SECRET]";

export function maskSecrets(input: string): string {
  let masked = input;

  // Mask specific token patterns
  masked = masked.replace(/\b(sk_live_[0-9a-zA-Z_]{16,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(sk_test_[0-9a-zA-Z_]{16,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(rk_live_[0-9a-zA-Z_]{16,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(rk_test_[0-9a-zA-Z_]{16,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(sbp_[a-f0-9_]{32,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(
    /postgres:\/\/[^:]+:[^@]+@[^\s"']+/g,
    "postgres://[REDACTED]:[REDACTED]@[REDACTED]"
  );
  masked = masked.replace(/\b(ghp_[a-zA-Z0-9_]{30,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(gho_[a-zA-Z0-9_]{30,})\b/g, MASK_REPLACEMENT);
  masked = masked.replace(/\b(github_pat_[a-zA-Z0-9_]{20,})\b/g, MASK_REPLACEMENT);

  // Mask assignment values for key/secret patterns
  masked = masked.replace(
    /((?:api[_-]?key|secret|token|password|auth|jwt)\s*[:=]\s*["'])([^"']+)(["'])/gi,
    `$1${MASK_REPLACEMENT}$3`
  );

  return masked;
}
