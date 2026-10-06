import crypto from "crypto";

/**
 * Normalizes source code snippets by stripping comments, extra whitespace,
 * and replacing local variable names with generic tokens while preserving
 * structure, operators, string literals, and API keywords.
 */
export function canonicalizeCodeSnippet(snippet: string): string {
  if (!snippet) return "";

  // 1. Remove line comments (//...) and block comments (/*...*/)
  let cleaned = snippet.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");

  // 2. List of preserved structural / framework / API keywords
  const preservedKeywords = new Set([
    "export",
    "async",
    "function",
    "const",
    "let",
    "var",
    "return",
    "await",
    "if",
    "else",
    "try",
    "catch",
    "POST",
    "GET",
    "PUT",
    "DELETE",
    "PATCH",
    "NextResponse",
    "Request",
    "Response",
    "NextRequest",
    "json",
    "text",
    "insert",
    "update",
    "from",
    "select",
    "eq",
    "where",
    "WHERE",
    "SELECT",
    "FROM",
    "INSERT",
    "UPDATE",
    "stripe",
    "checkout",
    "sessions",
    "create",
    "constructEvent",
    "webhooks",
    "paymentIntents",
    "supabase",
    "createClient",
    "auth",
    "getUser",
    "getSession",
    "storage",
    "process",
    "env",
    "NEXT_PUBLIC_SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "parse",
    "z",
    "object",
    "string",
    "number",
    "boolean",
    "schema",
  ]);

  // Replace variable identifiers with 'VAR', preserving API keywords & uppercase constants
  cleaned = cleaned.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, (match) => {
    if (preservedKeywords.has(match) || match === match.toUpperCase()) {
      return match;
    }
    return "VAR";
  });

  // 3. Normalize whitespace and punctuation spacing
  cleaned = cleaned.replace(/\s*([\.\(\),;\{\}\:=])\s*/g, "$1");
  cleaned = cleaned.replace(/\s+/g, " ").trim();

  return cleaned;
}

/**
 * Computes a resilient fingerprint for a Finding that survives:
 * 1. Code reformatting (whitespace/newlines/comments)
 * 2. Moving code to a different file or path
 * 3. Renaming local variables
 */
export function computeResilientFingerprint(finding: {
  ruleId: string;
  evidenceChain?: Array<{ kind: string; maskedSnippet: string }>;
  explanation?: string;
}): string {
  const ruleId = finding.ruleId || "unknown-rule";

  const snippets = (finding.evidenceChain || [])
    .map((hop) => canonicalizeCodeSnippet(hop.maskedSnippet))
    .filter(Boolean);

  const canonicalContent =
    snippets.length > 0 ? snippets.join("|") : canonicalizeCodeSnippet(finding.explanation || "");

  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${canonicalContent}`)
    .digest("hex")
    .substring(0, 16);

  return `${ruleId}-${hash}`;
}
