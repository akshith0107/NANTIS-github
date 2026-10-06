export interface RuleExplanation {
  ruleId: string;
  title: string;
  whatsWrong: string;
  howStrangerCouldAbuseIt: string;
  howToFixIt: string;
}

export const RULE_EXPLANATIONS: Record<string, RuleExplanation> = {
  "api-route-no-auth": {
    ruleId: "api-route-no-auth",
    title: "API Route Missing Authentication Check",
    whatsWrong:
      "Route handler executes state mutations or retrieves sensitive data without verifying user session authentication.",
    howStrangerCouldAbuseIt:
      "An unauthenticated caller can issue HTTP requests directly to the endpoint to read or modify database records.",
    howToFixIt:
      "Validate user authentication at the beginning of the handler using getServerSession(), auth.getUser(), or an explicit session guard.",
  },
  "server-action-no-auth": {
    ruleId: "server-action-no-auth",
    title: "Server Action Missing Authentication Check",
    whatsWrong:
      "Next.js Server Action ('use server') executes database writes or state changes without validating caller identity.",
    howStrangerCouldAbuseIt:
      "An attacker can invoke the exported server action directly over RPC, bypassing client-side UI authorization checks.",
    howToFixIt:
      "Validate caller identity and session tokens at the top of the server action function before performing operations.",
  },
  "middleware-matcher-gap": {
    ruleId: "middleware-matcher-gap",
    title: "Middleware Matcher Excludes Sensitive Route Handler",
    whatsWrong:
      "Route handler path is excluded from middleware config.matcher patterns and lacks an in-route authentication check.",
    howStrangerCouldAbuseIt:
      "An unauthenticated caller can bypass middleware protection because the route path is excluded from matcher coverage.",
    howToFixIt:
      "Update config.matcher in middleware.ts to include the route path prefix or add local session validation within the route handler.",
  },
  "missing-ownership-check": {
    ruleId: "missing-ownership-check",
    title: "Database Query Missing User Ownership Filter",
    whatsWrong:
      "Database query filters strictly by resource ID extracted from request params without verifying ownership against the authenticated user's ID.",
    howStrangerCouldAbuseIt:
      "An attacker can substitute arbitrary resource IDs (IDOR) to view or modify records belonging to other tenants or users.",
    howToFixIt:
      "Include .eq('user_id', session.userId) or .eq('tenant_id', session.tenantId) in database query conditions.",
  },
  "mass-assignment": {
    ruleId: "mass-assignment",
    title: "Mass Assignment Vulnerability in DB Write",
    whatsWrong:
      "Unvalidated request JSON body is passed directly into a database insert or update operation.",
    howStrangerCouldAbuseIt:
      "An attacker can inject unexpected fields (such as role: 'admin' or is_verified: true) into the payload to override sensitive record fields.",
    howToFixIt:
      "Validate request payloads with Zod schema parsing (schema.parse(body)) or explicitly extract allowed properties into a whitelisted object.",
  },
  "missing-rls-in-migration": {
    ruleId: "missing-rls-in-migration",
    title: "Row Level Security (RLS) Not Enabled in Table Migration",
    whatsWrong:
      "Database migration creates or alters a table without issuing ALTER TABLE ... ENABLE ROW LEVEL SECURITY.",
    howStrangerCouldAbuseIt:
      "If Row Level Security is disabled, PostgREST API requests can bypass table access policies and read or write table data.",
    howToFixIt:
      "Execute ALTER TABLE tablename ENABLE ROW LEVEL SECURITY; in the database migration file.",
  },
  "supabase-permissive-policy": {
    ruleId: "supabase-permissive-policy",
    title: "Supabase RLS Policy Uses Permissive Condition (USING true)",
    whatsWrong:
      "Supabase RLS policy uses USING (true) or WITH CHECK (true) for database operations.",
    howStrangerCouldAbuseIt:
      "Any client with a public anon key can read, update, or delete records in the table without restriction.",
    howToFixIt:
      "Replace (true) with explicit user condition checks such as auth.uid() = user_id.",
  },
  "supabase-service-role-leak": {
    ruleId: "supabase-service-role-leak",
    title: "Supabase Service-Role Key Exposed in Client Code",
    whatsWrong:
      "SUPABASE_SERVICE_ROLE_KEY is referenced in client component code or public API routes.",
    howStrangerCouldAbuseIt:
      "Callers obtaining the service role key can bypass all RLS policies and execute administrative queries against the database.",
    howToFixIt:
      "Keep SUPABASE_SERVICE_ROLE_KEY exclusively on server-side background processors and use anon/user keys for client interactions.",
  },
  "supabase-storage-public-or-unprotected": {
    ruleId: "supabase-storage-public-or-unprotected",
    title: "Supabase Storage Bucket Public or Lacks RLS Policies",
    whatsWrong:
      "Supabase storage bucket is configured as public or lacks RLS access policies.",
    howStrangerCouldAbuseIt:
      "Unauthenticated users can list, download, or overwrite objects stored in the bucket.",
    howToFixIt:
      "Set public: false on private storage buckets and define RLS storage policies on storage.objects.",
  },
  "stripe-webhook-no-signature": {
    ruleId: "stripe-webhook-no-signature",
    title: "Stripe Webhook Missing Signature Verification",
    whatsWrong:
      "Stripe webhook route processes incoming events without calling stripe.webhooks.constructEvent().",
    howStrangerCouldAbuseIt:
      "An attacker can forge fake webhook payloads (such as checkout.session.completed) to trigger unauthorized account provisioning or order fulfillment.",
    howToFixIt:
      "Pass raw request body and stripe-signature header to stripe.webhooks.constructEvent() before handling event objects.",
  },
  "stripe-webhook-parsed-body": {
    ruleId: "stripe-webhook-parsed-body",
    title: "Stripe Webhook Verifies Parsed Body Instead of Raw Payload",
    whatsWrong:
      "Stripe webhook constructEvent() is called with parsed JSON or re-serialized body string instead of raw request body.",
    howStrangerCouldAbuseIt:
      "Re-serializing JSON alters whitespace and formatting, causing signature verification to fail or accept tampered events.",
    howToFixIt:
      "Read the raw unparsed payload using await req.text() or buffer and pass it directly to constructEvent().",
  },
  "stripe-user-controlled-price": {
    ruleId: "stripe-user-controlled-price",
    title: "User-Controlled Price Parameter in Stripe Checkout",
    whatsWrong:
      "Price or unit_amount passed to Stripe Checkout or PaymentIntent is taken directly from user request input without database price verification.",
    howStrangerCouldAbuseIt:
      "An attacker can modify unit_amount in HTTP requests to set arbitrary prices (such as $0.01) for items.",
    howToFixIt:
      "Fetch item prices from database (dbProduct.price) on the server rather than trusting client-provided amounts.",
  },
  "stripe-secret-key-client-leak": {
    ruleId: "stripe-secret-key-client-leak",
    title: "Stripe Secret Key Accessible in Client Bundle",
    whatsWrong:
      "STRIPE_SECRET_KEY is exported or bundled into client-side Next.js code ('use client').",
    howStrangerCouldAbuseIt:
      "Anyone inspecting client JavaScript bundles can extract the secret key and issue administrative API requests to Stripe.",
    howToFixIt:
      "Use NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY on client components and keep STRIPE_SECRET_KEY strictly in server-side handlers.",
  },
  "use-client-secret-leak": {
    ruleId: "use-client-secret-leak",
    title: "Client Component Imports Private Server Secret",
    whatsWrong:
      "Client component ('use client') imports or references private server environment variables.",
    howStrangerCouldAbuseIt:
      "Bundled JavaScript exposes private environment variables to client browsers.",
    howToFixIt:
      "Move secret logic to server components or API routes and reference only NEXT_PUBLIC_ prefixed variables on the client.",
  },
  "hardcoded-secret": {
    ruleId: "hardcoded-secret",
    title: "Hardcoded API Key or Secret Credential",
    whatsWrong:
      "Hardcoded API keys, private keys, or tokens embedded in source code files.",
    howStrangerCouldAbuseIt:
      "Source code exposure or repository leaks grant unauthorized access to external services.",
    howToFixIt:
      "Move credentials to environment variables (.env) and access them via process.env.",
  },
  "committed-env-file": {
    ruleId: "committed-env-file",
    title: "Committed Environment Credentials File",
    whatsWrong:
      ".env or .env.local containing credentials committed to version control.",
    howStrangerCouldAbuseIt:
      "Anyone with repository read access can obtain production credentials and API keys.",
    howToFixIt:
      "Add .env patterns to .gitignore and remove committed credential files from repository history.",
  },
  "cookie-missing-flags": {
    ruleId: "cookie-missing-flags",
    title: "Session Cookie Missing Recommended Attributes",
    whatsWrong:
      "Session cookies created without HttpOnly, SameSite, or transport encryption flags.",
    howStrangerCouldAbuseIt:
      "Absence of HttpOnly permits client-side script token theft via XSS; missing SameSite enables CSRF attacks.",
    howToFixIt:
      "Configure cookie options with httpOnly: true, sameSite: 'lax' (or 'strict'), and secure: true.",
  },
  "permissive-cors": {
    ruleId: "permissive-cors",
    title: "Permissive Cross-Origin Resource Sharing (CORS) Header",
    whatsWrong:
      "CORS response header set to Access-Control-Allow-Origin: * on authenticated API endpoints.",
    howStrangerCouldAbuseIt:
      "External websites can issue cross-origin requests to read response data from authenticated user sessions.",
    howToFixIt:
      "Set Access-Control-Allow-Origin to specific trusted origin domains.",
  },
  "debug-mode-production": {
    ruleId: "debug-mode-production",
    title: "Debug Verbosity or Stack Traces Enabled in Production",
    whatsWrong:
      "Application debug mode or verbose logging enabled in production configurations.",
    howStrangerCouldAbuseIt:
      "Error stack traces and debug output expose internal system paths and database schemas to callers.",
    howToFixIt:
      "Set NODE_ENV=production and disable debug verbosity flags.",
  },
  "ci-overbroad-permissions": {
    ruleId: "ci-overbroad-permissions",
    title: "CI Workflow Specifies Overbroad Job Permissions",
    whatsWrong:
      "GitHub Actions workflow specifies permissions: write-all or lacks scoped job permissions.",
    howStrangerCouldAbuseIt:
      "Compromised workflow steps or pull requests can abuse repository write privileges to modify code or releases.",
    howToFixIt:
      "Declare minimal required permissions per job (such as permissions: { contents: 'read' }).",
  },
  "ci-unpinned-action": {
    ruleId: "ci-unpinned-action",
    title: "Unpinned Third-Party GitHub Action",
    whatsWrong:
      "Third-party GitHub Action referenced by mutable tag (@v1) instead of immutable commit SHA.",
    howStrangerCouldAbuseIt:
      "An attacker compromising the action maintainer account can overwrite the release tag with malicious code.",
    howToFixIt:
      "Pin third-party actions to full 40-character commit SHAs (e.g. @a81bbbf8298c0fa036f9e625293d49e214...).",
  },
  "ci-pull-request-target-checkout": {
    ruleId: "ci-pull-request-target-checkout",
    title: "Pull Request Target Trigger Checks Out Untrusted Code",
    whatsWrong:
      "GitHub Actions workflow uses pull_request_target trigger and checks out untrusted PR code.",
    howStrangerCouldAbuseIt:
      "Forked pull requests can execute malicious code with write permissions and access repository secrets.",
    howToFixIt:
      "Avoid checking out untrusted PR head commits in pull_request_target workflows or use standard pull_request triggers.",
  },
  "ci-secrets-echoed": {
    ruleId: "ci-secrets-echoed",
    title: "CI Workflow Script Echoes Secret Variables",
    whatsWrong:
      "CI workflow script echoes or logs secret environment variables to build output.",
    howStrangerCouldAbuseIt:
      "Anyone viewing CI build logs can read plain-text secret tokens.",
    howToFixIt:
      "Remove echo statements containing secret variables from workflow run steps.",
  },
  "test-gap-high-churn-untested": {
    ruleId: "test-gap-high-churn-untested",
    title: "Critical Module Has High Change Frequency But No Unit Tests",
    whatsWrong:
      "Critical auth, payment, RLS, or webhook module has high git commit change frequency but zero test files referencing it.",
    howStrangerCouldAbuseIt:
      "Frequent modifications to critical paths without automated test coverage increase the risk of introducing regression flaws unnoticed.",
    howToFixIt:
      "Add automated unit/integration tests targeting the critical module.",
  },
};

export function getRuleExplanation(ruleId: string): RuleExplanation {
  return (
    RULE_EXPLANATIONS[ruleId] || {
      ruleId,
      title: `Rule ${ruleId}`,
      whatsWrong: `Configuration or implementation flaw detected for ${ruleId}.`,
      howStrangerCouldAbuseIt: `An attacker could exploit the missing control to bypass authorization checks.`,
      howToFixIt: `Review implementation against documented access control patterns and add appropriate guards.`,
    }
  );
}
