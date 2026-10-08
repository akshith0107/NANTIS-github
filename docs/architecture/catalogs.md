# NANTIS Security Catalogs Architecture & Specification

## 1. Overview & Objectives

NANTIS uses **versioned data-driven security catalogs** (JSON / YAML validated via Zod schemas) instead of hardcoded detector logic.

Catalogs decouple framework-specific metadata (such as Next.js route handlers, Server Actions, Middleware matchers, Supabase client calls, and Stripe webhook verification) from core AST analysis algorithms. This allows security rules to be updated, versioned, and extended across framework upgrades without requiring codebase refactoring.

---

## 2. Catalog Schema Specification

Every catalog file MUST strictly conform to the `CatalogSchema` Zod validation definition.

### 2.1 Metadata & Versioning

- `version` (string, required): Schema version string using Semantic Versioning (e.g., `"1.0.0"`).
- `lastUpdated` (string, required): ISO 8601 timestamp string of the last catalog revision.
- `frameworkVersions` (object, required): Targeted framework version ranges that the catalog definitions were designed for:
  - `next`: e.g. `"^14.0.0 || ^15.0.0"`
  - `supabase`: e.g. `"^2.0.0"`
  - `stripe`: e.g. `"^14.0.0 || ^15.0.0"`

### 2.2 Categories

1. **`frameworkEntryPoints`**:
   Definitions for application entry points where external HTTP requests or user executions enter the application.
   - `id` (string): Unique identifier (e.g., `"nextjs-app-router-handler"`).
   - `kind`: `"route-handler"` | `"server-action"` | `"middleware"` | `"page-component"`.
   - `pattern`: File path glob pattern or AST signature (e.g., `"app/api/**/route.(ts|js|tsx|jsx)"`, `"use server"` directive).
   - `methods`: Array of supported HTTP methods (e.g., `["GET", "POST", "PUT", "DELETE"]`).

2. **`sources`**:
   Definitions for taint sources where untrusted user input enters execution scope.
   - `id` (string): Unique identifier (e.g., `"nextjs-request-params"`).
   - `name` (string): Human-readable source description.
   - `category`: `"query-param"` | `"route-param"` | `"request-body"` | `"request-header"` | `"cookie"` | `"webhook-payload"`.
   - `pattern`: Symbol or AST access pattern (e.g., `req.nextUrl.searchParams`, `params.<id>`, `req.json()`).

3. **`sinks`**:
   Definitions for security-sensitive operations (sinks) requiring guards or authorization checks.
   - `id` (string): Unique identifier (e.g., `"supabase-rls-bypass-sink"`).
   - `name` (string): Human-readable sink name.
   - `category`: `"database"` | `"payment"` | `"secret-leak"` | `"code-execution"` | `"auth-bypass"`.
   - `pattern`: Symbol or AST call pattern (e.g., `supabase.from()`, `stripe.paymentIntents.create()`, `new Stripe()`).
   - `requiredGuards`: Array of required guard catalog IDs (e.g., `["stripe-signature-guard"]`, `["supabase-user-auth-guard"]`).

4. **`sanitizersValidators`**:
   Definitions for data sanitizers, schema validators, and signature checkers.
   - `id` (string): Unique identifier (e.g., `"stripe-webhook-signature-verifier"`).
   - `name` (string): Human-readable sanitizer name.
   - `kind`: `"signature-verifier"` | `"schema-validator"` | `"sanitizer-function"`.
   - `pattern`: Symbol pattern (e.g., `stripe.webhooks.constructEvent`, `zod.parse`).

5. **`authGuards`**:
   Definitions for authentication/authorization checks that protect routes and operations.
   - `id` (string): Unique identifier (e.g., `"supabase-get-user-auth"`).
   - `name` (string): Human-readable auth guard name.
   - `pattern`: Symbol or function pattern (e.g., `supabase.auth.getUser()`, `assertRepoAccess()`, `getServerSession()`).

---

## 3. Data Format Example (Next.js & Supabase/Stripe)

```json
{
  "version": "1.0.0",
  "lastUpdated": "2026-10-04T00:00:00Z",
  "frameworkVersions": {
    "next": "^14.0.0 || ^15.0.0",
    "supabase": "^2.0.0",
    "stripe": "^14.0.0 || ^15.0.0"
  },
  "frameworkEntryPoints": [
    {
      "id": "nextjs-app-route-handler",
      "kind": "route-handler",
      "pattern": "app/api/**/route.(ts|js|tsx|jsx)",
      "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"]
    },
    {
      "id": "nextjs-server-action",
      "kind": "server-action",
      "pattern": "'use server' || \"use server\"",
      "methods": ["POST"]
    },
    {
      "id": "nextjs-middleware-matcher",
      "kind": "middleware",
      "pattern": "middleware.(ts|js)",
      "methods": ["GET", "POST", "PUT", "DELETE"]
    }
  ],
  "sources": [
    {
      "id": "nextjs-search-params",
      "name": "Next.js URL Search Parameters",
      "category": "query-param",
      "pattern": "req.nextUrl.searchParams"
    },
    {
      "id": "nextjs-request-json",
      "name": "Next.js Request JSON Body",
      "category": "request-body",
      "pattern": "await req.json()"
    }
  ],
  "sinks": [
    {
      "id": "supabase-db-query-sink",
      "name": "Supabase Client Database Query",
      "category": "database",
      "pattern": "supabase.from",
      "requiredGuards": ["supabase-get-user-auth"]
    },
    {
      "id": "stripe-webhook-handler-sink",
      "name": "Stripe Webhook Event Processing",
      "category": "payment",
      "pattern": "app/api/webhooks/stripe",
      "requiredGuards": ["stripe-construct-event-signature-guard"]
    }
  ],
  "sanitizersValidators": [
    {
      "id": "stripe-construct-event-signature-guard",
      "name": "Stripe Webhook Signature Verification",
      "kind": "signature-verifier",
      "pattern": "stripe.webhooks.constructEvent"
    }
  ],
  "authGuards": [
    {
      "id": "supabase-get-user-auth",
      "name": "Supabase Get User Authentication",
      "pattern": "supabase.auth.getUser"
    },
    {
      "id": "nantis-assert-repo-access",
      "name": "NANTIS Tenant Access Control Guard",
      "pattern": "assertRepoAccess"
    }
  ]
}
```

---

## 4. Loader & Zod Validation Lifecycle

```
JSON Catalog Data -> Zod Schema Validation (`CatalogSchema.parse()`) -> Typed Catalog Memory Object
```

1. **Load**: `loadCatalog(jsonOrObj)` parses catalog data.
2. **Validate**: `CatalogSchema.parse()` verifies schema structure, versioning, framework version compatibility, and category arrays.
3. **Fail-Fast**: Any missing required fields, illegal category values, or invalid pattern syntax cause `ZodError` exceptions immediately at load time.
