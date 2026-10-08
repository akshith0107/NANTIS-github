# NANTIS — Static Security Analysis Engine & Web Dashboard

NANTIS is a static security analysis suite and local web dashboard designed to detect security anti-patterns, missing authorization checks, misconfigured database migration policies, exposed secret keys, and CI workflow flaws across TypeScript, Next.js, Supabase, Stripe, and project configuration files.

> **Status Notice**: NANTIS is currently a local development tool and prototype static analyzer. It operates using an in-memory database store for local analysis sessions.

---

## 1. What NANTIS Currently Is

NANTIS provides a deterministic static analysis engine, automated AST patch generation for select rules, and an interactive local HTTP dashboard for reviewing security findings.

### Key Capabilities
- **Static AST & Config Analysis**: Analyzes TypeScript source code, Next.js route handlers, Supabase migration SQL, Stripe integration code, package dependencies, and GitHub Actions workflow files.
- **Evidence Chain Builder**: Constructs multi-hop evidence steps tracing findings from source to sink.
- **Credential Redaction**: Automatically redacts recognized API keys, tokens, and credentials in reported code snippets and log outputs.
- **Interactive Finding Classification**: Allows developers to label findings as `Real issue`, `False positive`, or `Not sure`, and export labeled findings as JSON.
- **AST Code Transformations**: Generates diff patches (`git apply` compatible) for supported remediation rules.
- **Sandboxed Shallow Clones**: Performs shallow git checkouts (`--depth 1`) in temporary directories with git hooks, symlinks, and LFS smudge filters explicitly disabled.

---

## 2. Current Supported Analysis Scope

NANTIS currently implements **19 static security detectors** evaluating **23 rule definitions**:

| Domain | Rule ID | Description |
|---|---|---|
| **Next.js & API Routes** | `api-route-no-auth` | Detects API routes lacking session verification or access control |
| | `server-action-no-auth` | Detects Next.js Server Actions lacking authentication checks |
| | `middleware-matcher-gap` | Identifies route patterns bypassed by Next.js middleware matchers |
| | `missing-ownership-check` | Identifies missing resource ownership assertions in route handlers |
| | `mass-assignment` | Flags unvetted request payload binding into database queries |
| **Supabase Security** | `missing-rls-in-migration` | Detects Supabase migration tables created without Row Level Security enabled |
| | `supabase-permissive-policy` | Flags overly permissive Supabase RLS policies (e.g. `USING (true)`) |
| | `supabase-service-role-leak` | Identifies client-side code referencing Supabase service role keys |
| | `supabase-storage-public-or-unprotected` | Detects unauthenticated or publicly accessible storage buckets |
| **Stripe Integration** | `stripe-webhook-no-signature` | Identifies Stripe webhook handlers skipping signature verification |
| | `stripe-webhook-parsed-body` | Detects webhook handlers receiving parsed JSON instead of raw request body |
| | `stripe-user-controlled-price` | Identifies client-supplied price or amount values passed to Stripe Checkout |
| | `stripe-secret-key-client-leak` | Detects Stripe secret keys exposed in client-accessible files |
| **Secrets & Credentials** | `hardcoded-secret` | Scans source code for hardcoded API keys, Stripe secret keys, and JWT secrets |
| | `committed-env-file` | Detects committed `.env` or `.env.local` files containing environment secrets |
| | `use-client-secret-leak` | Identifies sensitive environment keys in `"use client"` React components |
| | `scanGitHistory` | Scans git repository commit history for committed credentials |
| **Dependencies & Config** | `vulnerable-dependency` | Checks `package.json` dependencies against known vulnerability databases |
| | `cookie-missing-flags` | Flags HTTP cookies set without `HttpOnly`, `Secure`, or `SameSite` flags |
| | `permissive-cors` | Flags wildcard CORS headers (`Access-Control-Allow-Origin: *`) |
| | `debug-mode-production` | Identifies debug flags enabled in production configurations |
| **CI & Workflows** | `ci-overbroad-permissions` | Flags GitHub Actions workflows with unneeded `permissions: write-all` |
| | `ci-unpinned-action` | Identifies GitHub Actions pinned to floating tags instead of full commit SHAs |
| | `ci-pull-request-target-checkout` | Detects unsafe checkouts of untrusted code in `pull_request_target` workflows |
| | `ci-secrets-echoed` | Flags workflow steps echoing secret variables into log outputs |

---

## 3. Current Architecture

NANTIS is structured as a TypeScript monorepo:

```
e:\gnu
├── apps/
│   └── web/                   # HTTP Web Server & User Interface
│       ├── src/
│       │   ├── db/            # In-memory database client & schema definitions
│       │   ├── lib/           # Session decoding, OAuth, GitHub App tokens & URL validation
│       │   ├── routes/        # Controller route handlers & presentation templates
│       │   └── server.ts      # Native HTTP server entry point
│       └── test/              # Web application & security regression test suite
├── packages/
│   ├── core/                  # Static Analysis Engine
│   │   ├── src/
│   │   │   ├── detectors/     # 19 AST detector modules & detector registry
│   │   │   ├── fixes/         # AST patch generators & proof engine
│   │   │   ├── cli/           # CLI scan, compare, scoreboard & mutation harness
│   │   │   └── walker.ts      # Fast project file walker & parser
│   │   └── test/              # Core engine unit & mutation test suite
│   └── worker/                # Sandboxed Task Execution Worker
│       ├── src/
│       │   ├── git/           # Hardened shallow git clone runner
│       │   └── queue/         # In-memory scan job queue & processor
│       └── test/              # Worker & clone sandbox tests
├── docs/                      # Architectural & Audit Documentation
│   ├── architecture/          # System architecture, schemas, and sandbox specifications
│   └── audits/                # Independent system audit reports
└── fixtures/                  # Synthetic test fixtures for detector benchmarking
```

### Data & Control Flow
1. **Request Intake**: Scans are initiated via web UI (`/scans`), REST API, or CLI (`npm run scan`).
2. **Authorization Lock**: Requests check user session permissions and repository access snapshots (`assertRepoAccess`).
3. **Sandboxed Checkout**: Repositories are cloned into ephemeral isolation directories with shallow depth 1 (`--depth 1`) and git hooks/symlinks/LFS disabled.
4. **AST Detection**: `runAllDetectors` walks file trees and executes all 19 registered detector rules.
5. **Evidence & Presentation**: Findings are assigned confidence tiers (`Proven`, `Likely`, `Needs review`, `Hygiene`) and rendered on the Findings Dashboard.

---

## 4. Local Installation & Requirements

### Requirements
- **Node.js**: `v20.0.0` or higher
- **pnpm**: `v9.0.0` or higher (or `npm`)

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/akshith0107/NANTIS-github.git
   cd NANTIS-github
   ```
2. Install workspace dependencies:
   ```bash
   pnpm install
   ```
3. Configure local environment variables:
   ```bash
   cp .env.example .env
   ```

---

## 5. Development & CLI Commands

### Development Web Server
Start the local HTTP web server (default port `3000`):
```bash
npm run dev
```

### CLI Static Scanner
Run a static scan against any local project directory:
```bash
npm run scan -- /path/to/project
```
Options:
- `--json`: Output findings in JSON format.
- `--baseline <path>`: Compare findings against a saved baseline JSON file.
- `--save-baseline <path>`: Save current findings to a baseline JSON file.

### Benchmarking & Mutation Harness
Run precision/recall benchmark evaluation across test fixtures:
```bash
npm run scoreboard
```
Run the automated AST code mutation harness:
```bash
npm run mutation-harness
```

---

## 6. Testing, Typecheck & Lint Commands

Run full workspace test battery (Vitest):
```bash
npx vitest run
```

Run TypeScript typecheck across all workspace packages:
```bash
npm run typecheck
```

Run ESLint check across all workspace packages:
```bash
npm run lint
```

Build production TypeScript artifacts:
```bash
npm run build
```

---

## 7. Security & Credential Handling Notes

- **Ephemeral Token Lifetime**: User OAuth access tokens are held in volatile memory only during OAuth authentication callbacks and repository snapshot sync, then immediately discarded. User tokens are **never stored** in the database or session cookies.
- **Isolated Git Authentication**: GitHub App Installation Access Tokens (`ghs_...`) are passed to git shallow clones strictly via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`, and `GIT_CONFIG_VALUE_0` environment variables. Tokens never appear in CLI command arguments (`ps aux` safe) and are never written to disk `.git/config` files.
- **Hardened Git Clone Environment**: Clones execute with `core.hooksPath=/dev/null` (prevents malicious hook execution), `core.symlinks=false` (prevents directory escape via symbolic links), and `filter.lfs.smudge=` (prevents remote LFS binary downloads).
- **Session Security**: Session cookies use HMAC-SHA256 signatures, `HttpOnly`, and `SameSite=Lax` controls. Dev bypass authentication (`/auth/dev-login`) is strictly restricted to local loopback (`127.0.0.1`) in development mode and rejected in production.

---

## 8. Current Limitations & Feature Matrix

### Current Status
- **Database Storage**: Uses volatile in-memory JavaScript `Map` storage. Server restarts reset local user sessions and scan records.
- **Remediation Generators**: Automated AST code fix generators are implemented for **3 rules** (`missing-rls-in-migration`, `stripe-webhook-no-signature`, `vulnerable-dependency`). The remaining 20 rules provide manual resolution guidance.
- **GitHub PR Publishing**: Local development mode renders fix diff previews; remote Pull Request creation requires a configured GitHub App installation.
- **Benchmark Suite**: Precision and recall metrics (100% target) are evaluated against synthetic internal test fixtures.

### Current vs. Planned Capabilities

| Capability | Current State | Planned / Future |
|---|---|---|
| **Analysis Engine** | AST rules for TS/JS, Next.js, Supabase, Stripe, CI | Python, Go, and Java detector packs |
| **Data Storage** | Volatile in-memory JavaScript `Map` collections | Persistent PostgreSQL / SQLite storage driver |
| **Scan Execution** | Ephemeral local sandboxed git clones | Distributed background worker queue workers |
| **Fix Generation** | 3 automated AST fix generators (`git apply` diffs) | Automated fix generators across all 23 rules |
| **Authentication** | Local dev login & GitHub OAuth | Team role-based access control (RBAC) & SAML |

---

## 9. Architectural & Audit Documentation

For detailed technical specifications, schema definitions, and audit reports, refer to:

- [System Architecture Map](file:///e:/gnu/docs/architecture/ARCHITECTURE.md) (`docs/architecture/ARCHITECTURE.md`)
- [Data Model & Finding Schema](file:///e:/gnu/docs/architecture/finding-schema.md) (`docs/architecture/finding-schema.md`)
- [Git Sandbox Specification](file:///e:/gnu/docs/architecture/sandbox.md) (`docs/architecture/sandbox.md`)
- [System Audit Report #3](file:///e:/gnu/docs/audits/AUDIT_REPORT_3.md) (`docs/audits/AUDIT_REPORT_3.md`)
- [GitHub OAuth Connect Audit](file:///e:/gnu/docs/audits/GITHUB_CONNECT_REPORT.md) (`docs/audits/GITHUB_CONNECT_REPORT.md`)
