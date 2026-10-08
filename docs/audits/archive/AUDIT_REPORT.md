# NANTIS Independent Security & Architecture Audit Report

**Audit Date**: October 6, 2026  
**Auditor**: Independent Security Engineering Auditor  
**Repository**: NANTIS (`@nantis/core`, `@nantis/worker`, `@nantis/web`)

---

## 1. Executive Verdict

NANTIS contains a high-quality, functional core scanning engine with resilient AST fingerprinting, sandboxed git cloning, OSV vulnerability lookup with fail-safe error handling, automated AST structured fixes, and a precision/recall mutation test harness. However, the system is an **in-memory prototype** rather than a production web application. The web application (`apps/web`) lacks an HTTP server listener (`http.createServer` / Fastify / Express), uses an in-memory `Map` store rather than a real PostgreSQL database, and the Pull Request publisher (`publishFixPR`) returns hardcoded mock GitHub PR URLs rather than making real Octokit API calls to GitHub. Furthermore, sandbox verification runs `npm test` directly on local host node processes without container isolation, exposing worker hosts to potential remote code execution via malicious repository test scripts.

---

## 2. Scorecard Table

| Functional Area | Status | Evidence | Primary Blocker |
|---|---|---|---|
| **Core Scanning Engine** | **REAL** | `packages/core/src/detectors/registry.ts:42-164` | None (19 registered detectors, 100% test pass) |
| **Resilient Fingerprinting** | **REAL** | `packages/core/src/fingerprint.ts:99-120` | None (canonical AST hashing, survives renames & line shifts) |
| **OSV Dependency Lookup** | **REAL** | `packages/core/src/osv/client.ts:51-104`, `dependencies.ts:153-177` | None (Queries OSV API with 5s timeout, falls back to "dependency check incomplete") |
| **Sandboxed Git Clone** | **REAL** | `packages/worker/src/git/clone-sandbox.ts:36-107` | None (Disables git hooks, symlinks, LFS scripts, global config, 30s timeout) |
| **Path Traversal & Symlink Safety** | **REAL** | `packages/core/src/walker.ts:111-167` | None (`fs.realpathSync` prevents symlink escaping outside root) |
| **Fix Engine (Structured Edits)** | **PARTIAL** | `packages/core/src/fixes/patch-engine.ts:69-97` | Only 3 rules have automated fix handlers; 20 rules fall back to `suggested-manual` |
| **Sandbox Fix Verification** | **REAL** | `packages/core/src/fixes/verification-runner.ts:11-160` | Runs `npm test` locally without Docker/container isolation |
| **Proof Engine** | **REAL** | `packages/core/src/fixes/proof/proof-engine.ts:11-40` | Evaluates proof labels ("Proven by policy simulation / handler replay") |
| **Mutation Harness & Scoreboard** | **REAL** | `packages/core/src/mutation/harness.ts:193-340` | None (Measures precision & recall against labeled fixture corpus) |
| **Secret Masking** | **REAL** | `packages/core/src/masking.ts:8-32` | None (Redacts live/test Stripe, Supabase, GitHub tokens from evidence/logs) |
| **Web API Access Control** | **REAL** | `apps/web/src/routes/registry.ts:22-95` | All 9 API routes execute `assertRepoAccess` |
| **Database Persistence** | **STUB / MOCKED** | `apps/web/src/db/client.ts:13-21` | In-memory `Map` data store; zero PostgreSQL/Supabase database driver |
| **Web HTTP Server** | **MISSING** | `apps/web/src/index.ts:1-17` | No HTTP server listener (`http.createServer` or web framework) in `apps/web` |
| **GitHub PR Publisher** | **MOCKED** | `packages/core/src/fixes/pr-publisher.ts:184,207` | `publishFixPR` returns mock URL `https://github.com/example/repo/pull/...` |

---

## 3. Score & Readiness Classification

* **Overall Score**: **6.5 / 10**
* **Readiness Classification**: **Alpha / Prototype**

### Justification
The core analysis engine, git clone sandbox, AST fix engine, resilient fingerprinting, and mutation harness are fully functional, thoroughly tested, and operate cleanly without mocks. However, the system cannot be deployed to production as a web application because `apps/web` has no HTTP server listener, database storage is volatile in-memory maps, PR creation uses hardcoded mock URLs, and local execution of `npm test` inside worker processes poses a host security risk.

---

## 4. Delta from Previous Audit (4.5/10 -> 6.5/10)

| Previously Reported Gap | Current Status | Evidence |
|---|---|---|
| **Detector Registry Fragmentation** | **FIXED** | [packages/core/src/detectors/registry.ts](file:///e:/gnu/packages/core/src/detectors/registry.ts#L42-L164) unifies all 19 detectors; enforced by test in [packages/core/test/detector_registry.test.ts](file:///e:/gnu/packages/core/test/detector_registry.test.ts#L6-L28). |
| **Patch Engine Diff Appending** | **FIXED** | Refactored in [packages/core/src/fixes/patch-engine.ts](file:///e:/gnu/packages/core/src/fixes/patch-engine.ts#L69-L97); handlers return structured edits (`StructuredEdit[]`), verified before replacement. |
| **Forced Offline OSV Lookup** | **FIXED** | [packages/core/src/detectors/dependencies.ts](file:///e:/gnu/packages/core/src/detectors/dependencies.ts#L179-L260) queries OSV.dev with 5s timeout; falls back to `"dependency check incomplete"` when offline/unreachable. |
| **Verification Runner Multistore Noise** | **FIXED** | [packages/core/src/fixes/verification-runner.ts](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L36-L44) accepts `initialFindings` to filter pre-existing findings. |
| **E2E Integration Test Missing** | **FIXED** | Created [packages/core/test/e2e_workflow.test.ts](file:///e:/gnu/packages/core/test/e2e_workflow.test.ts) running full scan, fix, verification, and diff workflow without mocks. |
| **Missing HTTP Server Listener** | **NOT FIXED** | `apps/web` still contains handler functions without an HTTP listener entrypoint. |
| **In-Memory Database Store** | **NOT FIXED** | [apps/web/src/db/client.ts](file:///e:/gnu/apps/web/src/db/client.ts#L14-L20) still uses volatile JavaScript `Map` objects. |
| **Mocked GitHub PR Publisher** | **NOT FIXED** | [packages/core/src/fixes/pr-publisher.ts](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L184,L207) still returns hardcoded mock URLs. |

---

## 5. Top 10 Technical Problems

1. **Mocked PR Publisher (No Real GitHub Octokit API Calls)**  
   *Location*: [packages/core/src/fixes/pr-publisher.ts:184,207](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L184)  
   *Issue*: `publishFixPR` returns hardcoded mock URL (`https://github.com/example/repo/pull/...`) instead of creating real GitHub branches and Pull Requests via Octokit API.

2. **Missing HTTP Entrypoint Server in `apps/web`**  
   *Location*: [apps/web/src/index.ts:1-17](file:///e:/gnu/apps/web/src/index.ts#L1-L17)  
   *Issue*: `apps/web` exports route definitions (`API_ROUTE_REGISTRY`), but there is no executable file calling `http.createServer()` or starting a web server framework.

3. **In-Memory Volatile Database (`Map` Store)**  
   *Location*: [apps/web/src/db/client.ts:14-20](file:///e:/gnu/apps/web/src/db/client.ts#L14-L20)  
   *Issue*: Scans, users, repositories, findings, and audit logs are stored in JS `Map` instances and in-memory arrays. All state is lost when the process restarts.

4. **Untrusted Code Execution in Sandbox Verification**  
   *Location*: [packages/core/src/fixes/verification-runner.ts:116](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L116)  
   *Issue*: `runSandboxVerification` calls `execSync("npm test")` directly on the host machine OS without Docker or gVisor container isolation. Scanned repos with malicious `npm test` scripts can execute arbitrary host shell commands.

5. **Fix Handler Coverage Limited to 3 of 23 Rules**  
   *Location*: [packages/core/src/fixes/patch-engine.ts:170-194](file:///e:/gnu/packages/core/src/fixes/patch-engine.ts#L170-L194)  
   *Issue*: Automated fixes exist only for `dependency-bump`, `missing-rls-in-migration`, and `stripe-webhook-no-signature`. The remaining 20 security rules fall back to `suggested-manual`.

6. **TypeScript Strict Typecheck Compilation Failures**  
   *Location*: `fixtures/e2e-nextjs-supabase-stripe/app/api/webhooks/stripe/route.ts:1-3`, `packages/core/test/approval_ui.test.ts:9`, `packages/core/test/pr_publisher.test.ts:41`  
   *Issue*: Running `npm run typecheck` (`tsc --noEmit`) fails with 6 errors due to unused variables in test fixtures and missing `edits` properties on mock `FixResultAutomated` test objects.

7. **ESLint Linting Failures**  
   *Location*: [apps/web/src/routes/false-positive-route.ts:46](file:///e:/gnu/apps/web/src/routes/false-positive-route.ts#L46), `apps/web/test/false_positive_and_pages.test.ts:47`  
   *Issue*: `npm run lint` (`eslint .`) fails with 6 errors due to explicit `any` usage and unused fixture variables.

8. **Separate Detector List in Mutation Harness**  
   *Location*: [packages/core/src/mutation/harness.ts:164-185](file:///e:/gnu/packages/core/src/mutation/harness.ts#L164-L185)  
   *Issue*: `mutation/harness.ts` maintains an inline array function `runDetectors` listing detectors individually rather than calling `runAllDetectors(filesMap)` from `detectors/registry.ts`.

9. **Trivial Assertion Unit Tests in Package Shells**  
   *Location*: [apps/web/test/web.test.ts:4-8](file:///e:/gnu/apps/web/test/web.test.ts#L4-L8), [packages/worker/test/worker.test.ts:4-8](file:///e:/gnu/packages/worker/test/worker.test.ts#L4-L8)  
   *Issue*: Tests assert trivial string constants (`expect(APP_NAME).toBe("nantis-web")`) to artificially inflate package test file counts.

10. **Hardcoded Default Installation ID in API Route Handler**  
    *Location*: [apps/web/src/routes/api-routes.ts:104](file:///e:/gnu/apps/web/src/routes/api-routes.ts#L104)  
    *Issue*: `handleCreateScan` hardcodes `installationId: 1` when queueing scan jobs instead of looking up the repository's registered installation ID.

---

## 6. Security Review of NANTIS Itself

1. **Host Remote Code Execution via `npm test` in Sandbox Verification**  
   *Severity*: **CRITICAL**  
   *Detail*: `verification-runner.ts` executes `npm test` on untrusted repository code in local host temp directories. A malicious repository can define arbitrary commands in `package.json` scripts or lifecycle hooks.  
   *Mitigation Required*: Execute verification tests inside isolated containers (Docker / gVisor) with network egress disabled.

2. **In-Memory Store Loss & State Reset**  
   *Severity*: **HIGH**  
   *Detail*: Because `DatabaseClient` relies on JavaScript `Map` objects, process restarts wipe all scan history, user sessions, and false-positive audit reports.  
   *Mitigation Required*: Connect `DatabaseClient` to a persistent PostgreSQL / Supabase database instance.

3. **In-Memory IAT Token Cache Memory Leak**  
   *Severity*: **MEDIUM**  
   *Detail*: [apps/web/src/lib/github-app.ts:33](file:///e:/gnu/apps/web/src/lib/github-app.ts#L33) uses `iatMemoryCache` `Map` without an automatic cache eviction interval for expired installation tokens.  
   *Mitigation Required*: Implement TTL cleanup for `iatMemoryCache`.

---

## 7. End-to-End Execution Proof

To empirically verify the pipeline on real external code, an un-mocked test fixture repository was created outside the project workspace at `C:\Users\AKSHITH REDDY\AppData\Local\Temp\nantis-audit-proof-HPgWYI`.

### Execution Steps & Real Output
1. **File Walking**: `walkDirectory` traversed the external directory and built `filesMap`.
2. **Scanner Pipeline**: `runAllDetectors` scanned the files and detected 3 real security findings:
   - `missing-lockfile` in `package.json`
   - `missing-rls-in-migration` in `supabase/migrations/20260101_init.sql`
   - `stripe-webhook-no-signature` in `app/api/webhooks/stripe/route.ts`
3. **Patch Sandbox & Verification**: `processFixInTempSandbox` created a temporary sandbox, applied structured edits for `missing-rls-in-migration`, ran rescan verification, and passed with `verificationReport.passed = true`.
4. **Generated Unified Diff**:
   ```diff
   --- supabase/migrations/20260101_init.sql
   +++ supabase/migrations/20260101_init.sql
   @@ patch @@
   +ALTER TABLE users ENABLE ROW LEVEL SECURITY;
   +CREATE POLICY "Needs Human Review: tenant access policy" ON users FOR ALL USING (auth.uid() = user_id);
   ```

---

## 8. The ONE Next Task

**Task**: Replace the mock implementation in [packages/core/src/fixes/pr-publisher.ts](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L113-L226) with real GitHub Octokit API calls (`octokit.rest.git.createRef` and `octokit.rest.pulls.create`).

**Why**: Scanning, structured fix generation, sandbox verification, and diff computation are fully functional and empirically verified. Replacing the mock PR publisher with real GitHub API integration will enable NANTIS to create actual Pull Requests on GitHub repositories.

---

## 9. Unverified Claims

1. **GitHub App Webhook Ingestion in Production**: Unverified because no live public URL or GitHub App webhook secret is configured to receive production webhooks.
2. **Live OSV Network Lookup Performance under Rate Limits**: Unverified under heavy concurrency (>100 batch requests/sec).

---

## 10. Manual Verification Guide (5 Verification Actions)

1. **Run Full Test Suite**:
   ```bash
   npm test
   ```
   *Expected Output*: 44 test files passed, 169 tests passed.

2. **Verify Typecheck Failures**:
   ```bash
   npm run typecheck
   ```
   *Expected Output*: 6 TypeScript compilation errors in test files and fixtures.

3. **Verify ESLint Failures**:
   ```bash
   npm run lint
   ```
   *Expected Output*: 6 ESLint error messages.

4. **Run External E2E Fixture Scan**:
   ```bash
   npx tsx packages/core/src/cli/scan.ts "fixtures/e2e-nextjs-supabase-stripe" --json
   ```
   *Expected Output*: JSON array containing `missing-rls-in-migration` and `stripe-webhook-no-signature` findings.

5. **Inspect Mock PR Publisher**:
   ```bash
   grep -n "example/repo" packages/core/src/fixes/pr-publisher.ts
   ```
   *Expected Output*: Hardcoded `https://github.com/example/repo/pull/` URL strings on lines 184 and 207.
