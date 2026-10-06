# NANTIS Follow-Up Independent Audit Report 2

**Audit Date**: October 6, 2026  
**Auditor**: Independent Security Engineering Auditor  
**Repository**: NANTIS (`@nantis/core`, `@nantis/worker`, `@nantis/web`)

---

## 1. Executive Verdict

NANTIS has successfully eliminated host code execution vulnerabilities in sandbox verification, unified detector execution across CLI, Worker, and Mutation Harness via a single registry, removed hardcoded installation IDs in API routes, and cleared trivial test placeholders. The static security scanning engine, lockfile parsers, OSV dependency client with fail-safe fallbacks, resilient fingerprinting, and AST structured fix generation operate with high precision and 100% unit/integration test pass rates. However, NANTIS remains an **in-memory prototype** overall because `apps/web` has no HTTP server listener (`http.createServer` / Fastify / Express), database state relies on volatile JavaScript `Map` objects, Pull Request creation returns hardcoded mock URLs (`example/repo`), and the RLS fix generator hardcodes a `user_id` column rather than inspecting SQL table schemas.

---

## 2. Scores & Readiness Classification

* **Engine Score**: **8.5 / 10**  
  *Justification*: The core engine contains 19 unified detectors, resilient AST snippet hashing, sandboxed git cloning flags, fail-safe OSV queries, structured AST fixes, and safe host verification defaults. It loses 1.5 points because diff output uses a static `"@@ patch @@"` header instead of calculated line ranges (`@@ -a,b +c,d @@`) and the RLS fix rule hardcodes `user_id` without inspecting SQL column definitions.
* **Whole App Score**: **4.5 / 10**  
  *Justification*: The web app (`apps/web`) cannot serve live HTTP requests (no HTTP server entrypoint), stores all users/repos/scans in volatile JS `Map` memory, and returns mock PR URLs (`example/repo`) without making real GitHub Octokit API calls.
* **Readiness Classification**: **Alpha / Prototype**

---

## 3. Verification of Previous Audit Findings

| Previously Reported Finding | Status | Empirical Evidence |
|---|---|---|
| **Host script execution in `verification-runner.ts`** | **FIXED** | [packages/core/src/fixes/verification-runner.ts:14,71](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L14) defaults to `{ runTypecheck: true, runTests: false, runBuild: false }`. `npm test` and `npm install` execution on the host are completely removed. `npx tsc --noEmit` is the only host execution left. Opting into tests without `containerRunner` marks `isWeak: true` and skips host execution. Empirically verified via external experiment script: marker file was **NOT** written to host disk. |
| **Mutation Harness separate detector list** | **FIXED** | [packages/core/src/mutation/harness.ts:164](file:///e:/gnu/packages/core/src/mutation/harness.ts#L164) calls `runAllDetectors(filesMap, { offlineMode: true, targetFolder: "/fixtures/mutation-harness" })` from `detectors/registry.ts`. |
| **Worker (`scan-processor.ts`) shared registry** | **FIXED** | [packages/worker/src/processor/scan-processor.ts:151](file:///e:/gnu/packages/worker/src/processor/scan-processor.ts#L151) calls `runAllDetectors(filesMap, { targetFolder: jobTempDir, offlineMode: true })`. |
| **Hardcoded `installationId: 1` in `api-routes.ts`** | **FIXED** | [apps/web/src/routes/api-routes.ts:100-108](file:///e:/gnu/apps/web/src/routes/api-routes.ts#L100-L108) looks up the repository's installation via `db.getInstallation(repository.installation_id)` and returns a `400` error if missing. |
| **Trivial constant tests (`web.test.ts`, `worker.test.ts`)** | **FIXED** | Files `apps/web/test/web.test.ts` and `packages/worker/test/worker.test.ts` have been deleted. |
| **Build error count (`npm run typecheck` & `npm run lint`)** | **PARTIAL** | `npm run typecheck` and `npm run lint` pass with 0 errors on clean workspace state. However, running `npx vitest run` dynamically overwrites [fixtures/e2e-nextjs-supabase-stripe/app/api/webhooks/stripe/route.ts](file:///e:/gnu/fixtures/e2e-nextjs-supabase-stripe/app/api/webhooks/stripe/route.ts) with un-typed code, causing subsequent `npm run typecheck` calls to report 4 TS errors and `npm run lint` to report 2 errors until cleaned. |
| **Unified diff line ranges** | **NOT FIXED** | [packages/core/src/fixes/patch-engine.ts:114](file:///e:/gnu/packages/core/src/fixes/patch-engine.ts#L114) outputs a static `"@@ patch @@"` header instead of calculating standard line numbers (`@@ -a,b +c,d @@`). |
| **RLS fix column checking** | **NOT FIXED** | [packages/core/src/fixes/rules/enable-rls.ts:68](file:///e:/gnu/packages/core/src/fixes/rules/enable-rls.ts#L68) hardcodes `(auth.uid() = user_id)` without checking if `user_id` exists in the SQL `CREATE TABLE` columns. |
| **IAT Memory Cache TTL Eviction** | **NOT FIXED** | [apps/web/src/lib/github-app.ts:33](file:///e:/gnu/apps/web/src/lib/github-app.ts#L33) uses `iatMemoryCache` `Map` without background TTL pruning. |

---

## 4. Feature Status Table

| Feature | Status | Evidence | Blocker |
|---|---|---|---|
| **Detectors & Central Registry** | **REAL** | `packages/core/src/detectors/registry.ts:42-164` (19 detectors registered) | None |
| **OSV Online & Fallback** | **REAL** | `packages/core/src/osv/client.ts:51-104`, `dependencies.ts:153-177` | None (Falls back to "dependency check incomplete" on offline/timeout) |
| **Sandboxed Git Clone** | **REAL** | `packages/worker/src/git/clone-sandbox.ts:36-107` | None (Shallow clone, hooks/symlinks/LFS disabled, 30s timeout) |
| **Walker Path Safety** | **REAL** | `packages/core/src/walker.ts:111-167` | None (`fs.realpathSync` blocks symlink escape outside root) |
| **Resilient Fingerprints** | **REAL** | `packages/core/src/fingerprint.ts:99-120` | None (Canonical AST hashing; verified stable across variable renames & line shifts in `resilient_fingerprint.test.ts`) |
| **Secret Masking** | **REAL** | `packages/core/src/masking.ts:8-32` | None (Redacts tokens from evidence chains & logs) |
| **Fix Engine (Structured Edits)** | **PARTIAL** | `packages/core/src/fixes/patch-engine.ts:69-97` | Only 3 automated handlers (`dependency-bump`, `missing-rls-in-migration`, `stripe-webhook-no-signature`); 20 rules return `suggested-manual` |
| **Diff Generation** | **PARTIAL** | `packages/core/src/fixes/patch-engine.ts:114` | Uses static `"@@ patch @@"` instead of calculating `@@ -a,b +c,d @@` line ranges |
| **Verification Runner** | **REAL** | `packages/core/src/fixes/verification-runner.ts:14-159` | Default is safe rescan + `tsc` only; test/build script execution on host is removed |
| **Proof Engine** | **REAL** | `packages/core/src/fixes/proof/proof-engine.ts:11-40` | Evaluates proof labels ("Proven by policy simulation / handler replay") |
| **Mutation Scoreboard** | **REAL** | `packages/core/src/mutation/harness.ts:193-340` | All 23 rules pass threshold checks (Precision: 100.0%, Recall: 100.0%) |
| **Web HTTP Server** | **MISSING** | `apps/web/src/index.ts:1-17` | No HTTP server listener (`http.createServer` / Express / Fastify) |
| **Database Persistence** | **STUB / MOCKED** | `apps/web/src/db/client.ts:14-20` | JavaScript `Map` memory store; zero PostgreSQL driver |
| **Auth & Webhooks** | **REAL** | `apps/web/src/lib/webhook-signature.ts`, `apps/web/src/routes/webhook.ts` | Timing-safe HMAC verification and push deduplication implemented |
| **GitHub PR Publisher** | **MOCKED** | `packages/core/src/fixes/pr-publisher.ts:184,207` | Returns fake URL `https://github.com/example/repo/pull/...` |
| **API Routes Access Control** | **REAL** | `apps/web/src/routes/registry.ts:22-95` | All 9 API routes execute `assertRepoAccess` check |

---

## 5. Top 10 Technical Problems

1. **Mocked PR Publisher (No Octokit API Calls)**  
   *Location*: [packages/core/src/fixes/pr-publisher.ts:184,207](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L184)  
   *Issue*: `publishFixPR` returns a hardcoded mock URL (`https://github.com/example/repo/pull/...`) instead of creating real GitHub branches and Pull Requests via Octokit API.

2. **Missing HTTP Entrypoint Server in `apps/web`**  
   *Location*: [apps/web/src/index.ts:1-17](file:///e:/gnu/apps/web/src/index.ts#L1-L17)  
   *Issue*: `apps/web` exports route handlers but does not contain an executable file calling `http.createServer()` or starting an HTTP server framework.

3. **In-Memory Volatile Database Store**  
   *Location*: [apps/web/src/db/client.ts:14-20](file:///e:/gnu/apps/web/src/db/client.ts#L14-L20)  
   *Issue*: State (users, repos, scans, findings, audit logs) is stored in JavaScript `Map` instances and cleared on process restart.

4. **Hardcoded Column Name in RLS Fix Generator**  
   *Location*: [packages/core/src/fixes/rules/enable-rls.ts:68](file:///e:/gnu/packages/core/src/fixes/rules/enable-rls.ts#L68)  
   *Issue*: `fixEnableRLS` appends `USING (auth.uid() = user_id)` without checking whether `user_id` exists in the table definition. If a table uses `account_id` or `owner_id`, the generated migration SQL will fail PostgreSQL execution.

5. **Static Diff Line Header Placeholder (`@@ patch @@`)**  
   *Location*: [packages/core/src/fixes/patch-engine.ts:114](file:///e:/gnu/packages/core/src/fixes/patch-engine.ts#L114)  
   *Issue*: `generateUnifiedDiff` outputs `"@@ patch @@"` instead of calculating standard line numbers (`@@ -a,b +c,d @@`).

6. **E2E Test File Overwrites Fixture Route File**  
   *Location*: [packages/core/test/e2e_workflow.test.ts:36-39](file:///e:/gnu/packages/core/test/e2e_workflow.test.ts#L36-L39)  
   *Issue*: `e2e_workflow.test.ts` writes un-typed code (`req` without type annotation and unused `stripe` import) to `fixtures/e2e-nextjs-supabase-stripe/app/api/webhooks/stripe/route.ts` during Vitest runs, causing subsequent `npm run typecheck` and `npm run lint` calls to fail until cleaned up.

7. **Fix Handler Coverage Limited to 3 of 23 Rules**  
   *Location*: [packages/core/src/fixes/patch-engine.ts:170-194](file:///e:/gnu/packages/core/src/fixes/patch-engine.ts#L170-L194)  
   *Issue*: Automated fix rules exist only for `dependency-bump`, `missing-rls-in-migration`, and `stripe-webhook-no-signature`. The remaining 20 rules return `suggested-manual`.

8. **In-Memory IAT Token Cache Lacks Eviction Interval**  
   *Location*: [apps/web/src/lib/github-app.ts:33](file:///e:/gnu/apps/web/src/lib/github-app.ts#L33)  
   *Issue*: Expired installation tokens remain stored in `iatMemoryCache` until overwritten or manually cleared.

9. **Docker Container Sandbox Runner Unimplemented**  
   *Location*: [packages/core/src/fixes/verification-runner.ts:74](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L74)  
   *Issue*: `containerRunner` is defined as an interface in `types.ts`, but no default Docker / gVisor container runner implementation is provided in production worker setup. Opt-in tests return `isWeak: true`.

10. **Single Repository Installation Limitation in API Routes**  
    *Location*: [apps/web/src/routes/api-routes.ts:100](file:///e:/gnu/apps/web/src/routes/api-routes.ts#L100)  
    *Issue*: `handleCreateScan` checks `repository.installation_id` against the DB, but `apps/web` does not yet support multi-installation token rotation across GitHub orgs.

---

## 6. Security Review of NANTIS Itself

1. **Host Untrusted Code Execution Risk**: **RESOLVED**  
   `runSandboxVerification` no longer executes `npm test` or lifecycle hooks on the host. Host execution is limited to static typechecking (`npx tsc --noEmit`).

2. **Tenant Data Leakage via Unauthenticated API Routes**: **LOW RISK**  
   All 9 API routes execute `await assertRepoAccess(userId, targetId)` before returning findings, scans, or repository data. Unauthenticated or unauthorized requests return `404 Not found` to prevent ID enumeration.

3. **HMAC Webhook Replay & Forgery**: **LOW RISK**  
   `verifyGitHubWebhookSignature` uses `crypto.timingSafeEqual` for HMAC-SHA256 signature verification before JSON parsing. Push webhooks enforce a 10-second deduplication window and a maximum queue limit of 50 pending jobs.

---

## 7. End-to-End Execution Proof

The pipeline was executed end-to-end on a throwaway fixture created outside the project workspace at `C:\Users\AKSHITH REDDY\AppData\Local\Temp\nantis-e2e-proof-repo-XIzJTg`:

### Empirical Results
1. **Directory Walk & Registry Scan**: `walkDirectory` traversed the repository. `runAllDetectors` scanned with 19 registered detectors and produced 2 real findings:
   - `[HIGH] missing-rls-in-migration` in `supabase/migrations/20260101_init.sql`
   - `[CRITICAL] stripe-webhook-no-signature` in `app/api/webhooks/stripe/route.ts`
2. **Patch Generation & Sandbox Verification**: `processFixInTempSandbox` created a temp sandbox, applied structured edits for `missing-rls-in-migration`, ran rescan verification, and passed without executing host scripts (`verificationReport.passed = true`).
3. **Unified Diff Generated**:
   ```diff
   --- supabase/migrations/20260101_init.sql
   +++ supabase/migrations/20260101_init.sql
   @@ patch @@
   +ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
   +CREATE POLICY "Needs Human Review: tenant access policy" ON invoices FOR ALL USING (auth.uid() = user_id);
   ```
4. **PR Publisher Step**: `publishFixPR` executed and returned `prUrl: https://github.com/example/repo/pull/11797704` (halting at the mock GitHub API boundary).

---

## 8. The ONE Next Task

**Task**: Replace the mock implementation in [packages/core/src/fixes/pr-publisher.ts](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L113-L226) with real GitHub Octokit API calls (`octokit.rest.git.createRef` and `octokit.rest.pulls.create`).

**Why**: Host code execution security holes have been eliminated, detectors are unified, and sandbox verification operates cleanly. Real GitHub PR publishing is the single remaining blocker preventing NANTIS from creating real security fix Pull Requests on target GitHub repositories.

---

## 9. Unverified Claims

1. **Production Webhook Processing**: Unverified against live GitHub webhooks because no public URL endpoint is hosted or exposed.
2. **Multi-Tenant Concurrent Worker Queue Scaling**: Unverified under heavy load (>50 concurrent workers).

---

## 10. Manual Verification Guide (5 Verification Actions)

1. **Verify Host Script Execution Prevention (Security Experiment)**:
   ```bash
   npx tsx "C:\Users\AKSHITH REDDY\.gemini\antigravity-ide\brain\67ba8d1b-aedd-495d-afa0-5d148a08e45a\scratch\verify_exp.ts"
   ```
   *Expected Output*: `Verification Report Passed: true`, `Checks Run: [ 'rescan' ]`, `Marker file exists on host disk?: false`.

2. **Run Full Vitest Suite**:
   ```bash
   npx vitest run
   ```
   *Expected Output*: 42 test files passed, 168 tests passed.

3. **Verify Unified Detector Registry Test**:
   ```bash
   npx vitest run packages/core/test/detector_registry.test.ts
   ```
   *Expected Output*: All 3 tests passed (verifying 19 detectors registered).

4. **Run E2E Proof Script**:
   ```bash
   npx tsx "C:\Users\AKSHITH REDDY\.gemini\antigravity-ide\brain\67ba8d1b-aedd-495d-afa0-5d148a08e45a\scratch\e2e_proof_script.ts"
   ```
   *Expected Output*: Real diff printed, PR URL returned as `https://github.com/example/repo/pull/...`.

5. **Inspect Mock PR Publisher**:
   ```bash
   grep -n "example/repo" packages/core/src/fixes/pr-publisher.ts
   ```
   *Expected Output*: Lines 184 and 207 containing `https://github.com/example/repo/pull/`.
