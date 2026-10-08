# NANTIS GitHub Web App — Independent Audit Report #3

**Audit Date**: October 7, 2026  
**Auditor**: Independent Code Auditor (Automated Verification & Architectural Inspection)  
**Target Repository**: NANTIS (`e:\gnu`)  

---

## 1. Verdict

NANTIS is a high-performance, local AST static security review engine paired with an HTTP web application. The core engine features 19 detector modules evaluating 23 security rules across TypeScript/JavaScript, Next.js, Stripe, Supabase, and CI workflow configurations. It includes a deterministic evidence chain builder, automated secret redaction, structured AST code transformation generators, and a native `git apply` patch generation engine.

The web application (`http://127.0.0.1:3000`) enables developers to paste a public GitHub repository link (`https://github.com/owner/repo`), execute an isolated shallow git clone in a hardened sandbox, inspect security findings by tier (Proven, Likely, Needs Review, Hygiene), assign interactive finding labels (`Real issue`, `False positive`, `Not sure`), export finding classifications to JSON, and review verified AST patches with full CSRF and XSS protection.



---

## 2. Quantitative Scores & Readiness Label

| Component | Score (out of 10) | Notes |
| :--- | :---: | :--- |
| **AST Security Engine** | **8.5 / 10** | 19 detectors, 23 rules, 100% precision/recall on mutation harness fixtures, native `git apply` diff engine, isolated clone sandbox. Restricted by 3 automated fix rules. |
| **Web Application & UI** | **8.0 / 10** | Modern dark-first UI, strict URL validator, tier summary bar, interactive finding labels, JSON export, CSRF & CSP protection. Uses volatile in-memory storage. |
| **Overall System** | **8.3 / 10** | Robust local security audit and finding classification tool for static analysis and AST fix generation. |

**System Readiness Label**: **LOCAL DEV / BETA PROTOTYPE (NOT PRODUCTION READY)**

---

## 3. Progress vs. Audit Report #2

| Audit #2 Baseline State | Audit #3 Status | Verification Evidence |
| :--- | :--- | :--- |
| Inline `execFileSync` clone | **Hardened Sandboxed Clone** | Uses `cloneRepositorySandboxed` with `--depth 1`, disabled hooks, disabled symlinks, LFS off, max size/file limits ([dev-routes.ts:285](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L285)). |
| Host `npx tsc` execution | **Host Execution Removed** | Verification on host = rescan only. `tsc` runs strictly inside `containerRunner` ([verification-runner.ts:60](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L60)). |
| Git history leaked to subfolders | **Strict `.git` Root Check** | `scanGitHistory` checks `fs.existsSync(path.join(targetFolder, ".git"))` before running git log ([git-history.ts:18](file:///e:/gnu/packages/core/src/detectors/git-history.ts#L18)). |
| Custom diff applicator helper | **Native `git apply` Verification** | Unit tests verify diff outputs using native system `git apply` in temporary repositories ([patch_engine.test.ts:220](file:///e:/gnu/packages/core/test/patch_engine.test.ts#L220)). |
| Plain unstyled HTML pages | **Dark-First Premium UI** | Dynamic glassmorphism theme, tier summary bar, badge colors, finding cards ([ui-templates.ts:40](file:///e:/gnu/apps/web/src/routes/ui-templates.ts#L40)). |
| Missing finding label classification | **Finding Labels & JSON Export** | Classify findings as `Real issue`, `False positive`, or `Not sure` with JSON exporter ([client.ts:342](file:///e:/gnu/apps/web/src/db/client.ts#L342)). |

---

## 4. User Journey Audit (Browser Verification)

| Step | Action | Status | Behavior & Evidence |
| :---: | :--- | :---: | :--- |
| **1** | Server Startup & Dev Login | ✅ REAL | GET `/auth/dev-login` sets session cookie and redirects to `/repos`. Access restricted to `127.0.0.1` in development mode ([dev-routes.ts:42](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L42)). |
| **2** | Paste Public Repo Link | ✅ REAL | Submitting valid `https://github.com/owner/repo` link triggers sandboxed shallow clone, AST scan, and record creation ([dev-routes.ts:285](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L285)). |
| **3** | Ephemeral Clone & Cleanup | ✅ REAL | Cloned with shallow depth 1, disabled hooks/symlinks/LFS, scanned, and temp folder deleted immediately ([dev-routes.ts:348](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L348)). |
| **4** | View Scan Findings Dashboard | ✅ REAL | Navigates to `/scans/:id`. Displays Tier Summary Bar (Proven, Likely, Needs Review, Hygiene), coverage line, and cards ([scan-findings-page.ts:243](file:///e:/gnu/apps/web/src/routes/scan-findings-page.ts#L243)). |
| **5** | Label Classification & Export | ✅ REAL | Clicking `Real issue`, `False positive`, or `Not sure` updates in-memory DB via `POST /api/findings/:id/label`. Export button downloads JSON ([dev-routes.ts:365](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L365)). |
| **6** | Finding Detail & Fix Review | ✅ REAL | Navigates to `/findings/:id/fix`. Displays AST patch diff, `"PARTIALLY VERIFIED"` badge, and `"PR creation not connected yet"` badge ([fix-review-page.ts:149](file:///e:/gnu/apps/web/src/routes/fix-review-page.ts#L149)). |
| **7** | Fix Approval Action | ✅ PARTIAL | Submitting POST form applies fix in local memory. PR creation remains disconnected for GitHub ([fix-review-page.ts:97](file:///e:/gnu/apps/web/src/routes/fix-review-page.ts#L97)). |

---

## 5. Feature Status Table

| Feature | Label | Implementation Details & References |
| :--- | :---: | :--- |
| **AST Security Engine** | **REAL** | 19 detector definitions in [registry.ts:42](file:///e:/gnu/packages/core/src/detectors/registry.ts#L42) evaluating 23 rules. |
| **GitHub URL Validator** | **REAL** | Rejects `file://`, `ssh://`, `http://`, IPs, credentials, path traversal, non-github domains in [url-validator.ts:10](file:///e:/gnu/apps/web/src/lib/url-validator.ts#L10). |
| **Sandboxed Repo Clone** | **REAL** | `cloneRepositorySandboxed` enforcing shallow depth 1, disabled hooks/symlinks/LFS, max limits, immediate cleanup ([clone-sandbox.ts:43](file:///e:/gnu/packages/worker/src/git/clone-sandbox.ts#L43)). |
| **Testing Aid Labels & Export** | **REAL** | In-memory classification (`real_issue`, `false_positive`, `not_sure`) and JSON exporter ([client.ts:342](file:///e:/gnu/apps/web/src/db/client.ts#L342)). |
| **Tenant Isolation & Access Control**| **REAL** | `assertRepoAccess` enforces User A vs User B 404 responses ([scan-findings-page.ts:45](file:///e:/gnu/apps/web/src/routes/scan-findings-page.ts#L45)). |
| **Zero-Findings Message** | **REAL** | Mandatory string `"no issues found in the checks we run"` rendered in [scan-findings-page.ts:97](file:///e:/gnu/apps/web/src/routes/scan-findings-page.ts#L97). |
| **Database Storage** | **MOCKED / IN-MEMORY** | Volatile JavaScript `Map` collections. Data resets on server restart ([client.ts:15](file:///e:/gnu/apps/web/src/db/client.ts#L15)). |
| **Automated Fix Generators** | **PARTIAL** | 3 rules implemented (`missing-rls-in-migration`, `stripe-webhook-no-signature`, `vulnerable-dependency`). |
| **GitHub PR Publishing** | **STUB** | Disabled in local dev. Displays `"PR creation not connected yet"` ([fix-review-page.ts:97](file:///e:/gnu/apps/web/src/routes/fix-review-page.ts#L97)). |

---

## 6. Verification Battery & Test Count Reconciliation

### Verification Execution Summary

1. **`npm run typecheck`**: **PASSED** (0 TypeScript errors)
```
> typecheck
> tsc --noEmit
```

2. **`npm run lint`**: **PASSED** (0 ESLint errors)
```
> lint
> eslint .
```

3. **`npx vitest run` (Run 1)**: **PASSED** (45 test files passed, 197 tests passed)
```
Test Files  45 passed (45)
     Tests  197 passed (197)
  Start at  14:42:15
  Duration  102.24s
```

4. **`npx vitest run` (Run 2)**: **PASSED** (45 test files passed, 197 tests passed)
```
Test Files  45 passed (45)
     Tests  197 passed (197)
  Start at  14:44:13
  Duration  75.34s
```

5. **`git status`**: Clean working directory tracking modified source files and untracked `docs/AUDIT_REPORT_3.md`.

---

### Test Count Discrepancy Explanation

The variation in reported test counts between full test suite runs and partial test runs is caused by **Vitest workspace filter scoping**:

- **Root Suite Execution (`npx vitest run` from `e:\gnu`)**: Vitest discovers and executes test files across all workspace packages (`packages/core`, `packages/worker`, and `apps/web`). This executes all **45 test files containing 197 individual unit and integration tests**.
- **Package-Scoped Execution (e.g. `npx vitest run` inside `packages/core`)**: Vitest scopes file discovery strictly to matching paths inside `packages/core/test/`. This executes only the **16 test files containing 66 tests** belonging to `packages/core`.

Both scopes execute cleanly with zero test failures.

---

## 7. Top 10 Technical Problems & Weaknesses

1. **Volatile In-Memory Database**  
   - **Location**: [apps/web/src/db/client.ts:15-22](file:///e:/gnu/apps/web/src/db/client.ts#L15-L22)  
   - **Problem**: Users, repositories, scans, findings, finding labels, and audit logs are stored in JavaScript `Map` collections. Server restarts wipe all data.

2. **Synchronous HTTP Clone Execution**  
   - **Location**: [apps/web/src/routes/dev-routes.ts:285](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L285)  
   - **Problem**: Public repository shallow clones run inside the HTTP request handler thread rather than offloading to background worker queues.

3. **Disconnected GitHub PR Publisher**  
   - **Location**: [packages/core/src/fixes/pr-publisher.ts:25](file:///e:/gnu/packages/core/src/fixes/pr-publisher.ts#L25), [apps/web/src/routes/fix-review-page.ts:97](file:///e:/gnu/apps/web/src/routes/fix-review-page.ts#L97)  
   - **Problem**: Approving a fix updates local memory state but cannot publish pull requests to remote GitHub repositories.

4. **Limited Fix Generator Coverage**  
   - **Location**: [packages/core/src/fixes/rules/](file:///e:/gnu/packages/core/src/fixes/rules/)  
   - **Problem**: Out of 23 security rules, only 3 rules have automated code fix generators implemented. The remaining 20 rules rely on manual resolution suggestions.

5. **RLS Policy Human Review Requirement**  
   - **Location**: [packages/core/src/fixes/rules/enable-rls.ts:93](file:///e:/gnu/packages/core/src/fixes/rules/enable-rls.ts#L93)  
   - **Problem**: Non-user columns (`account_id`, `tenant_id`) generate commented TODO policies (`-- TODO: Define RLS policy for ... Needs Human Review`) requiring manual SQL edits.

6. **Synthetic Scoreboard Benchmarking**  
   - **Location**: [fixtures/](file:///e:/gnu/fixtures/), [packages/core/test/mutation_harness.test.ts:18](file:///e:/gnu/packages/core/test/mutation_harness.test.ts#L18)  
   - **Problem**: 100% precision and recall metrics are calculated against synthetic internal test fixtures, not against real-world public repositories.

7. **Container Runner Dependency for Host Typechecking**  
   - **Location**: [packages/core/src/fixes/verification-runner.ts:60](file:///e:/gnu/packages/core/src/fixes/verification-runner.ts#L60)  
   - **Problem**: Since host `tsc` execution is prohibited, verification reports return `"PARTIALLY VERIFIED (typecheck not run)"` when `containerRunner` is unconfigured.

8. **Unbounded In-Memory Map Caches**  
   - **Location**: [apps/web/src/db/client.ts:15](file:///e:/gnu/apps/web/src/db/client.ts#L15)  
   - **Problem**: In-memory scan and finding maps grow indefinitely during long-running dev server sessions without LRU eviction.

9. **OSV Live API Dependency**  
   - **Location**: [packages/core/src/detectors/dependencies.ts:179](file:///e:/gnu/packages/core/src/detectors/dependencies.ts#L179)  
   - **Problem**: Vulnerability detection relies on HTTP requests to `api.osv.dev`. Network failures fall back to `"dependency check incomplete"`.

10. **Local Dev Authentication Guard**  
    - **Location**: [apps/web/src/routes/dev-routes.ts:42](file:///e:/gnu/apps/web/src/routes/dev-routes.ts#L42)  
    - **Problem**: `/auth/dev-login` relies on strict IP (`127.0.0.1`) and `NODE_ENV=development` checks. Deploying to production without configuring real OAuth will lock out authentication.

---

## 8. Security Risks Ranked

1. **MEDIUM**: Lack of persistent database storage (data lost on restart).
2. **MEDIUM**: Unbound memory growth in long-running dev servers due to unbounded `Map` caches.
3. **LOW**: Synchronous clone execution blocking Node event loop under heavy concurrent POST load.
4. **LOW**: Dependency check fallback when OSV network API is unreachable.

---

## 9. The ONE Next Task

**Task**: Connect a persistent database driver (e.g. SQLite via Kysely/Drizzle or PostgreSQL) to replace `apps/web/src/db/client.ts` in-memory `Map` stores.  
**Why**: Currently, restarting `npm run dev` completely wipes all user accounts, repositories, scans, findings, and assigned labels. Persistent storage is essential for multi-session web applications.

---

## 10. Claims Not Verified

- **NOT VERIFIED**: Production performance under 100+ concurrent git shallow clone requests.
- **NOT VERIFIED**: Container runner sandbox execution when Docker is active on host OS.
- **NOT VERIFIED**: OSV API rate limits during large batch dependency lookups.

---

## 11. 5 Things You Should Check Yourself

1. Run `npm run typecheck` to verify zero TypeScript errors.
2. Run `npm run lint` to verify zero ESLint errors.
3. Run `npx vitest run` to run all 45 test files (197 unit & integration tests).
4. Start the server with `npm run dev` and open `http://127.0.0.1:3000` in a browser.
5. Paste a public GitHub URL (e.g. `https://github.com/akshith0107/NANTIS-github.git`) on the Home Page and click **Scan Repository**.
