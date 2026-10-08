# NANTIS Codebase Cleanup & Refactoring Plan

## 1. Proposed Target Folder Structure

```
e:\gnu
├── apps/
│   └── web/
│       ├── src/
│       │   ├── db/              # In-memory database client & schema definitions
│       │   ├── lib/             # OAuth, GitHub App JWT, Session & URL validation
│       │   ├── routes/          # Web HTTP route handlers & UI templates
│       │   │   ├── auth/        # Login, callback, logout & disconnect routes
│       │   │   ├── pages/       # Home, Repos, Findings, Fix review, Privacy pages
│       │   │   └── api/         # Scans, Repos, Webhook & Dev API endpoints
│       │   └── server.ts        # HTTP server entry point
│       └── test/                # Web application integration test battery
├── packages/
│   ├── core/
│   │   ├── src/
│   │   │   ├── detectors/       # 19 static security detector modules & registry
│   │   │   ├── fixes/           # AST patch generators, proof engine & publishers
│   │   │   ├── cli/             # CLI scan, scoreboard & mutation harness
│   │   │   └── walker.ts        # Fast AST project walker & file parser
│   │   └── test/                # Core engine unit & mutation tests
│   └── worker/
│       ├── src/
│       │   ├── git/             # Sandboxed git clone & credential isolation
│       │   └── queue/           # Scan job queue & processor
│       └── test/                # Worker & sandbox tests
└── docs/
    ├── architecture/            # Architecture overview, schema & sandbox docs
    ├── audits/                  # Audit & compliance reports
    └── screenshots/             # Interface verification screenshots
```

---

## 2. Proposed Cleanup Tasks by Phase

### Phase 1 — Safe Deletions

1. **Delete Leftover Dev Scratch Files**
   - **What**: Delete `scratch/capture_screenshots.js`, `scratch/capture_screenshots.ts`, `scratch/contrast_check.ts`, `scratch/test_browser_journey.ts`.
   - **Why**: Temporary dev scratch files created for one-off tasks; not imported by any package script, build, or test.
   - **Evidence**: Grep search confirms zero imports in `src/`, `packages/`, `apps/`, or `package.json`.
   - **Risk**: Low.
   - **Phase**: Phase 1.

2. **Delete Leftover Source-Folder Build Artifacts**
   - **What**: Delete `packages/core/test-utils/index.js`, `packages/core/test-utils/index.d.ts`, `packages/worker/src/index.d.ts.map`, `packages/worker/src/types.d.ts.map`.
   - **Why**: Compiled JS/declaration map outputs committed directly inside source directories instead of build output.
   - **Evidence**: Source TypeScript files (`.ts`) are compiled via build scripts into `dist/`.
   - **Risk**: Low.
   - **Phase**: Phase 1.

3. **Delete Obsolete Audit Reports & Temporary Notes**
   - **What**: Delete `docs/AUDIT_REPORT.md`, `docs/AUDIT_REPORT_2.md`, `docs/LOCAL_RUN_REPORT.md`, `docs/decisions.md`.
   - **Why**: Superseded by updated documentation: `docs/AUDIT_REPORT_3.md`, `docs/GITHUB_CONNECT_REPORT.md`, and `docs/ARCHITECTURE.md`.
   - **Evidence**: Historical audit notes from earlier development phases.
   - **Risk**: Low.
   - **Phase**: Phase 1.

4. **Update `.gitignore`**
   - **What**: Add `*.d.ts.map`, `*.js.map`, `test-results/`, `scoreboard.json`, `mutation-scoreboard.json` to `.gitignore`.
   - **Why**: Prevent build maps, test result logs, and generated scoreboards from being committed.
   - **Evidence**: Keeps `git status` clean after running vitest and scoreboard benchmarks.
   - **Risk**: Low.
   - **Phase**: Phase 1.

---

### Phase 2 — Reorganize

5. **Organize `docs/` Directory Structure**
   - **What**: Group markdown documentation into clean subdirectories:
     - `docs/architecture/` (`ARCHITECTURE.md`, `catalogs.md`, `finding-schema.md`, `sandbox.md`, `stages.md`, `web-design.md`)
     - `docs/audits/` (`AUDIT_REPORT_3.md`, `GITHUB_CONNECT_REPORT.md`, `UI_REPORT.md`)
     - `docs/screenshots/` (existing UI screenshot PNG files)
   - **Why**: Prevents flat documentation file clutter in root `docs/`.
   - **Evidence**: `git mv` preserves full commit history while improving repository navigation.
   - **Risk**: Low.
   - **Phase**: Phase 2.

6. **Standardize Test File Names & Structure**
   - **What**: Use consistent camelCase / snake_case naming across test suites in `apps/web/test/` and `packages/core/test/`.
   - **Why**: Homogenize test file naming conventions.
   - **Evidence**: All vitest suites will be referenced with matching paths.
   - **Risk**: Low.
   - **Phase**: Phase 2.

---

### Phase 3 — Consolidate Duplicates & Refactor Large Files

7. **Consolidate Detector Re-exporter**
   - **What**: Consolidate `packages/core/src/detectors/routes-and-migrations.ts` re-exports directly into `packages/core/src/detectors/registry.ts`.
   - **Why**: `routes-and-migrations.ts` is a 4-line re-export wrapper forwarding symbols from `nextjs-rules.ts`, `supabase.ts`, and `stripe.ts`.
   - **Evidence**: Direct imports from `registry.ts` simplify detector discovery.
   - **Risk**: Low (imports will be preserved/updated).
   - **Phase**: Phase 3.

8. **Refactor Oversized `scan-findings-page.ts`**
   - **What**: Split `apps/web/src/routes/scan-findings-page.ts` (735 lines) into:
     - `scan-findings-renderer.ts` (HTML string templates, tab scripts, CSS styling)
     - `scan-findings-page.ts` (Route handler, session verification, DB queries)
   - **Why**: Separates HTML presentation from backend orchestration, improving maintainability.
   - **Evidence**: Keeps security assertions intact while reducing file complexity.
   - **Risk**: Medium (verify via typecheck, lint, and full vitest).
   - **Phase**: Phase 3.

---

### Phase 4 — Developer Experience

9. **Create Root `README.md`**
   - **What**: Write comprehensive `README.md` with:
     - NANTIS security review engine overview
     - Installation instructions (`npm install`)
     - How to start local web app (`npm run dev`)
     - How to run test suite (`npm run test`)
     - How to run quality checks (`npm run typecheck`, `npm run lint`)
     - Folder layout map linking to `docs/architecture/ARCHITECTURE.md`
     - Core security & credential rules
   - **Why**: Provides a single onboarding document for developers.
   - **Evidence**: Essential root documentation for workspace entry.
   - **Risk**: Low.
   - **Phase**: Phase 4.

10. **Clean Up `package.json` Scripts & Confirm `.env.example`**
    - **What**: Ensure root and workspace `package.json` scripts have clear names (`dev`, `build`, `test`, `typecheck`, `lint`) and verify `.env.example` has all required empty environment variables.
    - **Why**: Standardizes developer workflows.
    - **Evidence**: Clean developer experience.
    - **Risk**: Low.
    - **Phase**: Phase 4.
