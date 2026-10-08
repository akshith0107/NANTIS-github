# NANTIS Visual & UI Design System Audit Report

## Executive Summary
This report documents the design system overhaul of NANTIS, eliminating legacy dark-theme CSS, inline dark overrides, and unreadable gradient text in favor of a single high-contrast light design system (`docs/design/dashboard-reference.png`).

All text/background color pairs meet or exceed **WCAG AA contrast requirements (>= 4.5:1 ratio)**.

---

## 1. WCAG AA Contrast Audit Results

The contrast ratio table below was generated via automated color calculation script (`scratch/contrast_check.ts`) using the W3C relative luminance formula:

| Element / Pair Name | Text Color | Background Color | Contrast Ratio | WCAG AA Requirement | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Primary Text on Page Background | `#0f172a` | `#f8fafc` | **17.06 : 1** | >= 4.5 : 1 | ✅ PASS |
| Primary Text on Card Surface | `#0f172a` | `#ffffff` | **17.85 : 1** | >= 4.5 : 1 | ✅ PASS |
| Secondary Text on Card Surface | `#475569` | `#ffffff` | **7.58 : 1** | >= 4.5 : 1 | ✅ PASS |
| Muted Text on Card Surface | `#64748b` | `#ffffff` | **4.76 : 1** | >= 4.5 : 1 | ✅ PASS |
| Critical Severity Badge | `#dc2626` | `#ffffff` | **4.83 : 1** | >= 4.5 : 1 | ✅ PASS |
| High Severity Badge | `#c2410c` | `#ffffff` | **5.18 : 1** | >= 4.5 : 1 | ✅ PASS |
| Medium Severity Badge | `#b45309` | `#ffffff` | **5.02 : 1** | >= 4.5 : 1 | ✅ PASS |
| Low Severity Badge | `#1d4ed8` | `#ffffff` | **6.70 : 1** | >= 4.5 : 1 | ✅ PASS |
| Proven Confidence Tier | `#7e22ce` | `#f3e8ff` | **5.92 : 1** | >= 4.5 : 1 | ✅ PASS |
| Likely Confidence Tier | `#c2410c` | `#ffedd5` | **4.52 : 1** | >= 4.5 : 1 | ✅ PASS |
| Needs Review Tier | `#b91c1c` | `#fee2e2` | **5.30 : 1** | >= 4.5 : 1 | ✅ PASS |
| Hygiene Confidence Tier | `#047857` | `#d1fae5` | **4.84 : 1** | >= 4.5 : 1 | ✅ PASS |
| Sidebar Link Normal | `#64748b` | `#ffffff` | **4.76 : 1** | >= 4.5 : 1 | ✅ PASS |
| Sidebar Link Active | `#0f172a` | `#f1f5f9` | **16.30 : 1** | >= 4.5 : 1 | ✅ PASS |
| Primary Action Button | `#ffffff` | `#0f172a` | **17.85 : 1** | >= 4.5 : 1 | ✅ PASS |

---

## 2. Page-by-Page Reference Comparison & Screenshot Matrix

| Page / State | Matches Reference? | Screenshot Path | Differences / Remaining Gaps |
| :--- | :--- | :--- | :--- |
| **Home / Dashboard (Empty)** | Close Match | [`docs/screenshots/home_empty.png`](file:///e:/gnu/docs/screenshots/home_empty.png) | High alignment with reference card structure and light neutral background. URL input uses `https://github.com/owner/repo` placeholder. Top bar dynamically displays "No repositories yet" when no scans exist. Hint text simplified to "Public GitHub repositories only.". Dev local folder input has distinct label. Empty state designed with clean dashed border. |
| **Home / Dashboard (Scanned)** | Close Match | [`docs/screenshots/home_scanned.png`](file:///e:/gnu/docs/screenshots/home_scanned.png) | Dynamic session counter and recent scans list display scanned repositories. Header dropdown updates to show user's active repository. |
| **Repositories List** | Close Match | [`docs/screenshots/repos.png`](file:///e:/gnu/docs/screenshots/repos.png) | Cards render in light mode with `#f1f5f9` public/private badges. Only user-accessible repositories are shown. |
| **Scan Results** | Close Match | [`docs/screenshots/scan_results.png`](file:///e:/gnu/docs/screenshots/scan_results.png) | High contrast layout. Confidence tier badges (Proven/Likely/Review/Hygiene) render with distinct colors. Table filter pills use solid primary dark buttons when selected. |
| **Finding Detail (Evidence Tab)** | Close Match | [`docs/screenshots/finding_detail_evidence.png`](file:///e:/gnu/docs/screenshots/finding_detail_evidence.png) | Code snippet container renders in high-contrast dark theme (`#0f172a` background with `#f8fafc` text) for readable source code and evidence hop tags. |
| **Finding Detail (Fix Tab)** | Close Match | [`docs/screenshots/finding_detail_fix.png`](file:///e:/gnu/docs/screenshots/finding_detail_fix.png) | Automated fix description and "Review & Apply Fix" primary action button render in high contrast. |
| **Fix Review** | Close Match | [`docs/screenshots/fix_review.png`](file:///e:/gnu/docs/screenshots/fix_review.png) | Side-by-side or unified diff container with light card headers and primary approval button. |
| **Fixes Management** | Partial Match | [`docs/screenshots/fixes.png`](file:///e:/gnu/docs/screenshots/fixes.png) | Honest non-connected state card matching light design tokens. Shows "Not connected yet" badge for local dev mode. |
| **Pull Requests** | Partial Match | [`docs/screenshots/pull_requests.png`](file:///e:/gnu/docs/screenshots/pull_requests.png) | Honest non-connected state card matching light design tokens. Shows "Not connected yet" badge for local dev mode. |
| **Settings** | Partial Match | [`docs/screenshots/settings.png`](file:///e:/gnu/docs/screenshots/settings.png) | Honest non-connected state card matching light design tokens. Shows "Not connected yet" badge for local dev mode. |
| **404 Page** | Close Match | [`docs/screenshots/404.png`](file:///e:/gnu/docs/screenshots/404.png) | Rendered inside standard page layout with top bar, sidebar, and light centered error card. |
| **Scan In Progress** | Close Match | [`docs/screenshots/scan_in_progress.png`](file:///e:/gnu/docs/screenshots/scan_in_progress.png) | Status indicator shows running status without hardcoded fake data. |
| **Failed Scan Error** | Close Match | [`docs/screenshots/failed_scan.png`](file:///e:/gnu/docs/screenshots/failed_scan.png) | Error card displays sanitized error message with clear warning styling. |

---

## 3. Deleted Legacy & Dark-Theme CSS

The following leftover dark-theme colors, inline style attributes, and unreadable gradient overlays were permanently removed:
- Removed `background: linear-gradient(135deg, #f8fafc, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;` from page title in `home-page.ts`. Replaced with solid high-contrast `#0f172a`.
- Removed leftover dark container background `#0d1322` from recent scans cards. Replaced with `#ffffff` light card and `#e2e8f0` border.
- Removed dark radial gradient `background: radial-gradient(circle at top right, #151d30, #111827)` from form cards. Replaced with `.ui-card` light surface.
- Removed legacy dark background `rgba(17, 24, 39, 0.6)` from secondary cards.
- Removed dark background `#1f2937` from repository public/private badges in `repos-page.ts`. Replaced with `#f1f5f9` badge background and `#475569` text.
- Replaced standalone dark themes (`#0f172a` body background, `#1e293b` container background) in `privacy-page.ts` and `rules-catalog-page.ts` with standard `renderPageLayout` light theme.
- Removed hardcoded top-bar repository fallback `"akshith0107 / NANTIS-github"`. Top bar dynamically renders `"No repositories yet"` when zero scans exist or lists only the user's accessible repositories.

---

## 4. Security & Test Assertion Audit

To ensure security invariants remain 100% strict, no XSS, CSRF, or tenant-isolation assertions were weakened.

### Assertion Modifications:
1. `apps/web/test/repos_page.test.ts`:
   - Line 87: Updated string matching for Scan button HTML to include new `.btn .btn-black` CSS class (`<button type="button" data-repo-id="${repoA.id}" class="btn btn-black" style="padding: 6px 14px; font-size: 12px;">Scan</button>`).
2. `apps/web/test/topbar_tenant_isolation.test.ts`:
   - Added new test verifying User B never sees User A's repositories in top bar header dropdown.
   - Added new test verifying User with 0 scans sees `"No repositories yet"` in header dropdown.

---

## 5. Verification Commands Battery Results

- `npm run typecheck`: **PASSED** (0 errors)
- `npm run lint`: **PASSED** (0 warnings/errors)
- `npx vitest run` (1st execution): **PASSED** (46 test files, 199 tests passed)
- `npx vitest run` (2nd execution): **PASSED** (46 test files, 199 tests passed)
- `git status`: Verified tracked and untracked file status cleanly.
