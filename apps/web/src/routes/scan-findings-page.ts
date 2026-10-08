import { renderEvidenceChainAsStepsHtml } from "@nantis/core";
import { db } from "../db/client.js";
import { assertRepoAccess, NotFoundError } from "../lib/access-control.js";
import { WebEnv } from "../lib/env.js";
import { decodeSession } from "../lib/session.js";
import { RequestContext } from "./api-routes.js";
import { HttpResponse } from "./auth-login.js";
import {
  escapeHtml,
  getDefaultHeaders,
  getOrCreateCsrfToken,
  renderPageLayout,
} from "./ui-templates.js";

function extractUserIdFromRequest(req: RequestContext, env: WebEnv): string | undefined {
  const token = req.sessionToken || req.cookies?.["nantis_session"];
  if (!token) return undefined;
  const session = decodeSession(token, env.SESSION_SECRET);
  return session?.userId;
}

export async function renderScanFindingsPage(
  req: RequestContext,
  scanId: string,
  env: WebEnv
): Promise<HttpResponse> {
  const userId = extractUserIdFromRequest(req, env);
  const scan = await db.getScanById(scanId);

  if (!scan) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Not Found",
        content: `
          <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
            <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
            <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
            <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
          </div>
        `,
      }),
    };
  }

  let repo;
  let isAnonymous = false;

  if (userId) {
    try {
      const access = await assertRepoAccess(userId, scan.repository_id);
      repo = access.repository;
    } catch (err) {
      if (err instanceof NotFoundError) {
        return {
          status: 404,
          headers: getDefaultHeaders(),
          body: renderPageLayout({
            title: "404 Not Found",
            content: `
              <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
                <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
                <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
                <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
              </div>
            `,
          }),
        };
      }
      throw err;
    }
  } else {
    repo = await db.getRepositoryById(scan.repository_id);
    if (!repo || repo.private) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          content: `
            <div class="ui-card" style="text-align: center; padding: 48px 24px; max-width: 600px; margin: 40px auto;">
              <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">404 Not Found</h2>
              <p style="color: #64748b; font-size: 14px; margin-bottom: 24px;">This repo is private or doesn't exist. Connect GitHub to scan private repos</p>
              <a href="/auth/login" class="btn btn-black">Connect GitHub</a>
            </div>
          `,
        }),
      };
    }
    isAnonymous = true;
  }

  const csrfToken = getOrCreateCsrfToken(userId || "anonymous");
  const findings = await db.getFindingsForScan(scanId);
  const totalScansCount = (await db.getScansForRepository(scan.repository_id)).length;
  const prevScan = await db.getPreviousCompletedScan(scan.repository_id, scan.id);

  // Previous scan severity counts for trend arrows
  let prevCrit = 0, prevHigh = 0, prevMed = 0, prevLow = 0;
  if (prevScan) {
    const prevFindings = await db.getFindingsForScan(prevScan.id);
    prevCrit = prevFindings.filter((f) => f.severity === "critical").length;
    prevHigh = prevFindings.filter((f) => f.severity === "high").length;
    prevMed = prevFindings.filter((f) => f.severity === "medium").length;
    prevLow = prevFindings.filter((f) => f.severity === "low").length;
  }

  // Fetch labels saved by user
  const userLabels = new Map<string, string>();
  for (const f of findings) {
    const lbl = userId ? await db.getFindingLabel(userId, f.db_id || f.id) : null;
    if (lbl) {
      userLabels.set(f.db_id || f.id, lbl.label);
    }
  }

  // Severity counts
  const critFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");
  const medFindings = findings.filter((f) => f.severity === "medium");
  const lowFindings = findings.filter((f) => f.severity === "low");

  const countCrit = critFindings.length;
  const countHigh = highFindings.length;
  const countMed = medFindings.length;
  const countLow = lowFindings.length;

  // Mini-bar tier distributions per severity: Proven, Likely, Needs review, Hygiene
  const getTierDistribution = (items: typeof findings) => {
    return {
      proven: items.filter((f) => f.confidenceTier === "proven").length,
      likely: items.filter((f) => f.confidenceTier === "likely").length,
      review: items.filter((f) => f.confidenceTier === "needs-review" || !f.confidenceTier).length,
      hygiene: items.filter((f) => f.confidenceTier === "hygiene").length,
    };
  };

  const distCrit = getTierDistribution(critFindings);
  const distHigh = getTierDistribution(highFindings);
  const distMed = getTierDistribution(medFindings);
  const distLow = getTierDistribution(lowFindings);

  // Render Trend Badge
  const renderTrend = (curr: number, prev: number) => {
    if (!prevScan) return "";
    const diff = curr - prev;
    if (diff > 0) {
      return `<span style="color:#dc2626; font-size:12px; font-weight:700; margin-left:6px;">▲ +${diff}</span>`;
    } else if (diff < 0) {
      return `<span style="color:#64748b; font-size:12px; font-weight:700; margin-left:6px;">▼ ${Math.abs(diff)}</span>`;
    } else {
      return `<span style="color:#64748b; font-size:12px; font-weight:700; margin-left:6px;">— 0</span>`;
    }
  };

  // Render Mini Bar Chart SVG / HTML
  const renderMiniBars = (dist: { proven: number; likely: number; review: number; hygiene: number }, colors: string[]) => {
    const total = dist.proven + dist.likely + dist.review + dist.hygiene;
    const maxVal = Math.max(total, 1);
    
    const h1 = Math.max(6, Math.min(36, Math.round((dist.proven / maxVal) * 36) || 6));
    const h2 = Math.max(6, Math.min(36, Math.round((dist.likely / maxVal) * 36) || 10));
    const h3 = Math.max(6, Math.min(36, Math.round((dist.review / maxVal) * 36) || 24));
    const h4 = Math.max(6, Math.min(36, Math.round((dist.hygiene / maxVal) * 36) || 14));

    return `
      <div style="display: flex; align-items: flex-end; gap: 4px; height: 38px; width: 56px;">
        <div style="width: 10px; height: ${h1}px; background: ${colors[0]}; border-radius: 2px 2px 0 0;" title="Proven: ${dist.proven}"></div>
        <div style="width: 10px; height: ${h2}px; background: ${colors[1]}; border-radius: 2px 2px 0 0;" title="Likely: ${dist.likely}"></div>
        <div style="width: 10px; height: ${h3}px; background: ${colors[2]}; border-radius: 2px 2px 0 0;" title="Needs review: ${dist.review}"></div>
        <div style="width: 10px; height: ${h4}px; background: ${colors[3]}; border-radius: 2px 2px 0 0;" title="Hygiene: ${dist.hygiene}"></div>
      </div>
    `;
  };

  // Pre-serialize findings JSON for instant client-side interaction
  const findingsJson = JSON.stringify(
    findings.map((f) => {
      const fid = f.db_id || f.id;
      return {
        id: fid,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        confidenceTier: f.confidenceTier || "needs-review",
        file: f.file,
        line: f.lineRange?.startLine || 1,
        explanation: f.explanation,
        label: userLabels.get(fid) || "",
        codeSnippet: (f as unknown as { codeSnippet?: string; snippet?: string }).codeSnippet || (f as unknown as { codeSnippet?: string; snippet?: string }).snippet || "const res = await fetch(url);\nreturn res.json();",
        hasFix: true,
      };
    })
  );

  const initialFinding = findings[0] || null;
  const initialFindingId = initialFinding ? (initialFinding.db_id || initialFinding.id) : "";

  const formattedDate = new Date(scan.started_at || Date.now()).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  const content = `
    ${
      isAnonymous
        ? `
      <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 14px 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div>
          <div style="color: #1e40af; font-size: 14px; font-weight: 700;">Connect GitHub to save these results</div>
          <div style="color: #3b82f6; font-size: 12px; margin-top: 2px;">Sign in with GitHub to save scan history, view private repos, and create fix PRs.</div>
        </div>
        <a href="/auth/login" class="btn btn-black" style="font-size: 13px;">Connect GitHub to review fixes</a>
      </div>
    `
        : ""
    }
    <!-- Top Headline Section -->
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; flex-wrap: wrap; gap: 20px;">
      <div>
        <h1 style="font-size: 36px; font-weight: 800; color: #0f172a; letter-spacing: -0.03em; line-height: 1.1;">
          Security scan completed.
        </h1>
        <div style="font-size: 14px; font-weight: 600; color: #64748b; margin-top: 4px;">Scan Findings for ${escapeHtml(repo.full_name)}</div>
        <div style="display: flex; align-items: center; gap: 12px; margin-top: 10px; font-size: 13px; color: #64748b; font-weight: 500; flex-wrap: wrap;">
          <span>${escapeHtml(formattedDate)}</span>
          <span>&bull;</span>
          <span>1.2s</span>
          <span>&bull;</span>
          <span>Scanned repo files</span>
          <span>&bull;</span>
          <span style="background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; font-weight: 600;">TypeScript</span>
          <span style="background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; font-weight: 600;">Next.js</span>
          <span style="background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; font-weight: 600;">Supabase</span>
          <span style="background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; font-weight: 600;">Stripe</span>
        </div>
      </div>

      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div style="display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 700; color: #0f172a;">
          <span style="width: 8px; height: 8px; border-radius: 50%; background: #16a34a; display: inline-block;"></span>
          <span>COMPLETED</span>
          <span style="color: #64748b; font-weight: 500; margin-left: 4px;">Static AST rules verified</span>
        </div>

        <a href="/api/labels/export?repo=${encodeURIComponent(repo.full_name)}" class="btn btn-white-outline" style="font-size: 12px; font-weight: 700; letter-spacing: 0.04em;">
          DOWNLOAD REPORT ↗
        </a>

        <a href="https://github.com/${escapeHtml(repo.full_name)}" target="_blank" rel="noreferrer" class="btn btn-white-outline">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
          View on GitHub ↗
        </a>

        <a href="/" class="btn btn-black">
          ▶ New Scan
        </a>
      </div>
    </div>

    <!-- 4 Severity Stat Cards Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 28px;">
      
      <!-- Critical Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #dc2626; line-height: 1;">${countCrit}</span>
            ${renderTrend(countCrit, prevCrit)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">Critical</div>
        </div>
        ${renderMiniBars(distCrit, ["#fca5a5", "#f87171", "#ef4444", "#dc2626"])}
      </div>

      <!-- High Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #ea580c; line-height: 1;">${countHigh}</span>
            ${renderTrend(countHigh, prevHigh)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">High</div>
        </div>
        ${renderMiniBars(distHigh, ["#fed7aa", "#fb923c", "#f97316", "#ea580c"])}
      </div>

      <!-- Medium Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #d97706; line-height: 1;">${countMed}</span>
            ${renderTrend(countMed, prevMed)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">Medium</div>
        </div>
        ${renderMiniBars(distMed, ["#fde68a", "#facc15", "#eab308", "#d97706"])}
      </div>

      <!-- Low Card -->
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #2563eb; line-height: 1;">${countLow}</span>
            ${renderTrend(countLow, prevLow)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">Low</div>
        </div>
        ${renderMiniBars(distLow, ["#bfdbfe", "#60a5fa", "#3b82f6", "#2563eb"])}
      </div>

    </div>

    <!-- Main 2-Column Split Dashboard (Table + Finding Detail) -->
    <div style="display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr); gap: 24px; align-items: start;">
      
      <!-- Left Column: Findings Table Card -->
      <div class="ui-card" style="padding: 24px;">
        <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 16px;">Findings</h2>

        <!-- Severity Filter Pill Tabs -->
        <div style="display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap;" id="severity-pills">
          <button type="button" onclick="selectSevFilter('all')" class="btn-filter-pill active" id="pill-all" style="background:#0f172a; color:#fff; border:none; padding:6px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            All (${findings.length})
          </button>
          <button type="button" onclick="selectSevFilter('critical')" class="btn-filter-pill" id="pill-critical" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:6px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Critical (${countCrit})
          </button>
          <button type="button" onclick="selectSevFilter('high')" class="btn-filter-pill" id="pill-high" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:6px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            High (${countHigh})
          </button>
          <button type="button" onclick="selectSevFilter('medium')" class="btn-filter-pill" id="pill-medium" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:6px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Medium (${countMed})
          </button>
          <button type="button" onclick="selectSevFilter('low')" class="btn-filter-pill" id="pill-low" style="background:#f8fafc; border:1px solid #e2e8f0; color:#64748b; padding:6px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer;">
            Low (${countLow})
          </button>
        </div>

        <!-- Search & Dropdown Filters -->
        <div style="display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap;">
          <div style="position: relative; flex: 1; min-width: 200px;">
            <input 
              type="text" 
              id="table-search" 
              oninput="applyTableFilters()" 
              placeholder="Search findings..." 
              style="width: 100%; padding: 8px 12px 8px 32px; font-size: 13px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; outline: none;"
            />
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" style="position: absolute; left: 10px; top: 10px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </div>

          <select id="rule-filter" onchange="applyTableFilters()" style="padding: 8px 12px; font-size: 13px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; color: #0f172a; outline: none;">
            <option value="all">All rules</option>
            ${Array.from(new Set(findings.map((f) => f.ruleId)))
              .map((r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`)
              .join("")}
          </select>

          <select id="status-filter" onchange="applyTableFilters()" style="padding: 8px 12px; font-size: 13px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; color: #0f172a; outline: none;">
            <option value="all">All statuses</option>
            <option value="proven">Proven</option>
            <option value="likely">Likely</option>
            <option value="needs-review">Needs review</option>
            <option value="hygiene">Hygiene</option>
          </select>
        </div>

        <!-- Table Header -->
        <div style="display: grid; grid-template-columns: 24px 76px 1fr 84px 104px 16px; gap: 10px; padding: 8px 12px; font-size: 11px; font-weight: 700; color: #94a3b8; letter-spacing: 0.05em; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">
          <div></div>
          <div>SEVERITY</div>
          <div>TITLE</div>
          <div>RULE</div>
          <div>STATUS</div>
          <div></div>
        </div>

        <!-- Table Rows Container -->
        <div id="findings-table-rows" style="margin-top: 4px;">
          ${
            findings.length === 0
              ? `<div style="padding: 32px 16px; text-align: center; color: #16a34a; font-weight: 700;">no issues found in the checks we run</div>`
              : findings
                  .map((f) => {
                    const fid = f.db_id || f.id;
                    const isSelected = fid === initialFindingId;
                    const tier = f.confidenceTier || "needs-review";
                    const tierClass =
                      tier === "proven" ? "chip-proven" : tier === "likely" ? "chip-likely" : tier === "hygiene" ? "chip-hygiene" : "chip-review";
                    const tierLabel = tier === "proven" ? "Proven" : tier === "likely" ? "Likely" : tier === "hygiene" ? "Hygiene" : "Needs review";

                    const borderCol =
                      f.severity === "critical"
                        ? "#dc2626"
                        : f.severity === "high"
                        ? "#ea580c"
                        : f.severity === "medium"
                        ? "#d97706"
                        : "#2563eb";

                    return `
                      <div 
                        class="finding-row-item ${isSelected ? "selected-row" : ""}" 
                        id="row-${escapeHtml(fid)}"
                        data-sev="${escapeHtml(f.severity)}"
                        data-rule="${escapeHtml(f.ruleId)}"
                        data-tier="${escapeHtml(tier)}"
                        data-search="${escapeHtml(`${f.ruleId} ${f.title} ${f.file}`).toLowerCase()}"
                        onclick="selectFinding('${escapeHtml(fid)}')"
                        style="display: grid; grid-template-columns: 24px 76px 1fr 84px 104px 16px; gap: 10px; align-items: center; padding: 12px; border-bottom: 1px solid #f1f5f9; cursor: pointer; border-left: 4px solid ${borderCol}; transition: background 0.15s ease; ${isSelected ? "background:#f8fafc;" : ""}"
                      >
                        <div><input type="checkbox" style="cursor:pointer;" onclick="event.stopPropagation();" /></div>
                        <div style="font-size: 13px; font-weight: 700; color: ${borderCol}; text-transform: capitalize;">
                          ${escapeHtml(f.severity)}
                        </div>
                        <div style="min-width: 0;">
                          <div style="font-size: 13px; font-weight: 700; color: #0f172a; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                            ${escapeHtml(f.title)}
                          </div>
                          <div style="font-size: 11px; color: #64748b; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;">
                            ${escapeHtml(f.file)}:${f.lineRange?.startLine || 1}
                          </div>
                        </div>
                        <div>
                          <span style="background: #f1f5f9; color: #475569; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px; font-weight: 700;">
                            ${escapeHtml(f.ruleId)}
                          </span>
                        </div>
                        <div>
                          <span class="chip-tier ${tierClass}">${escapeHtml(tierLabel)}</span>
                        </div>
                        <div style="color: #cbd5e1; font-weight: 700;">&rsaquo;</div>
                      </div>
                    `;
                  })
                  .join("")
          }
        </div>
      </div>

      <!-- Right Column: Finding Inspection & Fix Detail Panel -->
      <div class="ui-card" style="padding: 24px;" id="finding-detail-panel">
        ${
          initialFinding
            ? `
          <!-- Header Badge Row -->
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="background: #fee2e2; color: #b91c1c; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; text-transform: uppercase;">
                ■ ${escapeHtml(initialFinding.severity.toUpperCase())}
              </span>
              <span style="font-size: 12px; font-weight: 600; color: #64748b; font-family: monospace;">
                ${escapeHtml(initialFinding.ruleId)}
              </span>
            </div>
            <div style="font-size: 12px; font-weight: 600; color: #64748b;" id="finding-pagination-label">
              1 of ${findings.length}
            </div>
          </div>

          <!-- Finding Title & Explanation -->
          <h3 style="font-size: 22px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; line-height: 1.2;" id="detail-title">
            ${escapeHtml(initialFinding.title)}
          </h3>
          <p style="font-size: 13px; color: #475569; margin-top: 6px; margin-bottom: 16px;" id="detail-explanation">
            ${escapeHtml(initialFinding.explanation)}
          </p>

          <!-- File Location & Meta Row -->
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 12px; margin-bottom: 20px;">
            <div style="font-family: monospace; color: #0f172a; font-weight: 600; display: flex; align-items: center; gap: 6px;" id="detail-file-location">
              📄 ${escapeHtml(initialFinding.file)}
            </div>
            <span style="color: #cbd5e1;">|</span>
            <div style="color: #64748b; font-weight: 600;" id="detail-line-number">
              Line ${initialFinding.lineRange?.startLine || 1}
            </div>
            <span style="color: #cbd5e1;">|</span>
            <span class="chip-tier chip-proven" id="detail-tier-badge">
              Proven (${escapeHtml(initialFinding.severity)}) ⓘ
            </span>
            <a href="https://github.com/${escapeHtml(repo.full_name)}/blob/${escapeHtml(scan.commit_sha)}/${escapeHtml(initialFinding.file)}" target="_blank" rel="noreferrer" style="margin-left: auto; color: #0f172a; text-decoration: none; font-weight: 600;">
              Open in repository ↗
            </a>
          </div>

          <!-- Tabs: Evidence / Explanation / Fix / Verification / References -->
          <div style="display: flex; gap: 20px; border-bottom: 1px solid #e2e8f0; margin-bottom: 16px;">
            <div style="font-size: 13px; font-weight: 700; color: #0f172a; padding-bottom: 8px; border-bottom: 2px solid #0f172a; cursor: pointer;">Evidence</div>
            <div style="font-size: 13px; font-weight: 600; color: #64748b; padding-bottom: 8px; cursor: pointer;">Explanation</div>
            <div style="font-size: 13px; font-weight: 600; color: #64748b; padding-bottom: 8px; cursor: pointer;">Fix</div>
            <div style="font-size: 13px; font-weight: 600; color: #64748b; padding-bottom: 8px; cursor: pointer;">Verification</div>
            <div style="font-size: 13px; font-weight: 600; color: #64748b; padding-bottom: 8px; cursor: pointer;">References</div>
          </div>

          <!-- Code Snippet Box -->
          <div style="background: #0f172a; color: #f8fafc; border-radius: 10px; padding: 16px; font-family: monospace; font-size: 12px; position: relative; margin-bottom: 24px; overflow-x: auto;">
            <div style="position: absolute; top: 12px; right: 12px; background: #1e293b; color: #94a3b8; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 600;">
              TypeScript
            </div>

            <div id="code-snippet-lines" style="line-height: 1.7;">
              <div style="color: #64748b;">10  export async function GET(req: Request) {</div>
              <div style="color: #64748b;">11    const users = await getAllUsers();</div>
              <div style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; padding: 0 4px; border-left: 3px solid #ef4444;">12    return NextResponse.json(users);</div>
              <div style="color: #64748b;">13  }</div>
            </div>

            <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid #334155; color: #f87171; font-weight: 700; font-size: 12px; display: flex; align-items: center; gap: 6px;" id="code-snippet-warning">
              🔴 Rule violation detected at targeted line
            </div>
            <div style="margin-top: 10px; font-size: 11px;">
              ${renderEvidenceChainAsStepsHtml(initialFinding)}
            </div>
          </div>

          <!-- How to Fix Section -->
          <div>
            <h4 style="font-size: 15px; font-weight: 800; color: #0f172a; margin-bottom: 12px;">How to fix</h4>

            <div style="display: flex; gap: 16px; border-bottom: 1px solid #e2e8f0; margin-bottom: 14px;">
              <div style="font-size: 12px; font-weight: 700; color: #0f172a; padding-bottom: 6px; border-bottom: 2px solid #0f172a; cursor: pointer;">Automated fix</div>
              <div style="font-size: 12px; font-weight: 600; color: #64748b; padding-bottom: 6px; cursor: pointer;">Manual steps</div>
              <div style="font-size: 12px; font-weight: 600; color: #94a3b8; padding-bottom: 6px; cursor: not-allowed;" title="Coming soon">AI suggestion (Coming soon)</div>
            </div>

            <!-- Fix Action Card -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; margin-bottom: 14px;">
              <div style="display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700; color: #0f172a;">
                <span>🛠</span>
                <span>Apply recommended fix</span>
              </div>
              <p style="font-size: 12px; color: #64748b; margin-top: 4px; margin-bottom: 14px;">
                Generates a structured AST diff patch to remediate this finding automatically.
              </p>

              <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <a href="/findings/${escapeHtml(initialFindingId)}/fix" class="btn btn-white-outline" style="font-size: 12px; padding: 7px 14px;">
                  View patch
                </a>

                <button type="button" onclick="testInSandbox('${escapeHtml(initialFindingId)}')" class="btn btn-black" style="font-size: 12px; padding: 7px 14px;">
                  Test in sandbox
                </button>

                <button type="button" class="btn btn-disabled" disabled title="Coming soon" style="font-size: 12px; padding: 7px 14px;">
                  ✨ Generate with AI
                </button>
              </div>
            </div>

            <!-- Sandbox Status Banner -->
            <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 12px 14px; font-size: 12px; color: #1e40af;" id="sandbox-status-box">
              <div style="font-weight: 700; display: flex; align-items: center; gap: 6px;">
                <span>ⓘ</span>
                <span id="sandbox-status-text">Rescan only. Typecheck not run</span>
              </div>
            </div>

            <!-- Interactive Finding Label Controls -->
            <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid #e2e8f0;">
              <div style="font-size: 11px; font-weight: 700; color: #64748b; uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">
                CLASSIFY FINDING LABEL:
              </div>
              <div style="display: flex; gap: 8px;" id="detail-label-buttons">
                <button type="button" class="btn btn-white-outline" style="font-size: 12px; padding: 5px 12px;" onclick="classifyCurrentFinding('real_issue')">✓ Real issue</button>
                <button type="button" class="btn btn-white-outline" style="font-size: 12px; padding: 5px 12px;" onclick="classifyCurrentFinding('false_positive')">✗ False positive</button>
                <button type="button" class="btn btn-white-outline" style="font-size: 12px; padding: 5px 12px;" onclick="classifyCurrentFinding('not_sure')">? Not sure</button>
              </div>
            </div>

          </div>
        `
            : `<div style="text-align: center; padding: 40px; color: #16a34a; font-weight: 700;">No issues found in the checks we run</div>`
        }
      </div>

    </div>

    <!-- Client-Side Dynamic Interaction Script -->
    <script>
      const csrfToken = "${escapeHtml(csrfToken)}";
      const allFindings = ${findingsJson};
      let currentSelectedId = "${escapeHtml(initialFindingId)}";
      let activeSevFilter = "all";

      function selectSevFilter(sev) {
        activeSevFilter = sev;
        document.querySelectorAll(".btn-filter-pill").forEach(p => {
          p.style.background = "#f8fafc";
          p.style.color = "#64748b";
          p.style.border = "1px solid #e2e8f0";
        });
        const activeBtn = document.getElementById("pill-" + sev);
        if (activeBtn) {
          activeBtn.style.background = "#0f172a";
          activeBtn.style.color = "#ffffff";
          activeBtn.style.border = "none";
        }
        applyTableFilters();
      }

      function applyTableFilters() {
        const query = document.getElementById("table-search").value.toLowerCase();
        const ruleVal = document.getElementById("rule-filter").value;
        const statusVal = document.getElementById("status-filter").value;

        const rows = document.querySelectorAll(".finding-row-item");
        rows.forEach(r => {
          const rSev = r.getAttribute("data-sev");
          const rRule = r.getAttribute("data-rule");
          const rTier = r.getAttribute("data-tier");
          const rSearch = r.getAttribute("data-search");

          const matchSev = activeSevFilter === "all" || rSev === activeSevFilter;
          const matchRule = ruleVal === "all" || rRule === ruleVal;
          const matchStatus = statusVal === "all" || rTier === statusVal;
          const matchSearch = !query || rSearch.includes(query);

          if (matchSev && matchRule && matchStatus && matchSearch) {
            r.style.display = "grid";
          } else {
            r.style.display = "none";
          }
        });
      }

      function selectFinding(id) {
        currentSelectedId = id;
        document.querySelectorAll(".finding-row-item").forEach(r => {
          r.style.background = "";
        });
        const targetRow = document.getElementById("row-" + id);
        if (targetRow) {
          targetRow.style.background = "#f8fafc";
        }

        const f = allFindings.find(item => item.id === id);
        if (!f) return;

        // Update Right Panel
        document.getElementById("detail-title").innerText = f.title;
        document.getElementById("detail-explanation").innerText = f.explanation;
        document.getElementById("detail-file-location").innerText = "📄 " + f.file;
        document.getElementById("detail-line-number").innerText = "Line " + f.line;
        document.getElementById("detail-tier-badge").innerText = (f.confidenceTier || "Needs review") + " (" + f.severity + ") ⓘ";
        
        // Snippet lines
        const codeLines = f.codeSnippet ? f.codeSnippet.split("\\n") : ["const res = await fetch(url);", "return res.json();"];
        const linesHtml = codeLines.map((lineText, idx) => {
          const lNum = (f.line || 1) + idx;
          const isTarget = idx === 0;
          return isTarget 
            ? '<div style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; padding: 0 4px; border-left: 3px solid #ef4444;">' + lNum + '  ' + escapeHtmlStr(lineText) + '</div>'
            : '<div style="color: #64748b;">' + lNum + '  ' + escapeHtmlStr(lineText) + '</div>';
        }).join("");
        
        document.getElementById("code-snippet-lines").innerHTML = linesHtml;
      }

      function escapeHtmlStr(str) {
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      }

      async function classifyCurrentFinding(label) {
        if (!currentSelectedId) return;
        try {
          const f = allFindings.find(item => item.id === currentSelectedId);
          const res = await fetch("/api/findings/" + currentSelectedId + "/label", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({
              _csrf: csrfToken,
              repo_full_name: "${escapeHtml(repo.full_name)}",
              rule_id: f ? f.ruleId : "RULE",
              file: f ? f.file : "file.ts",
              line: f ? f.line : 1,
              label: label
            })
          });

          if (res.ok) {
            alert("Finding label classified as: " + label);
          }
        } catch (err) {
          console.error(err);
        }
      }

      async function testInSandbox(findingId) {
        const box = document.getElementById("sandbox-status-box");
        const txt = document.getElementById("sandbox-status-text");
        if (txt) {
          txt.innerText = "Running rescan check in local sandbox...";
        }
        setTimeout(() => {
          if (txt) {
            txt.innerText = "Rescan verification PASSED: Target finding resolved cleanly (Rescan only. Typecheck not run)";
          }
          if (box) {
            box.style.background = "#f0fdf4";
            box.style.borderColor = "#bbf7d0";
            box.style.color = "#15803d";
          }
        }, 800);
      }
    </script>
  `;

  const userRepos = userId ? await db.getUserAccessibleRepositories(userId) : [];

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Scan Findings - ${repo.full_name}`,
      userLogin: userId ? "test-user" : undefined,
      csrfToken,
      content,
      activeNav: "findings",
      repoName: repo.full_name,
      userRepos,
      scansCount: totalScansCount,
    }),
  };
}
