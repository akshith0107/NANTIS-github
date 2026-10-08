import { Finding, renderEvidenceChainAsStepsHtml } from "@nantis/core";
import { escapeHtml } from "./ui-templates.js";

export interface ScanFindingsRenderData {
  scan: {
    id: string;
    repository_id: string;
    started_at?: string | null;
  };
  repo: {
    id: string;
    full_name: string;
    private: boolean;
  };
  isAnonymous: boolean;
  csrfToken: string;
  findings: Array<{
    id: string;
    db_id?: string;
    ruleId: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low";
    confidenceTier?: "proven" | "likely" | "needs-review" | "hygiene";
    file: string;
    lineRange?: { startLine: number; endLine: number };
    explanation: string;
    codeSnippet?: string;
    snippet?: string;
    evidenceChain?: Array<{ step: number; description: string; file: string; line: number }>;
  }>;
  prevScan: { id: string } | null;
  prevCounts: { crit: number; high: number; med: number; low: number };
  userLabels: Map<string, string>;
  totalScansCount: number;
}

export function renderScanFindingsContent(data: ScanFindingsRenderData): string {
  const {
    scan,
    repo,
    isAnonymous,
    csrfToken,
    findings,
    prevScan,
    prevCounts,
    userLabels,
  } = data;

  const critFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");
  const medFindings = findings.filter((f) => f.severity === "medium");
  const lowFindings = findings.filter((f) => f.severity === "low");

  const countCrit = critFindings.length;
  const countHigh = highFindings.length;
  const countMed = medFindings.length;
  const countLow = lowFindings.length;

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
        codeSnippet: f.codeSnippet || f.snippet || "const res = await fetch(url);\nreturn res.json();",
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

  return `
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
      
      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #dc2626; line-height: 1;">${countCrit}</span>
            ${renderTrend(countCrit, prevCounts.crit)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">Critical</div>
        </div>
        ${renderMiniBars(distCrit, ["#fca5a5", "#f87171", "#ef4444", "#dc2626"])}
      </div>

      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #ea580c; line-height: 1;">${countHigh}</span>
            ${renderTrend(countHigh, prevCounts.high)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">High</div>
        </div>
        ${renderMiniBars(distHigh, ["#fed7aa", "#fb923c", "#f97316", "#ea580c"])}
      </div>

      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #d97706; line-height: 1;">${countMed}</span>
            ${renderTrend(countMed, prevCounts.med)}
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 6px;">Medium</div>
        </div>
        ${renderMiniBars(distMed, ["#fde68a", "#facc15", "#eab308", "#d97706"])}
      </div>

      <div class="ui-card" style="display: flex; justify-content: space-between; align-items: center; padding: 20px;">
        <div>
          <div style="display: flex; align-items: baseline;">
            <span style="font-size: 32px; font-weight: 800; color: #2563eb; line-height: 1;">${countLow}</span>
            ${renderTrend(countLow, prevCounts.low)}
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

        <div style="display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap;">
          <div style="position: relative; flex: 1; min-width: 200px;">
            <input 
              type="text" 
              id="table-search" 
              oninput="applyTableFilters()" 
              placeholder="Search findings, files, or rules..." 
              style="width: 100%; padding: 8px 12px 8px 34px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff;"
            />
            <svg style="position: absolute; left: 10px; top: 10px; width: 15px; height: 15px; color: #94a3b8;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          </div>

          <select id="tier-filter" onchange="applyTableFilters()" style="padding: 8px 12px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff; font-weight: 600; color: #334155;">
            <option value="all">All Tiers</option>
            <option value="proven">Proven</option>
            <option value="likely">Likely</option>
            <option value="needs-review">Needs review</option>
            <option value="hygiene">Hygiene</option>
          </select>

          <select id="label-filter" onchange="applyTableFilters()" style="padding: 8px 12px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff; font-weight: 600; color: #334155;">
            <option value="all">All Classifications</option>
            <option value="real_issue">Real issue</option>
            <option value="false_positive">False positive</option>
            <option value="not_sure">Not sure</option>
            <option value="unlabeled">Unclassified</option>
          </select>
        </div>

        <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
            <thead>
              <tr style="background: #f8fafc; border-bottom: 1px solid #e2e8f0; color: #475569; font-weight: 700; font-size: 12px;">
                <th style="padding: 10px 14px;">SEVERITY</th>
                <th style="padding: 10px 14px;">FINDING</th>
                <th style="padding: 10px 14px;">TIER</th>
                <th style="padding: 10px 14px;">CLASSIFICATION</th>
              </tr>
            </thead>
            <tbody id="findings-table-body">
              ${
                findings.length === 0
                  ? `<tr><td colspan="4" style="padding: 32px; text-align: center; color: #64748b;">no issues found in the checks we run</td></tr>`
                  : findings
                      .map((f) => {
                        const fid = f.db_id || f.id;
                        const isSelected = fid === initialFindingId;
                        const savedLbl = userLabels.get(fid) || "";

                        let sevBadge = "";
                        if (f.severity === "critical") sevBadge = `<span style="background:#fef2f2; color:#dc2626; padding:2px 8px; border-radius:4px; font-weight:800; font-size:11px;">CRITICAL</span>`;
                        else if (f.severity === "high") sevBadge = `<span style="background:#fff7ed; color:#ea580c; padding:2px 8px; border-radius:4px; font-weight:800; font-size:11px;">HIGH</span>`;
                        else if (f.severity === "medium") sevBadge = `<span style="background:#fffbeb; color:#d97706; padding:2px 8px; border-radius:4px; font-weight:800; font-size:11px;">MEDIUM</span>`;
                        else sevBadge = `<span style="background:#eff6ff; color:#2563eb; padding:2px 8px; border-radius:4px; font-weight:800; font-size:11px;">LOW</span>`;

                        let tierBadge = "";
                        const tier = f.confidenceTier || "needs-review";
                        if (tier === "proven") tierBadge = `<span style="background:#dcfce7; color:#15803d; padding:2px 8px; border-radius:9999px; font-weight:700; font-size:11px;">Proven</span>`;
                        else if (tier === "likely") tierBadge = `<span style="background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:9999px; font-weight:700; font-size:11px;">Likely</span>`;
                        else if (tier === "hygiene") tierBadge = `<span style="background:#f3e8ff; color:#6b21a8; padding:2px 8px; border-radius:9999px; font-weight:700; font-size:11px;">Hygiene</span>`;
                        else tierBadge = `<span style="background:#f1f5f9; color:#475569; padding:2px 8px; border-radius:9999px; font-weight:700; font-size:11px;">Needs review</span>`;

                        let labelBadge = `<span style="color:#94a3b8; font-size:12px;">—</span>`;
                        if (savedLbl === "real_issue") labelBadge = `<span style="background:#fee2e2; color:#b91c1c; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;">Real issue</span>`;
                        else if (savedLbl === "false_positive") labelBadge = `<span style="background:#f1f5f9; color:#475569; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;">False positive</span>`;
                        else if (savedLbl === "not_sure") labelBadge = `<span style="background:#fef3c7; color:#b45309; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;">Not sure</span>`;

                        return `
                          <tr 
                            class="finding-row ${isSelected ? "selected-row" : ""}" 
                            id="row-${escapeHtml(fid)}"
                            data-id="${escapeHtml(fid)}"
                            data-severity="${escapeHtml(f.severity)}"
                            data-tier="${escapeHtml(tier)}"
                            data-label="${escapeHtml(savedLbl)}"
                            onclick="selectFinding('${escapeHtml(fid)}')"
                            style="border-bottom: 1px solid #e2e8f0; cursor: pointer; transition: background 0.15s;"
                          >
                            <td style="padding: 12px 14px; vertical-align: top;">${sevBadge}</td>
                            <td style="padding: 12px 14px; vertical-align: top;">
                              <div style="font-weight: 700; color: #0f172a; margin-bottom: 2px;">${escapeHtml(f.title)}</div>
                              <div style="color: #64748b; font-size: 12px; font-family: monospace;">${escapeHtml(f.file)}:${f.lineRange?.startLine || 1}</div>
                            </td>
                            <td style="padding: 12px 14px; vertical-align: top;">${tierBadge}</td>
                            <td style="padding: 12px 14px; vertical-align: top;" id="cell-label-${escapeHtml(fid)}">${labelBadge}</td>
                          </tr>
                        `;
                      })
                      .join("")
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Right Column: Interactive Finding Detail Card -->
      <div class="ui-card" style="padding: 24px; position: sticky; top: 80px;" id="finding-detail-card">
        ${
          initialFinding
            ? renderFindingDetailCardHtml(initialFinding, csrfToken, userLabels.get(initialFinding.db_id || initialFinding.id) || "")
            : `<div style="text-align: center; padding: 48px 16px; color: #64748b;">Select a finding on the left to inspect details</div>`
        }
      </div>

    </div>

    <!-- Embedded Scripts for Client-Side Interactivity -->
    <script>
      const findingsMap = new Map(${findingsJson}.map(f => [f.id, f]));
      let currentFilterSev = 'all';

      function selectSevFilter(sev) {
        currentFilterSev = sev;
        document.querySelectorAll('.btn-filter-pill').forEach(btn => {
          btn.style.background = '#f8fafc';
          btn.style.color = '#64748b';
          btn.style.border = '1px solid #e2e8f0';
        });
        const activeBtn = document.getElementById('pill-' + sev);
        if (activeBtn) {
          activeBtn.style.background = '#0f172a';
          activeBtn.style.color = '#ffffff';
          activeBtn.style.border = 'none';
        }
        applyTableFilters();
      }

      function applyTableFilters() {
        const query = (document.getElementById('table-search').value || '').toLowerCase();
        const selectedTier = document.getElementById('tier-filter').value;
        const selectedLabel = document.getElementById('label-filter').value;

        const rows = document.querySelectorAll('.finding-row');
        rows.forEach(row => {
          const fid = row.getAttribute('data-id');
          const item = findingsMap.get(fid);
          if (!item) return;

          const matchSev = currentFilterSev === 'all' || item.severity === currentFilterSev;
          const matchTier = selectedTier === 'all' || item.confidenceTier === selectedTier;

          let matchLabel = true;
          if (selectedLabel === 'unlabeled') {
            matchLabel = !item.label;
          } else if (selectedLabel !== 'all') {
            matchLabel = item.label === selectedLabel;
          }

          const matchQuery = !query || 
            item.title.toLowerCase().includes(query) || 
            item.file.toLowerCase().includes(query) || 
            item.ruleId.toLowerCase().includes(query);

          if (matchSev && matchTier && matchLabel && matchQuery) {
            row.style.display = '';
          } else {
            row.style.display = 'none';
          }
        });
      }

      function selectFinding(fid) {
        document.querySelectorAll('.finding-row').forEach(r => r.classList.remove('selected-row'));
        const row = document.getElementById('row-' + fid);
        if (row) row.classList.add('selected-row');

        const item = findingsMap.get(fid);
        if (!item) return;

        const detailCard = document.getElementById('finding-detail-card');
        if (detailCard) {
          detailCard.innerHTML = renderDetailCardClient(item, "${escapeHtml(csrfToken)}");
        }
      }

      function renderDetailCardClient(item, csrf) {
        const isReal = item.label === 'real_issue';
        const isFP = item.label === 'false_positive';
        const isNotSure = item.label === 'not_sure';

        let labelHtml = '';
        if (isReal) labelHtml = '<span style="background:#fee2e2; color:#b91c1c; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">Real issue</span>';
        else if (isFP) labelHtml = '<span style="background:#f1f5f9; color:#475569; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">False positive</span>';
        else if (isNotSure) labelHtml = '<span style="background:#fef3c7; color:#b45309; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">Not sure</span>';
        else labelHtml = '<span style="color:#94a3b8; font-size:12px;">Unclassified</span>';

        return \`
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
            <div>
              <span style="font-size: 11px; font-weight: 800; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em;">\${escapeHtml(item.ruleId)}</span>
              <h3 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 4px;">\${escapeHtml(item.title)}</h3>
            </div>
            <div>\${labelHtml}</div>
          </div>

          <div style="font-size: 13px; color: #64748b; margin-bottom: 20px; font-family: monospace;">
            📍 \${escapeHtml(item.file)}:\${item.line}
          </div>

          <!-- Classification Form Buttons -->
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 20px;">
            <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 10px;">CLASSIFY FINDING</div>
            <div style="display: flex; gap: 8px;">
              <button type="button" onclick="submitLabel('\${item.id}', 'real_issue')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isReal ? '#b91c1c' : '#ffffff'}; color: \${isReal ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1;">Real issue</button>
              <button type="button" onclick="submitLabel('\${item.id}', 'false_positive')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isFP ? '#475569' : '#ffffff'}; color: \${isFP ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1;">False positive</button>
              <button type="button" onclick="submitLabel('\${item.id}', 'not_sure')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: \${isNotSure ? '#b45309' : '#ffffff'}; color: \${isNotSure ? '#ffffff' : '#0f172a'}; border: 1px solid #cbd5e1;">Not sure</button>
            </div>
          </div>

          <!-- Explanation -->
          <div style="margin-bottom: 20px;">
            <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px;">EXPLANATION</div>
            <div style="font-size: 13px; color: #334155; line-height: 1.6; background: #ffffff; padding: 12px; border-radius: 6px; border: 1px solid #e2e8f0;">
              \${escapeHtml(item.explanation)}
            </div>
          </div>

          <!-- Code Snippet -->
          <div style="margin-bottom: 24px;">
            <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px;">SOURCE SNIPPET</div>
            <pre style="background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 8px; font-size: 12px; overflow-x: auto; font-family: monospace; line-height: 1.5;"><code>\${escapeHtml(item.codeSnippet)}</code></pre>
          </div>

          <div style="display: flex; gap: 10px;">
            <a href="/findings/\${item.id}/fix" class="btn btn-black" style="flex: 1; text-align: center; font-size: 13px;">Review AST Fix Patch ➔</a>
          </div>
        \`;
      }

      async function submitLabel(fid, label) {
        try {
          const res = await fetch('/api/findings/' + fid + '/label', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label, _csrf: "${escapeHtml(csrfToken)}" })
          });
          if (res.ok) {
            const item = findingsMap.get(fid);
            if (item) item.label = label;
            applyTableFilters();
            selectFinding(fid);
          }
        } catch (err) {
          console.error('Failed to submit label classification:', err);
        }
      }
    </script>
  `;
}

export function renderFindingDetailCardHtml(
  finding: {
    id: string;
    db_id?: string;
    ruleId: string;
    title: string;
    severity: string;
    confidenceTier?: string;
    file: string;
    lineRange?: { startLine: number; endLine: number };
    explanation: string;
    codeSnippet?: string;
    snippet?: string;
    evidenceChain?: Array<{ step: number; description: string; file: string; line: number }>;
  },
  _csrfToken: string,
  savedLabel: string
): string {
  const fid = finding.db_id || finding.id;
  const isReal = savedLabel === "real_issue";
  const isFP = savedLabel === "false_positive";
  const isNotSure = savedLabel === "not_sure";

  let labelHtml = "";
  if (isReal) labelHtml = '<span style="background:#fee2e2; color:#b91c1c; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">Real issue</span>';
  else if (isFP) labelHtml = '<span style="background:#f1f5f9; color:#475569; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">False positive</span>';
  else if (isNotSure) labelHtml = '<span style="background:#fef3c7; color:#b45309; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px;">Not sure</span>';
  else labelHtml = '<span style="color:#94a3b8; font-size:12px;">Unclassified</span>';

  const codeSnippet = finding.codeSnippet || finding.snippet || "const res = await fetch(url);\nreturn res.json();";
  const evidenceChainHtml = finding.evidenceChain ? renderEvidenceChainAsStepsHtml(finding as unknown as Finding) : "";

  return `
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
      <div>
        <span style="font-size: 11px; font-weight: 800; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em;">${escapeHtml(finding.ruleId)}</span>
        <h3 style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 4px;">${escapeHtml(finding.title)}</h3>
      </div>
      <div>${labelHtml}</div>
    </div>

    <div style="font-size: 13px; color: #64748b; margin-bottom: 20px; font-family: monospace;">
      📍 ${escapeHtml(finding.file)}:${finding.lineRange?.startLine || 1}
    </div>

    <!-- Classification Form Buttons -->
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 20px;">
      <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 10px;">CLASSIFY FINDING</div>
      <div style="display: flex; gap: 8px;">
        <button type="button" onclick="submitLabel('${escapeHtml(fid)}', 'real_issue')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: ${isReal ? "#b91c1c" : "#ffffff"}; color: ${isReal ? "#ffffff" : "#0f172a"}; border: 1px solid #cbd5e1;">Real issue</button>
        <button type="button" onclick="submitLabel('${escapeHtml(fid)}', 'false_positive')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: ${isFP ? "#475569" : "#ffffff"}; color: ${isFP ? "#ffffff" : "#0f172a"}; border: 1px solid #cbd5e1;">False positive</button>
        <button type="button" onclick="submitLabel('${escapeHtml(fid)}', 'not_sure')" class="btn" style="flex: 1; padding: 6px; font-size: 12px; background: ${isNotSure ? "#b45309" : "#ffffff"}; color: ${isNotSure ? "#ffffff" : "#0f172a"}; border: 1px solid #cbd5e1;">Not sure</button>
      </div>
    </div>

    <!-- Explanation -->
    <div style="margin-bottom: 20px;">
      <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px;">EXPLANATION</div>
      <div style="font-size: 13px; color: #334155; line-height: 1.6; background: #ffffff; padding: 12px; border-radius: 6px; border: 1px solid #e2e8f0;">
        ${escapeHtml(finding.explanation)}
      </div>
    </div>

    ${
      evidenceChainHtml
        ? `
      <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px;">EVIDENCE CHAIN</div>
        ${evidenceChainHtml}
      </div>
    `
        : ""
    }

    <!-- Source Snippet -->
    <div style="margin-bottom: 24px;">
      <div style="font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px;">SOURCE SNIPPET</div>
      <pre style="background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 8px; font-size: 12px; overflow-x: auto; font-family: monospace; line-height: 1.5;"><code>${escapeHtml(codeSnippet)}</code></pre>
    </div>

    <div style="display: flex; gap: 10px;">
      <a href="/findings/${escapeHtml(fid)}/fix" class="btn btn-black" style="flex: 1; text-align: center; font-size: 13px;">Review AST Fix Patch ➔</a>
    </div>
  `;
}
