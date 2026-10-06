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
  if (!userId) {
    return {
      status: 401,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "401 Unauthorized",
        content: `<h1>401 Authentication Required</h1><p>Please sign in to view scan results.</p>`,
      }),
    };
  }

  const scan = await db.getScanById(scanId);
  const targetRepoId = scan ? scan.repository_id : `non_existent_${scanId}`;

  let repo;
  try {
    const access = await assertRepoAccess(userId, targetRepoId);
    repo = access.repository;
  } catch (err) {
    if (err instanceof NotFoundError) {
      return {
        status: 404,
        headers: getDefaultHeaders(),
        body: renderPageLayout({
          title: "404 Not Found",
          content: `<h1>404 Not Found</h1><p>The requested scan does not exist or you do not have permission to view it.</p>`,
        }),
      };
    }
    throw err;
  }

  if (!scan) {
    return {
      status: 404,
      headers: getDefaultHeaders(),
      body: renderPageLayout({
        title: "404 Not Found",
        content: `<h1>404 Not Found</h1><p>Scan record not found.</p>`,
      }),
    };
  }

  const csrfToken = getOrCreateCsrfToken(userId);
  const findings = await db.getFindingsForScan(scanId);

  // Fetch labels saved by user
  const userLabels = new Map<string, string>();
  for (const f of findings) {
    const lbl = await db.getFindingLabel(userId, f.db_id || f.id);
    if (lbl) {
      userLabels.set(f.db_id || f.id, lbl.label);
    }
  }

  // Tier counts
  const countProven = findings.filter((f) => f.confidenceTier === "proven").length;
  const countLikely = findings.filter((f) => f.confidenceTier === "likely").length;
  const countReview = findings.filter((f) => f.confidenceTier === "needs-review" || !f.confidenceTier).length;
  const countHygiene = findings.filter((f) => f.confidenceTier === "hygiene").length;

  let findingsSectionHtml = "";

  if (scan.status === "done" || scan.status === "completed") {
    if (findings.length === 0) {
      findingsSectionHtml = `
        <div class="card" style="text-align: center; padding: 48px 24px;">
          <div style="font-size: 2rem; margin-bottom: 12px;">✅</div>
          <p class="no-findings" style="font-size: 1.2rem; font-weight: 700; color: #34d399;">
            no issues found in the checks we run
          </p>
          <p style="color: var(--text-dim); font-size: 0.85rem; margin-top: 8px;">
            Static AST security scanner completed analysis without triggering any active detection rules.
          </p>
        </div>
      `;
    } else {
      const cardsHtml = findings
        .map((f) => {
          const findingId = f.db_id || f.id;
          const currentLabel = userLabels.get(findingId) || "";

          const tier = f.confidenceTier || "needs-review";
          const tierClass =
            tier === "proven"
              ? "tier-proven"
              : tier === "likely"
              ? "tier-likely"
              : tier === "hygiene"
              ? "tier-hygiene"
              : "tier-review";

          return `
            <div class="card finding-item" data-tier="${tier}" data-search="${escapeHtml(`${f.ruleId} ${f.title} ${f.file}`).toLowerCase()}" style="border-left: 4px solid var(--border-highlight);">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 12px;">
                <div>
                  <span class="badge-tier ${tierClass}">${escapeHtml(tier.replace("_", " "))}</span>
                  <h3 style="font-size: 1.15rem; font-weight: 700; margin-top: 6px;">[${escapeHtml(f.severity.toUpperCase())}] ${escapeHtml(f.title)}</h3>
                </div>
                <a href="/findings/${escapeHtml(findingId)}/fix" class="btn btn-success" style="padding: 6px 14px; font-size: 0.85rem; white-space: nowrap;">
                  View & Review Fix &rarr;
                </a>
              </div>

              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; font-size: 0.85rem; margin-bottom: 12px; padding: 10px; background: #0d1322; border-radius: 6px;">
                <div><span style="color: var(--text-dim);">Rule ID:</span> <code style="color: #60a5fa;">${escapeHtml(f.ruleId)}</code></div>
                <div><span style="color: var(--text-dim);">Location:</span> <span style="font-family: monospace;">${escapeHtml(f.file)}:${f.lineRange.startLine}</span></div>
              </div>

              <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 14px;">${escapeHtml(f.explanation)}</p>

              ${renderEvidenceChainAsStepsHtml(f)}

              <!-- Interactive Testing Aid Classification Controls -->
              <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim);">
                  Testing Aid Label:
                </div>
                <div style="display: flex; gap: 8px;" id="label-group-${escapeHtml(findingId)}">
                  <button 
                    type="button" 
                    class="btn btn-outline ${currentLabel === "real_issue" ? "active-real" : ""}" 
                    style="padding: 4px 12px; font-size: 0.8rem; ${currentLabel === "real_issue" ? "background: #16a34a; color: #fff; border-color: #16a34a;" : ""}"
                    onclick="setFindingLabel('${escapeHtml(findingId)}', '${escapeHtml(repo.full_name)}', '${escapeHtml(f.ruleId)}', '${escapeHtml(f.file)}', ${f.lineRange.startLine}, 'real_issue')"
                  >
                    ✓ Real issue
                  </button>
                  <button 
                    type="button" 
                    class="btn btn-outline ${currentLabel === "false_positive" ? "active-fp" : ""}" 
                    style="padding: 4px 12px; font-size: 0.8rem; ${currentLabel === "false_positive" ? "background: #dc2626; color: #fff; border-color: #dc2626;" : ""}"
                    onclick="setFindingLabel('${escapeHtml(findingId)}', '${escapeHtml(repo.full_name)}', '${escapeHtml(f.ruleId)}', '${escapeHtml(f.file)}', ${f.lineRange.startLine}, 'false_positive')"
                  >
                    ✗ False positive
                  </button>
                  <button 
                    type="button" 
                    class="btn btn-outline ${currentLabel === "not_sure" ? "active-sure" : ""}" 
                    style="padding: 4px 12px; font-size: 0.8rem; ${currentLabel === "not_sure" ? "background: #4b5563; color: #fff; border-color: #4b5563;" : ""}"
                    onclick="setFindingLabel('${escapeHtml(findingId)}', '${escapeHtml(repo.full_name)}', '${escapeHtml(f.ruleId)}', '${escapeHtml(f.file)}', ${f.lineRange.startLine}, 'not_sure')"
                  >
                    ? Not sure
                  </button>
                </div>
              </div>
            </div>
          `;
        })
        .join("");

      findingsSectionHtml = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
          <div style="display: flex; gap: 12px; align-items: center; flex: 1; min-width: 280px;">
            <select id="tier-filter" onchange="filterFindings()" style="width: auto; padding: 8px 12px; font-size: 0.85rem;">
              <option value="all">All Confidence Tiers (${findings.length})</option>
              <option value="proven">Proven (${countProven})</option>
              <option value="likely">Likely (${countLikely})</option>
              <option value="needs-review">Needs Review (${countReview})</option>
              <option value="hygiene">Hygiene (${countHygiene})</option>
            </select>
            <input 
              type="text" 
              id="search-input" 
              oninput="filterFindings()" 
              placeholder="Search findings..." 
              style="padding: 8px 12px; font-size: 0.85rem; max-width: 300px;"
            />
          </div>
          <a href="/api/labels/export?repo=${encodeURIComponent(repo.full_name)}" class="btn btn-outline" style="font-size: 0.85rem; padding: 8px 16px;">
            📥 Export Labels (JSON)
          </a>
        </div>

        <div id="findings-container">
          ${cardsHtml}
        </div>
      `;
    }
  } else if (scan.status === "failed") {
    findingsSectionHtml = `
      <div class="card" style="border-left: 4px solid var(--badge-review);">
        <h2 style="color: var(--badge-review); font-size: 1.2rem; font-weight: 700;">Scan Failed</h2>
        <p style="color: var(--text-muted); margin-top: 8px;">${escapeHtml(scan.error_message || "Scan execution encountered an unexpected error.")}</p>
      </div>
    `;
  } else {
    findingsSectionHtml = `
      <div class="card" style="text-align: center; padding: 40px;">
        <h2 style="font-size: 1.2rem; font-weight: 700; margin-bottom: 8px;">Scan in Progress...</h2>
        <p style="color: var(--text-muted);">Status: <strong>${escapeHtml(scan.status.toUpperCase())}</strong></p>
      </div>
    `;
  }

  const content = `
    <div style="max-width: 1000px; margin: 0 auto;">
      <div style="margin-bottom: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap;">
          <div>
            <h1 style="font-size: 1.8rem; font-weight: 800;">
              Scan Findings for ${escapeHtml(repo.full_name)}
            </h1>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-top: 4px;">
              Scan ID: <code style="color: var(--text-muted);">${escapeHtml(scan.id)}</code> &bull; 
              Commit: <code style="color: var(--text-muted);">${escapeHtml(scan.commit_sha)}</code> &bull; 
              Branch: <code style="color: var(--text-muted);">${escapeHtml(scan.branch)}</code>
            </p>
          </div>
          <div>
            <span class="verification-badge">WEAK verification</span>
          </div>
        </div>
      </div>

      <!-- Tier Summary Bar -->
      <div class="card" style="padding: 16px 24px; margin-bottom: 20px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; text-align: center;">
          <div style="padding: 10px; background: #0d1322; border-radius: 8px;">
            <div style="font-size: 1.4rem; font-weight: 800; color: #a78bfa;">${countProven}</div>
            <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-dim);">Proven</div>
          </div>
          <div style="padding: 10px; background: #0d1322; border-radius: 8px;">
            <div style="font-size: 1.4rem; font-weight: 800; color: #fbbf24;">${countLikely}</div>
            <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-dim);">Likely</div>
          </div>
          <div style="padding: 10px; background: #0d1322; border-radius: 8px;">
            <div style="font-size: 1.4rem; font-weight: 800; color: #f87171;">${countReview}</div>
            <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-dim);">Needs Review</div>
          </div>
          <div style="padding: 10px; background: #0d1322; border-radius: 8px;">
            <div style="font-size: 1.4rem; font-weight: 800; color: #34d399;">${countHygiene}</div>
            <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-dim);">Hygiene</div>
          </div>
        </div>

        <div style="margin-top: 16px; font-size: 0.8rem; color: var(--text-dim); text-align: center;">
          Scanned JS/TS files across AST syntax nodes in local memory scanner.
        </div>
      </div>

      ${findingsSectionHtml}
    </div>

    <script>
      const csrfToken = "${escapeHtml(csrfToken)}";

      function filterFindings() {
        const tier = document.getElementById("tier-filter").value;
        const query = document.getElementById("search-input").value.toLowerCase();
        const items = document.querySelectorAll(".finding-item");

        items.forEach(item => {
          const itemTier = item.getAttribute("data-tier");
          const itemSearch = item.getAttribute("data-search");

          const matchesTier = (tier === "all" || itemTier === tier);
          const matchesSearch = (!query || itemSearch.includes(query));

          if (matchesTier && matchesSearch) {
            item.style.display = "block";
          } else {
            item.style.display = "none";
          }
        });
      }

      async function setFindingLabel(findingId, repoFullName, ruleId, file, line, label) {
        try {
          const res = await fetch("/api/findings/" + findingId + "/label", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({
              _csrf: csrfToken,
              repo_full_name: repoFullName,
              rule_id: ruleId,
              file: file,
              line: line,
              label: label
            })
          });

          if (res.ok) {
            // Update UI buttons state
            const group = document.getElementById("label-group-" + findingId);
            if (group) {
              const btns = group.querySelectorAll("button");
              btns.forEach(b => {
                b.style.background = "";
                b.style.color = "";
                b.style.borderColor = "";
              });

              const targetText = label === "real_issue" ? "Real issue" : label === "false_positive" ? "False positive" : "Not sure";
              const color = label === "real_issue" ? "#16a34a" : label === "false_positive" ? "#dc2626" : "#4b5563";
              
              btns.forEach(b => {
                if (b.innerText.includes(targetText)) {
                  b.style.background = color;
                  b.style.color = "#fff";
                  b.style.borderColor = color;
                }
              });
            }
          } else {
            alert("Failed to save label.");
          }
        } catch (err) {
          console.error(err);
          alert("Error saving label.");
        }
      }
    </script>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: `Scan Findings - ${repo.full_name}`,
      userLogin: extractUserIdFromRequest(req, env) ? "test-user" : undefined,
      csrfToken,
      content,
    }),
  };
}
