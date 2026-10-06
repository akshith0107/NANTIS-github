import { RULE_EXPLANATIONS } from "@nantis/core";
import { HttpResponse } from "./auth-login.js";

export async function renderRulesCatalogPage(): Promise<HttpResponse> {
  const ruleEntries = Object.values(RULE_EXPLANATIONS);

  const catalogHtml = ruleEntries
    .map(
      (rule) => `
    <div class="rule-card" id="rule-${rule.ruleId}">
      <div class="rule-header">
        <h2>${rule.title}</h2>
        <code class="rule-id-badge">${rule.ruleId}</code>
      </div>
      <div class="rule-section">
        <h3>What's Wrong</h3>
        <p>${rule.whatsWrong}</p>
      </div>
      <div class="rule-section">
        <h3>How a Stranger Could Abuse It</h3>
        <p>${rule.howStrangerCouldAbuseIt}</p>
      </div>
      <div class="rule-section">
        <h3>How to Fix It</h3>
        <p>${rule.howToFixIt}</p>
      </div>
    </div>
  `
    )
    .join("");

  const pageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nantis Security Rules Catalog</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    .header { text-align: center; margin-bottom: 3rem; }
    .header h1 { font-size: 2.25rem; color: #60a5fa; margin-bottom: 0.5rem; }
    .header p { color: #94a3b8; font-size: 1.1rem; }
    .catalog-grid { display: grid; gap: 1.5rem; max-width: 1100px; margin: 0 auto; }
    .rule-card { background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 1.5rem; }
    .rule-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.75rem; }
    .rule-header h2 { margin: 0; font-size: 1.25rem; color: #f1f5f9; }
    .rule-id-badge { background: #3b82f6; color: #ffffff; padding: 0.25rem 0.6rem; border-radius: 0.375rem; font-size: 0.85rem; }
    .rule-section { margin-top: 1rem; }
    .rule-section h3 { font-size: 0.95rem; text-transform: uppercase; color: #94a3b8; margin: 0 0 0.25rem 0; letter-spacing: 0.05em; }
    .rule-section p { margin: 0; color: #cbd5e1; line-height: 1.5; font-size: 0.95rem; }
  </style>
</head>
<body>
  <div style="background:#f59e0b;color:#000;text-align:center;padding:6px;font-weight:bold;">DEV MODE - In-Memory Local Development</div>
  <div class="header">
    <h1>Nantis Rules Catalog</h1>
    <p>Comprehensive public documentation of static rules, vulnerability patterns, and mitigation guides.</p>
  </div>
  <div class="catalog-grid">
    ${catalogHtml}
  </div>
</body>
</html>`;

  return {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: pageHtml,
  };
}
