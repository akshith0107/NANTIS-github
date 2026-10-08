import { RULE_EXPLANATIONS } from "@nantis/core";
import { getDefaultHeaders, renderPageLayout } from "./ui-templates.js";
import { HttpResponse } from "./auth-login.js";

export async function renderRulesCatalogPage(): Promise<HttpResponse> {
  const ruleEntries = Object.values(RULE_EXPLANATIONS);

  const catalogHtml = ruleEntries
    .map(
      (rule) => `
    <div class="ui-card" id="rule-${rule.ruleId}" style="margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
        <h2 style="font-size: 18px; font-weight: 700; color: #0f172a; margin: 0;">${rule.title}</h2>
        <span style="background: #2563eb; color: #ffffff; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; font-family: monospace;">${rule.ruleId}</span>
      </div>
      <div style="margin-top: 12px;">
        <h3 style="font-size: 11px; text-transform: uppercase; color: #64748b; margin: 0 0 4px 0; letter-spacing: 0.05em; font-weight: 700;">What's Wrong</h3>
        <p style="margin: 0 0 14px 0; color: #334155; line-height: 1.5; font-size: 14px;">${rule.whatsWrong}</p>
      </div>
      <div>
        <h3 style="font-size: 11px; text-transform: uppercase; color: #64748b; margin: 0 0 4px 0; letter-spacing: 0.05em; font-weight: 700;">How a Stranger Could Abuse It</h3>
        <p style="margin: 0 0 14px 0; color: #334155; line-height: 1.5; font-size: 14px;">${rule.howStrangerCouldAbuseIt}</p>
      </div>
      <div>
        <h3 style="font-size: 11px; text-transform: uppercase; color: #64748b; margin: 0 0 4px 0; letter-spacing: 0.05em; font-weight: 700;">How to Fix It</h3>
        <p style="margin: 0; color: #334155; line-height: 1.5; font-size: 14px;">${rule.howToFixIt}</p>
      </div>
    </div>
  `
    )
    .join("");

  const content = `
    <div style="max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
      <div style="text-align: center; margin-bottom: 8px;">
        <h1 style="font-size: 28px; font-weight: 800; color: #0f172a; margin-bottom: 6px;">Nantis Rules Catalog</h1>
        <p style="color: #64748b; font-size: 14px;">Comprehensive public documentation of static rules, vulnerability patterns, and mitigation guides.</p>
      </div>
      <div>
        ${catalogHtml}
      </div>
    </div>
  `;

  return {
    status: 200,
    headers: getDefaultHeaders(),
    body: renderPageLayout({
      title: "Rules Catalog",
      content,
    }),
  };
}
