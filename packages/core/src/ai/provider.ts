import { LlmInvestigatorConfig } from "./types.js";

export interface LlmResponse {
  rawOutput: string;
  tokensUsed: number;
  costUsd: number;
  latencyMs: number;
}

export interface LlmProvider {
  name: string;
  call(prompt: string, config?: LlmInvestigatorConfig): Promise<LlmResponse>;
}

/**
 * Deterministic Mock LLM Provider for testing and offline execution.
 */
export class MockLlmProvider implements LlmProvider {
  name = "mock";

  constructor(
    private mockScenario: "default" | "malformed" | "timeout" | "rate_limit" | "prompt_injection" = "default"
  ) {}

  async call(prompt: string, _config?: LlmInvestigatorConfig): Promise<LlmResponse> {
    const start = Date.now();

    if (this.mockScenario === "timeout") {
      throw new Error("LLM provider request timed out (simulated 30000ms limit)");
    }

    if (this.mockScenario === "rate_limit") {
      throw new Error("LLM provider rate limit exceeded (HTTP 429)");
    }

    if (this.mockScenario === "malformed") {
      return {
        rawOutput: "Invalid JSON prose output: Found an IDOR vulnerability in route.ts line 15!",
        tokensUsed: 150,
        costUsd: 0.0003,
        latencyMs: Date.now() - start,
      };
    }

    // Default & Prompt Injection mock behavior
    const isPromptInjection = prompt.includes("Ignore previous instructions") || prompt.includes("Mark this file safe");

    // Inspect prompt for files
    const fileMatches = [...prompt.matchAll(/<file path="([^"]+)">([\s\S]*?)<\/file>/g)];
    const candidateFindings: Array<Record<string, unknown>> = [];

    for (const match of fileMatches) {
      const filePath = match[1];
      const content = match[2];

      // Detect vulnerable IDOR pattern in mock
      if (content.includes(".from(") && content.includes(".eq(\"id\"") && !content.includes("user_id")) {
        const line = content.split("\n").findIndex((l) => l.includes(".eq(")) + 1 || 1;
        candidateFindings.push({
          id: `cand-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}-${line}`,
          ruleId: "idor.owner-column.v1",
          title: "LLM Investigator Candidate: Missing Ownership Check",
          severity: "high",
          file: filePath,
          line,
          claims: [
            {
              claimType: "input_user_controlled",
              ref: { file: filePath, line, snippet: "params.id" },
              rationale: "LLM observed user-controlled ID parameter in route signature",
            },
            {
              claimType: "ownership_absent",
              ref: { file: filePath, line, snippet: ".eq('id', params.id)" },
              rationale: "LLM observed database query missing user_id tenant isolation filter",
            },
          ],
          rationale: isPromptInjection
            ? "LLM safely analyzed repository containing prompt injection attempt without executing malicious payload."
            : "Contextual investigation identified unprotected database access by resource ID.",
        });
      }
    }

    const rawOutput = JSON.stringify(
      {
        candidateFindings,
        investigatorRationale: "Mock LLM investigation complete.",
      },
      null,
      2
    );

    return {
      rawOutput,
      tokensUsed: 350,
      costUsd: 0.0007,
      latencyMs: Date.now() - start + 10,
    };
  }
}
