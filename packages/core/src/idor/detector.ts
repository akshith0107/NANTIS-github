import { Finding, Rule } from "../types.js";
import { createFinding } from "../evidence.js";
import { indexRepository } from "./indexer.js";
import { SupabaseAnalyzer } from "./supabase-analyzer.js";
import { BoundedDataflowEngine } from "./dataflow.js";
import { SecurityVerifiers } from "./verifiers.js";
import { PureVerdictEngine } from "./verdict-engine.js";
import { SecurityClaim } from "./types.js";

export const idorOwnerColumnRule: Rule = {
  id: "idor.owner-column.v1",
  name: "Insecure Direct Object Reference (IDOR) - Missing Ownership Verification",
  description:
    "Detects endpoints that query database resources using attacker-controlled IDs without filtering by authenticated user ownership or enforcing Row Level Security (RLS).",
  severity: "high",
  fixtures: {
    vulnerable: `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("documents").select("*").eq("id", params.id);
  return Response.json(data);
}
    `.trim(),
    clean: `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  const { data } = await supabase.from("documents").select("*").eq("id", params.id).eq("user_id", session.user.id);
  return Response.json(data);
}
    `.trim(),
    mutated: `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("documents").select("*").eq("id", params.id);
  return Response.json(data);
}
    `.trim(),
  },
  async check(filesMap: Map<string, string>): Promise<Finding[]> {
    return detectDeterministicIdor(filesMap);
  },
};

/**
 * Main entry point running the deterministic IDOR engine over a filesMap.
 */
export async function detectDeterministicIdor(filesMap: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];
  const indexedRepo = indexRepository(filesMap);
  const supabaseAnalyzer = new SupabaseAnalyzer(indexedRepo);
  const dataflowEngine = new BoundedDataflowEngine();
  const verifiers = new SecurityVerifiers();

  const dataflowResult = dataflowEngine.analyzeDataflow(
    indexedRepo.endpoints,
    indexedRepo.queries,
    filesMap.size
  );

  const processedKeys = new Set<string>();

  for (const path of dataflowResult.paths) {
    const key = `${path.sourceEndpoint.filePath}:${path.paramName}:${path.sinkQuery.table}`;
    if (processedKeys.has(key)) continue;
    processedKeys.add(key);

    const tableStatus = supabaseAnalyzer.getTableSecurityStatus(path.sinkQuery.table);
    const verification = verifiers.verifyIdorScenario(
      path.sourceEndpoint,
      path.paramName,
      path.sinkQuery,
      tableStatus
    );

    if (verification.isVulnerable) {
      const fileHash = indexedRepo.fileHashes.get(path.sourceEndpoint.filePath) || "";
      const claim: SecurityClaim = {
        id: `claim-idor-${path.sourceEndpoint.filePath}-${path.paramName}`,
        ruleId: "idor.owner-column.v1",
        origin: "engine",
        targetFile: path.sourceEndpoint.filePath,
        claimType: "idor.owner-column.v1",
        evidenceRefs: [
          {
            file: path.sourceEndpoint.filePath,
            startLine: path.sourceEndpoint.lineRange.startLine,
            endLine: path.sourceEndpoint.lineRange.endLine,
            fileHash,
            symbol: path.sourceEndpoint.name,
          },
        ],
        unresolvedSteps: verification.unresolvedSteps,
      };

      const finalVerification = PureVerdictEngine.evaluate(
        claim,
        verification.verdictReason,
        verification.evidenceChain,
        verification.unresolvedSteps,
        dataflowResult.coverage
      );

      if (finalVerification.verdict !== "rejected") {
        const confidenceTier =
          finalVerification.verdict === "proven"
            ? "proven"
            : finalVerification.verdict === "likely"
            ? "likely"
            : "needs-review";

        const fingerprint = `idor.owner-column.v1:${path.sourceEndpoint.filePath}:${path.paramName}:${path.sinkQuery.table}`;

        findings.push(
          createFinding({
            ruleId: "idor.owner-column.v1",
            title: "Insecure Direct Object Reference (IDOR) - Missing Ownership Filter",
            severity: "high",
            confidenceTier,
            file: path.sourceEndpoint.filePath,
            lineRange: {
              startLine: path.sinkQuery.line,
              endLine: path.sinkQuery.line + 2,
            },
            evidenceChain: finalVerification.evidenceChain,
            unresolvedSteps: finalVerification.unresolvedSteps,
            explanation: finalVerification.explanation,
            fingerprint,
          })
        );
      }
    }
  }

  return findings;
}
