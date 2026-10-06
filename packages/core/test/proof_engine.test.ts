import { describe, expect, it } from "vitest";
import {
  evaluateProof,
  isSandboxDirectory,
  simulateRLSPolicyAccess,
  replayMissingAuthHandler,
} from "../src/fixes/index.js";

describe("Proof Engine (RLS Simulation & Handler Replay)", () => {
  it("refuses to run replay execution when target directory is outside the sandbox", () => {
    const rootPath = "C:/Production/Workspace/MyRepo";
    expect(isSandboxDirectory(rootPath)).toBe(false);

    const result = evaluateProof(
      rootPath,
      "missing-rls-in-migration",
      "CREATE TABLE users (id text);",
      "CREATE TABLE users (id text); ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
    );

    expect(result.executedInSandbox).toBe(false);
    expect(result.label).toBe("Not proven, reasoned from code");
    expect(result.refusalReason).toContain("Refused proof replay execution");
  });

  it("evaluates Case (a): RLS policy simulation for User A reading User B's row", () => {
    const beforeSQL = "CREATE TABLE invoices (id text, user_id text);";
    const afterSQL = [
      "CREATE TABLE invoices (id text, user_id text);",
      "ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;",
      'CREATE POLICY "tenant isolation" ON invoices FOR ALL USING (auth.uid() = user_id);',
    ].join("\n");

    const rlsResult = simulateRLSPolicyAccess(
      beforeSQL,
      afterSQL,
      { id: "user_tenant_A" },
      { user_id: "user_tenant_B" }
    );

    expect(rlsResult.beforeAllowed).toBe(true);
    expect(rlsResult.afterAllowed).toBe(false);
    expect(rlsResult.proven).toBe(true);

    const proof = evaluateProof(
      "/tmp/nantis-sandbox-123",
      "missing-rls-in-migration",
      beforeSQL,
      afterSQL
    );

    expect(proof.executedInSandbox).toBe(true);
    expect(proof.label).toBe("Proven by policy simulation");
  });

  it("evaluates Case (b): Missing-auth route handler replay without user session", () => {
    const beforeCode = `export async function POST(req) { const body = await req.json(); return save(body); }`;
    const afterCode = `export async function POST(req) { const session = await getServerSession(); if (!session) return new Response('Unauthorized', { status: 401 }); return save(); }`;

    const replayResult = replayMissingAuthHandler(beforeCode, afterCode);

    expect(replayResult.beforeStatusCode).toBe(200);
    expect(replayResult.afterStatusCode).toBe(401);
    expect(replayResult.proven).toBe(true);

    const proof = evaluateProof(
      "E:/temp/nantis-fix-sandbox-xyz",
      "api-route-no-auth",
      beforeCode,
      afterCode
    );

    expect(proof.executedInSandbox).toBe(true);
    expect(proof.label).toBe("Proven by handler replay");
  });
});
