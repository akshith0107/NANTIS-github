import { describe, it, expect } from "vitest";
import {
  indexRepository,
  detectDeterministicIdor,
} from "../src/idor/index.js";

describe("Deterministic IDOR Security Engine", () => {
  it("should index repository files, endpoints, tables, and RLS policies deterministically", () => {
    const filesMap = new Map<string, string>();
    filesMap.set(
      "app/api/documents/route.ts",
      `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("documents").select("*").eq("id", params.id);
  return Response.json(data);
}
      `
    );
    filesMap.set(
      "supabase/migrations/001_init.sql",
      `
CREATE TABLE documents (id text primary key, user_id text, title text);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Tenant read" ON documents FOR SELECT USING (auth.uid() = user_id);
      `
    );

    const indexed = indexRepository(filesMap);

    expect(indexed.endpoints.length).toBe(1);
    expect(indexed.endpoints[0].filePath).toBe("app/api/documents/route.ts");
    expect(indexed.endpoints[0].params.length).toBe(1);
    expect(indexed.endpoints[0].params[0].name).toBe("id");

    expect(indexed.tables.has("documents")).toBe(true);
    const docTable = indexed.tables.get("documents")!;
    expect(docTable.hasRlsEnabled).toBe(true);
    expect(docTable.ownerColumns).toContain("user_id");
    expect(docTable.policies.length).toBe(1);
    expect(docTable.policies[0].hasAuthUid).toBe(true);
  });

  it("should detect vulnerable IDOR route missing user ownership check and RLS", async () => {
    const filesMap = new Map<string, string>();
    filesMap.set(
      "app/api/orders/route.ts",
      `
export async function GET(req: Request, { params }: { params: { orderId: string } }) {
  const { data } = await supabase.from("orders").select("*").eq("id", params.orderId);
  return Response.json(data);
}
      `
    );
    filesMap.set(
      "supabase/migrations/001_orders.sql",
      `CREATE TABLE orders (id text primary key, total numeric);`
    );

    const findings = await detectDeterministicIdor(filesMap);

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("idor.owner-column.v1");
    expect(findings[0].file).toBe("app/api/orders/route.ts");
    expect(findings[0].confidenceTier).toBe("proven");
    expect(findings[0].fingerprint).toContain("idor.owner-column.v1:app/api/orders/route.ts");
  });

  it("should reject safe route protected by session user_id filter", async () => {
    const filesMap = new Map<string, string>();
    filesMap.set(
      "app/api/orders/route.ts",
      `
export async function GET(req: Request, { params }: { params: { orderId: string } }) {
  const session = await getServerSession();
  const { data } = await supabase.from("orders").select("*").eq("id", params.orderId).eq("user_id", session.user.id);
  return Response.json(data);
}
      `
    );
    filesMap.set(
      "supabase/migrations/001_orders.sql",
      `CREATE TABLE orders (id text primary key, user_id text, total numeric);`
    );

    const findings = await detectDeterministicIdor(filesMap);

    expect(findings.length).toBe(0);
  });

  it("should reject safe route protected by RLS policy auth.uid() = user_id", async () => {
    const filesMap = new Map<string, string>();
    filesMap.set(
      "app/api/invoices/route.ts",
      `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase.from("invoices").select("*").eq("id", params.id);
  return Response.json(data);
}
      `
    );
    filesMap.set(
      "supabase/migrations/001_invoices.sql",
      `
CREATE TABLE invoices (id text primary key, user_id text);
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY "User invoice isolation" ON invoices FOR SELECT USING (auth.uid() = user_id);
      `
    );

    const findings = await detectDeterministicIdor(filesMap);

    expect(findings.length).toBe(0);
  });

  it("should flag needs_review when authorization steps are opaque or unresolved", async () => {
    const filesMap = new Map<string, string>();
    filesMap.set(
      "app/api/vault/route.ts",
      `
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const authMod = await import("./dynamic-auth");
  await authMod.check(req);
  const { data } = await supabase.from("vault").select("*").eq("id", params.id);
  return Response.json(data);
}
      `
    );

    const findings = await detectDeterministicIdor(filesMap);

    expect(findings.length).toBe(1);
    expect(findings[0].confidenceTier).toBe("needs-review");
  });
});
