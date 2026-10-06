import { describe, expect, it } from "vitest";
import {
  fixDependencyBump,
  fixEnableRLS,
  fixStripeWebhookVerification,
} from "../src/fixes/index.js";

describe("Three Fix Rules Implementation & Manual Fallbacks", () => {
  // Fix 1: Dependency Bump
  describe("Fix Rule 1: Dependency Bump to Fixed Version", () => {
    it("generates automated patch when package.json contains target dependency", () => {
      const filesMap = new Map<string, string>([
        ["package.json", JSON.stringify({ dependencies: { axios: "0.21.1" } }, null, 2)],
      ]);

      const result = fixDependencyBump(filesMap, "package.json", "axios", "1.7.4");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain('axios": "^1.7.4"');
        expect(result.riskLevel).toBe("low");
      }
    });

    it("falls back to suggested-manual when dependency is missing from package.json", () => {
      const filesMap = new Map<string, string>([
        ["package.json", JSON.stringify({ dependencies: { lodash: "4.17.21" } }, null, 2)],
      ]);

      const result = fixDependencyBump(filesMap, "package.json", "axios", "1.7.4");

      expect(result.kind).toBe("suggested-manual");
      if (result.kind === "suggested-manual") {
        expect(result.reason).toContain("was not found");
        expect(result.suggestion).toContain("axios");
      }
    });
  });

  // Fix 2: Enable RLS
  describe("Fix Rule 2: Enable RLS with Template Review Policy", () => {
    it("generates automated patch adding ENABLE RLS and template policy for user_id column", () => {
      const filesMap = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.invoices (id uuid PRIMARY KEY, user_id uuid);"],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(result.edits[0].replacementContent).toContain("auth.uid() = user_id");
        expect(result.proofLabel).toBe("Not proven, reasoned from code");
      }
    });

    it("generates automated patch with owner_id column when matched", () => {
      const filesMap = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.projects (id uuid PRIMARY KEY, owner_id uuid);"],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(result.edits[0].replacementContent).toContain("auth.uid() = owner_id");
        expect(result.proofLabel).toBe("Not proven, reasoned from code");
      }
    });

    it("generates commented TODO policy for non-user identifier columns like account_id and tenant_id", () => {
      const filesMapAccount = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.billing (id uuid PRIMARY KEY, account_id uuid);"],
      ]);

      const resultAccount = fixEnableRLS(filesMapAccount, "supabase/migrations/20260101_init.sql");
      expect(resultAccount.kind).toBe("automated");
      if (resultAccount.kind === "automated") {
        expect(resultAccount.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(resultAccount.edits[0].replacementContent).toContain("-- TODO: Define RLS policy for billing. Needs Human Review");
        expect(resultAccount.proofLabel).toBe("Not proven, reasoned from code");
      }

      const filesMapTenant = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.tenants (id uuid PRIMARY KEY, tenant_id uuid);"],
      ]);

      const resultTenant = fixEnableRLS(filesMapTenant, "supabase/migrations/20260101_init.sql");
      expect(resultTenant.kind).toBe("automated");
      if (resultTenant.kind === "automated") {
        expect(resultTenant.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(resultTenant.edits[0].replacementContent).toContain("-- TODO: Define RLS policy for tenants. Needs Human Review");
        expect(resultTenant.proofLabel).toBe("Not proven, reasoned from code");
      }
    });

    it("generates commented TODO policy and sets proofLabel to Not proven when no ownership column exists", () => {
      const filesMap = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.logs (id uuid PRIMARY KEY, created_at timestamp);"],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(result.edits[0].replacementContent).toContain("-- TODO: Define RLS policy for logs. Needs Human Review");
        expect(result.proofLabel).toBe("Not proven, reasoned from code");
      }
    });

    it("generates commented TODO policy and sets proofLabel to Not proven when multiple candidate ownership columns exist", () => {
      const filesMap = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "CREATE TABLE public.memberships (id uuid PRIMARY KEY, user_id uuid, tenant_id uuid);"],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain("ENABLE ROW LEVEL SECURITY");
        expect(result.edits[0].replacementContent).toContain("-- TODO: Define RLS policy for memberships. Needs Human Review");
        expect(result.proofLabel).toBe("Not proven, reasoned from code");
      }
    });

    it("falls back to suggested-manual when SQL migration shape does not match CREATE TABLE", () => {
      const filesMap = new Map<string, string>([
        ["supabase/migrations/20260101_init.sql", "-- Arbitrary comment without CREATE TABLE statement"],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("suggested-manual");
      if (result.kind === "suggested-manual") {
        expect(result.reason).toContain("Could not identify target SQL CREATE TABLE");
      }
    });

    it("NEGATIVE TEST: clean SQL migration already having ENABLE RLS is NEVER modified", () => {
      const filesMap = new Map<string, string>([
        [
          "supabase/migrations/20260101_init.sql",
          "CREATE TABLE public.invoices (id uuid);\nALTER TABLE invoices ENABLE ROW LEVEL SECURITY;\nCREATE POLICY \"tenant access\" ON invoices FOR SELECT USING (auth.uid() = user_id);",
        ],
      ]);

      const result = fixEnableRLS(filesMap, "supabase/migrations/20260101_init.sql");

      expect(result.kind).toBe("suggested-manual");
      if (result.kind === "suggested-manual") {
        expect(result.reason).toContain("already enabled");
      }
    });
  });

  // Fix 3: Stripe Webhook Signature Verification
  describe("Fix Rule 3: Stripe Webhook Signature Verification", () => {
    it("generates automated AST patch inserting stripe.webhooks.constructEvent into POST handler", () => {
      const routeCode = [
        'import { stripe } from "@/lib/stripe";',
        'export async function POST(req) {',
        '  const body = await req.json();',
        '  return new Response("OK");',
        '}',
      ].join("\n");

      const filesMap = new Map<string, string>([
        ["app/api/webhooks/stripe/route.ts", routeCode],
      ]);

      const result = fixStripeWebhookVerification(filesMap, "app/api/webhooks/stripe/route.ts");

      expect(result.kind).toBe("automated");
      if (result.kind === "automated") {
        expect(result.edits[0].replacementContent).toContain("stripe.webhooks.constructEvent");
        expect(result.proofLabel).toBe("Proven by handler replay");
      }
    });

    it("falls back to suggested-manual when route code lacks POST function or Stripe import", () => {
      const invalidCode = 'export async function GET(req) { return new Response("hello"); }';
      const filesMap = new Map<string, string>([
        ["app/api/webhooks/stripe/route.ts", invalidCode],
      ]);

      const result = fixStripeWebhookVerification(filesMap, "app/api/webhooks/stripe/route.ts");

      expect(result.kind).toBe("suggested-manual");
      if (result.kind === "suggested-manual") {
        expect(result.reason).toContain("lacks POST handler or existing Stripe client");
      }
    });

    it("NEGATIVE TEST: clean Stripe webhook handler already having signature check is NEVER modified", () => {
      const cleanRouteCode = [
        'import { stripe } from "@/lib/stripe";',
        'export async function POST(req) {',
        '  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature"), "secret");',
        '  return new Response("OK");',
        '}',
      ].join("\n");

      const filesMap = new Map<string, string>([
        ["app/api/webhooks/stripe/route.ts", cleanRouteCode],
      ]);

      const result = fixStripeWebhookVerification(filesMap, "app/api/webhooks/stripe/route.ts");

      expect(result.kind).toBe("suggested-manual");
      if (result.kind === "suggested-manual") {
        expect(result.reason).toContain("already invokes stripe.webhooks.constructEvent");
      }
    });
  });
});
