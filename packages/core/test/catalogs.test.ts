import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { loadCatalog, loadDefaultCatalogs, mergeCatalogs } from "../src/catalogs/loader.js";
import { Catalog } from "../src/catalogs/schema.js";

describe("Versioned Security Catalogs & Zod Schema Loader (packages/core)", () => {
  it("should validate and load a valid catalog JSON data structure", () => {
    const validJson = JSON.stringify({
      version: "1.2.3",
      lastUpdated: "2026-10-04T12:00:00Z",
      frameworkVersions: {
        next: "^14.0.0",
      },
      frameworkEntryPoints: [
        {
          id: "custom-entry-point",
          kind: "route-handler",
          pattern: "app/api/**/route.ts",
          methods: ["GET", "POST"],
        },
      ],
      sources: [
        {
          id: "custom-source",
          name: "URL Search Parameter",
          category: "query-param",
          pattern: "req.nextUrl.searchParams",
        },
      ],
      sinks: [
        {
          id: "custom-sink",
          name: "Payment Sink",
          category: "payment",
          pattern: "stripe.paymentIntents.create",
          requiredGuards: ["auth-guard-id"],
        },
      ],
      sanitizersValidators: [
        {
          id: "custom-sanitizer",
          name: "Signature Verifier",
          kind: "signature-verifier",
          pattern: "stripe.webhooks.constructEvent",
        },
      ],
      authGuards: [
        {
          id: "custom-auth-guard",
          name: "Tenant Access Guard",
          pattern: "assertRepoAccess",
        },
      ],
    });

    const catalog: Catalog = loadCatalog(validJson);

    expect(catalog.version).toBe("1.2.3");
    expect(catalog.frameworkVersions.next).toBe("^14.0.0");
    expect(catalog.frameworkEntryPoints.length).toBe(1);
    expect(catalog.sources.length).toBe(1);
    expect(catalog.sinks.length).toBe(1);
    expect(catalog.sanitizersValidators.length).toBe(1);
    expect(catalog.authGuards.length).toBe(1);
  });

  it("should fail validation and throw ZodError when catalog schema is invalid or missing required version", () => {
    const invalidJson = JSON.stringify({
      version: "invalid_semver_format",
      lastUpdated: "2026-10-04T12:00:00Z",
      frameworkVersions: {},
      frameworkEntryPoints: [
        {
          id: "invalid-entry",
          kind: "unknown-kind-type", // Invalid enum value
          pattern: "",
        },
      ],
    });

    expect(() => loadCatalog(invalidJson)).toThrow(ZodError);
  });

  it("should load built-in default catalogs and contain Next.js, Server Actions, Middleware, Supabase, and Stripe examples", () => {
    const catalog = loadDefaultCatalogs();

    expect(catalog.version).toBeDefined();
    expect(catalog.frameworkVersions.next).toBeDefined();
    expect(catalog.frameworkVersions.supabase).toBeDefined();
    expect(catalog.frameworkVersions.stripe).toBeDefined();

    // 1. Next.js App Router Route Handler Entry Point
    const routeHandler = catalog.frameworkEntryPoints.find(
      (e) => e.id === "nextjs-app-route-handler"
    );
    expect(routeHandler).toBeDefined();
    expect(routeHandler?.kind).toBe("route-handler");
    expect(routeHandler?.pattern).toContain("route.");

    // 2. Next.js Server Action Entry Point
    const serverAction = catalog.frameworkEntryPoints.find((e) => e.id === "nextjs-server-action");
    expect(serverAction).toBeDefined();
    expect(serverAction?.kind).toBe("server-action");
    expect(serverAction?.pattern).toContain("use server");

    // 3. Next.js Middleware Matcher Entry Point
    const middleware = catalog.frameworkEntryPoints.find(
      (e) => e.id === "nextjs-middleware-matcher"
    );
    expect(middleware).toBeDefined();
    expect(middleware?.kind).toBe("middleware");
    expect(middleware?.pattern).toContain("middleware.");

    // 4. Supabase DB Client Call Sink & Auth Guard
    const supabaseSink = catalog.sinks.find((s) => s.id === "supabase-db-query-sink");
    expect(supabaseSink).toBeDefined();
    expect(supabaseSink?.category).toBe("database");
    expect(supabaseSink?.pattern).toBe("supabase.from");

    const supabaseAuth = catalog.authGuards.find((a) => a.id === "supabase-auth-get-user");
    expect(supabaseAuth).toBeDefined();
    expect(supabaseAuth?.pattern).toBe("supabase.auth.getUser");

    // 5. Stripe Webhook Signature Verifier
    const stripeVerifier = catalog.sanitizersValidators.find(
      (v) => v.id === "stripe-construct-event"
    );
    expect(stripeVerifier).toBeDefined();
    expect(stripeVerifier?.kind).toBe("signature-verifier");
    expect(stripeVerifier?.pattern).toBe("stripe.webhooks.constructEvent");
  });

  it("should merge multiple validated catalogs cleanly", () => {
    const cat1: Catalog = loadCatalog({
      version: "1.0.0",
      lastUpdated: "2026-10-04T00:00:00Z",
      frameworkVersions: { next: "^14.0.0" },
      frameworkEntryPoints: [{ id: "e1", kind: "route-handler", pattern: "app/api" }],
      sources: [],
      sinks: [],
      sanitizersValidators: [],
      authGuards: [],
    });

    const cat2: Catalog = loadCatalog({
      version: "1.0.0",
      lastUpdated: "2026-10-04T00:00:00Z",
      frameworkVersions: { stripe: "^15.0.0" },
      frameworkEntryPoints: [],
      sources: [],
      sinks: [{ id: "s1", name: "Stripe Sink", category: "payment", pattern: "stripe.pay" }],
      sanitizersValidators: [],
      authGuards: [],
    });

    const merged = mergeCatalogs([cat1, cat2]);

    expect(merged.frameworkVersions.next).toBe("^14.0.0");
    expect(merged.frameworkVersions.stripe).toBe("^15.0.0");
    expect(merged.frameworkEntryPoints.length).toBe(1);
    expect(merged.sinks.length).toBe(1);
  });
});
