import { describe, expect, it } from "vitest";
import { computeResilientFingerprint, canonicalizeCodeSnippet } from "../src/fingerprint.js";
import { Finding } from "../src/types.js";

describe("Resilient Fingerprinting System", () => {
  it("should canonicalize code snippets by stripping whitespace, comments, and local variable names", () => {
    const originalSnippet = `
      // Read body from request
      const body = await req.json();
      const { amount } = body;
    `;

    const canonical = canonicalizeCodeSnippet(originalSnippet);
    expect(canonical).not.toContain("body");
    expect(canonical).not.toContain("amount");
    expect(canonical).toContain("VAR");
    expect(canonical).toContain("json");
  });

  it("should generate identical fingerprints despite code reformatting (whitespace, newlines, comments)", () => {
    const finding1: Omit<Finding, "id"> = {
      ruleId: "mass-assignment",
      title: "Mass Assignment Vulnerability",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/profiles/route.ts",
      lineRange: { startLine: 5, endLine: 10 },
      explanation: "Unvalidated request body passed to database insert",
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/profiles/route.ts",
          line: 5,
          maskedSnippet: "const body = await req.json();",
          confidence: "high",
          note: "Source request body",
        },
        {
          kind: "sink",
          file: "app/api/profiles/route.ts",
          line: 10,
          maskedSnippet: "await supabase.from('profiles').insert(body);",
          confidence: "high",
          note: "Sink database insert",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const finding2Reformatted: Omit<Finding, "id"> = {
      ruleId: "mass-assignment",
      title: "Mass Assignment Vulnerability",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/profiles/route.ts",
      lineRange: { startLine: 15, endLine: 25 }, // Line numbers changed
      explanation: "Unvalidated request body passed to database insert",
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/profiles/route.ts",
          line: 15,
          // Reformatted with extra spaces and comments
          maskedSnippet: "  // Inline comment\n  const body  =  await  req.json( ) ;  ",
          confidence: "high",
          note: "Source request body",
        },
        {
          kind: "sink",
          file: "app/api/profiles/route.ts",
          line: 25,
          maskedSnippet:
            "  /* Block comment */\n  await   supabase . from ( 'profiles' ) . insert ( body ) ;  ",
          confidence: "high",
          note: "Sink database insert",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const fp1 = computeResilientFingerprint(finding1);
    const fp2 = computeResilientFingerprint(finding2Reformatted);

    expect(fp1).toBe(fp2);
  });

  it("should generate identical fingerprints when code/function is moved to a different file path", () => {
    const findingOriginalFile: Omit<Finding, "id"> = {
      ruleId: "stripe-user-controlled-price",
      title: "User-Controlled Price in Stripe Checkout",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/checkout/route.ts",
      lineRange: { startLine: 7, endLine: 15 },
      explanation: "User payload passed directly to unit_amount",
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/checkout/route.ts",
          line: 7,
          maskedSnippet: "const { amount } = await req.json();",
          confidence: "high",
          note: "Client request payload",
        },
        {
          kind: "sink",
          file: "app/api/checkout/route.ts",
          line: 15,
          maskedSnippet: "stripe.checkout.sessions.create({ unit_amount: amount });",
          confidence: "high",
          note: "Stripe checkout session create",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const findingMovedFile: Omit<Finding, "id"> = {
      ruleId: "stripe-user-controlled-price",
      title: "User-Controlled Price in Stripe Checkout",
      severity: "high",
      confidenceTier: "likely",
      file: "lib/stripe/handlers/checkout-processor.ts", // Moved file path!
      lineRange: { startLine: 100, endLine: 120 },
      explanation: "User payload passed directly to unit_amount",
      evidenceChain: [
        {
          kind: "source",
          file: "lib/stripe/handlers/checkout-processor.ts",
          line: 100,
          maskedSnippet: "const { amount } = await req.json();",
          confidence: "high",
          note: "Client request payload",
        },
        {
          kind: "sink",
          file: "lib/stripe/handlers/checkout-processor.ts",
          line: 120,
          maskedSnippet: "stripe.checkout.sessions.create({ unit_amount: amount });",
          confidence: "high",
          note: "Stripe checkout session create",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const fp1 = computeResilientFingerprint(findingOriginalFile);
    const fp2 = computeResilientFingerprint(findingMovedFile);

    expect(fp1).toBe(fp2);
  });

  it("should generate identical fingerprints when local variables are renamed", () => {
    const findingOriginalVars: Omit<Finding, "id"> = {
      ruleId: "api-route-no-auth",
      title: "API Route Missing Authentication Check",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/users/route.ts",
      lineRange: { startLine: 4, endLine: 10 },
      explanation: "Handler performs DB lookup without auth guard",
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/users/route.ts",
          line: 4,
          maskedSnippet: "export async function GET(req: Request) { const { id } = params; }",
          confidence: "high",
          note: "Route handler entry point",
        },
        {
          kind: "sink",
          file: "app/api/users/route.ts",
          line: 10,
          maskedSnippet: "db.select().from(users).where(eq(users.id, id));",
          confidence: "high",
          note: "Database query",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const findingRenamedVars: Omit<Finding, "id"> = {
      ruleId: "api-route-no-auth",
      title: "API Route Missing Authentication Check",
      severity: "high",
      confidenceTier: "likely",
      file: "app/api/users/route.ts",
      lineRange: { startLine: 4, endLine: 10 },
      explanation: "Handler performs DB lookup without auth guard",
      evidenceChain: [
        {
          kind: "source",
          file: "app/api/users/route.ts",
          line: 4,
          // Renamed req -> clientRequestPayload, id -> userIdParameter
          maskedSnippet:
            "export async function GET(clientRequestPayload: Request) { const { userIdParameter } = routeParams; }",
          confidence: "high",
          note: "Route handler entry point",
        },
        {
          kind: "sink",
          file: "app/api/users/route.ts",
          line: 10,
          maskedSnippet:
            "dbClientInstance.select().from(accountTable).where(eq(accountTable.id, userIdParameter));",
          confidence: "high",
          note: "Database query",
        },
      ],
      unresolvedSteps: [],
      fingerprint: "",
    };

    const fp1 = computeResilientFingerprint(findingOriginalVars);
    const fp2 = computeResilientFingerprint(findingRenamedVars);

    expect(fp1).toBe(fp2);
  });
});
