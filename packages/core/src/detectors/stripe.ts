import { Finding, EvidenceHop } from "../types.js";
import { createFinding } from "../evidence.js";

/**
 * 1. detectStripeWebhookIssues (stripe-webhook-no-signature)
 * Detects Stripe Webhook handlers missing signature verification.
 */
export async function detectStripeWebhookIssues(filesMap: Map<string, string>): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (
      !/(^|\/)app\/api\/.*route\.(ts|js|tsx|jsx)$/i.test(normPath) ||
      (!normPath.includes("webhook") && !normPath.includes("stripe"))
    ) {
      continue;
    }

    const lines = content.split("\n");
    const postHandlerRegex = /export\s+async\s+function\s+POST\s*\(/g;

    let match: RegExpExecArray | null;
    while ((match = postHandlerRegex.exec(content)) !== null) {
      const matchIndex = match.index;
      const startLine = content.slice(0, matchIndex).split("\n").length;

      let openBraces = 0;
      let startedBraces = false;
      let endLine = startLine;

      for (let i = startLine - 1; i < lines.length; i++) {
        const line = lines[i];
        for (const char of line) {
          if (char === "{") {
            openBraces++;
            startedBraces = true;
          } else if (char === "}") {
            openBraces--;
          }
        }
        if (startedBraces && openBraces === 0) {
          endLine = i + 1;
          break;
        }
      }

      const codeWithoutComments = content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*/g, "");
      const hasSignatureVerification =
        /constructEvent/i.test(codeWithoutComments) ||
        /stripe-signature/i.test(codeWithoutComments) ||
        /verifyHeader/i.test(codeWithoutComments);

      if (!hasSignatureVerification) {
        const maskedSnippet = lines
          .slice(startLine - 1, Math.min(endLine, startLine + 3))
          .join("\n")
          .trim();

        findings.push(
          createFinding({
            ruleId: "stripe-webhook-no-signature",
            title: "Stripe Webhook Missing Signature Verification",
            severity: "critical",
            confidenceTier: "likely",
            file: normPath,
            lineRange: {
              startLine,
              endLine: endLine > startLine ? endLine : startLine,
            },
            evidenceChain: [
              {
                kind: "sink",
                file: normPath,
                line: startLine,
                maskedSnippet,
                confidence: "high",
                note: "Stripe webhook handler processes events without verifying stripe-signature header or constructEvent",
              },
            ],
            unresolvedSteps: [],
            explanation:
              "Stripe webhook POST handler parses incoming request payload directly without verifying the signature header via stripe.webhooks.constructEvent(). According to Stripe Webhook Documentation (https://stripe.com/docs/webhooks/signatures), unverified webhook endpoints can be targeted by attackers forging fake payment events.",
            fingerprint: `stripe-webhook-no-signature-${normPath}`,
          })
        );
      }
    }
  }

  return findings;
}

/**
 * 2. detectStripeWebhookParsedBody (stripe-webhook-parsed-body)
 * Detects Stripe Webhook calling constructEvent with a parsed JSON body instead of the raw unparsed payload string.
 */
export async function detectStripeWebhookParsedBody(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (
      !normPath.endsWith(".ts") &&
      !normPath.endsWith(".tsx") &&
      !normPath.endsWith(".js") &&
      !normPath.endsWith(".jsx")
    ) {
      continue;
    }

    if (!content.includes("constructEvent")) continue;

    const lines = content.split("\n");

    // Check if constructEvent is called with JSON.stringify, parsed JSON, or req.json()
    const hasReqJson = /req\.json\(\)|request\.json\(\)/i.test(content);
    const passesParsedBody =
      /constructEvent\s*\(\s*JSON\.stringify/i.test(content) ||
      /constructEvent\s*\(\s*data/i.test(content) ||
      /constructEvent\s*\(\s*parsedBody/i.test(content) ||
      (hasReqJson && !/req\.text\(\)|request\.text\(\)/i.test(content));

    if (passesParsedBody) {
      let fnLine = lines.findIndex((l) => /export\s+async\s+function/i.test(l)) + 1;
      if (fnLine === 0)
        fnLine =
          lines.findIndex((l) => l.includes("req.json()") || l.includes("request.json()")) + 1;
      if (fnLine === 0) fnLine = lines.findIndex((l) => l.includes("constructEvent")) + 1 || 1;
      const constructLine = lines.findIndex((l) => l.includes("constructEvent")) + 1 || fnLine;

      const maskedSnippet = lines
        .slice(Math.max(0, fnLine - 1), constructLine)
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line: fnLine,
          maskedSnippet: lines[fnLine - 1]?.trim() || "const body = await req.json()",
          confidence: "high",
          note: "Request body parsed as JSON object instead of raw unparsed string/buffer",
        },
        {
          kind: "flow",
          file: normPath,
          line: constructLine,
          maskedSnippet:
            lines[constructLine - 1]?.trim() || "stripe.webhooks.constructEvent(parsedBody, ...)",
          confidence: "high",
          note: "Parsed object or re-serialized JSON string passed to constructEvent()",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line: constructLine,
          maskedSnippet,
          confidence: "high",
          note: "Lacks raw unparsed request payload string (await req.text())",
        },
        {
          kind: "sink",
          file: normPath,
          line: constructLine,
          maskedSnippet,
          confidence: "high",
          note: "Breaks HMAC signature verification or permits payload formatting tampering",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "stripe-webhook-parsed-body",
          title: "Stripe Webhook Verifies Parsed Body Instead of Raw Payload",
          severity: "high",
          confidenceTier: "likely",
          file: normPath,
          lineRange: { startLine: fnLine, endLine: constructLine },
          evidenceChain,
          unresolvedSteps: [],
          explanation:
            "Stripe webhook constructEvent() is called with a parsed JSON body or re-serialized JSON string. According to official Stripe Webhook Signature Verification Documentation (https://stripe.com/docs/webhooks/signatures#verify-manually), you MUST pass the exact raw request payload string/buffer (e.g. await req.text()). Re-serializing parsed JSON alters formatting/whitespace and breaks HMAC verification.",
          fingerprint: `stripe-parsed-body-${normPath}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 3. detectStripeUserControlledPrice (stripe-user-controlled-price)
 * Detects Stripe checkout/payment intent creation taking price/amount directly from user request.
 */
export async function detectStripeUserControlledPrice(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (
      !normPath.endsWith(".ts") &&
      !normPath.endsWith(".tsx") &&
      !normPath.endsWith(".js") &&
      !normPath.endsWith(".jsx")
    ) {
      continue;
    }

    const hasStripeCheckout = /checkout\.sessions\.create|paymentIntents\.create/i.test(content);
    if (!hasStripeCheckout) continue;

    // Check if user parameter is passed directly to unit_amount or amount
    const isUserControlled =
      /unit_amount:\s*(?:[a-zA-Z0-9_.]+\.amount|userSubmittedAmount|amount|[a-zA-Z0-9_.]+)/i.test(
        content
      ) || /amount:\s*[a-zA-Z0-9_.]+\.amount/i.test(content);

    const hasVerifiedDbPrice =
      /getProductFromDb|getProductPriceFromDb|dbProduct|price:\s*dbProduct/i.test(content);

    if (isUserControlled && !hasVerifiedDbPrice) {
      const lines = content.split("\n");
      let inputLine = lines.findIndex((l) => l.includes(".json()") || /params/i.test(l)) + 1;
      if (inputLine === 0)
        inputLine = lines.findIndex((l) => /unit_amount:|amount:/i.test(l)) + 1 || 1;
      const line = inputLine;

      const maskedSnippet = lines
        .slice(Math.max(0, line - 1), Math.min(lines.length, line + 3))
        .join("\n")
        .trim();

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line,
          maskedSnippet: lines[line - 1]?.trim() || "const { amount } = await req.json();",
          confidence: "high",
          note: "Price/amount parameter extracted directly from HTTP client request body",
        },
        {
          kind: "flow",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "User-controlled amount parameter passed directly into Stripe session creation payload",
        },
        {
          kind: "sink",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Stripe checkout session or payment intent created with client-supplied unit_amount",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Missing server-side database price lookup or Stripe Price ID validation",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "stripe-user-controlled-price",
          title: "Stripe Payment Amount Taken From User Request",
          severity: "high",
          confidenceTier: "likely",
          file: normPath,
          lineRange: { startLine: line, endLine: line },
          evidenceChain,
          unresolvedSteps: [],
          explanation:
            "Payment session or payment intent creation uses a price/amount parameter directly supplied by the client. According to Stripe Checkout Security Guidelines (https://stripe.com/docs/payments/checkout/how-checkout-works), payment amounts and line items MUST be determined server-side via verified Price IDs or server database lookups to prevent price tampering.",
          fingerprint: `stripe-user-price-${normPath}`,
        })
      );
    }
  }

  return findings;
}

/**
 * 4. detectStripeSecretKeyClientLeak (stripe-secret-key-client-leak)
 * Detects Stripe secret API key used in client components.
 */
export async function detectStripeSecretKeyClientLeak(
  filesMap: Map<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const [filePath, content] of filesMap.entries()) {
    const normPath = filePath.replace(/\\/g, "/");
    if (
      !normPath.endsWith(".ts") &&
      !normPath.endsWith(".tsx") &&
      !normPath.endsWith(".js") &&
      !normPath.endsWith(".jsx")
    ) {
      continue;
    }

    const isClientComponent = /^\s*['"]use client['"]/m.test(content);
    if (!isClientComponent) continue;

    const containsSecretKey =
      /STRIPE_SECRET_KEY/i.test(content) ||
      /sk_live_[a-zA-Z0-9]{24,}/.test(content) ||
      /sk_test_[a-zA-Z0-9]{24,}/.test(content);

    if (containsSecretKey) {
      const lines = content.split("\n");
      const line = lines.findIndex((l) => /STRIPE_SECRET_KEY|sk_live_|sk_test_/.test(l)) + 1 || 1;

      const maskedSnippet = lines[line - 1]?.trim() || "new Stripe(process.env.STRIPE_SECRET_KEY!)";

      const evidenceChain: EvidenceHop[] = [
        {
          kind: "source",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Stripe secret API key reference (STRIPE_SECRET_KEY or sk_test_...)",
        },
        {
          kind: "flow",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Secret key instantiated in file with 'use client' directive",
        },
        {
          kind: "sink",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Secret API key bundled into client browser JavaScript assets",
        },
        {
          kind: "missing-guard",
          file: normPath,
          line,
          maskedSnippet,
          confidence: "high",
          note: "Exposes full administrative Stripe account access to browser users",
        },
      ];

      findings.push(
        createFinding({
          ruleId: "stripe-secret-key-client-leak",
          title: "Stripe Secret API Key Leaked in Client Component",
          severity: "critical",
          confidenceTier: "proven",
          file: normPath,
          lineRange: { startLine: line, endLine: line },
          evidenceChain,
          unresolvedSteps: [],
          explanation:
            "Stripe secret API key is referenced inside a client component ('use client'). According to official Stripe API Key Security Documentation (https://stripe.com/docs/keys#safe-use-of-api-keys), secret keys (sk_live_ / sk_test_) possess unrestricted account control and must NEVER be included in client-side code. Use publishable keys (pk_live_ / pk_test_) for client components.",
          fingerprint: `stripe-secret-leak-${normPath}`,
        })
      );
    }
  }

  return findings;
}
