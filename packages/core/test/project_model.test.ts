import { describe, expect, it } from "vitest";
import { ProjectModel } from "../src/project-model.js";

describe("ProjectModel ts-morph AST caching and symbol lookup", () => {
  it("should parse files into memory and extract imports, exports, and symbols", () => {
    const files = new Map<string, string>([
      [
        "src/stripe.ts",
        `import Stripe from "stripe";
export function createStripeClient(apiKey: string) {
  return new Stripe(apiKey);
}`,
      ],
      [
        "src/index.ts",
        `import { createStripeClient } from "./stripe.js";
export const client = createStripeClient("sk_test_FAKE");`,
      ],
    ]);

    const model = new ProjectModel(files);

    // Test getSourceFile caching
    const stripeFile = model.getSourceFile("src/stripe.ts");
    expect(stripeFile).toBeDefined();

    // Test getImports
    const imports = model.getImports("src/stripe.ts");
    expect(imports.length).toBe(1);
    expect(imports[0].moduleSpecifier).toBe("stripe");
    expect(imports[0].defaultImport).toBe("Stripe");

    // Test getExports
    const exportsList = model.getExports("src/stripe.ts");
    expect(exportsList.some((e) => e.name === "createStripeClient")).toBe(true);

    // Test symbol lookup
    const symbols = model.findSymbols("createStripeClient");
    expect(symbols.length).toBeGreaterThanOrEqual(2);
    const filePaths = symbols.map((s) => s.filePath);
    expect(filePaths).toContain("src/stripe.ts");
    expect(filePaths).toContain("src/index.ts");
  });
});
