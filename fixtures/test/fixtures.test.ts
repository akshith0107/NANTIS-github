import { describe, expect, it } from "vitest";
import { FIXTURES_DIR } from "../src/index.js";

describe("fixtures package trivial test", () => {
  it("exports fixtures dir name", () => {
    expect(FIXTURES_DIR).toBe("fixtures");
  });
});
