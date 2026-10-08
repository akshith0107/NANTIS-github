import { describe, it, expect } from "vitest";
import { runIdorBenchmark } from "../src/idor/benchmark.js";

describe("Deterministic IDOR 30-Case Benchmark Suite", () => {
  it("should run complete 30-case benchmark and satisfy precision and recall thresholds", async () => {
    const metrics = await runIdorBenchmark();

    console.log("\n================ NANTIS IDOR 30-CASE BENCHMARK RESULTS ================\n");
    console.log(`Total Test Cases:       ${metrics.totalCases} (17 Vulnerable, 10 Safe, 3 Abstain)`);
    console.log(`True Positives (TP):     ${metrics.truePositives}`);
    console.log(`True Negatives (TN):     ${metrics.trueNegatives}`);
    console.log(`False Positives (FP):    ${metrics.falsePositives}`);
    console.log(`False Negatives (FN):    ${metrics.falseNegatives}`);
    console.log(`Abstentions:            ${metrics.abstentions}`);
    console.log("------------------------------------------------------------------------");
    console.log(`Precision:              ${metrics.precision.toFixed(1)}% (Threshold >= 90.0%)`);
    console.log(`Recall:                 ${metrics.recall.toFixed(1)}% (Threshold >= 80.0%)`);
    console.log(`False Positive Rate:    ${metrics.falsePositiveRate.toFixed(1)}%`);
    console.log(`False Negative Rate:    ${metrics.falseNegativeRate.toFixed(1)}%`);
    console.log(`Abstention Rate:        ${metrics.abstentionRate.toFixed(1)}%`);
    console.log(`Overall Coverage:       ${metrics.overallCoverage.toFixed(1)}%`);
    console.log("========================================================================\n");

    expect(metrics.totalCases).toBe(30);
    expect(metrics.vulnerableCases).toBe(17);
    expect(metrics.safeCases).toBe(10);
    expect(metrics.abstainCases).toBe(3);

    // Performance threshold assertions
    expect(metrics.precision).toBeGreaterThanOrEqual(90.0);
    expect(metrics.recall).toBeGreaterThanOrEqual(80.0);
    expect(metrics.overallCoverage).toBe(100.0);
    expect(metrics.falsePositives).toBe(0);
    expect(metrics.falseNegatives).toBe(0);
  });
});
