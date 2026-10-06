import fs from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import { runScan } from "../src/cli/scan.js";
import { runScoreboard } from "../src/cli/scoreboard.js";

const FIXTURES_DIR = path.resolve(__dirname, "../../../fixtures");
const SCOREBOARD_JSON_PATH = path.resolve(__dirname, "../../../scoreboard.json");

describe("CLI Scan & Scoreboard Tools (packages/core/src/cli)", () => {
  it("should run scan on a clean fixture directory and return exit code 0", async () => {
    const cleanDir = path.join(FIXTURES_DIR, "hardcoded-secret/clean");
    const { findings, exitCode } = await runScan(cleanDir, { json: true });

    expect(exitCode).toBe(0);
    expect(findings.length).toBe(0);
  });

  it("should run scan on a vulnerable fixture directory and return exit code 1 with findings", async () => {
    const vulnDir = path.join(FIXTURES_DIR, "hardcoded-secret/vulnerable");
    const { findings, exitCode } = await runScan(vulnDir, { json: true });

    expect(exitCode).toBe(1);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe("hardcoded-secret");
  });

  it("should return exit code 2 when target directory does not exist", async () => {
    const { exitCode } = await runScan("non_existent_folder_xyz123");
    expect(exitCode).toBe(2);
  });

  it("should run scoreboard across all fixtures, print summary, and write scoreboard.json", async () => {
    const { scoreboard, exitCode } = await runScoreboard();

    expect(exitCode).toBe(0);
    expect(scoreboard.length).toBeGreaterThan(0);

    for (const entry of scoreboard) {
      expect(entry.ruleId).toBeDefined();
      expect(entry.precision).toContain("%");
      expect(entry.recall).toContain("%");
    }

    expect(fs.existsSync(SCOREBOARD_JSON_PATH)).toBe(true);
    const jsonContent = fs.readFileSync(SCOREBOARD_JSON_PATH, "utf-8");
    const parsed = JSON.parse(jsonContent);
    expect(Array.isArray(parsed)).toBe(true);
  });
});
