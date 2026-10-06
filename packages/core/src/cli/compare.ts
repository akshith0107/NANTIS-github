import path from "path";
import { runScan } from "./scan.js";
import { loadBaseline, saveBaseline, updateBaseline } from "../baseline.js";

export async function runCompareCli(): Promise<number> {
  const args = process.argv.slice(2);
  const baselinePath = args.find((a) => a.endsWith(".json")) || ".nantis-baseline.json";
  const targetDir = args.find((a) => !a.startsWith("--") && !a.endsWith(".json")) || ".";
  const updateFlag = args.includes("--update");
  const jsonFlag = args.includes("--json");
  const showUnchangedFlag = args.includes("--show-unchanged");

  const resolvedBaselinePath = path.resolve(baselinePath);

  const { exitCode, comparison } = await runScan(targetDir, {
    json: jsonFlag,
    baselinePath: resolvedBaselinePath,
    showUnchanged: showUnchangedFlag,
  });

  if (updateFlag && comparison) {
    const existingBaseline = loadBaseline(resolvedBaselinePath);
    const updated = updateBaseline(existingBaseline, comparison);
    saveBaseline(resolvedBaselinePath, updated);
    console.log(`Baseline updated at: ${resolvedBaselinePath}`);
  }

  return exitCode;
}

if (process.argv[1]?.includes("compare.ts") || process.argv[1]?.includes("compare.js")) {
  runCompareCli().then((exitCode) => {
    process.exit(exitCode);
  });
}
