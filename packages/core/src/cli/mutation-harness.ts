import { runMutationHarness } from "../mutation/harness.js";

runMutationHarness().then(({ exitCode }) => {
  process.exit(exitCode);
});
