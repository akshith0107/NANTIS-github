# NANTIS Security Engine — Quality Thresholds & Mutation Harness Stages

This document outlines the required precision and recall quality thresholds for NANTIS security rules and the automated mutation harness pipeline.

---

## 1. Quality Thresholds

All security detector rules in NANTIS must satisfy the following minimum precision and recall thresholds across test fixture suites (including hand-crafted vulnerable, mutated, clean, and automated AST-mutated variants):

| Metric        | Minimum Threshold | Description                                                                                                                                       |
| ------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Precision** | **90.0%**         | $\frac{\text{True Positives}}{\text{True Positives} + \text{False Positives}} \ge 90.0\%$ (Clean code must stay clean with minimal false alarms). |
| **Recall**    | **80.0%**         | $\frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}} \ge 80.0\%$ (Vulnerable code variants must be reliably detected).   |

> [!IMPORTANT]
> If any security detector rule drops below **90% Precision** or **80% Recall** during CI build or mutation harness verification, the verification pipeline MUST fail with exit code `1`.

---

## 2. Automated Mutation Harness Pipeline

The mutation harness (`packages/core/src/cli/mutation-harness.ts`) takes each vulnerable fixture and automatically applies 5 AST and structural code transformations:

1. **Variable Renaming**: Replaces identifier names (e.g. `req` $\rightarrow$ `clientRequestPayload`, `amount` $\rightarrow$ `userSubmittedAmount`, `body` $\rightarrow$ `parsedBodyObject`, `params` $\rightarrow$ `routeUrlParams`).
2. **Code Movement**: Moves auxiliary logic to secondary helper modules (`.helper.ts`) and re-exports/imports functions.
3. **Helper Wrapping**: Wraps request handling and database calls in generic inner/outer helper functions (`__executeWithSecurityContext`).
4. **Code Reformatting**: Adjusts line breaks, spacing, indentation, and comment structures.
5. **Unrelated Sanitizer Injection**: Injects dummy sanitizer functions (`sanitizeUnrelatedHeader`) that do not sanitize the vulnerable taint path.

---

## 3. Evaluation & CI Execution

The mutation harness evaluates detectors against:

- **Vulnerable Fixtures**: Verifies True Positives (`TP`).
- **Hand-crafted Mutated Fixtures**: Verifies resilience against manual refactoring.
- **Automated Mutated Fixtures**: Verifies resilience against automated code transformations.
- **Clean Fixtures**: Verifies zero False Positives (`FP = 0`).

To run the mutation harness manually or in CI:

```bash
pnpm run mutation-harness
```
