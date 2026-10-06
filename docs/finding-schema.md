# NANTIS Finding Schema Specification

This document defines the finding data model, evidence chain representation, secret masking rules, and fingerprint generation algorithm for `@nantis/core`.

---

## 1. Finding & EvidenceHop Schema

### `Finding`

The primary output object emitted by `@nantis/core` inspection rules.

```typescript
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ConfidenceTier = "proven" | "likely" | "needs-review" | "hygiene";
export type FindingStatus = "new" | "fixed" | "unchanged" | "reintroduced";

export interface LineRange {
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface GitCommitMeta {
  commit?: string;
  pr?: number;
  author?: string;
  date?: string;
}

export interface FindingFix {
  description: string;
  diff?: string;
}

export interface Finding {
  /** Unique finding UUID v4 */
  id: string;

  /** Rule identifier (e.g., "stripe-missing-signature-verify") */
  ruleId: string;

  /** Human-readable short title */
  title: string;

  /** Risk severity level */
  severity: Severity;

  /** Engine confidence tier */
  confidenceTier: ConfidenceTier;

  /** Normalized relative path to affected file */
  file: string;

  /** Line and column range of the target sink */
  lineRange: LineRange;

  /** Ordered evidence chain tracing source -> flow -> sink / missing guard */
  evidenceChain: EvidenceHop[];

  /** Engine analysis steps that could not be statically resolved */
  unresolvedSteps: UnresolvedStep[];

  /** Plain English explanation of vulnerability and impact */
  explanation: string;

  /** Suggested automated fix or patch guidance */
  fix?: FindingFix;

  /** Deterministic SHA-256 fingerprint for vulnerability tracking across refactors */
  fingerprint: string;

  /** Git metadata associated with when the issue was introduced */
  introducedIn?: GitCommitMeta;

  /** Finding lifecycle status across scans */
  status?: FindingStatus;
}
```

---

### `EvidenceHop`

Represents an individual step in the dataflow, control flow, or configuration sequence supporting a finding.

```typescript
export type EvidenceHopKind =
  | "source" // Tainted input source (e.g. req.json(), params)
  | "flow" // Intermediary assignment / transformation
  | "sink" // Dangerous function or database call
  | "missing-guard" // Expected security check that was omitted or bypassed
  | "config"; // Misconfigured environment or header setting

export type HopConfidence = "high" | "medium" | "low";

export interface EvidenceHop {
  /** Hop role in the evidence chain */
  kind: EvidenceHopKind;

  /** Relative file path of the hop */
  file: string;

  /** Line number of the hop */
  line: number;

  /**
   * Pre-masked code snippet.
   * MUST be masked at construction time. Never contains unmasked secrets.
   */
  maskedSnippet: string;

  /** Engine confidence in this specific hop step */
  confidence: HopConfidence;

  /** Contextual note describing what occurred at this hop */
  note: string;
}
```

---

### `UnresolvedStep`

Captures analysis boundaries where the static engine could not follow dataflow (e.g., dynamic imports, opaque external library calls, indirect property lookups).

```typescript
export type UnresolvedReason =
  "dynamic-import" | "opaque-call" | "dynamic-property" | "external-library";

export interface UnresolvedStep {
  description: string;
  location: {
    file: string;
    line: number;
  };
  reason: UnresolvedReason;
}
```

---

## 2. Secret Masking Rule (Construction Time)

1. **Mandatory Construction-Time Masking**:
   Code snippets assigned to `EvidenceHop.maskedSnippet` MUST be processed through `maskSecret()` _prior to_ or _at_ instantiation of the `EvidenceHop` or `Finding` object.
2. **Leakage Prevention Standard**:
   `maskSecret()` guarantees that no raw secret token (Stripe keys, Supabase service keys, database passwords, JWTs, GitHub PATs) is retained.
   - At most **4 non-secret characters** (such as prefix `sk_l` or suffix) are revealed.
   - Remaining characters are replaced by `[REDACTED_SECRET]`.
3. **No Unmasked Storage**:
   Raw source code strings containing potential secrets are discarded immediately after AST extraction and snippet masking. Raw findings are never stored in memory or on disk.

---

## 3. Fingerprint Generation Algorithm

### Objective

Produce a stable, deterministic hash for each finding that remains **identical** when:

- Code is moved up or down by N lines (e.g. 50 lines).
- Whitespace, indentation, formatting, or comments change.
- Non-structural variables outside the taint path are renamed.

### Inputs

1. `ruleId`: Exact rule string.
2. `normalizedSinkLocation`: `file` relative path + AST enclosing scope symbol identifier (e.g. `app/api/webhooks/stripe/route.ts::POST::stripe.webhooks.constructEvent`). Line numbers are excluded.
3. `evidenceChainShape`: An ordered array of normalized hop signatures:
   ```json
   [
     { "kind": "source", "file": "app/api/webhooks/stripe/route.ts", "token": "req.text" },
     { "kind": "sink", "file": "app/api/webhooks/stripe/route.ts", "token": "constructEvent" }
   ]
   ```

### Algorithm Steps

1. Construct normalized object:
   ```typescript
   const payload = {
     ruleId: finding.ruleId,
     file: finding.file.toLowerCase(),
     sinkSymbol: extractAstScopeSymbol(finding),
     hops: finding.evidenceChain.map((h) => ({
       kind: h.kind,
       file: h.file.toLowerCase(),
       token: extractAstToken(h.maskedSnippet),
     })),
   };
   ```
2. Serialize `payload` to canonical JSON (sorted keys).
3. Compute SHA-256 hash digest (hex encoded).

### Edge Cases

- **Anonymous Callbacks**: If the sink function is inside an anonymous arrow function, the scope symbol falls back to the top-level exported handler (e.g., `export default` or `POST`) + AST node call type.
- **Multiple Identical Sinks in Same Function**: Differentiated by evidence chain AST tokens (e.g. distinct argument parameter names) rather than line numbers.
- **File Renames**: If a file is renamed, the fingerprint changes (intentional, as the finding status changes to `new` in the renamed file).

---

## 4. Proposed Zod Validation Schema Preview

```typescript
import { z } from "zod";

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export const ConfidenceTierSchema = z.enum(["proven", "likely", "needs-review", "hygiene"]);
export const EvidenceHopKindSchema = z.enum(["source", "flow", "sink", "missing-guard", "config"]);

export const EvidenceHopSchema = z.object({
  kind: EvidenceHopKindSchema,
  file: z.string().min(1),
  line: z.number().int().positive(),
  maskedSnippet: z.string(),
  confidence: z.enum(["high", "medium", "low"]),
  note: z.string(),
});

export const UnresolvedStepSchema = z.object({
  description: z.string(),
  location: z.object({
    file: z.string().min(1),
    line: z.number().int().positive(),
  }),
  reason: z.enum(["dynamic-import", "opaque-call", "dynamic-property", "external-library"]),
});

export const FindingSchema = z.object({
  id: z.string().uuid(),
  ruleId: z.string().min(1),
  title: z.string().min(1),
  severity: SeveritySchema,
  confidenceTier: ConfidenceTierSchema,
  file: z.string().min(1),
  lineRange: z.object({
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive(),
    startColumn: z.number().int().positive().optional(),
    endColumn: z.number().int().positive().optional(),
  }),
  evidenceChain: z.array(EvidenceHopSchema),
  unresolvedSteps: z.array(UnresolvedStepSchema),
  explanation: z.string().min(1),
  fix: z
    .object({
      description: z.string(),
      diff: z.string().optional(),
    })
    .optional(),
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  introducedIn: z
    .object({
      commit: z.string().optional(),
      pr: z.number().optional(),
      author: z.string().optional(),
      date: z.string().optional(),
    })
    .optional(),
  status: z.enum(["new", "fixed", "unchanged", "reintroduced"]).optional(),
});
```
