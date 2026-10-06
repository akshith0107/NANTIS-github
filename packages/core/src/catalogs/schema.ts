import { z } from "zod";

export const FrameworkVersionsSchema = z.record(z.string(), z.string());

export const FrameworkEntryPointSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(["route-handler", "server-action", "middleware", "page-component"]),
  pattern: z.string().min(1),
  methods: z.array(z.string()).optional(),
  description: z.string().optional(),
});

export const SourceDefinitionSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  category: z.enum([
    "query-param",
    "route-param",
    "request-body",
    "request-header",
    "cookie",
    "webhook-payload",
  ]),
  pattern: z.string().min(1),
  description: z.string().optional(),
});

export const SinkDefinitionSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  category: z.enum(["database", "payment", "secret-leak", "code-execution", "auth-bypass"]),
  pattern: z.string().min(1),
  requiredGuards: z.array(z.string()).optional(),
  description: z.string().optional(),
});

export const SanitizerValidatorSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  kind: z.enum(["signature-verifier", "schema-validator", "sanitizer-function"]),
  pattern: z.string().min(1),
  description: z.string().optional(),
});

export const AuthGuardSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  pattern: z.string().min(1),
  description: z.string().optional(),
});

export const CatalogSchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  lastUpdated: z.string(),
  frameworkVersions: FrameworkVersionsSchema,
  frameworkEntryPoints: z.array(FrameworkEntryPointSchema).default([]),
  sources: z.array(SourceDefinitionSchema).default([]),
  sinks: z.array(SinkDefinitionSchema).default([]),
  sanitizersValidators: z.array(SanitizerValidatorSchema).default([]),
  authGuards: z.array(AuthGuardSchema).default([]),
});

export type FrameworkVersions = z.infer<typeof FrameworkVersionsSchema>;
export type FrameworkEntryPoint = z.infer<typeof FrameworkEntryPointSchema>;
export type SourceDefinition = z.infer<typeof SourceDefinitionSchema>;
export type SinkDefinition = z.infer<typeof SinkDefinitionSchema>;
export type SanitizerValidator = z.infer<typeof SanitizerValidatorSchema>;
export type AuthGuard = z.infer<typeof AuthGuardSchema>;
export type Catalog = z.infer<typeof CatalogSchema>;
