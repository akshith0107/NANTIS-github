import fs from "fs";
import path from "path";
import { Catalog, CatalogSchema } from "./schema.js";

import nextjsCatalogData from "./data/nextjs.json" with { type: "json" };
import supabaseStripeCatalogData from "./data/supabase-stripe.json" with { type: "json" };

/**
 * Parses and validates catalog JSON data against the versioned Zod CatalogSchema.
 * Throws a detailed ZodError if validation fails.
 */
export function loadCatalog(input: string | object): Catalog {
  const parsedObj = typeof input === "string" ? JSON.parse(input) : input;
  return CatalogSchema.parse(parsedObj);
}

/**
 * Merges multiple validated Catalog objects into a unified Catalog instance.
 */
export function mergeCatalogs(catalogs: Catalog[]): Catalog {
  if (catalogs.length === 0) {
    return loadCatalog({
      version: "1.0.0",
      lastUpdated: new Date().toISOString(),
      frameworkVersions: {},
      frameworkEntryPoints: [],
      sources: [],
      sinks: [],
      sanitizersValidators: [],
      authGuards: [],
    });
  }

  const mergedFrameworkVersions: Record<string, string> = {};
  const frameworkEntryPoints = [];
  const sources = [];
  const sinks = [];
  const sanitizersValidators = [];
  const authGuards = [];

  for (const cat of catalogs) {
    Object.assign(mergedFrameworkVersions, cat.frameworkVersions);
    frameworkEntryPoints.push(...cat.frameworkEntryPoints);
    sources.push(...cat.sources);
    sinks.push(...cat.sinks);
    sanitizersValidators.push(...cat.sanitizersValidators);
    authGuards.push(...cat.authGuards);
  }

  return {
    version: catalogs[0].version,
    lastUpdated: new Date().toISOString(),
    frameworkVersions: mergedFrameworkVersions,
    frameworkEntryPoints,
    sources,
    sinks,
    sanitizersValidators,
    authGuards,
  };
}

/**
 * Loads default built-in framework security catalogs (Next.js, Supabase, Stripe).
 */
export function loadDefaultCatalogs(): Catalog {
  const nextjsCat = loadCatalog(nextjsCatalogData);
  const supabaseStripeCat = loadCatalog(supabaseStripeCatalogData);
  return mergeCatalogs([nextjsCat, supabaseStripeCat]);
}

/**
 * Loads a catalog from a specified filesystem path.
 */
export function loadCatalogFromFile(filePath: string): Catalog {
  const absolutePath = path.resolve(filePath);
  const content = fs.readFileSync(absolutePath, "utf-8");
  return loadCatalog(content);
}
