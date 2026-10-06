export interface StackDetectionResult {
  hasNextAppRouter: boolean;
  hasSupabase: boolean;
  hasStripe: boolean;
  details: {
    nextAppRouterFiles: string[];
    supabaseMigrationsCount: number;
    stripeSdkDetected: boolean;
  };
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export function detectStack(files: Map<string, string>): StackDetectionResult {
  let hasNextAppRouter = false;
  let hasSupabase = false;
  let hasStripe = false;

  const nextAppRouterFiles: string[] = [];
  let supabaseMigrationsCount = 0;
  let stripeSdkDetected = false;

  // Check package.json for dependencies
  const pkgContent = files.get("package.json");
  if (pkgContent) {
    try {
      const pkg = JSON.parse(pkgContent) as PackageJson;
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      if ("next" in allDeps) {
        // Next.js present in dependencies
      }

      if (
        "@supabase/supabase-js" in allDeps ||
        "@supabase/ssr" in allDeps ||
        "@supabase/auth-helpers-nextjs" in allDeps
      ) {
        hasSupabase = true;
      }

      if ("stripe" in allDeps || "@stripe/stripe-js" in allDeps) {
        hasStripe = true;
        stripeSdkDetected = true;
      }
    } catch {
      // Ignore invalid package.json format
    }
  }

  // Scan file layout and code imports
  for (const [relPath, content] of files.entries()) {
    const normalized = relPath.replace(/\\/g, "/");

    // Next.js App Router detection
    if (
      normalized.startsWith("app/") ||
      normalized.includes("/app/") ||
      normalized.endsWith("route.ts") ||
      normalized.endsWith("route.js") ||
      normalized.endsWith("middleware.ts") ||
      normalized.endsWith("middleware.js")
    ) {
      hasNextAppRouter = true;
      nextAppRouterFiles.push(normalized);
    }

    // Supabase detection
    if (normalized.includes("supabase/migrations/")) {
      hasSupabase = true;
      supabaseMigrationsCount++;
    } else if (content.includes("@supabase/supabase-js") || content.includes("@supabase/ssr")) {
      hasSupabase = true;
    }

    // Stripe detection
    if (
      content.includes('from "stripe"') ||
      content.includes("from 'stripe'") ||
      content.includes("stripe.webhooks.constructEvent")
    ) {
      hasStripe = true;
      stripeSdkDetected = true;
    }
  }

  return {
    hasNextAppRouter,
    hasSupabase,
    hasStripe,
    details: {
      nextAppRouterFiles,
      supabaseMigrationsCount,
      stripeSdkDetected,
    },
  };
}
