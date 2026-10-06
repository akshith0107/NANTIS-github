import { Project, SourceFile, Node } from "ts-morph";
import { Catalog } from "../catalogs/schema.js";
import { loadDefaultCatalogs } from "../catalogs/loader.js";

export type EntryPointKind = "route-handler" | "server-action" | "middleware" | "client-boundary";

export type AuthGuardStatus = "guarded" | "unguarded" | "unresolved";

export interface EntryPointInfo {
  id: string;
  kind: EntryPointKind;
  filePath: string;
  name: string;
  methods?: string[];
  matcher?: string | string[];
  authGuardStatus: AuthGuardStatus;
  detectedGuards: string[];
  isUnresolved: boolean;
  unresolvedReason?: string;
  lineRange?: { startLine: number; endLine: number };
}

export interface MiddlewareInfo {
  filePath: string;
  matcher?: string | string[];
  hasAuthGuard: boolean;
  authGuardStatus: AuthGuardStatus;
  detectedGuards: string[];
  isUnresolved: boolean;
  unresolvedReason?: string;
}

export interface NextjsAdapterAnalysisResult {
  entryPoints: EntryPointInfo[];
  middlewareInfo?: MiddlewareInfo;
}

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/**
 * Normalizes file paths to use forward slashes.
 */
function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

/**
 * Converts a Next.js App Router route.ts file path to its URL path.
 * e.g., "app/api/user/route.ts" -> "/api/user"
 * "app/route.ts" -> "/"
 */
export function convertFilePathToRouteUrl(filePath: string): string {
  const normalized = normalizePath(filePath);
  const match = normalized.match(/(?:^|\/)app\/(.*?)\/route\.(?:ts|js|tsx|jsx)$/i);
  if (match) {
    const routePart = match[1];
    return routePart ? `/${routePart}` : "/";
  }
  if (/(?:^|\/)app\/route\.(?:ts|js|tsx|jsx)$/i.test(normalized)) {
    return "/";
  }
  return "/" + normalized;
}

/**
 * Checks if a route URL path is matched by Next.js middleware matcher rules.
 */
export function isPathMatchedByMiddleware(
  routeUrlPath: string,
  matcher?: string | string[]
): boolean {
  if (!matcher) {
    // If no matcher is defined, Next.js middleware runs on all paths by default
    return true;
  }

  const matchers = Array.isArray(matcher) ? matcher : [matcher];

  for (const m of matchers) {
    if (m === "/" || m === "/*" || m === "/:path*") return true;

    // Convert Next.js matcher syntax to regex
    // :path* -> (?:/.*)?
    // :path+ -> /.+
    // (.*) -> .*
    let regexStr = m
      .replace(/\/:path\*/g, "(?:/.*)?")
      .replace(/:path\*/g, "(?:/.*)?")
      .replace(/\/:path\+/g, "/.+")
      .replace(/:path\+/g, ".+")
      .replace(/:[a-zA-Z0-9_]+/g, "[^/]+");

    if (!regexStr.startsWith("^")) {
      regexStr = "^" + regexStr;
    }
    if (!regexStr.endsWith("$")) {
      regexStr = regexStr + "$";
    }

    try {
      const regex = new RegExp(regexStr);
      if (regex.test(routeUrlPath)) {
        return true;
      }
    } catch {
      // If regex compilation fails (e.g. complex negative lookahead), check prefix match
      const prefix = m.replace(/[\*\(\)\:]/g, "").split("/")[1];
      if (prefix && routeUrlPath.startsWith(`/${prefix}`)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Detects catalog auth guards in a ts-morph AST node or source text.
 */
function detectGuardsInNode(node: Node | SourceFile, catalog: Catalog): string[] {
  const detected = new Set<string>();
  const text = node.getText();

  // 1. Check against catalog authGuards patterns
  for (const guard of catalog.authGuards) {
    if (guard.pattern && text.includes(guard.pattern)) {
      detected.add(guard.id || guard.name);
    }
  }

  // 2. Check standard built-in auth guard patterns
  const builtInGuards: Array<{ id: string; pattern: RegExp }> = [
    { id: "next-auth-get-session", pattern: /\bgetServerSession\b/ },
    { id: "next-auth-auth", pattern: /\bauth\s*\(/ },
    { id: "nantis-assert-repo-access", pattern: /\bassertRepoAccess\b/ },
    { id: "supabase-auth-get-user", pattern: /supabase\.auth\.getUser/ },
    { id: "supabase-auth-get-session", pattern: /supabase\.auth\.getSession/ },
    { id: "verify-session", pattern: /\bverifySession\b/ },
    { id: "use-session", pattern: /\buseSession\b/ },
    { id: "use-auth", pattern: /\buseAuth\b/ },
  ];

  for (const guard of builtInGuards) {
    if (guard.pattern.test(text)) {
      detected.add(guard.id);
    }
  }

  return Array.from(detected);
}

/**
 * Checks for unresolved constructs (dynamic import, eval, new Function) in AST node.
 */
function detectUnresolvedInNode(node: Node | SourceFile): {
  isUnresolved: boolean;
  unresolvedReason?: string;
} {
  const text = node.getText();

  if (/\bimport\s*\(/.test(text)) {
    return {
      isUnresolved: true,
      unresolvedReason: "Dynamic import 'import(...)' detected on path",
    };
  }

  if (/\beval\s*\(/.test(text) || /new\s+Function\s*\(/.test(text)) {
    return {
      isUnresolved: true,
      unresolvedReason: "Dynamic code execution (eval / new Function) detected on path",
    };
  }

  return { isUnresolved: false };
}

/**
 * Main adapter entry point analyzing Next.js App Router codebase.
 */
export function analyzeNextjsAppRouter(
  filesMap: Map<string, string>,
  customCatalog?: Catalog
): NextjsAdapterAnalysisResult {
  const catalog = customCatalog ?? loadDefaultCatalogs();
  const entryPoints: EntryPointInfo[] = [];

  const project = new Project({
    useInMemoryFileSystem: true,
    skipAddingFilesFromTsConfig: true,
  });

  const sourceFilesMap = new Map<string, SourceFile>();
  for (const [filePath, content] of filesMap.entries()) {
    const norm = normalizePath(filePath);
    if (
      norm.endsWith(".ts") ||
      norm.endsWith(".tsx") ||
      norm.endsWith(".js") ||
      norm.endsWith(".jsx")
    ) {
      const sf = project.createSourceFile(norm, content, { overwrite: true });
      sourceFilesMap.set(norm, sf);
    }
  }

  // --- Step 1: Analyze Middleware First ---
  let middlewareInfo: MiddlewareInfo | undefined = undefined;

  for (const [normPath, sf] of sourceFilesMap.entries()) {
    if (/(?:^|\/)(?:src\/)?middleware\.(?:ts|js|tsx|jsx)$/i.test(normPath)) {
      let matchers: string[] | undefined = undefined;

      // Extract config.matcher
      sf.forEachDescendant((node) => {
        if (Node.isPropertyAssignment(node) && node.getName() === "matcher") {
          const init = node.getInitializer();
          if (init && Node.isStringLiteral(init)) {
            matchers = [init.getLiteralValue()];
          } else if (init && Node.isNoSubstitutionTemplateLiteral(init)) {
            matchers = [init.getLiteralValue()];
          } else if (init && Node.isArrayLiteralExpression(init)) {
            matchers = init
              .getElements()
              .map((el) => {
                if (Node.isStringLiteral(el) || Node.isNoSubstitutionTemplateLiteral(el)) {
                  return el.getLiteralValue();
                }
                return el.getText().replace(/['"]/g, "");
              })
              .filter(Boolean);
          }
        }
      });

      const detectedGuards = detectGuardsInNode(sf, catalog);
      const unresolvedCheck = detectUnresolvedInNode(sf);

      let authGuardStatus: AuthGuardStatus = "unguarded";
      if (detectedGuards.length > 0) {
        authGuardStatus = "guarded";
      } else if (unresolvedCheck.isUnresolved) {
        authGuardStatus = "unresolved";
      }

      middlewareInfo = {
        filePath: normPath,
        matcher: matchers,
        hasAuthGuard: authGuardStatus === "guarded",
        authGuardStatus,
        detectedGuards,
        isUnresolved: unresolvedCheck.isUnresolved,
        unresolvedReason: unresolvedCheck.unresolvedReason,
      };

      entryPoints.push({
        id: `${normPath}:middleware`,
        kind: "middleware",
        filePath: normPath,
        name: "middleware",
        matcher: matchers,
        authGuardStatus,
        detectedGuards,
        isUnresolved: unresolvedCheck.isUnresolved,
        unresolvedReason: unresolvedCheck.unresolvedReason,
      });
      break; // Only one middleware file in Next.js
    }
  }

  // --- Step 2: Analyze Route Handlers (app/**/route.ts) ---
  for (const [normPath, sf] of sourceFilesMap.entries()) {
    if (!/(?:^|\/)app\/.*\/route\.(?:ts|js|tsx|jsx)$/i.test(normPath)) {
      continue;
    }

    const routeUrlPath = convertFilePathToRouteUrl(normPath);
    const isMiddlewareMatched = middlewareInfo
      ? isPathMatchedByMiddleware(routeUrlPath, middlewareInfo.matcher)
      : false;

    // Check exported functions / variables for HTTP methods
    for (const statement of sf.getStatements()) {
      // 1. Exported Function Declaration (export async function GET...)
      if (Node.isFunctionDeclaration(statement) && statement.isExported()) {
        const fnName = statement.getName();
        if (fnName && HTTP_METHODS.includes(fnName.toUpperCase())) {
          const method = fnName.toUpperCase();
          const startLine = statement.getStartLineNumber();
          const endLine = statement.getEndLineNumber();

          const directGuards = detectGuardsInNode(statement, catalog);
          const unresolvedCheck = detectUnresolvedInNode(statement);

          let authGuardStatus: AuthGuardStatus = "unguarded";
          let isUnresolved = unresolvedCheck.isUnresolved;
          let unresolvedReason = unresolvedCheck.unresolvedReason;
          const finalGuards = new Set<string>(directGuards);

          if (directGuards.length > 0) {
            authGuardStatus = "guarded";
          } else if (isMiddlewareMatched && middlewareInfo?.authGuardStatus === "guarded") {
            authGuardStatus = "guarded";
            middlewareInfo.detectedGuards.forEach((g) => finalGuards.add(g));
          } else if (unresolvedCheck.isUnresolved) {
            authGuardStatus = "unresolved";
          } else if (isMiddlewareMatched && middlewareInfo?.authGuardStatus === "unresolved") {
            authGuardStatus = "unresolved";
            isUnresolved = true;
            unresolvedReason = "Middleware on path has unresolved auth guard status";
          }

          entryPoints.push({
            id: `${normPath}:${method}`,
            kind: "route-handler",
            filePath: normPath,
            name: method,
            methods: [method],
            authGuardStatus,
            detectedGuards: Array.from(finalGuards),
            isUnresolved,
            unresolvedReason,
            lineRange: { startLine, endLine },
          });
        }
      }

      // 2. Exported Variable Statement (export const GET = ... or export const POST = withAuth(...))
      if (Node.isVariableStatement(statement) && statement.isExported()) {
        for (const decl of statement.getDeclarationList().getDeclarations()) {
          const declName = decl.getName();
          if (HTTP_METHODS.includes(declName.toUpperCase())) {
            const method = declName.toUpperCase();
            const startLine = decl.getStartLineNumber();
            const endLine = decl.getEndLineNumber();
            const initializer = decl.getInitializer();

            let unknownWrapperName: string | undefined = undefined;

            // Check if initializer is a call to a higher-order wrapper function
            if (initializer && Node.isCallExpression(initializer)) {
              const wrapperExpr = initializer.getExpression().getText();
              const isKnownGuard = catalog.authGuards.some(
                (g) => g.pattern === wrapperExpr || wrapperExpr.includes(g.pattern)
              );
              if (!isKnownGuard) {
                unknownWrapperName = wrapperExpr;
              }
            }

            const directGuards = detectGuardsInNode(decl, catalog);
            const unresolvedCheck = detectUnresolvedInNode(decl);

            let isUnresolved = unresolvedCheck.isUnresolved || !!unknownWrapperName;
            let unresolvedReason = unresolvedCheck.unresolvedReason;
            if (unknownWrapperName) {
              unresolvedReason = `Unknown wrapper function '${unknownWrapperName}' applied to route handler`;
            }

            let authGuardStatus: AuthGuardStatus = "unguarded";
            const finalGuards = new Set<string>(directGuards);

            if (directGuards.length > 0) {
              authGuardStatus = "guarded";
            } else if (isMiddlewareMatched && middlewareInfo?.authGuardStatus === "guarded") {
              authGuardStatus = "guarded";
              middlewareInfo.detectedGuards.forEach((g) => finalGuards.add(g));
            } else if (isUnresolved) {
              authGuardStatus = "unresolved";
            } else if (isMiddlewareMatched && middlewareInfo?.authGuardStatus === "unresolved") {
              authGuardStatus = "unresolved";
              isUnresolved = true;
              unresolvedReason = "Middleware on path has unresolved auth guard status";
            }

            entryPoints.push({
              id: `${normPath}:${method}`,
              kind: "route-handler",
              filePath: normPath,
              name: method,
              methods: [method],
              authGuardStatus,
              detectedGuards: Array.from(finalGuards),
              isUnresolved,
              unresolvedReason,
              lineRange: { startLine, endLine },
            });
          }
        }
      }
    }
  }

  // --- Step 3: Analyze Server Actions ('use server') ---
  for (const [normPath, sf] of sourceFilesMap.entries()) {
    const fullText = sf.getFullText();
    const hasFileLevelUseServer = /^\s*['"]use server['"]/m.test(fullText);

    sf.forEachDescendant((node) => {
      let isServerActionNode = false;
      let fnName = "default";
      let startLine = node.getStartLineNumber();
      let endLine = node.getEndLineNumber();

      if (Node.isFunctionDeclaration(node) && node.isExported()) {
        fnName = node.getName() || "default";
        if (hasFileLevelUseServer) {
          isServerActionNode = true;
        } else {
          // Check function body for inline 'use server'
          const body = node.getBody();
          if (body && /^\s*['"]use server['"]/m.test(body.getText())) {
            isServerActionNode = true;
          }
        }
      } else if (Node.isVariableDeclaration(node)) {
        const parentStmt = node.getParent()?.getParent();
        if (Node.isVariableStatement(parentStmt) && parentStmt.isExported()) {
          fnName = node.getName();
          const init = node.getInitializer();
          if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) {
            if (hasFileLevelUseServer) {
              isServerActionNode = true;
            } else {
              const body = init.getBody();
              if (body && /^\s*['"]use server['"]/m.test(body.getText())) {
                isServerActionNode = true;
              }
            }
          }
        }
      }

      if (isServerActionNode) {
        const entryId = `${normPath}:${fnName}`;
        // Avoid duplicate additions
        if (entryPoints.some((e) => e.id === entryId)) return;

        const directGuards = detectGuardsInNode(node, catalog);
        const unresolvedCheck = detectUnresolvedInNode(node);

        let authGuardStatus: AuthGuardStatus = "unguarded";
        if (directGuards.length > 0) {
          authGuardStatus = "guarded";
        } else if (unresolvedCheck.isUnresolved) {
          authGuardStatus = "unresolved";
        }

        entryPoints.push({
          id: entryId,
          kind: "server-action",
          filePath: normPath,
          name: fnName,
          authGuardStatus,
          detectedGuards: directGuards,
          isUnresolved: unresolvedCheck.isUnresolved,
          unresolvedReason: unresolvedCheck.unresolvedReason,
          lineRange: { startLine, endLine },
        });
      }
    });
  }

  // --- Step 4: Analyze 'use client' Boundaries ---
  for (const [normPath, sf] of sourceFilesMap.entries()) {
    const fullText = sf.getFullText();
    const hasUseClient = /^\s*['"]use client['"]/m.test(fullText);

    if (hasUseClient) {
      const baseName =
        normPath
          .split("/")
          .pop()
          ?.replace(/\.(?:ts|js|tsx|jsx)$/, "") || "ClientBoundary";
      const detectedGuards = detectGuardsInNode(sf, catalog);
      const unresolvedCheck = detectUnresolvedInNode(sf);

      let authGuardStatus: AuthGuardStatus = "unguarded";
      if (detectedGuards.length > 0) {
        authGuardStatus = "guarded";
      } else if (unresolvedCheck.isUnresolved) {
        authGuardStatus = "unresolved";
      }

      entryPoints.push({
        id: `${normPath}:client-boundary`,
        kind: "client-boundary",
        filePath: normPath,
        name: baseName,
        authGuardStatus,
        detectedGuards,
        isUnresolved: unresolvedCheck.isUnresolved,
        unresolvedReason: unresolvedCheck.unresolvedReason,
      });
    }
  }

  return {
    entryPoints,
    middlewareInfo,
  };
}
