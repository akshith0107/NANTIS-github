import { describe, expect, it } from "vitest";
import {
  analyzeNextjsAppRouter,
  convertFilePathToRouteUrl,
  isPathMatchedByMiddleware,
} from "../src/adapters/nextjs-app-router.js";
import { loadDefaultCatalogs } from "../src/catalogs/loader.js";

describe("Next.js App Router Adapter & Auth Guard Analyzer", () => {
  const catalog = loadDefaultCatalogs();

  it("should convert route file paths to Next.js URL route paths accurately", () => {
    expect(convertFilePathToRouteUrl("app/api/user/route.ts")).toBe("/api/user");
    expect(convertFilePathToRouteUrl("app/api/auth/[...nextauth]/route.ts")).toBe(
      "/api/auth/[...nextauth]"
    );
    expect(convertFilePathToRouteUrl("app/route.ts")).toBe("/");
    expect(convertFilePathToRouteUrl("src/app/api/v1/projects/route.ts")).toBe("/api/v1/projects");
  });

  it("should evaluate middleware path matching correctly", () => {
    expect(isPathMatchedByMiddleware("/api/user", "/api/:path*")).toBe(true);
    expect(isPathMatchedByMiddleware("/dashboard", ["/api/:path*", "/dashboard/:path*"])).toBe(
      true
    );
    expect(isPathMatchedByMiddleware("/public", "/api/:path*")).toBe(false);
    expect(isPathMatchedByMiddleware("/any-path", undefined)).toBe(true);
  });

  it("should analyze a CLEAN fixture with guarded route handlers, middleware, server actions, and client boundaries", () => {
    const cleanFiles = new Map<string, string>([
      [
        "middleware.ts",
        `
        import { assertRepoAccess } from "@/lib/auth";
        import { NextResponse } from "next/server";

        export async function middleware(req) {
          await assertRepoAccess("user-123", "repo-456");
          return NextResponse.next();
        }

        export const config = {
          matcher: "/api/:path*",
        };
        `,
      ],
      [
        "app/api/protected/route.ts",
        `
        import { getServerSession } from "next-auth";

        export async function GET(req: Request) {
          const session = await getServerSession();
          if (!session) return new Response("Unauthorized", { status: 401 });
          return Response.json({ status: "ok" });
        }
        `,
      ],
      [
        "app/actions/user.ts",
        `
        "use server";
        import { assertRepoAccess } from "@/lib/auth";

        export async function updateUserSettings(data: any) {
          await assertRepoAccess("user-1", "repo-1");
          return { success: true };
        }
        `,
      ],
      [
        "app/components/UserProfile.tsx",
        `
        "use client";
        import { useSession } from "next-auth/react";

        export default function UserProfile() {
          const session = useSession();
          return <div>User: {session.data?.user?.name}</div>;
        }
        `,
      ],
    ]);

    const result = analyzeNextjsAppRouter(cleanFiles, catalog);

    expect(result.middlewareInfo).toBeDefined();
    expect(result.middlewareInfo?.authGuardStatus).toBe("guarded");
    expect(result.middlewareInfo?.detectedGuards).toContain("nantis-assert-repo-access");

    const routeHandler = result.entryPoints.find((e) => e.kind === "route-handler");
    expect(routeHandler).toBeDefined();
    expect(routeHandler?.authGuardStatus).toBe("guarded");
    expect(routeHandler?.detectedGuards).toContain("next-auth-get-session");
    expect(routeHandler?.isUnresolved).toBe(false);

    const serverAction = result.entryPoints.find((e) => e.kind === "server-action");
    expect(serverAction).toBeDefined();
    expect(serverAction?.name).toBe("updateUserSettings");
    expect(serverAction?.authGuardStatus).toBe("guarded");
    expect(serverAction?.detectedGuards).toContain("nantis-assert-repo-access");

    const clientBoundary = result.entryPoints.find((e) => e.kind === "client-boundary");
    expect(clientBoundary).toBeDefined();
    expect(clientBoundary?.authGuardStatus).toBe("guarded");
    expect(clientBoundary?.detectedGuards).toContain("use-session");
  });

  it("should analyze a VULNERABLE fixture with unguarded route handlers, server actions, and middleware", () => {
    const vulnerableFiles = new Map<string, string>([
      [
        "middleware.ts",
        `
        import { NextResponse } from "next/server";

        export function middleware(req) {
          // Log only, no auth guard!
          console.log("Request received:", req.url);
          return NextResponse.next();
        }

        export const config = {
          matcher: "/dashboard/:path*",
        };
        `,
      ],
      [
        "app/api/unprotected/route.ts",
        `
        export async function POST(req: Request) {
          const body = await req.json();
          return Response.json({ status: "processed", data: body });
        }
        `,
      ],
      [
        "app/actions/insecure.ts",
        `
        "use server";

        export async function wipeDatabase() {
          console.log("Wiping database without auth check!");
          return { wiped: true };
        }
        `,
      ],
      [
        "app/components/UnprotectedClient.tsx",
        `
        "use client";

        export default function UnprotectedButton() {
          return <button onClick={() => alert("clicked")}>Click Me</button>;
        }
        `,
      ],
    ]);

    const result = analyzeNextjsAppRouter(vulnerableFiles, catalog);

    expect(result.middlewareInfo?.authGuardStatus).toBe("unguarded");

    const routeHandler = result.entryPoints.find((e) => e.kind === "route-handler");
    expect(routeHandler?.authGuardStatus).toBe("unguarded");
    expect(routeHandler?.isUnresolved).toBe(false);

    const serverAction = result.entryPoints.find((e) => e.kind === "server-action");
    expect(serverAction?.authGuardStatus).toBe("unguarded");
    expect(serverAction?.isUnresolved).toBe(false);

    const clientBoundary = result.entryPoints.find((e) => e.kind === "client-boundary");
    expect(clientBoundary?.authGuardStatus).toBe("unguarded");
    expect(clientBoundary?.isUnresolved).toBe(false);
  });

  it("should record UNRESOLVED cases for dynamic imports, unknown wrappers, and dynamic middleware logic", () => {
    const mutatedFiles = new Map<string, string>([
      [
        "app/api/dynamic-import/route.ts",
        `
        export async function GET(req: Request) {
          // Dynamic import cannot be statically verified
          const authLib = await import("./dynamic-auth-loader");
          authLib.checkCustomAuth(req);
          return Response.json({ status: "ok" });
        }
        `,
      ],
      [
        "app/api/unknown-wrapper/route.ts",
        `
        import { withObfuscatedAuth } from "@/lib/secret-framework";

        export const POST = withObfuscatedAuth(async (req: Request) => {
          return Response.json({ status: "ok" });
        });
        `,
      ],
      [
        "app/actions/dynamic-action.ts",
        `
        "use server";

        export async function dynamicServerAction() {
          const module = await import("../security/vault");
          module.decrypt();
          return { data: "vault" };
        }
        `,
      ],
    ]);

    const result = analyzeNextjsAppRouter(mutatedFiles, catalog);

    // 1. Dynamic import handler
    const dynamicHandler = result.entryPoints.find(
      (e) => e.filePath === "app/api/dynamic-import/route.ts"
    );
    expect(dynamicHandler).toBeDefined();
    expect(dynamicHandler?.authGuardStatus).toBe("unresolved");
    expect(dynamicHandler?.isUnresolved).toBe(true);
    expect(dynamicHandler?.unresolvedReason).toContain("Dynamic import");

    // 2. Unknown wrapper handler
    const unknownWrapperHandler = result.entryPoints.find(
      (e) => e.filePath === "app/api/unknown-wrapper/route.ts"
    );
    expect(unknownWrapperHandler).toBeDefined();
    expect(unknownWrapperHandler?.authGuardStatus).toBe("unresolved");
    expect(unknownWrapperHandler?.isUnresolved).toBe(true);
    expect(unknownWrapperHandler?.unresolvedReason).toContain(
      "Unknown wrapper function 'withObfuscatedAuth'"
    );

    // 3. Dynamic server action
    const dynamicAction = result.entryPoints.find(
      (e) => e.filePath === "app/actions/dynamic-action.ts"
    );
    expect(dynamicAction).toBeDefined();
    expect(dynamicAction?.authGuardStatus).toBe("unresolved");
    expect(dynamicAction?.isUnresolved).toBe(true);
    expect(dynamicAction?.unresolvedReason).toContain("Dynamic import");
  });

  it("should propagate middleware unresolved status to route handlers on matched paths", () => {
    const files = new Map<string, string>([
      [
        "middleware.ts",
        `
        export async function middleware(req) {
          const dyn = await import("./dynamic-guard");
          return dyn.verify(req);
        }

        export const config = {
          matcher: "/api/:path*",
        };
        `,
      ],
      [
        "app/api/data/route.ts",
        `
        export async function GET(req: Request) {
          return Response.json({ items: [] });
        }
        `,
      ],
    ]);

    const result = analyzeNextjsAppRouter(files, catalog);

    expect(result.middlewareInfo?.authGuardStatus).toBe("unresolved");
    expect(result.middlewareInfo?.isUnresolved).toBe(true);

    const handler = result.entryPoints.find((e) => e.kind === "route-handler");
    expect(handler).toBeDefined();
    expect(handler?.authGuardStatus).toBe("unresolved");
    expect(handler?.isUnresolved).toBe(true);
    expect(handler?.unresolvedReason).toContain(
      "Middleware on path has unresolved auth guard status"
    );
  });
});
