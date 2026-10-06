import { NextResponse } from "next/server";
import { assertRepoAccess } from "@/lib/auth";

export async function middleware(req: any) {
  await assertRepoAccess("user-123", "repo-456");
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*"],
};
