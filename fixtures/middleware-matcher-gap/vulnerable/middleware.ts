import { NextResponse } from "next/server";

export function middleware(req: any) {
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/public/:path*"],
};
