import { NextResponse } from "next/server";

export function setSessionCookie(res: NextResponse, token: string) {
  res.cookies.set("session", token, { httpOnly: false });
}

export function setCorsHeaders(res: NextResponse) {
  res.headers.set("Access-Control-Allow-Origin", "*");
}

export const debugConfig = { debug: true, NODE_ENV: "development" };
