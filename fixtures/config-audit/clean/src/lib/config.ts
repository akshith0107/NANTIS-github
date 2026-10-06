import { NextResponse } from "next/server";

export function setSessionCookie(res: NextResponse, token: string) {
  res.cookies.set("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
}

export function setCorsHeaders(res: NextResponse) {
  res.headers.set("Access-Control-Allow-Origin", "https://app.example.com");
}

export const debugConfig = { debug: false, NODE_ENV: "production" };
