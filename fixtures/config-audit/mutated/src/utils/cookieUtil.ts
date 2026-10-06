import { NextResponse } from "next/server";

export const applyAuthCookie = (response: NextResponse, jwtToken: string) => {
  // Cookie helper missing httpOnly and secure flags
  response.cookies.set("auth_token", jwtToken, { sameSite: "none" });
};
