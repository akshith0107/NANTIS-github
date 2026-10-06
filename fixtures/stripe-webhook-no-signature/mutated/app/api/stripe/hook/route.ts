import { NextResponse } from "next/server";
import { parseIncomingEvent } from "../../../helpers/stripeParser.js";

export async function POST(request: Request) {
  const payload = await parseIncomingEvent(request);
  return NextResponse.json({ status: payload.type });
}
