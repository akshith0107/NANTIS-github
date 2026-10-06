import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    // Process payment without checking stripe-signature header or constructEvent
  }
  return NextResponse.json({ received: true });
}
