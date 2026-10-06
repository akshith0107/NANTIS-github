import { NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const rawText = await req.text();
  const sig = req.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(rawText, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  return NextResponse.json({ received: true });
}
