import { NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const { amount, currency } = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: currency || "usd",
          product_data: { name: "Custom Item" },
          unit_amount: amount,
        },
        quantity: 1,
      },
    ],
    mode: "payment",
    success_url: "https://example.com/success",
  });
  return NextResponse.json({ url: session.url });
}
