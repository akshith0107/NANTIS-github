import { NextResponse } from "next/server";
import Stripe from "stripe";
import { getProductFromDb } from "@/lib/db";
import { assertRepoAccess } from "@/lib/auth";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  await assertRepoAccess("user-1", "checkout");
  const { productId } = await req.json();
  const dbProduct = await getProductFromDb(productId);

  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price: dbProduct.stripePriceId,
        quantity: 1,
      },
    ],
    mode: "payment",
    success_url: "https://example.com/success",
  });
  return NextResponse.json({ url: session.url });
}
