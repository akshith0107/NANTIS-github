import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const data = await req.json();
  const sig = req.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(data as any, sig, process.env.WEBHOOK_SECRET!);
  return Response.json({ status: "ok" });
}
