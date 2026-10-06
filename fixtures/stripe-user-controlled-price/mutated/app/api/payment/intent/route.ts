import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.json();
  const paymentIntent = await stripe.paymentIntents.create({
    amount: body.amount,
    currency: "usd",
  });
  return Response.json({ clientSecret: paymentIntent.client_secret });
}
