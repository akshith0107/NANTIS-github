import { stripe } from "@/lib/stripe";
export async function POST(req) {
  const body = await req.json();
  return new Response("OK");
}
