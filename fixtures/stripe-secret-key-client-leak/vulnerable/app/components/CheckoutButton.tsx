"use client";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export default function CheckoutButton() {
  return <button onClick={() => console.log("checkout")}>Checkout</button>;
}
