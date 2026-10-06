"use client";
import Stripe from "stripe";

const stripe = new Stripe("sk_test_FAKEFAKEFAKE_CLIENT_SECRET_KEY_12345");

export function PaymentForm() {
  return <div>Payment Form</div>;
}
