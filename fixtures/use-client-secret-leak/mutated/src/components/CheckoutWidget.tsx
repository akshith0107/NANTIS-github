"use client";

import { getClientStripeKey } from "../utils/stripeClient.js";

const key = getClientStripeKey();

export function CheckoutWidget() {
  return <div>Checkout {key.length}</div>;
}
