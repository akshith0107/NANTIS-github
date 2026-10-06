import Stripe from "stripe";
import { getPaymentKey } from "./helper.js";

export function createStripeClient() {
  const apiKey = getPaymentKey();
  return new Stripe(apiKey);
}
