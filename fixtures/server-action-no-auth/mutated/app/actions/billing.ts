"use server";

export async function cancelSubscription(subscriptionId: string) {
  // Missing auth check before database operation
  const db = getDbClient();
  await db.subscriptions.delete(subscriptionId);
  return { canceled: true };
}
