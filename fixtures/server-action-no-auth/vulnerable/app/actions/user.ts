"use server";
import { createClient } from "@supabase/supabase-js";

export async function updateUserEmail(newEmail: string) {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );
  await supabase.from("users").update({ email: newEmail });
  return { success: true };
}
