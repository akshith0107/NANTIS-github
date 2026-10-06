import { createClient } from "@supabase/supabase-js";

export async function fetchAllUserData() {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );
  const { data } = await supabase.from("users").select("*");
  return data;
}
