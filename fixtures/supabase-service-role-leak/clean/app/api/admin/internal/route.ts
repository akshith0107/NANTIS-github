import { assertRepoAccess } from "@/lib/auth";
import { createClient } from "@supabase/supabase-js";

export async function POST() {
  await assertRepoAccess("admin-1", "repo-1");
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
  return Response.json({ status: "ok" });
}
