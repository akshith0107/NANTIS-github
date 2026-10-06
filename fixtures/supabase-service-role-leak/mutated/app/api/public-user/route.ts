import { createClient } from "@supabase/supabase-js";

export async function GET() {
  // Service role key used in public unauthenticated API route handler
  const adminSupabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );
  const { data } = await adminSupabase.from("users").select("*");
  return Response.json({ data });
}
