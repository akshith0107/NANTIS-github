"use client";
import { createClient } from "@supabase/supabase-js";

export default function AdminPanel() {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );

  return <div>Admin Panel Client Component</div>;
}
