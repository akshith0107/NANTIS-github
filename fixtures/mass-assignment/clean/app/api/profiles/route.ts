import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { z } from "zod";

const ProfileSchema = z.object({
  name: z.string(),
  bio: z.string().optional(),
});

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const json = await req.json();
  const parsed = ProfileSchema.parse(json);

  const supabase = getSupabaseClient();
  const { data } = await supabase.from("profiles").insert({
    name: parsed.name,
    bio: parsed.bio,
  });

  return NextResponse.json({ data });
}
