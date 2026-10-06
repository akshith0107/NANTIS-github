import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { updateRecordInDb } from "../../../services/db.js";

export async function PUT(req: Request) {
  const session = await getServerSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const payload = await req.json();
  const result = await updateRecordInDb("users", payload);
  return NextResponse.json({ result });
}
