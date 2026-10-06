import { NextResponse } from "next/server";
import { fetchAllUserData } from "../../../services/db.js";

export async function POST() {
  const records = await fetchAllUserData();
  return NextResponse.json({ records });
}
