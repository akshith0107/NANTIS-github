import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { getOrderById } from "../../../services/db.js";

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(req.url);
  const orderId = searchParams.get("orderId");
  const order = await getOrderById(orderId);
  return NextResponse.json({ order });
}
