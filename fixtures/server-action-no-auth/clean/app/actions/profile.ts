"use server";
import { assertRepoAccess } from "@/lib/auth";

export async function updateUserProfile(profileData: any) {
  await assertRepoAccess("user-123", "repo-456");
  return { updated: true };
}
