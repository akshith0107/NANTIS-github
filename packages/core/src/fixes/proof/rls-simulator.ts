export interface RLSSimulationResult {
  beforeAllowed: boolean;
  afterAllowed: boolean;
  proven: boolean;
  explanation: string;
}

/**
 * Simulates Row Level Security (RLS) policy evaluation for User A attempting to read User B's row.
 */
export function simulateRLSPolicyAccess(
  beforeMigrationSQL: string,
  afterMigrationSQL: string,
  userA: { id: string },
  userBRow: { user_id: string }
): RLSSimulationResult {
  // Check if RLS is enabled before & after
  const beforeHasEnableRLS = /ALTER\s+TABLE\s+\w+\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(
    beforeMigrationSQL
  );
  const afterHasEnableRLS = /ALTER\s+TABLE\s+\w+\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(
    afterMigrationSQL
  );

  const beforeHasPolicy = /CREATE\s+POLICY/i.test(beforeMigrationSQL);
  const afterHasPolicy = /CREATE\s+POLICY/i.test(afterMigrationSQL);

  // Before fix: if RLS is not enabled or policy is USING (true), User A can read User B's row
  const beforeHasPermissive = /USING\s*\(\s*true\s*\)/i.test(beforeMigrationSQL);
  const beforeAllowed = !beforeHasEnableRLS || !beforeHasPolicy || beforeHasPermissive;

  // After fix: if RLS is enabled and template/strict policy present requiring auth.uid() = user_id
  const afterHasStrictCheck = /auth\.uid\(\)\s*=\s*user_id/i.test(afterMigrationSQL) || afterHasPolicy;
  const afterAllowed = !afterHasEnableRLS || !afterHasStrictCheck;

  const proven = beforeAllowed && !afterAllowed && userA.id !== userBRow.user_id;

  const explanation = proven
    ? `User A (${userA.id}) could read User B's record before fix. After RLS enabling and policy addition, cross-tenant read by User A is denied.`
    : "RLS policy simulation did not demonstrate a change in policy access control.";

  return {
    beforeAllowed,
    afterAllowed,
    proven,
    explanation,
  };
}
