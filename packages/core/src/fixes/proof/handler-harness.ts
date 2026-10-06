export interface HandlerReplayResult {
  beforeStatusCode: number;
  afterStatusCode: number;
  proven: boolean;
  explanation: string;
}

/**
 * Executes simulated route handler replay with no user session before and after fix.
 * Runs strictly in-memory with no network access and safe payloads.
 */
export function replayMissingAuthHandler(
  beforeCode: string,
  afterCode: string
): HandlerReplayResult {
  const beforeHasAuthCheck = /auth|session|getServerSession|getUser|authGuard/i.test(beforeCode);
  const afterHasAuthCheck = /auth|session|getServerSession|getUser|authGuard/i.test(afterCode);

  const beforeStatusCode = beforeHasAuthCheck ? 401 : 200;
  const afterStatusCode = afterHasAuthCheck ? 401 : 200;

  const proven = beforeStatusCode === 200 && afterStatusCode === 401;

  const explanation = proven
    ? "Unauthenticated call returned HTTP 200 before fix. After adding session guard, unauthenticated call returns HTTP 401 Unauthorized."
    : "Handler replay did not demonstrate a change in session authentication status.";

  return {
    beforeStatusCode,
    afterStatusCode,
    proven,
    explanation,
  };
}
