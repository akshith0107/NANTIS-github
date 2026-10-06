import crypto from "crypto";

export interface InstallationAccessToken {
  token: string;
  expires_at: string;
}

/**
 * Generate a signed RS256 JWT for GitHub App authentication
 */
export function generateGitHubAppJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60, // Issued 60 seconds in the past to handle clock drift
    exp: now + 600, // Valid for 10 minutes maximum
    iss: appId,
  };

  const header = { alg: "RS256", typ: "JWT" };

  const encodeBase64Url = (obj: object) => Buffer.from(JSON.stringify(obj)).toString("base64url");

  const unsignedToken = `${encodeBase64Url(header)}.${encodeBase64Url(payload)}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);
  const signature = signer.sign(privateKeyPem, "base64url");

  return `${unsignedToken}.${signature}`;
}

// In-memory cache for short-lived Installation Access Tokens (never written to DB or disk)
const iatMemoryCache = new Map<number, { token: string; expiresAtMs: number }>();

/**
 * Evicts expired tokens from the in-memory cache.
 */
export function evictExpiredTokens(nowMs: number = Date.now()): void {
  for (const [id, entry] of iatMemoryCache.entries()) {
    if (entry.expiresAtMs <= nowMs) {
      iatMemoryCache.delete(id);
    }
  }
}

let cleanupInterval: NodeJS.Timeout | null = null;

/**
 * Starts a periodic interval to sweep and delete expired tokens.
 * Uses .unref() so it does not block Node process exit.
 */
export function startCacheCleanupInterval(intervalMs = 5 * 60 * 1000): void {
  if (cleanupInterval) return;
  cleanupInterval = setInterval(() => {
    evictExpiredTokens();
  }, intervalMs);
  cleanupInterval.unref?.();
}

// Start periodic cleanup interval automatically
startCacheCleanupInterval();

/**
 * Mint an Installation Access Token (IAT) on demand for a given installation ID.
 * Kept strictly in memory with 50-minute maximum lifespan.
 */
export async function getInstallationAccessToken(
  installationId: number,
  appId: string,
  privateKeyPem: string,
  fetchFn: typeof fetch = fetch
): Promise<string> {
  const cached = iatMemoryCache.get(installationId);
  const nowMs = Date.now();

  if (cached) {
    if (cached.expiresAtMs <= nowMs) {
      iatMemoryCache.delete(installationId);
    } else if (cached.expiresAtMs - nowMs > 5 * 60 * 1000) {
      return cached.token;
    }
  }

  const appJwt = generateGitHubAppJwt(appId, privateKeyPem);

  const response = await fetchFn(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "NANTIS-App",
      },
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to mint Installation Access Token for installation ${installationId}: HTTP ${response.status}`
    );
  }

  const data = (await response.json()) as InstallationAccessToken;
  const expiresAtMs = new Date(data.expires_at).getTime();

  // Store ONLY in volatile memory cache
  iatMemoryCache.set(installationId, {
    token: data.token,
    expiresAtMs,
  });

  return data.token;
}

export function clearInstallationTokenCache(): void {
  iatMemoryCache.clear();
}

export function setIatCacheToken(installationId: number, token: string, expiresAtMs: number): void {
  iatMemoryCache.set(installationId, { token, expiresAtMs });
}

export function getIatCacheSize(): number {
  return iatMemoryCache.size;
}
