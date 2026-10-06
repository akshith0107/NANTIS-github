import crypto from "crypto";

export interface SessionData {
  userId: string;
  githubUserId: number;
  githubLogin: string;
  createdAt: number;
}

export interface CookieOptions {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Lax" | "Strict" | "None";
  path: string;
  maxAge?: number;
}

/**
 * Generate a cryptographically secure random state token for CSRF protection
 */
export function generateCsrfStateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Sign session payload string using HMAC-SHA256 with secret key
 */
export function signSessionPayload(payload: string, secret: string): string {
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${signature}`;
}

/**
 * Verify and decode signed session payload string
 */
export function verifySessionToken(token: string, secret: string): string | null {
  const lastDotIndex = token.lastIndexOf(".");
  if (lastDotIndex === -1) return null;

  const payload = token.slice(0, lastDotIndex);
  const signature = token.slice(lastDotIndex + 1);

  const expectedSignature = crypto.createHmac("sha256", secret).update(payload).digest("hex");

  const sigBuffer = Buffer.from(signature, "hex");
  const expBuffer = Buffer.from(expectedSignature, "hex");

  if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
    return null;
  }

  return payload;
}

/**
 * Encode session data into signed session cookie string
 */
export function encodeSession(session: SessionData, secret: string): string {
  const jsonPayload = Buffer.from(JSON.stringify(session)).toString("base64url");
  return signSessionPayload(jsonPayload, secret);
}

/**
 * Decode and verify signed session cookie
 */
export function decodeSession(token: string, secret: string): SessionData | null {
  const payload = verifySessionToken(token, secret);
  if (!payload) return null;

  try {
    const jsonStr = Buffer.from(payload, "base64url").toString("utf-8");
    return JSON.parse(jsonStr) as SessionData;
  } catch {
    return null;
  }
}

/**
 * Construct secure, HttpOnly, SameSite=Lax cookie options object
 */
export function buildSessionCookieOptions(
  sessionToken: string,
  isProduction = false
): CookieOptions {
  return {
    name: "nantis_session",
    value: sessionToken,
    httpOnly: true,
    secure: isProduction, // Strict HTTPS enforcement in production
    sameSite: "Lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 days
  };
}

/**
 * Serialize CookieOptions into HTTP Set-Cookie header string
 */
export function serializeCookie(options: CookieOptions): string {
  const parts = [`${options.name}=${options.value}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  return parts.join("; ");
}
