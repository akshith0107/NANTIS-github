import crypto from "crypto";

/**
 * Verify GitHub webhook HMAC-SHA256 signature (X-Hub-Signature-256)
 * Signature MUST be verified against raw request body BEFORE parsing payload.
 */
export function verifyGitHubWebhookSignature(
  rawBody: string | Buffer,
  signatureHeader: string | null | undefined,
  webhookSecret: string
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
    return false;
  }

  const expectedSignatureHex = signatureHeader.slice(7).trim();
  const computedSignatureHex = crypto
    .createHmac("sha256", webhookSecret)
    .update(rawBody)
    .digest("hex");

  const expectedBuffer = Buffer.from(expectedSignatureHex, "hex");
  const computedBuffer = Buffer.from(computedSignatureHex, "hex");

  if (expectedBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, computedBuffer);
}
