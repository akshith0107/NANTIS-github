import { describe, expect, it } from "vitest";
import { escapeHtml, getDefaultHeaders, getOrCreateCsrfToken, validateCsrfToken } from "../src/routes/ui-templates.js";
import { RequestContext } from "../src/routes/api-routes.js";

describe("XSS and CSRF Security Protections", () => {
  describe("escapeHtml", () => {
    it("escapes dangerous HTML characters", () => {
      const malicious = '<script>alert("XSS & attack")</script>';
      const escaped = escapeHtml(malicious);
      expect(escaped).not.toContain("<script>");
      expect(escaped).toBe("&lt;script&gt;alert(&quot;XSS &amp; attack&quot;)&lt;/script&gt;");
    });

    it("handles null, undefined, and non-string inputs safely", () => {
      expect(escapeHtml(null)).toBe("");
      expect(escapeHtml(undefined)).toBe("");
      expect(escapeHtml(12345)).toBe("12345");
    });
  });

  describe("CSRF Protection", () => {
    it("generates and validates CSRF token for a user", () => {
      const userId = "test-user-csrf-123";
      const token = getOrCreateCsrfToken(userId);
      expect(token).toBeDefined();

      const validReq: RequestContext = {
        method: "POST",
        path: "/api/dev/scan-public-repo",
        headers: {},
        cookies: {},
        clientIp: "127.0.0.1",
        query: {},
        body: { _csrf: token },
      };

      expect(validateCsrfToken(validReq, userId)).toBe(true);
    });

    it("rejects request with invalid or missing CSRF token", () => {
      const userId = "test-user-csrf-123";

      const invalidReq: RequestContext = {
        method: "POST",
        path: "/api/dev/scan-public-repo",
        headers: {},
        cookies: {},
        clientIp: "127.0.0.1",
        query: {},
        body: { _csrf: "wrong-token" },
      };

      expect(validateCsrfToken(invalidReq, userId)).toBe(false);
    });
  });

  describe("HTTP Security Headers", () => {
    it("includes nosniff and frame-ancestors none in default headers", () => {
      const headers = getDefaultHeaders();
      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
      expect(headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    });
  });
});
