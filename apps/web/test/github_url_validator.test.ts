import { describe, expect, it } from "vitest";
import { parseAndValidateGitHubUrl } from "../src/lib/url-validator.js";

describe("parseAndValidateGitHubUrl", () => {
  it("accepts valid https://github.com/owner/repo URLs", () => {
    const res = parseAndValidateGitHubUrl("https://github.com/expressjs/express");
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.data.owner).toBe("expressjs");
      expect(res.data.repo).toBe("express");
      expect(res.data.fullName).toBe("expressjs/express");
      expect(res.data.cloneUrl).toBe("https://github.com/expressjs/express.git");
      expect(res.data.canonicalUrl).toBe("https://github.com/expressjs/express");
    }
  });

  it("handles URLs ending with .git and trailing slashes", () => {
    const res = parseAndValidateGitHubUrl("https://github.com/owner/my-repo.git/");
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.data.owner).toBe("owner");
      expect(res.data.repo).toBe("my-repo");
    }
  });

  it("accepts www.github.com domain", () => {
    const res = parseAndValidateGitHubUrl("https://www.github.com/owner/repo");
    expect(res.valid).toBe(true);
  });

  it("rejects non-https protocols", () => {
    expect(parseAndValidateGitHubUrl("http://github.com/owner/repo").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("git://github.com/owner/repo").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("ssh://git@github.com:owner/repo").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("file:///C:/Users/secret").valid).toBe(false);
  });

  it("rejects embedded credentials in URL", () => {
    const res = parseAndValidateGitHubUrl("https://admin:secret@github.com/owner/repo");
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.error).toContain("credentials");
    }
  });

  it("rejects non-github hostnames and IPs", () => {
    expect(parseAndValidateGitHubUrl("https://gitlab.com/owner/repo").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("https://192.168.1.1/owner/repo").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("https://github.com.evil.com/owner/repo").valid).toBe(false);
  });

  it("rejects URLs missing repository or owner", () => {
    expect(parseAndValidateGitHubUrl("https://github.com/owner").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("https://github.com/").valid).toBe(false);
  });

  it("rejects path traversal and invalid characters", () => {
    expect(parseAndValidateGitHubUrl("https://github.com/../etc").valid).toBe(false);
    expect(parseAndValidateGitHubUrl("https://github.com/owner/..").valid).toBe(false);
  });
});
