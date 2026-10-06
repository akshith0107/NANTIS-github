export interface ValidatedGitHubUrl {
  owner: string;
  repo: string;
  fullName: string; // "owner/repo"
  cloneUrl: string; // "https://github.com/owner/repo.git"
  canonicalUrl: string; // "https://github.com/owner/repo"
}

export function parseAndValidateGitHubUrl(urlString: string): { valid: true; data: ValidatedGitHubUrl } | { valid: false; error: string } {
  if (!urlString || typeof urlString !== "string") {
    return { valid: false, error: "Repository URL is required." };
  }

  const trimmed = urlString.trim();

  // Basic format check before URL parsing
  if (!trimmed.toLowerCase().startsWith("https://")) {
    return { valid: false, error: "Only https:// GitHub URLs are allowed." };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: "Invalid URL syntax." };
  }

  // 1. Enforce HTTPS scheme
  if (parsed.protocol !== "https:") {
    return { valid: false, error: "Protocol must be https:" };
  }

  // 2. Enforce github.com host
  const host = parsed.hostname.toLowerCase();
  if (host !== "github.com" && host !== "www.github.com") {
    return { valid: false, error: "Only public repositories hosted on github.com are supported." };
  }

  // 3. Reject credentials in URL
  if (parsed.username || parsed.password) {
    return { valid: false, error: "URLs containing embedded credentials are not allowed." };
  }

  // 4. Reject non-standard port
  if (parsed.port && parsed.port !== "443") {
    return { valid: false, error: "Non-standard port is not allowed." };
  }

  // 5. Parse path segments
  const pathSegments = parsed.pathname
    .split("/")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (pathSegments.length < 2) {
    return { valid: false, error: "URL must include both owner and repository name (e.g. https://github.com/owner/repo)." };
  }

  let owner = pathSegments[0];
  let repo = pathSegments[1];

  // Strip trailing .git if present
  if (repo.toLowerCase().endsWith(".git")) {
    repo = repo.slice(0, -4);
  }

  // Validate owner and repo naming conventions
  const nameRegex = /^[a-zA-Z0-9_.-]{1,100}$/;
  if (!nameRegex.test(owner) || owner === "." || owner === "..") {
    return { valid: false, error: "Invalid GitHub owner/organization name." };
  }
  if (!nameRegex.test(repo) || repo === "." || repo === "..") {
    return { valid: false, error: "Invalid GitHub repository name." };
  }

  const fullName = `${owner}/${repo}`;
  const cloneUrl = `https://github.com/${owner}/${repo}.git`;
  const canonicalUrl = `https://github.com/${owner}/${repo}`;

  return {
    valid: true,
    data: {
      owner,
      repo,
      fullName,
      cloneUrl,
      canonicalUrl,
    },
  };
}
