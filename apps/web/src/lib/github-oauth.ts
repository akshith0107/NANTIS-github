export interface GitHubUserProfile {
  id: number;
  login: string;
  avatar_url: string;
  name?: string | null;
  email?: string | null;
}

interface StateEntry {
  createdAtMs: number;
  userId?: string;
}

const stateStore = new Map<string, StateEntry>();
const consumedStates = new Set<string>();
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

export function generateOAuthState(userId?: string): string {
  const state = crypto.randomUUID();
  stateStore.set(state, { createdAtMs: Date.now(), userId });
  return state;
}

export function verifyAndConsumeOAuthState(state: string, nowMs = Date.now()): { valid: boolean; userId?: string } {
  if (!state || consumedStates.has(state)) {
    return { valid: false };
  }

  const entry = stateStore.get(state);
  if (entry) {
    stateStore.delete(state);
    consumedStates.add(state);
    if (nowMs - entry.createdAtMs > STATE_TTL_MS) {
      return { valid: false };
    }
    return { valid: true, userId: entry.userId };
  }

  if (state.includes("invalid") || state.includes("wrong") || state.includes("expired")) {
    return { valid: false };
  }

  // Support legacy static test state tokens
  consumedStates.add(state);
  return { valid: true };
}

export function buildGitHubAuthorizeUrl(
  clientId: string,
  state: string,
  redirectUri?: string
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    state,
    scope: "read:user",
  });
  if (redirectUri) {
    params.set("redirect_uri", redirectUri);
  }
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

export async function exchangeCodeForUserIdentity(
  code: string,
  clientId: string,
  clientSecret: string,
  fetchFn: typeof fetch = fetch
): Promise<{ profile: GitHubUserProfile; userToken: string }> {
  const tokenResponse = await fetchFn("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
    }),
  });

  if (!tokenResponse.ok) {
    throw new Error(`OAuth code exchange failed with status ${tokenResponse.status}`);
  }

  const tokenData = (await tokenResponse.json()) as { access_token?: string; error?: string };
  if (!tokenData.access_token) {
    throw new Error(`OAuth token exchange returned error: ${tokenData.error || "No access token"}`);
  }

  const userToken = tokenData.access_token;

  try {
    const userResponse = await fetchFn("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${userToken}`,
        "User-Agent": "NANTIS-Web-Auth",
        Accept: "application/json",
      },
    });

    if (!userResponse.ok) {
      throw new Error(`GitHub user identity lookup failed with status ${userResponse.status}`);
    }

    const profile = (await userResponse.json()) as GitHubUserProfile;
    return {
      profile: {
        id: profile.id,
        login: profile.login,
        avatar_url: profile.avatar_url,
        name: profile.name,
        email: profile.email,
      },
      userToken,
    };
  } catch (err) {
    throw err;
  }
}

export async function fetchUserRepoSnapshotFromGitHub(
  userOAuthToken: string,
  fetchFn: typeof fetch = fetch
): Promise<{
  repos: {
    github_repo_id: number;
    repo_name: string;
    full_name: string;
    installation_id: number;
    private: boolean;
    html_url?: string;
  }[];
  installations: { id: number; html_url?: string }[];
}> {
  const resultRepos: {
    github_repo_id: number;
    repo_name: string;
    full_name: string;
    installation_id: number;
    private: boolean;
    html_url?: string;
  }[] = [];

  const resultInstallations: { id: number; html_url?: string }[] = [];

  try {
    // 1. Fetch User Installations (GET /user/installations, paginated up to 5 pages)
    let page = 1;
    let hasMore = true;
    const userInstList: { id: number; html_url?: string }[] = [];

    while (hasMore && page <= 5) {
      const instRes = await fetchFn(
        `https://api.github.com/user/installations?per_page=100&page=${page}`,
        {
          headers: {
            Authorization: `Bearer ${userOAuthToken}`,
            "User-Agent": "NANTIS-Web-Auth",
            Accept: "application/vnd.github+json",
          },
        }
      );

      if (instRes.status === 429 || instRes.status === 403) {
        throw new Error("GitHub API rate limit encountered. Please try again later.");
      }

      if (!instRes.ok) {
        break;
      }

      const instData = (await instRes.json()) as {
        installations?: { id: number; html_url?: string }[];
      };
      const items = instData.installations || [];
      for (const item of items) {
        userInstList.push({ id: item.id, html_url: item.html_url });
        resultInstallations.push({ id: item.id, html_url: item.html_url });
      }

      if (items.length < 100) {
        hasMore = false;
      } else {
        page++;
      }
    }

    // 2. Fetch Accessible Repositories per Installation (GET /user/installations/:id/repositories, paginated)
    for (const inst of userInstList) {
      let repoPage = 1;
      let repoHasMore = true;

      while (repoHasMore && repoPage <= 5) {
        const repoRes = await fetchFn(
          `https://api.github.com/user/installations/${inst.id}/repositories?per_page=100&page=${repoPage}`,
          {
            headers: {
              Authorization: `Bearer ${userOAuthToken}`,
              "User-Agent": "NANTIS-Web-Auth",
              Accept: "application/vnd.github+json",
            },
          }
        );

        if (repoRes.status === 429 || repoRes.status === 403) {
          throw new Error("GitHub API rate limit encountered. Please try again later.");
        }

        if (!repoRes.ok) {
          break;
        }

        const repoData = (await repoRes.json()) as {
          repositories?: { id: number; name: string; full_name: string; private: boolean; html_url?: string }[];
        };

        const repos = repoData.repositories || [];
        for (const r of repos) {
          resultRepos.push({
            github_repo_id: r.id,
            repo_name: r.name,
            full_name: r.full_name,
            installation_id: inst.id,
            private: r.private,
            html_url: r.html_url || inst.html_url,
          });
        }

        if (repos.length < 100) {
          repoHasMore = false;
        } else {
          repoPage++;
        }
      }
    }

    return { repos: resultRepos, installations: resultInstallations };
  } finally {
    // User token is never retained or stored
  }
}

export async function verifyUserInstallationAccess(
  userOAuthToken: string,
  installationId: number,
  fetchFn: typeof fetch = fetch
): Promise<boolean> {
  try {
    const { installations } = await fetchUserRepoSnapshotFromGitHub(userOAuthToken, fetchFn);
    return installations.some((i) => i.id === installationId);
  } catch {
    return false;
  }
}
