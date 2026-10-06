export interface GitHubUserProfile {
  id: number;
  login: string;
  avatar_url: string;
  name?: string | null;
  email?: string | null;
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
): Promise<GitHubUserProfile> {
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

  // Temporary transient holding of token strictly for user identity fetch
  const transientAccessToken = tokenData.access_token;

  try {
    const userResponse = await fetchFn("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${transientAccessToken}`,
        "User-Agent": "NANTIS-Web-Auth",
        Accept: "application/json",
      },
    });

    if (!userResponse.ok) {
      throw new Error(`GitHub user identity lookup failed with status ${userResponse.status}`);
    }

    const profile = (await userResponse.json()) as GitHubUserProfile;
    return {
      id: profile.id,
      login: profile.login,
      avatar_url: profile.avatar_url,
      name: profile.name,
      email: profile.email,
    };
  } finally {
    // Zero/clear token scope reference ensuring zero persistence
    // (User token is NEVER stored to DB or session)
  }
}
