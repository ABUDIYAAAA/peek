import { BadRequestError, UnauthorizedError } from "@peek/core";
import type {
  GitHubUserProfile,
  GitHubEmailRecord,
  GitHubOAuthTokens,
  GitHubRawInstallation,
} from "./types.js";

export function getGitHubAuthorizeUrl(options: {
  clientId: string;
  redirectUri?: string;
  state: string;
  scope?: string;
}): string {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", options.clientId);
  if (options.redirectUri) {
    url.searchParams.set("redirect_uri", options.redirectUri);
  }
  url.searchParams.set("state", options.state);
  url.searchParams.set("scope", options.scope ?? "read:user user:email");
  return url.toString();
}

export async function exchangeGitHubCode(options: {
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri?: string;
}): Promise<GitHubOAuthTokens> {
  const body: Record<string, string> = {
    client_id: options.clientId,
    client_secret: options.clientSecret,
    code: options.code,
  };
  if (options.redirectUri) {
    body.redirect_uri = options.redirectUri;
  }

  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "Peek-Auth-Worker",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new BadRequestError(
      `Failed to exchange GitHub OAuth code (HTTP ${response.status})`,
    );
  }

  const data = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    refresh_token_expires_in?: number;
    scope?: string;
    token_type?: string;
    error?: string;
    error_description?: string;
  };

  if (data.error || !data.access_token) {
    throw new UnauthorizedError(
      data.error_description ||
        data.error ||
        "Failed to exchange GitHub authorization code",
    );
  }

  const now = Date.now();
  const accessTokenExpiresAt = data.expires_in
    ? new Date(now + data.expires_in * 1000)
    : undefined;
  const refreshTokenExpiresAt = data.refresh_token_expires_in
    ? new Date(now + data.refresh_token_expires_in * 1000)
    : undefined;

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
    scope: data.scope,
    tokenType: data.token_type ?? "bearer",
  };
}

export async function refreshGitHubToken(options: {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}): Promise<GitHubOAuthTokens> {
  const body: Record<string, string> = {
    client_id: options.clientId,
    client_secret: options.clientSecret,
    grant_type: "refresh_token",
    refresh_token: options.refreshToken,
  };

  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "Peek-Auth-Worker",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new BadRequestError(
      `Failed to refresh GitHub user token (HTTP ${response.status})`,
    );
  }

  const data = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    refresh_token_expires_in?: number;
    scope?: string;
    token_type?: string;
    error?: string;
    error_description?: string;
  };

  if (data.error || !data.access_token) {
    throw new UnauthorizedError(
      data.error_description || data.error || "Failed to refresh GitHub token",
    );
  }

  const now = Date.now();
  const accessTokenExpiresAt = data.expires_in
    ? new Date(now + data.expires_in * 1000)
    : undefined;
  const refreshTokenExpiresAt = data.refresh_token_expires_in
    ? new Date(now + data.refresh_token_expires_in * 1000)
    : undefined;

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
    scope: data.scope,
    tokenType: data.token_type ?? "bearer",
  };
}

export async function fetchGitHubProfile(
  accessToken: string,
): Promise<GitHubUserProfile> {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Peek-Auth-Worker",
    },
  });

  if (!response.ok) {
    throw new UnauthorizedError(
      `Failed to fetch GitHub profile (HTTP ${response.status})`,
    );
  }

  return (await response.json()) as GitHubUserProfile;
}

export async function fetchGitHubPrimaryEmail(
  accessToken: string,
): Promise<string | null> {
  const response = await fetch("https://api.github.com/user/emails", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Peek-Auth-Worker",
    },
  });

  if (!response.ok) {
    return null;
  }

  const emails = (await response.json()) as GitHubEmailRecord[];
  const primaryVerified = emails.find((e) => e.primary && e.verified);
  if (primaryVerified) {
    return primaryVerified.email;
  }

  const anyVerified = emails.find((e) => e.verified);
  if (anyVerified) {
    return anyVerified.email;
  }

  return emails[0]?.email ?? null;
}

export async function fetchGitHubInstallations(
  accessToken: string,
): Promise<GitHubRawInstallation[]> {
  const response = await fetch("https://api.github.com/user/installations", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Peek-Auth-Worker",
    },
  });

  if (!response.ok) {
    // If not a GitHub App or no installations scope, return empty gracefully
    return [];
  }

  const data = (await response.json()) as {
    total_count: number;
    installations: GitHubRawInstallation[];
  };

  return data.installations ?? [];
}
