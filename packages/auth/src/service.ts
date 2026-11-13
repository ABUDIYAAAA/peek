import { BadRequestError, UnauthorizedError, type BaseEnv } from "@peek/core";
import type { Database, User } from "@peek/db";
import {
  getGitHubAuthorizeUrl,
  exchangeGitHubCode,
  fetchGitHubProfile,
  fetchGitHubPrimaryEmail,
  fetchGitHubInstallations,
} from "./github.js";
import {
  storeGitHubAccount,
  storeGitHubInstallation,
  syncUserInstallations,
} from "./github-storage.js";
import {
  syncUserFromGitHub,
  createSession,
  validateAndRotateSession,
  revokeSession,
} from "./session.js";
import { signAccessToken } from "./jwt.js";
import {
  getCookieConfig,
  createAuthCookies,
  clearAuthCookies,
  createStateCookie,
  clearStateCookie,
} from "./cookies.js";

export interface InitiateGitHubOAuthResult {
  url: string;
  stateCookie: string;
}

export interface HandleGitHubCallbackParams {
  db: Database;
  env: BaseEnv;
  code: string | undefined;
  state: string | undefined;
  savedState: string | null;
  installationId?: string;
  userAgent?: string;
  ipAddress?: string;
}

export interface HandleGitHubCallbackResult {
  user: User;
  cookies: string[];
  redirectUrl?: string;
}

export interface RefreshSessionParams {
  db: Database;
  env: BaseEnv;
  rawRefreshToken: string | null;
  userAgent?: string;
  ipAddress?: string;
}

export interface RefreshSessionResult {
  cookies: string[];
}

export interface LogoutParams {
  db?: Database;
  env: BaseEnv;
  rawRefreshToken: string | null;
}

export interface LogoutResult {
  clearCookies: string[];
}

export class AuthService {
  static initiateGitHubOAuth(env: BaseEnv): InitiateGitHubOAuthResult {
    const clientId = env.GITHUB_CLIENT_ID;
    if (!clientId || clientId === "mock_github_client_id") {
      console.warn("[AUTH] GITHUB_CLIENT_ID is using default mock value.");
    }

    const redirectUri =
      env.GITHUB_REDIRECT_URI || `${env.APP_URL}/api/v1/auth/github/callback`;
    const state = crypto.randomUUID();
    const stateCookie = createStateCookie(
      state,
      env.ENVIRONMENT === "production",
    );

    const url = getGitHubAuthorizeUrl({
      clientId,
      redirectUri,
      state,
    });

    return { url, stateCookie };
  }

  static async handleGitHubCallback(
    params: HandleGitHubCallbackParams,
  ): Promise<HandleGitHubCallbackResult> {
    const {
      db,
      env,
      code,
      state,
      savedState,
      installationId,
      userAgent,
      ipAddress,
    } = params;

    // 1. Verify CSRF state
    if (!state || !savedState || state !== savedState) {
      throw new BadRequestError(
        "Invalid or expired OAuth state parameter (CSRF protection failed)",
      );
    }

    if (!code) {
      throw new BadRequestError("Missing authorization code from GitHub");
    }

    const clientId = env.GITHUB_CLIENT_ID;
    const clientSecret = env.GITHUB_CLIENT_SECRET;
    const redirectUri =
      env.GITHUB_REDIRECT_URI || `${env.APP_URL}/api/v1/auth/github/callback`;

    // 2. Exchange code for GitHub tokens (both access_token and refresh_token)
    const gitHubTokens = await exchangeGitHubCode({
      clientId,
      clientSecret,
      code,
      redirectUri,
    });

    // 3. Fetch GitHub Profile & verified email
    const profile = await fetchGitHubProfile(gitHubTokens.accessToken);
    const primaryEmail =
      profile.email ??
      (await fetchGitHubPrimaryEmail(gitHubTokens.accessToken)) ??
      `${profile.login}@users.noreply.github.com`;

    // 4. Upsert user in D1 (preserve elevated roles on subsequent logins)
    const user = await syncUserFromGitHub(db, profile, primaryEmail);

    // 5. Store GitHub account tokens encrypted at rest (AES-256-GCM)
    await storeGitHubAccount(
      db,
      user.id,
      profile,
      gitHubTokens,
      env.ENCRYPTION_SECRET,
    );

    // 6. Discover & store GitHub App installations for this user
    try {
      const rawInstallations = await fetchGitHubInstallations(
        gitHubTokens.accessToken,
      );
      if (rawInstallations.length > 0) {
        await syncUserInstallations(db, user.id, rawInstallations);
      } else if (installationId) {
        // Fallback if installation_id was passed via query params during app install flow
        await storeGitHubInstallation(db, user.id, {
          id: parseInt(installationId, 10) || 0,
          account: {
            id: profile.id,
            login: profile.login,
            type: "User",
            avatar_url: profile.avatar_url,
          },
          repository_selection: "all",
          permissions: {},
        });
      }
    } catch (err) {
      console.warn("[AUTH] Could not fetch GitHub installations:", err);
    }

    // 7. Create Peek internal D1 session (HMAC-keyed with separate REFRESH_TOKEN_SECRET)
    const accessSecret = env.JWT_ACCESS_SECRET;
    const refreshSecret = env.REFRESH_TOKEN_SECRET;

    const session = await createSession(db, user.id, refreshSecret, {
      userAgent,
      ipAddress,
      duration: env.REFRESH_TOKEN_EXPIRY,
    });

    // 8. Sign Peek JWT access token with separate JWT_ACCESS_SECRET
    const accessToken = await signAccessToken(
      {
        id: user.id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      accessSecret,
      env.ACCESS_TOKEN_EXPIRY,
    );

    // 9. Generate HTTP-only cookies
    const cookieConfig = getCookieConfig(env);
    const [accessCookie, refreshCookie] = createAuthCookies(
      { accessToken, refreshToken: session.rawRefreshToken },
      cookieConfig,
    );
    const stateClearCookie = clearStateCookie(env.ENVIRONMENT === "production");

    return {
      user,
      cookies: [accessCookie, refreshCookie, stateClearCookie],
      redirectUrl: env.FRONTEND_URL || undefined,
    };
  }

  static async refreshSession(
    params: RefreshSessionParams,
  ): Promise<RefreshSessionResult> {
    const { db, env, rawRefreshToken, userAgent, ipAddress } = params;

    if (!rawRefreshToken) {
      throw new UnauthorizedError("Missing refresh cookie");
    }

    const accessSecret = env.JWT_ACCESS_SECRET;
    const refreshSecret = env.REFRESH_TOKEN_SECRET;

    // Validate and rotate in D1 using REFRESH_TOKEN_SECRET
    const { user, newRefreshToken } = await validateAndRotateSession(
      db,
      rawRefreshToken,
      refreshSecret,
      {
        userAgent,
        ipAddress,
        duration: env.REFRESH_TOKEN_EXPIRY,
      },
    );

    // Sign new access token using JWT_ACCESS_SECRET
    const newAccessToken = await signAccessToken(
      {
        id: user.id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      accessSecret,
      env.ACCESS_TOKEN_EXPIRY,
    );

    // Build new cookies
    const cookieConfig = getCookieConfig(env);
    const [accessCookie, refreshCookie] = createAuthCookies(
      { accessToken: newAccessToken, refreshToken: newRefreshToken },
      cookieConfig,
    );

    return {
      cookies: [accessCookie, refreshCookie],
    };
  }

  static async logout(params: LogoutParams): Promise<LogoutResult> {
    const { db, env, rawRefreshToken } = params;

    if (db && rawRefreshToken) {
      const refreshSecret = env.REFRESH_TOKEN_SECRET;
      await revokeSession(db, rawRefreshToken, refreshSecret);
    }

    const cookieConfig = getCookieConfig(env);
    const clearCookies = clearAuthCookies(cookieConfig);

    return { clearCookies };
  }
}
