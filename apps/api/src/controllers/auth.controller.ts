import type { Context } from "hono";
import { AuthService, getCookie, getCookieConfig } from "@peek/auth";
import type { AppEnv } from "../types.js";
import { respondSuccess } from "../helpers/respond.js";

export async function initiateGitHubLogin(
  c: Context<AppEnv>,
): Promise<Response> {
  const env = c.get("env");
  const logger = c.get("logger");
  const { url, stateCookie } = AuthService.initiateGitHubOAuth(env);

  logger?.info("Initiating GitHub OAuth redirect", {
    redirectTarget: "https://github.com/login/oauth/authorize",
  });

  c.header("Set-Cookie", stateCookie);
  return c.redirect(url, 302);
}

export async function handleGitHubCallback(
  c: Context<AppEnv>,
): Promise<Response> {
  const env = c.get("env");
  const db = c.get("db");
  const logger = c.get("logger");

  if (!db) {
    throw new Error("Database is not initialized on request");
  }

  const code = c.req.query("code");
  const state = c.req.query("state");
  const installationId = c.req.query("installation_id");
  const cookieHeader = c.req.header("cookie");
  const savedState = getCookie(cookieHeader, "peek_oauth_state");

  const userAgent = c.req.header("user-agent");
  const ipAddress =
    c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for");

  logger?.info("Processing GitHub OAuth callback", {
    hasCode: Boolean(code),
    hasState: Boolean(state),
    installationId: installationId ?? null,
  });

  const { user, cookies, redirectUrl } = await AuthService.handleGitHubCallback(
    {
      db,
      env,
      code,
      state,
      savedState,
      installationId,
      userAgent,
      ipAddress,
    },
  );

  logger?.info("GitHub OAuth authentication successful", {
    userId: user.id,
    username: user.username,
    role: user.role,
  });

  for (const cookie of cookies) {
    c.header("Set-Cookie", cookie, { append: true });
  }

  if (redirectUrl) {
    return c.redirect(redirectUrl, 302);
  }

  return respondSuccess(c, {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      role: user.role,
    },
    message: "Authenticated successfully",
  });
}

export async function refreshToken(c: Context<AppEnv>): Promise<Response> {
  const env = c.get("env");
  const db = c.get("db");
  const logger = c.get("logger");

  if (!db) {
    throw new Error("Database is not initialized on request");
  }

  const cookieConfig = getCookieConfig(env);
  const cookieHeader = c.req.header("cookie");
  const rawRefreshToken = getCookie(cookieHeader, cookieConfig.refreshName);

  const userAgent = c.req.header("user-agent");
  const ipAddress =
    c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for");

  const { cookies } = await AuthService.refreshSession({
    db,
    env,
    rawRefreshToken,
    userAgent,
    ipAddress,
  });

  logger?.info("Session refreshed and rotated successfully");

  for (const cookie of cookies) {
    c.header("Set-Cookie", cookie, { append: true });
  }

  return respondSuccess(c, {
    message: "Token rotated and refreshed successfully",
  });
}

export async function logout(c: Context<AppEnv>): Promise<Response> {
  const env = c.get("env");
  const db = c.get("db");
  const logger = c.get("logger");

  const cookieConfig = getCookieConfig(env);
  const cookieHeader = c.req.header("cookie");
  const rawRefreshToken = getCookie(cookieHeader, cookieConfig.refreshName);

  const { clearCookies } = await AuthService.logout({
    db,
    env,
    rawRefreshToken,
  });

  logger?.info("User session logged out and cleared");

  for (const cookie of clearCookies) {
    c.header("Set-Cookie", cookie, { append: true });
  }

  return respondSuccess(c, {
    message: "Logged out successfully",
  });
}

export async function getMe(c: Context<AppEnv>): Promise<Response> {
  const user = c.get("user");
  return respondSuccess(c, { user });
}
