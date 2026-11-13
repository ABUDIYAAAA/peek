import type { BaseEnv } from "@peek/core";
import type { CookieConfig } from "./types.js";
import { parseDurationToSeconds } from "./jwt.js";

export function getCookieConfig(env: BaseEnv): CookieConfig {
  const isProd = env.ENVIRONMENT === "production";
  const secure = env.COOKIE_SECURE !== undefined ? env.COOKIE_SECURE : isProd;

  return {
    accessName: env.COOKIE_ACCESS_NAME ?? "peek_access_token",
    refreshName: env.COOKIE_REFRESH_NAME ?? "peek_refresh_token",
    domain: env.COOKIE_DOMAIN || undefined,
    secure,
    sameSite: env.COOKIE_SAME_SITE ?? "lax",
    accessMaxAgeSeconds: parseDurationToSeconds(
      env.ACCESS_TOKEN_EXPIRY ?? "15m",
    ),
    refreshMaxAgeSeconds: parseDurationToSeconds(
      env.REFRESH_TOKEN_EXPIRY ?? "30d",
    ),
  };
}

export function serializeCookie(
  name: string,
  value: string,
  options: {
    maxAgeSeconds?: number;
    domain?: string;
    path?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: "lax" | "strict" | "none";
  } = {},
): string {
  const parts: string[] = [`${name}=${encodeURIComponent(value)}`];

  const path = options.path ?? "/";
  parts.push(`Path=${path}`);

  if (options.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${options.maxAgeSeconds}`);
    const expires = new Date(Date.now() + options.maxAgeSeconds * 1000);
    parts.push(`Expires=${expires.toUTCString()}`);
  }

  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }

  if (options.sameSite) {
    const s =
      options.sameSite.charAt(0).toUpperCase() +
      options.sameSite.slice(1).toLowerCase();
    parts.push(`SameSite=${s}`);
  }

  if (options.secure) {
    parts.push("Secure");
  }

  if (options.httpOnly !== false) {
    parts.push("HttpOnly");
  }

  return parts.join("; ");
}

export function parseCookies(
  cookieHeader: string | null | undefined,
): Record<string, string> {
  if (!cookieHeader) return {};

  const cookies: Record<string, string> = {};
  const pairs = cookieHeader.split(";");

  for (const pair of pairs) {
    const index = pair.indexOf("=");
    if (index === -1) continue;

    const key = pair.substring(0, index).trim();
    const val = pair.substring(index + 1).trim();
    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  }

  return cookies;
}

export function getCookie(
  cookieHeader: string | null | undefined,
  name: string,
): string | null {
  const cookies = parseCookies(cookieHeader);
  return cookies[name] ?? null;
}

export function createAuthCookies(
  tokens: { accessToken: string; refreshToken: string },
  config: CookieConfig,
): [accessCookie: string, refreshCookie: string] {
  const accessCookie = serializeCookie(config.accessName, tokens.accessToken, {
    maxAgeSeconds: config.accessMaxAgeSeconds,
    domain: config.domain,
    secure: config.secure,
    sameSite: config.sameSite,
    httpOnly: true,
  });

  const refreshCookie = serializeCookie(
    config.refreshName,
    tokens.refreshToken,
    {
      maxAgeSeconds: config.refreshMaxAgeSeconds,
      domain: config.domain,
      secure: config.secure,
      sameSite: config.sameSite,
      httpOnly: true,
    },
  );

  return [accessCookie, refreshCookie];
}

export function clearAuthCookies(
  config: CookieConfig,
): [clearAccess: string, clearRefresh: string] {
  const clearAccess = serializeCookie(config.accessName, "", {
    maxAgeSeconds: 0,
    domain: config.domain,
    secure: config.secure,
    sameSite: config.sameSite,
    httpOnly: true,
  });

  const clearRefresh = serializeCookie(config.refreshName, "", {
    maxAgeSeconds: 0,
    domain: config.domain,
    secure: config.secure,
    sameSite: config.sameSite,
    httpOnly: true,
  });

  return [clearAccess, clearRefresh];
}

export function createStateCookie(state: string, secure = false): string {
  return serializeCookie("peek_oauth_state", state, {
    maxAgeSeconds: 600, // 10 minutes
    secure,
    sameSite: "lax",
    httpOnly: true,
  });
}

export function clearStateCookie(secure = false): string {
  return serializeCookie("peek_oauth_state", "", {
    maxAgeSeconds: 0,
    secure,
    sameSite: "lax",
    httpOnly: true,
  });
}
