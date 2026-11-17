import { createMiddleware } from "hono/factory";
import { UnauthorizedError, ForbiddenError } from "@peek/core";
import { verifyAccessToken, getCookie, getCookieConfig } from "@peek/auth";
import type { UserRole } from "@peek/auth";
import type { AppEnv } from "../types.js";

/**
 * Hono middleware requiring a valid HTTP-only access cookie.
 * Verifies JWT payload and sets `c.set("user", payload)`.
 */
export const requireAuth = () =>
  createMiddleware<AppEnv>(async (c, next) => {
    const env = c.get("env") || (c.env as any);
    const accessSecret = env?.JWT_ACCESS_SECRET;

    if (!accessSecret) {
      throw new Error("JWT_ACCESS_SECRET is not configured on environment");
    }

    const cookieConfig = getCookieConfig(env);
    const cookieHeader = c.req.header("cookie");

    // Strictly read access token from HTTP-only cookie
    const token = getCookie(cookieHeader, cookieConfig.accessName);

    if (!token) {
      throw new UnauthorizedError(
        "Authentication required (missing access cookie)",
      );
    }

    const payload = await verifyAccessToken(token, accessSecret);
    c.set("user", payload);
    await next();
  });

/**
 * Hono middleware enforcing role-based access control.
 */
export const requireRole = (allowedRoles: UserRole[]) =>
  createMiddleware<AppEnv>(async (c, next) => {
    const user = c.get("user");
    if (!user) {
      throw new UnauthorizedError("Authentication required");
    }

    if (!allowedRoles.includes(user.role)) {
      throw new ForbiddenError(
        "Insufficient permissions to access this resource",
      );
    }

    await next();
  });
