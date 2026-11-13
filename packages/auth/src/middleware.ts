import { createMiddleware } from "hono/factory";
import { UnauthorizedError, ForbiddenError } from "@peek/core";
import type { UserRole, JwtPayload } from "./types.js";
import { verifyAccessToken } from "./jwt.js";
import { getCookie, getCookieConfig } from "./cookies.js";

export const requireAuth = () =>
  createMiddleware<{
    Bindings: Record<string, unknown>;
    Variables: {
      user?: JwtPayload;
      env?: any;
    };
  }>(async (c, next) => {
    const env = c.get("env") || c.env;
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

export const requireRole = (allowedRoles: UserRole[]) =>
  createMiddleware<{
    Bindings: Record<string, unknown>;
    Variables: {
      user?: JwtPayload;
    };
  }>(async (c, next) => {
    const user = c.get("user");
    if (!user) {
      throw new UnauthorizedError("Authentication required");
    }

    if (!allowedRoles.includes(user.role)) {
      throw new ForbiddenError(
        `Access denied. Requires one of roles: [${allowedRoles.join(", ")}] (current: ${user.role})`,
      );
    }

    await next();
  });
