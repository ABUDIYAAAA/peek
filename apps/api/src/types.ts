import type { Database } from "@peek/db";
import type { BaseEnv, Logger } from "@peek/core";
import type { JwtPayload } from "@peek/auth";

export interface Env {
  // Cloudflare D1 Database binding
  DB: D1Database;

  // Environment variables
  ENVIRONMENT?: string;
  PORT?: string | number;
  APP_NAME?: string;
  APP_URL?: string;
  LOG_LEVEL?: string;
  JWT_ACCESS_SECRET?: string;
  REFRESH_TOKEN_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_REDIRECT_URI?: string;
  FRONTEND_URL?: string;
  COOKIE_ACCESS_NAME?: string;
  COOKIE_REFRESH_NAME?: string;
  COOKIE_DOMAIN?: string;
  COOKIE_SECURE?: string | boolean;
  COOKIE_SAME_SITE?: string;
  ACCESS_TOKEN_EXPIRY?: string;
  REFRESH_TOKEN_EXPIRY?: string;
  [key: string]: unknown;
}

export interface Variables {
  db: Database;
  requestId: string;
  env: BaseEnv;
  logger: Logger;
  user?: JwtPayload;
  parsedBody?: unknown;
}

export interface AppEnv {
  Bindings: Env;
  Variables: Variables;
}
