import { createMiddleware } from "hono/factory";
import { createLogger, type LogLevel } from "@peek/core";
import type { AppEnv } from "../types.js";

export const loggerMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const start = Date.now();
  const requestId = c.get("requestId") || "unknown";
  const env = c.get("env");

  const minLevel = (env?.LOG_LEVEL ?? "info") as LogLevel;
  const isDev = (env?.ENVIRONMENT ?? "development") === "development";
  const appName = env?.APP_NAME ?? "peek";

  const logger = createLogger({
    name: appName,
    minLevel,
    isDev,
    context: {
      requestId,
    },
  });

  c.set("logger", logger);

  const method = c.req.method;
  const path = c.req.path;

  logger.debug(`Incoming request: ${method} ${path}`, {
    url: c.req.url,
    ip: c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for"),
    userAgent: c.req.header("user-agent"),
  });

  await next();

  const durationMs = Date.now() - start;
  const status = c.res.status;

  const logMeta = {
    method,
    path,
    status,
    durationMs,
  };

  const message = `${method} ${path} ${status} (${durationMs}ms)`;

  if (status >= 500) {
    logger.error(message, logMeta);
  } else if (status >= 400) {
    logger.warn(message, logMeta);
  } else {
    logger.info(message, logMeta);
  }
});
