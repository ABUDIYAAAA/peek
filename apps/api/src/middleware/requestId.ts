import { createMiddleware } from "hono/factory";
import type { AppEnv } from "../types.js";

export const requestIdMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const existingId = c.req.header("x-request-id");
  const requestId = existingId || crypto.randomUUID();

  c.set("requestId", requestId);
  await next();
  c.res.headers.set("X-Request-Id", requestId);
});
