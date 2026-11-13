import { createMiddleware } from "hono/factory";
import { validateEnv, type BaseEnv } from "@peek/core";
import type { AppEnv } from "../types.js";

let cachedValidatedEnv: BaseEnv | null = null;

export const envMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  if (!cachedValidatedEnv) {
    cachedValidatedEnv = validateEnv(c.env);
  }
  c.set("env", cachedValidatedEnv);
  await next();
});
