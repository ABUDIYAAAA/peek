import { createMiddleware } from "hono/factory";
import { createDb } from "@peek/db";
import type { AppEnv } from "../types.js";

export const dbMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  if (c.env?.DB) {
    const db = createDb(c.env.DB);
    c.set("db", db);
  }
  await next();
});
