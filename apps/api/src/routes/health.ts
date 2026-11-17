import { Hono } from "hono";
import { sql } from "@peek/db";
import { tryCatch } from "@peek/core";
import { pruneExpiredAuthRecords } from "@peek/auth";
import type { AppEnv } from "../types.js";
import { respondSuccess, respondError } from "../helpers/respond.js";

export const healthRouter = new Hono<AppEnv>();

healthRouter.get("/", async (c) => {
  const env = c.get("env");
  const db = c.get("db");

  let dbStatus: "connected" | "disconnected" | "not_configured" =
    "not_configured";

  if (db) {
    const [dbErr] = await tryCatch(db.run(sql`SELECT 1`));
    dbStatus = dbErr ? "disconnected" : "connected";
  }

  return respondSuccess(c, {
    status: "healthy",
    environment: env?.ENVIRONMENT ?? "unknown",
    version: "0.0.1",
    database: dbStatus,
    timestamp: new Date().toISOString(),
  });
});

healthRouter.post("/prune-expired", async (c) => {
  const db = c.get("db");
  if (!db) {
    return respondError(c, "Database unavailable", { status: 500 });
  }
  const result = await pruneExpiredAuthRecords(db);
  return respondSuccess(c, result);
});
