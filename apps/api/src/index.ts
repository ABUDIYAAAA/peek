import { Hono } from "hono";
import { cors } from "hono/cors";
import { oauthMetadataResponse } from "@modelcontextprotocol/server";
import type { AppEnv } from "./types.js";
import { requestIdMiddleware } from "./middleware/requestId.js";
import { envMiddleware } from "./middleware/env.js";
import { loggerMiddleware } from "./middleware/logger.js";
import { dbMiddleware } from "./middleware/db.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { notFoundHandler } from "./middleware/notFoundHandler.js";
import { healthRouter } from "./routes/health.js";
import { authRouter } from "./routes/auth.js";
import { oauthRouter } from "./routes/oauth.js";
import { machineIdentitiesRouter } from "./routes/machine-identities.js";
import { createMcpRouter, buildOAuthMetadataOptions } from "./mcp/index.js";
import { respondSuccess } from "./helpers/respond.js";

const app = new Hono<AppEnv>();

// Global Middlewares
app.use("*", requestIdMiddleware);
app.use("*", envMiddleware);
app.use("*", loggerMiddleware);
app.use("*", dbMiddleware);
app.use(
  "*",
  cors({
    origin: (origin) => origin || "*",
    credentials: true,
    allowHeaders: [
      "Content-Type",
      "Authorization",
      "X-Request-Id",
      "MCP-Protocol-Version",
    ],
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    exposeHeaders: ["X-Request-Id", "WWW-Authenticate"],
  }),
);

// Global Error and Not Found Handlers
app.onError(errorHandler);
app.notFound(notFoundHandler);

// OAuth 2.1 Discovery Endpoints (RFC 9728 Protected Resource + RFC 8414 AS Metadata)
app.all("/.well-known/*", async (c, next) => {
  const env = c.get("env");
  const metadataRes = oauthMetadataResponse(
    c.req.raw,
    buildOAuthMetadataOptions(env),
  );
  if (metadataRes) {
    return metadataRes;
  }
  await next();
});

// Root Index
app.get("/", (c) => {
  const env = c.get("env");
  return respondSuccess(c, {
    name: env?.APP_NAME ?? "peek",
    version: "0.0.1",
    description: "Peek Modular Hono & MCP API on Cloudflare Workers",
    endpoints: {
      health: "/health",
      mcp: "/mcp",
      oauthProtectedResourceMetadata:
        "/.well-known/oauth-protected-resource/mcp",
      oauthAuthorizationServerMetadata:
        "/.well-known/oauth-authorization-server",
      auth: "/api/v1/auth",
      oauth: "/api/v1/oauth",
      machineIdentities: "/api/v1/machine-identities",
      api: "/api/v1",
    },
  });
});

// Mount Routes
app.route("/health", healthRouter);
app.route("/mcp", createMcpRouter());

// V1 API Sub-router
const v1Router = new Hono<AppEnv>();
v1Router.get("/", (c) => respondSuccess(c, { message: "Peek API v1 ready" }));
v1Router.route("/auth", authRouter);
v1Router.route("/oauth", oauthRouter);
v1Router.route("/machine-identities", machineIdentitiesRouter);

app.route("/api/v1", v1Router);

export default app;
export type AppType = typeof app;
export * from "./types.js";
export * from "./helpers/respond.js";
export * from "./helpers/validate.js";
