import { Hono } from "hono";
import { requireAuth } from "@peek/auth";
import type { AppEnv } from "../types.js";
import {
  registerClient,
  redirectAuthorizeToFrontend,
  fetchConsentDetails,
  submitConsentDecision,
  exchangeToken,
  revokeTokenEndpoint,
} from "../controllers/oauth.controller.js";

export const oauthRouter = new Hono<AppEnv>();

// RFC 7591 Dynamic Client Registration (public, used by MCP clients like Antigravity)
oauthRouter.post("/register", registerClient);

// Browser authorize entry point (redirects to FRONTEND_URL/oauth/authorize)
oauthRouter.get("/authorize", redirectAuthorizeToFrontend);

// Consent details & decision endpoints (strictly HTTP-only user cookie auth)
oauthRouter.get("/consent-details", requireAuth(), fetchConsentDetails);
oauthRouter.post("/authorize", requireAuth(), submitConsentDecision);

// OAuth 2.1 PKCE token exchange & refresh
oauthRouter.post("/token", exchangeToken);

// RFC 7009 token revocation
oauthRouter.post("/revoke", revokeTokenEndpoint);
