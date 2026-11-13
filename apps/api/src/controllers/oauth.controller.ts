import type { Context } from "hono";
import {
  registerOAuthClient,
  validateAuthorizeRequest,
  getConsentDetails,
  approveAuthorization,
  exchangeAuthorizationCode,
  refreshMachineAccessToken,
  revokeMcpToken,
} from "@peek/auth";
import { BadRequestError, UnauthorizedError } from "@peek/core";
import type { AppEnv } from "../types.js";
import { respondSuccess } from "../helpers/respond.js";

/**
 * RFC 7591 Dynamic Client Registration (e.g. Antigravity registering itself).
 */
export async function registerClient(c: Context<AppEnv>): Promise<Response> {
  const db = c.get("db");
  const logger = c.get("logger");

  const body = await c.req.json().catch(() => {
    throw new BadRequestError("Invalid JSON request body");
  });

  const registered = await registerOAuthClient(db, body);

  logger?.info("Registered dynamic MCP OAuth client", {
    clientId: registered.client_id,
    clientName: registered.client_name,
  });

  return c.json(registered, 201);
}

/**
 * Browser authorization entry point opened by the coding agent.
 * Validates the OAuth 2.1 + PKCE query params and redirects to the PEEK frontend consent page.
 */
export async function redirectAuthorizeToFrontend(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const env = c.get("env");
  const logger = c.get("logger");

  const query = c.req.query();
  const validated = await validateAuthorizeRequest(db, {
    client_id: query.client_id,
    redirect_uri: query.redirect_uri,
    response_type: query.response_type,
    scope: query.scope,
    state: query.state,
    code_challenge: query.code_challenge,
    code_challenge_method: query.code_challenge_method,
    resource: query.resource,
  });

  const frontendBase = (env.FRONTEND_URL || env.APP_URL).replace(/\/+$/, "");
  const targetUrl = new URL(`${frontendBase}/oauth/authorize`);

  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined) {
      targetUrl.searchParams.set(k, v);
    }
  }

  logger?.info("Redirecting MCP OAuth authorization request to frontend", {
    clientId: validated.client.id,
    clientName: validated.client.clientName,
    frontendTarget: targetUrl.origin + targetUrl.pathname,
  });

  return c.redirect(targetUrl.toString(), 302);
}

/**
 * Authenticated JSON endpoint consumed by the PEEK frontend consent UI
 * to display the agent name and requested permissions.
 */
export async function fetchConsentDetails(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  const logger = c.get("logger");

  if (!user) {
    throw new UnauthorizedError("Authentication required");
  }

  const query = c.req.query();
  const details = await getConsentDetails(db, {
    client_id: query.client_id,
    redirect_uri: query.redirect_uri,
    response_type: query.response_type ?? "code",
    scope: query.scope,
    state: query.state,
    code_challenge: query.code_challenge,
    code_challenge_method: query.code_challenge_method,
    resource: query.resource,
  });

  logger?.debug("Loaded MCP OAuth consent details", {
    userId: user.sub,
    clientId: details.client.id,
  });

  return respondSuccess(c, details);
}

/**
 * Authenticated JSON endpoint called when the user clicks Approve or Deny on the consent screen.
 */
export async function submitConsentDecision(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  const logger = c.get("logger");

  if (!user) {
    throw new UnauthorizedError("Authentication required");
  }

  const body = await c.req.json<{
    client_id: string;
    redirect_uri: string;
    response_type?: string;
    scope?: string;
    state?: string;
    code_challenge: string;
    code_challenge_method?: string;
    resource?: string;
    approved: boolean;
    granted_scopes?: string[];
    identity_name?: string;
  }>();

  const result = await approveAuthorization(db, {
    ...body,
    userId: user.sub,
  });

  logger?.info("Processed MCP OAuth consent decision", {
    userId: user.sub,
    clientId: body.client_id,
    approved: result.approved,
    machineIdentityId: result.machineIdentityId,
  });

  return respondSuccess(c, result);
}

/**
 * Parses either application/x-www-form-urlencoded or application/json bodies
 * per RFC 6749 OAuth token endpoint requirements.
 */
async function parseOAuthFormOrJson(
  c: Context<AppEnv>,
): Promise<Record<string, string | undefined>> {
  const contentType = c.req.header("content-type") ?? "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const rawBody = await c.req.parseBody();
    const record: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(rawBody)) {
      if (typeof v === "string") {
        record[k] = v;
      }
    }
    return record;
  }

  return c.req.json<Record<string, string | undefined>>().catch(() => ({}));
}

/**
 * OAuth 2.1 Token Endpoint (supports authorization_code with PKCE & refresh_token).
 */
export async function exchangeToken(c: Context<AppEnv>): Promise<Response> {
  const db = c.get("db");
  const env = c.get("env");
  const logger = c.get("logger");

  const params = await parseOAuthFormOrJson(c);
  const grantType = params.grant_type;

  try {
    if (grantType === "authorization_code") {
      const tokenPayload = await exchangeAuthorizationCode(db, env, {
        code: params.code ?? "",
        codeVerifier: params.code_verifier ?? "",
        redirectUri: params.redirect_uri ?? "",
        clientId: params.client_id,
      });

      logger?.info("Issued Machine Identity OAuth tokens via authorization_code", {
        clientId: params.client_id,
        scope: tokenPayload.scope,
      });

      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json(tokenPayload, 200);
    }

    if (grantType === "refresh_token") {
      const tokenPayload = await refreshMachineAccessToken(db, env, {
        refreshToken: params.refresh_token ?? "",
        clientId: params.client_id,
      });

      logger?.info("Rotated Machine Identity OAuth tokens via refresh_token", {
        clientId: params.client_id,
      });

      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json(tokenPayload, 200);
    }

    return c.json(
      {
        error: "unsupported_grant_type",
        error_description: `Unsupported grant_type: ${grantType ?? "missing"}`,
      },
      400,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Token exchange failed";
    logger?.warn("OAuth token endpoint error", {
      grantType,
      clientId: params.client_id,
      error: message,
    });

    const oauthError =
      err instanceof UnauthorizedError ? "invalid_grant" : "invalid_request";
    return c.json(
      {
        error: oauthError,
        error_description: message,
      },
      400,
    );
  }
}

/**
 * RFC 7009 OAuth Token Revocation endpoint.
 */
export async function revokeTokenEndpoint(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const env = c.get("env");
  const logger = c.get("logger");

  const params = await parseOAuthFormOrJson(c);
  if (params.token) {
    await revokeMcpToken(db, env, params.token);
    logger?.info("Revoked Machine Identity OAuth token via RFC 7009 endpoint");
  }

  return c.json({ revoked: true }, 200);
}
