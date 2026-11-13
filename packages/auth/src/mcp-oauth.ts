import {
  eq,
  and,
  or,
  isNull,
  gt,
  type Database,
  type McpScope,
  type MachineIdentity,
  type MachineToken,
  type OAuthClient,
  type User,
} from "@peek/db";
import {
  oauthClients,
  machineIdentities,
  oauthAuthCodes,
  machineTokens,
  users,
} from "@peek/db";
import {
  BadRequestError,
  UnauthorizedError,
  type BaseEnv,
} from "@peek/core";
import { parseDurationToSeconds } from "./jwt.js";
import { hashRefreshToken } from "./session.js";
import {
  getScopeDetailsList,
  parseAndValidateScopes,
  type McpScopeDefinition,
} from "./mcp-scopes.js";

function generateRandomHex(bytesLength = 32): string {
  const bytes = new Uint8Array(bytesLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface RegisterClientInput {
  client_name: string;
  redirect_uris: string[];
  client_uri?: string;
  logo_uri?: string;
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
}

export interface RegisteredClientMetadata {
  client_id: string;
  client_id_issued_at: number;
  client_name: string;
  client_uri?: string;
  logo_uri?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
}

/**
 * RFC 7591 Dynamic Client Registration for coding agents (e.g. Antigravity, Cursor).
 */
export async function registerOAuthClient(
  db: Database,
  input: RegisterClientInput,
): Promise<RegisteredClientMetadata> {
  if (!input.client_name?.trim()) {
    throw new BadRequestError("client_name is required");
  }

  if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length === 0) {
    throw new BadRequestError("redirect_uris must be a non-empty array");
  }

  for (const uri of input.redirect_uris) {
    try {
      new URL(uri);
    } catch {
      throw new BadRequestError(`Invalid redirect_uri: ${uri}`);
    }
  }

  const clientId = `peek_client_${generateRandomHex(16)}`;
  const now = new Date();
  const grantTypes = input.grant_types?.length
    ? input.grant_types
    : ["authorization_code", "refresh_token"];
  const responseTypes = input.response_types?.length
    ? input.response_types
    : ["code"];
  const tokenEndpointAuthMethod = input.token_endpoint_auth_method ?? "none";

  await db.insert(oauthClients).values({
    id: clientId,
    clientName: input.client_name.trim(),
    clientUri: input.client_uri ?? null,
    logoUri: input.logo_uri ?? null,
    redirectUris: JSON.stringify(input.redirect_uris),
    grantTypes: JSON.stringify(grantTypes),
    responseTypes: JSON.stringify(responseTypes),
    tokenEndpointAuthMethod,
    createdAt: now,
  });

  return {
    client_id: clientId,
    client_id_issued_at: Math.floor(now.getTime() / 1000),
    client_name: input.client_name.trim(),
    client_uri: input.client_uri,
    logo_uri: input.logo_uri,
    redirect_uris: input.redirect_uris,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
  };
}

export interface AuthorizeRequestInput {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  resource?: string;
}

export interface ValidatedAuthorizeRequest {
  client: OAuthClient;
  redirectUri: string;
  scopes: McpScope[];
  state?: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  resource?: string;
}

/**
 * Validates OAuth 2.1 Authorization Code + PKCE query parameters.
 */
export async function validateAuthorizeRequest(
  db: Database,
  query: AuthorizeRequestInput,
): Promise<ValidatedAuthorizeRequest> {
  if (!query.client_id) {
    throw new BadRequestError("Missing client_id parameter");
  }

  const client = await db.query.oauthClients.findFirst({
    where: eq(oauthClients.id, query.client_id),
  });

  if (!client) {
    throw new BadRequestError(`Unknown client_id: ${query.client_id}`);
  }

  if (query.response_type !== "code") {
    throw new BadRequestError(
      `Unsupported response_type "${query.response_type ?? ""}". Only "code" is supported.`,
    );
  }

  if (!query.redirect_uri) {
    throw new BadRequestError("Missing redirect_uri parameter");
  }

  const allowedUris = JSON.parse(client.redirectUris) as string[];
  if (!allowedUris.includes(query.redirect_uri)) {
    throw new BadRequestError(
      "redirect_uri does not match any registered redirect URI for this client",
    );
  }

  if (!query.code_challenge) {
    throw new BadRequestError("PKCE code_challenge is required (OAuth 2.1)");
  }

  const method = query.code_challenge_method ?? "S256";
  if (method !== "S256") {
    throw new BadRequestError(
      'Unsupported code_challenge_method. Only "S256" is supported.',
    );
  }

  const scopes = parseAndValidateScopes(query.scope);

  return {
    client,
    redirectUri: query.redirect_uri,
    scopes,
    state: query.state,
    codeChallenge: query.code_challenge,
    codeChallengeMethod: "S256",
    resource: query.resource,
  };
}

export interface ConsentDetailsResult {
  client: {
    id: string;
    name: string;
    uri: string | null;
    logoUri: string | null;
  };
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  resource?: string;
  requestedPermissions: McpScopeDefinition[];
}

export async function getConsentDetails(
  db: Database,
  query: AuthorizeRequestInput,
): Promise<ConsentDetailsResult> {
  const validated = await validateAuthorizeRequest(db, query);

  return {
    client: {
      id: validated.client.id,
      name: validated.client.clientName,
      uri: validated.client.clientUri,
      logoUri: validated.client.logoUri,
    },
    redirectUri: validated.redirectUri,
    state: validated.state,
    codeChallenge: validated.codeChallenge,
    codeChallengeMethod: validated.codeChallengeMethod,
    resource: validated.resource,
    requestedPermissions: getScopeDetailsList(validated.scopes),
  };
}

export interface ApproveAuthorizationInput {
  userId: string;
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
}

export interface ApproveAuthorizationResult {
  redirectUrl: string;
  approved: boolean;
  machineIdentityId?: string;
}

/**
 * Processes the developer's approval/denial on the consent screen:
 * creates a linked Machine Identity and issues a 10-minute one-time PKCE auth code.
 */
export async function approveAuthorization(
  db: Database,
  input: ApproveAuthorizationInput,
): Promise<ApproveAuthorizationResult> {
  const validated = await validateAuthorizeRequest(db, {
    client_id: input.client_id,
    redirect_uri: input.redirect_uri,
    response_type: input.response_type ?? "code",
    scope: input.scope,
    state: input.state,
    code_challenge: input.code_challenge,
    code_challenge_method: input.code_challenge_method ?? "S256",
    resource: input.resource,
  });

  const targetUrl = new URL(validated.redirectUri);

  if (!input.approved) {
    targetUrl.searchParams.set("error", "access_denied");
    targetUrl.searchParams.set(
      "error_description",
      "The resource owner denied the authorization request",
    );
    if (validated.state) {
      targetUrl.searchParams.set("state", validated.state);
    }
    return {
      redirectUrl: targetUrl.toString(),
      approved: false,
    };
  }

  const grantedScopes: McpScope[] = input.granted_scopes
    ? parseAndValidateScopes(input.granted_scopes)
    : validated.scopes;

  if (grantedScopes.length === 0) {
    throw new BadRequestError("At least one permission scope must be granted");
  }

  const now = new Date();
  const machineIdentityId = crypto.randomUUID();
  const identityName =
    input.identity_name?.trim() || validated.client.clientName;

  await db.insert(machineIdentities).values({
    id: machineIdentityId,
    userId: input.userId,
    clientId: validated.client.id,
    name: identityName,
    scopes: JSON.stringify(grantedScopes),
    metadata: JSON.stringify({
      clientName: validated.client.clientName,
      authorizedAt: now.toISOString(),
    }),
    createdAt: now,
    updatedAt: now,
  });

  const rawCode = `peek_mac_${generateRandomHex(24)}`;
  const codeHash = await sha256Hex(rawCode);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  await db.insert(oauthAuthCodes).values({
    codeHash,
    clientId: validated.client.id,
    userId: input.userId,
    machineIdentityId,
    redirectUri: validated.redirectUri,
    scopes: JSON.stringify(grantedScopes),
    codeChallenge: validated.codeChallenge,
    codeChallengeMethod: "S256",
    resource: validated.resource ?? null,
    expiresAt,
    createdAt: now,
  });

  targetUrl.searchParams.set("code", rawCode);
  if (validated.state) {
    targetUrl.searchParams.set("state", validated.state);
  }

  return {
    redirectUrl: targetUrl.toString(),
    approved: true,
    machineIdentityId,
  };
}

export interface ExchangeCodeParams {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId?: string;
}

export interface OAuthTokenResponsePayload {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

async function issueMachineTokenPair(
  db: Database,
  env: BaseEnv,
  params: {
    machineIdentityId: string;
    userId: string;
    clientId: string;
    scopes: McpScope[];
    resource?: string | null;
  },
): Promise<OAuthTokenResponsePayload> {
  const accessToken = `peek_mat_${generateRandomHex(32)}`;
  const refreshToken = `peek_mrt_${generateRandomHex(32)}`;

  const accessTokenHash = await hashRefreshToken(
    accessToken,
    env.MCP_TOKEN_SECRET,
  );
  const refreshTokenHash = await hashRefreshToken(
    refreshToken,
    env.MCP_TOKEN_SECRET,
  );

  const accessDurationSec = parseDurationToSeconds(env.MCP_ACCESS_TOKEN_EXPIRY);
  const refreshDurationSec = parseDurationToSeconds(
    env.MCP_REFRESH_TOKEN_EXPIRY,
  );

  const now = new Date();
  const accessTokenExpiresAt = new Date(
    now.getTime() + accessDurationSec * 1000,
  );
  const refreshTokenExpiresAt = new Date(
    now.getTime() + refreshDurationSec * 1000,
  );

  await db.insert(machineTokens).values({
    id: crypto.randomUUID(),
    machineIdentityId: params.machineIdentityId,
    userId: params.userId,
    clientId: params.clientId,
    accessTokenHash,
    refreshTokenHash,
    scopes: JSON.stringify(params.scopes),
    resource: params.resource ?? null,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
    createdAt: now,
  });

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: accessDurationSec,
    refresh_token: refreshToken,
    scope: params.scopes.join(" "),
  };
}

/**
 * Exchanges a one-time authorization code + PKCE code_verifier for Machine Identity tokens.
 */
export async function exchangeAuthorizationCode(
  db: Database,
  env: BaseEnv,
  params: ExchangeCodeParams,
): Promise<OAuthTokenResponsePayload> {
  if (!params.code || !params.codeVerifier || !params.redirectUri) {
    throw new BadRequestError(
      "code, code_verifier, and redirect_uri are required",
    );
  }

  const codeHash = await sha256Hex(params.code);
  const now = new Date();

  // Atomically claim the authorization code in a single statement.
  // Concurrency guard: prevents race conditions where the same code is exchanged concurrently.
  const codeWhere = [
    eq(oauthAuthCodes.codeHash, codeHash),
    isNull(oauthAuthCodes.usedAt),
    gt(oauthAuthCodes.expiresAt, now),
  ];
  if (params.clientId) {
    codeWhere.push(eq(oauthAuthCodes.clientId, params.clientId));
  }

  const [authCode] = await db
    .update(oauthAuthCodes)
    .set({ usedAt: now })
    .where(and(...codeWhere))
    .returning();

  if (!authCode) {
    throw new UnauthorizedError(
      "Invalid, expired, or already used authorization code",
    );
  }

  if (authCode.redirectUri !== params.redirectUri) {
    throw new BadRequestError("redirect_uri mismatch");
  }

  // Verify PKCE S256
  const computedChallenge = await sha256Base64Url(params.codeVerifier);
  if (computedChallenge !== authCode.codeChallenge) {
    throw new UnauthorizedError("Invalid PKCE code_verifier");
  }

  const identity = await db.query.machineIdentities.findFirst({
    where: eq(machineIdentities.id, authCode.machineIdentityId),
  });

  if (!identity || identity.revokedAt) {
    throw new UnauthorizedError("Machine identity has been revoked");
  }

  const scopes = JSON.parse(authCode.scopes) as McpScope[];

  return issueMachineTokenPair(db, env, {
    machineIdentityId: authCode.machineIdentityId,
    userId: authCode.userId,
    clientId: authCode.clientId,
    scopes,
    resource: authCode.resource,
  });
}

/**
 * Rotates a Machine Identity refresh token and issues a fresh access/refresh token pair.
 */
export async function refreshMachineAccessToken(
  db: Database,
  env: BaseEnv,
  params: { refreshToken: string; clientId?: string },
): Promise<OAuthTokenResponsePayload> {
  if (!params.refreshToken) {
    throw new BadRequestError("refresh_token is required");
  }

  const tokenHash = await hashRefreshToken(
    params.refreshToken,
    env.MCP_TOKEN_SECRET,
  );
  const now = new Date();

  // Atomically claim and revoke the refresh token in a single statement.
  // Concurrency guard: prevents race conditions where the same refresh token is exchanged concurrently.
  const tokenWhere = [
    eq(machineTokens.refreshTokenHash, tokenHash),
    isNull(machineTokens.revokedAt),
    gt(machineTokens.refreshTokenExpiresAt, now),
  ];
  if (params.clientId) {
    tokenWhere.push(eq(machineTokens.clientId, params.clientId));
  }

  const [existingToken] = await db
    .update(machineTokens)
    .set({ revokedAt: now })
    .where(and(...tokenWhere))
    .returning();

  if (!existingToken) {
    throw new UnauthorizedError("Invalid or expired machine refresh token");
  }

  const identity = await db.query.machineIdentities.findFirst({
    where: eq(machineIdentities.id, existingToken.machineIdentityId),
  });

  if (!identity || identity.revokedAt) {
    throw new UnauthorizedError("Machine identity has been revoked");
  }

  const scopes = JSON.parse(existingToken.scopes) as McpScope[];

  return issueMachineTokenPair(db, env, {
    machineIdentityId: existingToken.machineIdentityId,
    userId: existingToken.userId,
    clientId: existingToken.clientId,
    scopes,
    resource: existingToken.resource,
  });
}

/**
 * RFC 7009 token revocation endpoint helper.
 */
export async function revokeMcpToken(
  db: Database,
  env: BaseEnv,
  rawToken: string,
): Promise<void> {
  if (!rawToken) return;

  const tokenHash = await hashRefreshToken(rawToken, env.MCP_TOKEN_SECRET);
  await db
    .update(machineTokens)
    .set({ revokedAt: new Date() })
    .where(
      or(
        eq(machineTokens.accessTokenHash, tokenHash),
        eq(machineTokens.refreshTokenHash, tokenHash),
      ),
    );
}

export interface VerifiedMcpSession {
  tokenRecord: MachineToken;
  machineIdentity: MachineIdentity;
  user: User;
  scopes: McpScope[];
  expiresAtSeconds: number;
}

/**
 * Verifies a Machine Identity Bearer token on every `/mcp` request.
 * Enforces instant revocation if either the token OR parent Machine Identity has `revokedAt` set.
 */
export async function verifyMcpBearerToken(
  db: Database,
  env: BaseEnv,
  rawAccessToken: string,
  ipAddress?: string,
): Promise<VerifiedMcpSession> {
  if (!rawAccessToken.startsWith("peek_mat_")) {
    throw new UnauthorizedError("Invalid MCP access token format");
  }

  const accessTokenHash = await hashRefreshToken(
    rawAccessToken,
    env.MCP_TOKEN_SECRET,
  );
  const now = new Date();

  const tokenRecord = await db.query.machineTokens.findFirst({
    where: and(
      eq(machineTokens.accessTokenHash, accessTokenHash),
      isNull(machineTokens.revokedAt),
      gt(machineTokens.accessTokenExpiresAt, now),
    ),
  });

  if (!tokenRecord) {
    throw new UnauthorizedError("Invalid, expired, or revoked MCP access token");
  }

  const machineIdentity = await db.query.machineIdentities.findFirst({
    where: eq(machineIdentities.id, tokenRecord.machineIdentityId),
  });

  if (!machineIdentity || machineIdentity.revokedAt) {
    throw new UnauthorizedError("Machine identity has been revoked");
  }

  const user = await db.query.users.findFirst({
    where: eq(users.id, tokenRecord.userId),
  });

  if (!user) {
    throw new UnauthorizedError("Linked user account not found");
  }

  // Record last used timestamp and IP asynchronously / best-effort
  await db
    .update(machineIdentities)
    .set({
      lastUsedAt: now,
      lastIpAddress: ipAddress ?? machineIdentity.lastIpAddress,
      updatedAt: now,
    })
    .where(eq(machineIdentities.id, machineIdentity.id));

  const scopes = JSON.parse(tokenRecord.scopes) as McpScope[];

  return {
    tokenRecord,
    machineIdentity,
    user,
    scopes,
    expiresAtSeconds: Math.floor(
      tokenRecord.accessTokenExpiresAt.getTime() / 1000,
    ),
  };
}
