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

const FORBIDDEN_URI_SCHEMES = new Set([
  "javascript:",
  "data:",
  "file:",
  "blob:",
  "about:",
  "vbscript:",
  "ws:",
  "wss:",
  "mailto:",
  "tel:",
  "sms:",
  "ftp:",
  "ftps:",
  "intent:",
]);

const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "[::1]", "localhost"]);

// Recognized native coding IDE & agent client URI schemes
const WELL_KNOWN_NATIVE_SCHEMES = new Set([
  "antigravity",
  "cursor",
  "vscode",
  "vscode-insiders",
  "windsurf",
  "claude",
  "zed",
  "sublime",
  "pycharm",
  "idea",
  "webstorm",
]);

/**
 * Validates an OAuth 2.1 redirect URI per RFC 8252 (Native Apps) & RFC 6749 §3.1.2.
 *
 * Rules:
 * 1. Must be a valid URI string, length between 1 and 2048 characters.
 * 2. MUST NOT contain fragment identifiers (#).
 * 3. Scheme MUST NOT be a dangerous pseudo-protocol (javascript:, data:, file:, etc.).
 * 4. Allowed schemes:
 *    - https: Remote secure web redirect.
 *    - http: Allowed ONLY for loopback interfaces (127.0.0.1, [::1], localhost).
 *    - Custom native scheme: Allowed if reverse domain notation (e.g. com.example.app)
 *      or recognized native scheme (antigravity, cursor, etc.), conforming to RFC 3986 §3.1.
 */
export function validateRedirectUri(uri: string): void {
  if (typeof uri !== "string" || !uri.trim()) {
    throw new BadRequestError("redirect_uri must be a non-empty string");
  }

  const trimmed = uri.trim();
  if (trimmed.length > 2048) {
    throw new BadRequestError(
      "redirect_uri exceeds maximum length of 2048 characters",
    );
  }

  // RFC 6749 §3.1.2: The endpoint URI MUST NOT include a fragment component.
  if (trimmed.includes("#")) {
    throw new BadRequestError(
      `redirect_uri must not contain a fragment identifier (#): ${trimmed}`,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new BadRequestError(`Invalid redirect_uri format: ${trimmed}`);
  }

  const protocol = parsed.protocol.toLowerCase();

  // Reject dangerous pseudo-protocols
  if (FORBIDDEN_URI_SCHEMES.has(protocol)) {
    throw new BadRequestError(
      `Forbidden redirect_uri scheme "${protocol}": ${trimmed}`,
    );
  }

  // Case 1: HTTPS (remote secure web)
  if (protocol === "https:") {
    if (!parsed.hostname || parsed.hostname.includes(" ")) {
      throw new BadRequestError(`Invalid hostname in redirect_uri: ${trimmed}`);
    }
    return;
  }

  // Case 2: HTTP (loopback only per RFC 8252 §7.3)
  if (protocol === "http:") {
    const hostname = parsed.hostname.toLowerCase();
    if (!LOOPBACK_HOSTNAMES.has(hostname)) {
      throw new BadRequestError(
        `Plain HTTP redirect_uri is only permitted on loopback interfaces (127.0.0.1, [::1], localhost). Received: ${trimmed}`,
      );
    }
    return;
  }

  // Case 3: Private-use Custom Native Scheme (e.g. antigravity:, cursor:, com.google.antigravity:)
  const schemeName = protocol.replace(/:$/, "");
  // RFC 3986 §3.1 scheme syntax: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  const isValidSchemeSyntax = /^[a-z][a-z0-9+.-]*$/.test(schemeName);
  if (!isValidSchemeSyntax || schemeName.length < 2 || schemeName.length > 64) {
    throw new BadRequestError(
      `Invalid custom scheme "${schemeName}" in redirect_uri: ${trimmed}`,
    );
  }

  const hasDot = schemeName.includes(".");
  const isWellKnown = WELL_KNOWN_NATIVE_SCHEMES.has(schemeName);
  const isAlphanumericNative = /^[a-z0-9-]{3,32}$/.test(schemeName);

  if (!hasDot && !isWellKnown && !isAlphanumericNative) {
    throw new BadRequestError(
      `Unsupported custom scheme "${schemeName}" in redirect_uri: ${trimmed}. Custom schemes must follow reverse-DNS notation (e.g. com.company.app) or be a recognized native client scheme.`,
    );
  }
}

/**
 * Validates a web URI (client_uri, logo_uri). Must be https: or loopback http:.
 */
export function validateWebUri(uri: string, fieldName: string): void {
  if (typeof uri !== "string" || !uri.trim()) {
    throw new BadRequestError(`${fieldName} must be a non-empty string`);
  }

  const trimmed = uri.trim();
  if (trimmed.length > 2048) {
    throw new BadRequestError(
      `${fieldName} exceeds maximum length of 2048 characters`,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new BadRequestError(`Invalid ${fieldName} format: ${trimmed}`);
  }

  const protocol = parsed.protocol.toLowerCase();
  if (FORBIDDEN_URI_SCHEMES.has(protocol)) {
    throw new BadRequestError(`Forbidden scheme "${protocol}" in ${fieldName}`);
  }

  if (
    protocol !== "https:" &&
    (protocol !== "http:" ||
      !LOOPBACK_HOSTNAMES.has(parsed.hostname.toLowerCase()))
  ) {
    throw new BadRequestError(
      `${fieldName} must use https: (or loopback http:). Received: ${trimmed}`,
    );
  }
}

/**
 * Checks if a requested redirect_uri matches any registered redirect URI for the client.
 * Implements RFC 8252 §7.3 loopback port variation rule:
 * For loopback HTTP redirect URIs (127.0.0.1, [::1], localhost), any port is allowed
 * as long as the scheme, loopback host, and pathname match.
 */
export function isRedirectUriAllowed(
  requestedUri: string,
  registeredUris: string[],
): boolean {
  // 1. Direct exact match
  if (registeredUris.includes(requestedUri)) {
    return true;
  }

  let requestedParsed: URL;
  try {
    requestedParsed = new URL(requestedUri);
  } catch {
    return false;
  }

  const requestedProto = requestedParsed.protocol.toLowerCase();
  const requestedHost = requestedParsed.hostname.toLowerCase();

  // 2. Loopback dynamic port matching (RFC 8252 §7.3)
  if (requestedProto === "http:" && LOOPBACK_HOSTNAMES.has(requestedHost)) {
    for (const regUri of registeredUris) {
      try {
        const regParsed = new URL(regUri);
        if (
          regParsed.protocol.toLowerCase() === "http:" &&
          regParsed.hostname.toLowerCase() === requestedHost &&
          regParsed.pathname === requestedParsed.pathname
        ) {
          return true;
        }
      } catch {
        continue;
      }
    }
  }

  return false;
}

/**
 * RFC 7591 Dynamic Client Registration for coding agents (e.g. Antigravity, Cursor).
 */
export async function registerOAuthClient(
  db: Database,
  input: RegisterClientInput,
): Promise<RegisteredClientMetadata> {
  const clientName = input.client_name?.trim();
  if (!clientName) {
    throw new BadRequestError("client_name is required");
  }

  if (clientName.length > 100) {
    throw new BadRequestError("client_name must not exceed 100 characters");
  }

  if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length === 0) {
    throw new BadRequestError("redirect_uris must be a non-empty array");
  }

  if (input.redirect_uris.length > 10) {
    throw new BadRequestError(
      "redirect_uris must not contain more than 10 entries",
    );
  }

  const validatedRedirectUris: string[] = [];
  for (const uri of input.redirect_uris) {
    validateRedirectUri(uri);
    validatedRedirectUris.push(uri.trim());
  }

  // Deduplicate
  const uniqueRedirectUris = Array.from(new Set(validatedRedirectUris));

  if (input.client_uri) {
    validateWebUri(input.client_uri, "client_uri");
  }

  if (input.logo_uri) {
    validateWebUri(input.logo_uri, "logo_uri");
  }

  // Validate grant_types
  const allowedGrantTypes = new Set(["authorization_code", "refresh_token"]);
  const grantTypes = input.grant_types?.length
    ? input.grant_types
    : ["authorization_code", "refresh_token"];

  for (const gt of grantTypes) {
    if (!allowedGrantTypes.has(gt)) {
      throw new BadRequestError(
        `Unsupported grant_type "${gt}". Only "authorization_code" and "refresh_token" are supported.`,
      );
    }
  }

  // Validate response_types
  const allowedResponseTypes = new Set(["code"]);
  const responseTypes = input.response_types?.length
    ? input.response_types
    : ["code"];

  for (const rt of responseTypes) {
    if (!allowedResponseTypes.has(rt)) {
      throw new BadRequestError(
        `Unsupported response_type "${rt}". Only "code" is supported.`,
      );
    }
  }

  const tokenEndpointAuthMethod = input.token_endpoint_auth_method ?? "none";
  if (tokenEndpointAuthMethod !== "none") {
    throw new BadRequestError(
      `Unsupported token_endpoint_auth_method "${tokenEndpointAuthMethod}". Only "none" is supported.`,
    );
  }

  const clientId = `peek_client_${generateRandomHex(16)}`;
  const now = new Date();

  await db.insert(oauthClients).values({
    id: clientId,
    clientName,
    clientUri: input.client_uri?.trim() ?? null,
    logoUri: input.logo_uri?.trim() ?? null,
    redirectUris: JSON.stringify(uniqueRedirectUris),
    grantTypes: JSON.stringify(grantTypes),
    responseTypes: JSON.stringify(responseTypes),
    tokenEndpointAuthMethod,
    createdAt: now,
  });

  return {
    client_id: clientId,
    client_id_issued_at: Math.floor(now.getTime() / 1000),
    client_name: clientName,
    client_uri: input.client_uri?.trim(),
    logo_uri: input.logo_uri?.trim(),
    redirect_uris: uniqueRedirectUris,
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

  // Validate redirect_uri format and scheme defense-in-depth
  validateRedirectUri(query.redirect_uri);

  const allowedUris = JSON.parse(client.redirectUris) as string[];
  if (!isRedirectUriAllowed(query.redirect_uri, allowedUris)) {
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
  const identityName =
    input.identity_name?.trim() || validated.client.clientName;

  // Check if active non-revoked identity already exists for this (userId, clientId)
  const existingIdentity = await db.query.machineIdentities.findFirst({
    where: and(
      eq(machineIdentities.userId, input.userId),
      eq(machineIdentities.clientId, validated.client.id),
      isNull(machineIdentities.revokedAt),
    ),
  });

  // If existing identity exists, update its scopes and name if necessary
  if (existingIdentity) {
    await db
      .update(machineIdentities)
      .set({
        name: identityName,
        scopes: JSON.stringify(grantedScopes),
        updatedAt: now,
      })
      .where(eq(machineIdentities.id, existingIdentity.id));
  }

  // Issue 10-minute PKCE auth code.
  // CRITICAL (FINDING-04): Do NOT insert a brand new machine_identities row on consent approval!
  // If the agent abandons authorization before exchanging the code, ZERO zombie identities are created.
  // The identity is materialized upon exchangeAuthorizationCode when PKCE is proven.
  const rawCode = `peek_mac_${generateRandomHex(24)}`;
  const codeHash = await sha256Hex(rawCode);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  await db.insert(oauthAuthCodes).values({
    codeHash,
    clientId: validated.client.id,
    userId: input.userId,
    machineIdentityId: existingIdentity?.id ?? null,
    identityName,
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
    machineIdentityId: existingIdentity?.id,
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

  // Resolve or materialize Machine Identity upon successful code exchange (FINDING-04)
  let targetIdentityId: string;

  if (authCode.machineIdentityId) {
    const identity = await db.query.machineIdentities.findFirst({
      where: eq(machineIdentities.id, authCode.machineIdentityId),
    });

    if (!identity || identity.revokedAt) {
      throw new UnauthorizedError("Machine identity has been revoked");
    }
    targetIdentityId = identity.id;
  } else {
    // Check if an active identity was created for this user & client
    let identity = await db.query.machineIdentities.findFirst({
      where: and(
        eq(machineIdentities.userId, authCode.userId),
        eq(machineIdentities.clientId, authCode.clientId),
        isNull(machineIdentities.revokedAt),
      ),
    });

    if (!identity) {
      const newIdentityId = crypto.randomUUID();
      const [created] = await db
        .insert(machineIdentities)
        .values({
          id: newIdentityId,
          userId: authCode.userId,
          clientId: authCode.clientId,
          name: authCode.identityName || "Coding Agent",
          scopes: authCode.scopes,
          metadata: JSON.stringify({
            clientName: authCode.clientId,
            activatedAt: now.toISOString(),
          }),
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      if (!created) {
        throw new Error("Failed to materialize machine identity");
      }
      identity = created;
    }

    targetIdentityId = identity.id;

    // Link identity back to authorization code record
    await db
      .update(oauthAuthCodes)
      .set({ machineIdentityId: targetIdentityId })
      .where(eq(oauthAuthCodes.codeHash, codeHash));
  }

  const scopes = JSON.parse(authCode.scopes) as McpScope[];

  return issueMachineTokenPair(db, env, {
    machineIdentityId: targetIdentityId,
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

  // Single round-trip consolidated join query across tokens -> identities -> users (FINDING-06)
  const rows = await db
    .select({
      tokenRecord: machineTokens,
      machineIdentity: machineIdentities,
      user: users,
    })
    .from(machineTokens)
    .innerJoin(
      machineIdentities,
      eq(machineTokens.machineIdentityId, machineIdentities.id),
    )
    .innerJoin(users, eq(machineTokens.userId, users.id))
    .where(
      and(
        eq(machineTokens.accessTokenHash, accessTokenHash),
        isNull(machineTokens.revokedAt),
        gt(machineTokens.accessTokenExpiresAt, now),
        isNull(machineIdentities.revokedAt),
      ),
    )
    .limit(1);

  const first = rows[0];
  if (!first) {
    throw new UnauthorizedError("Invalid, expired, or revoked MCP access token");
  }

  const { tokenRecord, machineIdentity, user } = first;

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
