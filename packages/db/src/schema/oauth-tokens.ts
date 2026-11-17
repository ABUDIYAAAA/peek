import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";
import { oauthClients } from "./oauth-clients.js";
import { machineIdentities } from "./machine-identities.js";

/**
 * Short-lived OAuth 2.1 Authorization Codes bound to PKCE S256 code challenges.
 */
export const oauthAuthCodes = sqliteTable("oauth_auth_codes", {
  codeHash: text("code_hash").primaryKey(),
  clientId: text("client_id")
    .notNull()
    .references(() => oauthClients.id, { onDelete: "cascade" }),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  machineIdentityId: text("machine_identity_id")
    .references(() => machineIdentities.id, { onDelete: "cascade" }),
  identityName: text("identity_name"),
  redirectUri: text("redirect_uri").notNull(),
  scopes: text("scopes").notNull(),
  codeChallenge: text("code_challenge").notNull(),
  codeChallengeMethod: text("code_challenge_method").notNull().default("S256"),
  resource: text("resource"),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  usedAt: integer("used_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

/**
 * Active Machine Identity OAuth access & refresh token pairs (HMAC-hashed at rest).
 */
export const machineTokens = sqliteTable("machine_tokens", {
  id: text("id").primaryKey(),
  machineIdentityId: text("machine_identity_id")
    .notNull()
    .references(() => machineIdentities.id, { onDelete: "cascade" }),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  clientId: text("client_id")
    .notNull()
    .references(() => oauthClients.id, { onDelete: "cascade" }),
  accessTokenHash: text("access_token_hash").notNull().unique(),
  refreshTokenHash: text("refresh_token_hash").notNull().unique(),
  scopes: text("scopes").notNull(),
  resource: text("resource"),
  accessTokenExpiresAt: integer("access_token_expires_at", {
    mode: "timestamp",
  }).notNull(),
  refreshTokenExpiresAt: integer("refresh_token_expires_at", {
    mode: "timestamp",
  }).notNull(),
  revokedAt: integer("revoked_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type OAuthAuthCode = typeof oauthAuthCodes.$inferSelect;
export type NewOAuthAuthCode = typeof oauthAuthCodes.$inferInsert;
export type MachineToken = typeof machineTokens.$inferSelect;
export type NewMachineToken = typeof machineTokens.$inferInsert;
