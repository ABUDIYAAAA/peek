import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";

/**
 * Dynamically registered or known OAuth 2.1 / MCP clients (RFC 7591),
 * such as Antigravity, Cursor, Claude Code, etc.
 */
export const oauthClients = sqliteTable("oauth_clients", {
  id: text("id").primaryKey(),
  clientName: text("client_name").notNull(),
  clientUri: text("client_uri"),
  logoUri: text("logo_uri"),
  redirectUris: text("redirect_uris").notNull(),
  grantTypes: text("grant_types")
    .notNull()
    .default('["authorization_code","refresh_token"]'),
  responseTypes: text("response_types").notNull().default('["code"]'),
  tokenEndpointAuthMethod: text("token_endpoint_auth_method")
    .notNull()
    .default("none"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type OAuthClient = typeof oauthClients.$inferSelect;
export type NewOAuthClient = typeof oauthClients.$inferInsert;
