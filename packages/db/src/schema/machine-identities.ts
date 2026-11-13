import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";
import { oauthClients } from "./oauth-clients.js";

export const MCP_SCOPES = [
  "projects:read",
  "sprints:read",
  "progress:write",
  "journals:write",
] as const;

export type McpScope = (typeof MCP_SCOPES)[number];

/**
 * An authorized coding agent installation ("Machine Identity") linked to a PEEK user account.
 */
export const machineIdentities = sqliteTable("machine_identities", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  clientId: text("client_id")
    .notNull()
    .references(() => oauthClients.id),
  name: text("name").notNull(),
  scopes: text("scopes").notNull(),
  metadata: text("metadata"),
  lastUsedAt: integer("last_used_at", { mode: "timestamp" }),
  lastIpAddress: text("last_ip_address"),
  revokedAt: integer("revoked_at", { mode: "timestamp" }),
  revokedReason: text("revoked_reason"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type MachineIdentity = typeof machineIdentities.$inferSelect;
export type NewMachineIdentity = typeof machineIdentities.$inferInsert;
