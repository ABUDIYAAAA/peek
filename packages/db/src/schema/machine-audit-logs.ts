import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";
import { machineIdentities } from "./machine-identities.js";

export const AUDIT_ACTION_TYPES = [
  "read",
  "create",
  "update",
  "delete",
  "execute",
] as const;

export type AuditActionType = (typeof AUDIT_ACTION_TYPES)[number];

export const AUDIT_STATUSES = ["success", "failed", "reverted"] as const;

export type AuditStatus = (typeof AUDIT_STATUSES)[number];

/**
 * Immutable, reversible audit log for every MCP action taken by a Machine Identity.
 * Captures `beforeState`, `afterState`, and `reverseAction` compensating metadata.
 */
export const machineAuditLogs = sqliteTable("machine_audit_logs", {
  id: text("id").primaryKey(),
  machineIdentityId: text("machine_identity_id")
    .notNull()
    .references(() => machineIdentities.id, { onDelete: "restrict" }),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  requestId: text("request_id").notNull(),
  toolName: text("tool_name").notNull(),
  actionType: text("action_type", { enum: AUDIT_ACTION_TYPES }).notNull(),
  scopeUsed: text("scope_used"),
  resourceType: text("resource_type"),
  resourceId: text("resource_id"),
  inputPayload: text("input_payload").notNull(),
  outputPayload: text("output_payload"),
  beforeState: text("before_state"),
  afterState: text("after_state"),
  reverseAction: text("reverse_action"),
  isReversible: integer("is_reversible", { mode: "boolean" })
    .notNull()
    .default(false),
  status: text("status", { enum: AUDIT_STATUSES }).notNull(),
  revertedAt: integer("reverted_at", { mode: "timestamp" }),
  revertedByUserId: text("reverted_by_user_id"),
  revertReason: text("revert_reason"),
  errorMessage: text("error_message"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  durationMs: integer("duration_ms").notNull(),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type MachineAuditLog = typeof machineAuditLogs.$inferSelect;
export type NewMachineAuditLog = typeof machineAuditLogs.$inferInsert;
