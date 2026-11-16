import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";
import { machineIdentities } from "./machine-identities.js";

export const PROGRESS_STATUSES = ["in_progress", "completed", "blocked"] as const;
export type ProgressStatus = (typeof PROGRESS_STATUSES)[number];

/**
 * Engineering progress updates submitted by developers or machine identities.
 */
export const engineeringProgress = sqliteTable("engineering_progress", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  machineIdentityId: text("machine_identity_id")
    .references(() => machineIdentities.id, { onDelete: "set null" }),
  summary: text("summary").notNull(),
  details: text("details"),
  blockers: text("blockers"),
  status: text("status", { enum: PROGRESS_STATUSES })
    .notNull()
    .default("in_progress"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type EngineeringProgress = typeof engineeringProgress.$inferSelect;
export type NewEngineeringProgress = typeof engineeringProgress.$inferInsert;
