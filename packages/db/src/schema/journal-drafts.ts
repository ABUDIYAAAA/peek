import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";
import { machineIdentities } from "./machine-identities.js";

/**
 * Engineering journal drafts created by users or machine identities.
 */
export const journalDrafts = sqliteTable("journal_drafts", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  machineIdentityId: text("machine_identity_id")
    .references(() => machineIdentities.id, { onDelete: "set null" }),
  title: text("title").notNull(),
  content: text("content").notNull(),
  tags: text("tags"), // JSON stringified array of tags
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type JournalDraft = typeof journalDrafts.$inferSelect;
export type NewJournalDraft = typeof journalDrafts.$inferInsert;
