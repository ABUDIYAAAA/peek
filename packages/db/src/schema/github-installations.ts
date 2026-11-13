import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./users.js";

export const githubInstallations = sqliteTable("github_installations", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  installationId: text("installation_id").notNull().unique(),
  targetId: text("target_id"),
  targetType: text("target_type", { enum: ["User", "Organization"] })
    .notNull()
    .default("User"),
  accountLogin: text("account_login").notNull(),
  accountAvatarUrl: text("account_avatar_url"),
  repositorySelection: text("repository_selection", {
    enum: ["all", "selected"],
  })
    .notNull()
    .default("all"),
  permissions: text("permissions"), // JSON stringified permissions
  installedAt: integer("installed_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export type GitHubInstallation = typeof githubInstallations.$inferSelect;
export type NewGitHubInstallation = typeof githubInstallations.$inferInsert;
