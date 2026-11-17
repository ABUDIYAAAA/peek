import { relations } from "drizzle-orm";
import { users } from "./users.js";
import { oauthClients } from "./oauth-clients.js";
import { machineIdentities } from "./machine-identities.js";
import { machineTokens, oauthAuthCodes } from "./oauth-tokens.js";
import { machineAuditLogs } from "./machine-audit-logs.js";
import { journalDrafts } from "./journal-drafts.js";
import { engineeringProgress } from "./engineering-progress.js";

export const usersRelations = relations(users, ({ many }) => ({
  machineIdentities: many(machineIdentities),
  machineTokens: many(machineTokens),
  machineAuditLogs: many(machineAuditLogs),
  journalDrafts: many(journalDrafts),
  engineeringProgress: many(engineeringProgress),
}));

export const oauthClientsRelations = relations(oauthClients, ({ many }) => ({
  machineIdentities: many(machineIdentities),
  machineTokens: many(machineTokens),
  authCodes: many(oauthAuthCodes),
}));

export const machineIdentitiesRelations = relations(
  machineIdentities,
  ({ one, many }) => ({
    user: one(users, {
      fields: [machineIdentities.userId],
      references: [users.id],
    }),
    client: one(oauthClients, {
      fields: [machineIdentities.clientId],
      references: [oauthClients.id],
    }),
    tokens: many(machineTokens),
    auditLogs: many(machineAuditLogs),
  }),
);

export const machineTokensRelations = relations(machineTokens, ({ one }) => ({
  machineIdentity: one(machineIdentities, {
    fields: [machineTokens.machineIdentityId],
    references: [machineIdentities.id],
  }),
  user: one(users, {
    fields: [machineTokens.userId],
    references: [users.id],
  }),
  client: one(oauthClients, {
    fields: [machineTokens.clientId],
    references: [oauthClients.id],
  }),
}));

export const oauthAuthCodesRelations = relations(oauthAuthCodes, ({ one }) => ({
  client: one(oauthClients, {
    fields: [oauthAuthCodes.clientId],
    references: [oauthClients.id],
  }),
  user: one(users, {
    fields: [oauthAuthCodes.userId],
    references: [users.id],
  }),
  machineIdentity: one(machineIdentities, {
    fields: [oauthAuthCodes.machineIdentityId],
    references: [machineIdentities.id],
  }),
}));

export const machineAuditLogsRelations = relations(
  machineAuditLogs,
  ({ one }) => ({
    machineIdentity: one(machineIdentities, {
      fields: [machineAuditLogs.machineIdentityId],
      references: [machineIdentities.id],
    }),
    user: one(users, {
      fields: [machineAuditLogs.userId],
      references: [users.id],
    }),
  }),
);

export const journalDraftsRelations = relations(journalDrafts, ({ one }) => ({
  user: one(users, {
    fields: [journalDrafts.userId],
    references: [users.id],
  }),
  machineIdentity: one(machineIdentities, {
    fields: [journalDrafts.machineIdentityId],
    references: [machineIdentities.id],
  }),
}));

export const engineeringProgressRelations = relations(
  engineeringProgress,
  ({ one }) => ({
    user: one(users, {
      fields: [engineeringProgress.userId],
      references: [users.id],
    }),
    machineIdentity: one(machineIdentities, {
      fields: [engineeringProgress.machineIdentityId],
      references: [machineIdentities.id],
    }),
  }),
);
