import {
  eq,
  and,
  desc,
  type Database,
  type MachineIdentity,
  type MachineAuditLog,
} from "@peek/db";
import {
  machineIdentities,
  machineTokens,
  machineAuditLogs,
} from "@peek/db";
import { NotFoundError } from "@peek/core";

export async function listMachineIdentities(
  db: Database,
  userId: string,
): Promise<MachineIdentity[]> {
  return db
    .select()
    .from(machineIdentities)
    .where(eq(machineIdentities.userId, userId))
    .orderBy(desc(machineIdentities.createdAt));
}

export interface MachineIdentityDetailsResult {
  identity: MachineIdentity;
  recentAuditLogs: MachineAuditLog[];
}

export async function getMachineIdentityDetails(
  db: Database,
  userId: string,
  machineIdentityId: string,
): Promise<MachineIdentityDetailsResult> {
  const identity = await db.query.machineIdentities.findFirst({
    where: and(
      eq(machineIdentities.id, machineIdentityId),
      eq(machineIdentities.userId, userId),
    ),
  });

  if (!identity) {
    throw new NotFoundError("Machine identity not found");
  }

  const recentAuditLogs = await db
    .select()
    .from(machineAuditLogs)
    .where(
      and(
        eq(machineAuditLogs.machineIdentityId, machineIdentityId),
        eq(machineAuditLogs.userId, userId),
      ),
    )
    .orderBy(desc(machineAuditLogs.createdAt))
    .limit(25);

  return {
    identity,
    recentAuditLogs,
  };
}

/**
 * Instantly revokes a Machine Identity and all of its issued OAuth access & refresh tokens.
 */
export async function revokeMachineIdentity(
  db: Database,
  userId: string,
  machineIdentityId: string,
  reason?: string,
): Promise<MachineIdentity> {
  const existing = await db.query.machineIdentities.findFirst({
    where: and(
      eq(machineIdentities.id, machineIdentityId),
      eq(machineIdentities.userId, userId),
    ),
  });

  if (!existing) {
    throw new NotFoundError("Machine identity not found");
  }

  const now = new Date();
  const revokeReason = reason?.trim() || "Revoked by user";

  const [updated] = await db
    .update(machineIdentities)
    .set({
      revokedAt: existing.revokedAt ?? now,
      revokedReason: existing.revokedReason ?? revokeReason,
      updatedAt: now,
    })
    .where(
      and(
        eq(machineIdentities.id, machineIdentityId),
        eq(machineIdentities.userId, userId),
      ),
    )
    .returning();

  // Revoke every access and refresh token tied to this Machine Identity immediately
  await db
    .update(machineTokens)
    .set({ revokedAt: now })
    .where(eq(machineTokens.machineIdentityId, machineIdentityId));

  return updated ?? existing;
}
