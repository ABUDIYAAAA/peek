import {
  type Database,
  oauthAuthCodes,
  sessions,
  machineTokens,
  lte,
  isNotNull,
  or,
  and,
} from "@peek/db";

export interface PruneOptions {
  /**
   * Grace period buffer in days for revoked machine tokens to remain queryable for audit logs.
   * Defaults to 7 days.
   */
  revokedTokenGraceDays?: number;
  now?: Date;
}

export interface PruneResult {
  prunedAuthCodes: number;
  prunedSessions: number;
  prunedMachineTokens: number;
  timestamp: Date;
}

/**
 * Prunes expired and consumed ephemeral authentication records from Cloudflare D1.
 * Addresses FINDING-07: prevents unbounded accumulation of PKCE auth codes, sessions, and tokens.
 */
export async function pruneExpiredAuthRecords(
  db: Database,
  options: PruneOptions = {},
): Promise<PruneResult> {
  const now = options.now ?? new Date();
  const graceDays = options.revokedTokenGraceDays ?? 7;
  const revokedGraceDate = new Date(
    now.getTime() - graceDays * 24 * 60 * 60 * 1000,
  );

  // 1. Prune expired or consumed PKCE authorization codes (10 min lifespan)
  const deletedCodes = await db
    .delete(oauthAuthCodes)
    .where(
      or(
        isNotNull(oauthAuthCodes.usedAt),
        lte(oauthAuthCodes.expiresAt, now),
      ),
    )
    .returning({ codeHash: oauthAuthCodes.codeHash });

  // 2. Prune expired or revoked user sessions
  const deletedSessions = await db
    .delete(sessions)
    .where(
      or(
        isNotNull(sessions.revokedAt),
        lte(sessions.expiresAt, now),
      ),
    )
    .returning({ id: sessions.id });

  // 3. Prune expired machine tokens (refresh token expired OR revoked beyond grace period)
  const deletedTokens = await db
    .delete(machineTokens)
    .where(
      or(
        lte(machineTokens.refreshTokenExpiresAt, now),
        and(
          isNotNull(machineTokens.revokedAt),
          lte(machineTokens.revokedAt, revokedGraceDate),
        ),
      ),
    )
    .returning({ id: machineTokens.id });

  return {
    prunedAuthCodes: deletedCodes.length,
    prunedSessions: deletedSessions.length,
    prunedMachineTokens: deletedTokens.length,
    timestamp: now,
  };
}
