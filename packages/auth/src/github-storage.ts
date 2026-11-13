import { eq } from "@peek/db";
import type { Database } from "@peek/db";
import { githubAccounts, githubInstallations } from "@peek/db";
import { encryptString, safeDecryptString } from "@peek/core";
import { refreshGitHubToken } from "./github.js";
import type {
  GitHubUserProfile,
  GitHubOAuthTokens,
  GitHubRawInstallation,
} from "./types.js";

/**
 * Stores or updates a GitHub account record, encrypting the access and refresh tokens
 * at rest with AES-256-GCM using `encryptionSecret`.
 */
export async function storeGitHubAccount(
  db: Database,
  userId: string,
  profile: GitHubUserProfile,
  tokens: GitHubOAuthTokens,
  encryptionSecret: string,
) {
  const githubUserId = String(profile.id);

  const existing = await db.query.githubAccounts.findFirst({
    where: eq(githubAccounts.githubUserId, githubUserId),
  });

  const now = new Date();

  // Encrypt sensitive OAuth tokens before persisting to D1
  const encryptedAccessToken = await encryptString(
    tokens.accessToken,
    encryptionSecret,
  );
  const encryptedRefreshToken = tokens.refreshToken
    ? await encryptString(tokens.refreshToken, encryptionSecret)
    : undefined;

  if (existing) {
    const [updated] = await db
      .update(githubAccounts)
      .set({
        userId,
        username: profile.login,
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken ?? existing.refreshToken,
        accessTokenExpiresAt:
          tokens.accessTokenExpiresAt ?? existing.accessTokenExpiresAt,
        refreshTokenExpiresAt:
          tokens.refreshTokenExpiresAt ?? existing.refreshTokenExpiresAt,
        scope: tokens.scope ?? existing.scope,
        tokenType: tokens.tokenType ?? existing.tokenType,
        updatedAt: now,
      })
      .where(eq(githubAccounts.id, existing.id))
      .returning();

    return updated ?? existing;
  }

  const [created] = await db
    .insert(githubAccounts)
    .values({
      id: crypto.randomUUID(),
      userId,
      githubUserId,
      username: profile.login,
      accessToken: encryptedAccessToken,
      refreshToken: encryptedRefreshToken,
      accessTokenExpiresAt: tokens.accessTokenExpiresAt,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      scope: tokens.scope,
      tokenType: tokens.tokenType,
      createdAt: now,
      updatedAt: now,
    })
    .returning();

  return created;
}

/**
 * Retrieves a GitHub account by user ID, decrypting the access and refresh tokens.
 */
export async function getDecryptedGitHubAccount(
  db: Database,
  userId: string,
  encryptionSecret: string,
) {
  const account = await db.query.githubAccounts.findFirst({
    where: eq(githubAccounts.userId, userId),
  });

  if (!account) {
    return null;
  }

  const decryptedAccessToken = await safeDecryptString(
    account.accessToken,
    encryptionSecret,
  );

  const decryptedRefreshToken = account.refreshToken
    ? await safeDecryptString(account.refreshToken, encryptionSecret)
    : null;

  return {
    ...account,
    accessToken: decryptedAccessToken,
    refreshToken: decryptedRefreshToken,
  };
}

/**
 * Refreshes an expired GitHub OAuth access token using the stored encrypted refresh token,
 * then persists the new encrypted tokens in D1.
 */
export async function refreshAndStoreGitHubTokens(
  db: Database,
  userId: string,
  options: {
    clientId: string;
    clientSecret: string;
    encryptionSecret: string;
  },
) {
  const account = await getDecryptedGitHubAccount(
    db,
    userId,
    options.encryptionSecret,
  );

  if (!account || !account.refreshToken) {
    throw new Error(
      "No refresh token available to refresh GitHub access credentials",
    );
  }

  const newTokens = await refreshGitHubToken({
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    refreshToken: account.refreshToken,
  });

  const encryptedAccessToken = await encryptString(
    newTokens.accessToken,
    options.encryptionSecret,
  );
  const encryptedRefreshToken = newTokens.refreshToken
    ? await encryptString(newTokens.refreshToken, options.encryptionSecret)
    : undefined;

  const [updated] = await db
    .update(githubAccounts)
    .set({
      accessToken: encryptedAccessToken,
      refreshToken: encryptedRefreshToken ?? account.refreshToken,
      accessTokenExpiresAt:
        newTokens.accessTokenExpiresAt ?? account.accessTokenExpiresAt,
      refreshTokenExpiresAt:
        newTokens.refreshTokenExpiresAt ?? account.refreshTokenExpiresAt,
      scope: newTokens.scope ?? account.scope,
      tokenType: newTokens.tokenType ?? account.tokenType,
      updatedAt: new Date(),
    })
    .where(eq(githubAccounts.id, account.id))
    .returning();

  return {
    account: updated,
    tokens: newTokens,
  };
}

export async function storeGitHubInstallation(
  db: Database,
  userId: string,
  installation: GitHubRawInstallation,
) {
  const installationIdStr = String(installation.id);

  const existing = await db.query.githubInstallations.findFirst({
    where: eq(githubInstallations.installationId, installationIdStr),
  });

  const now = new Date();
  const targetType =
    installation.account?.type === "Organization" ? "Organization" : "User";

  if (existing) {
    const [updated] = await db
      .update(githubInstallations)
      .set({
        userId,
        targetId: String(installation.account?.id ?? ""),
        targetType,
        accountLogin: installation.account?.login ?? "unknown",
        accountAvatarUrl: installation.account?.avatar_url,
        repositorySelection: installation.repository_selection ?? "all",
        permissions: JSON.stringify(installation.permissions ?? {}),
        updatedAt: now,
      })
      .where(eq(githubInstallations.id, existing.id))
      .returning();

    return updated ?? existing;
  }

  const [created] = await db
    .insert(githubInstallations)
    .values({
      id: crypto.randomUUID(),
      userId,
      installationId: installationIdStr,
      targetId: String(installation.account?.id ?? ""),
      targetType,
      accountLogin: installation.account?.login ?? "unknown",
      accountAvatarUrl: installation.account?.avatar_url,
      repositorySelection: installation.repository_selection ?? "all",
      permissions: JSON.stringify(installation.permissions ?? {}),
      installedAt: installation.created_at
        ? new Date(installation.created_at)
        : now,
      createdAt: now,
      updatedAt: now,
    })
    .returning();

  return created;
}

export async function syncUserInstallations(
  db: Database,
  userId: string,
  installations: GitHubRawInstallation[],
) {
  const results = [];
  for (const inst of installations) {
    const stored = await storeGitHubInstallation(db, userId, inst);
    if (stored) {
      results.push(stored);
    }
  }
  return results;
}
