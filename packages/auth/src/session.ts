import { eq, and, isNull, gt } from "@peek/db";
import type { Database, User } from "@peek/db";
import { users, sessions } from "@peek/db";
import { UnauthorizedError } from "@peek/core";
import { parseDurationToSeconds } from "./jwt.js";
import type { GitHubUserProfile } from "./types.js";

async function getHmacKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

export async function hashRefreshToken(
  token: string,
  secret: string,
): Promise<string> {
  const key = await getHmacKey(secret);
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(token),
  );
  return Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateSecureRandomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function syncUserFromGitHub(
  db: Database,
  profile: GitHubUserProfile,
  primaryEmail: string,
): Promise<User> {
  const githubIdStr = String(profile.id);

  // 1. Try to find user by GitHub ID
  const existingByGithub = await db.query.users.findFirst({
    where: eq(users.githubId, githubIdStr),
  });

  if (existingByGithub) {
    // Update profile fields but strictly preserve existing role
    const [updated] = await db
      .update(users)
      .set({
        username: profile.login,
        name: profile.name ?? existingByGithub.name,
        avatarUrl: profile.avatar_url ?? existingByGithub.avatarUrl,
        email: primaryEmail || existingByGithub.email,
        updatedAt: new Date(),
      })
      .where(eq(users.id, existingByGithub.id))
      .returning();

    return updated ?? existingByGithub;
  }

  // 2. Try to find user by email
  const existingByEmail = await db.query.users.findFirst({
    where: eq(users.email, primaryEmail),
  });

  if (existingByEmail) {
    // Link GitHub ID to existing user account and preserve role
    const [updated] = await db
      .update(users)
      .set({
        githubId: githubIdStr,
        username: profile.login,
        name: profile.name ?? existingByEmail.name,
        avatarUrl: profile.avatar_url ?? existingByEmail.avatarUrl,
        updatedAt: new Date(),
      })
      .where(eq(users.id, existingByEmail.id))
      .returning();

    return updated ?? existingByEmail;
  }

  // 3. Create fresh user with default role: 'user'
  const newUserId = crypto.randomUUID();
  const [created] = await db
    .insert(users)
    .values({
      id: newUserId,
      githubId: githubIdStr,
      username: profile.login,
      email: primaryEmail,
      name: profile.name ?? profile.login,
      avatarUrl: profile.avatar_url,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    })
    .returning();

  if (!created) {
    throw new Error("Failed to create user in database");
  }

  return created;
}

export async function createSession(
  db: Database,
  userId: string,
  secret: string,
  options: {
    userAgent?: string;
    ipAddress?: string;
    duration?: string;
  } = {},
): Promise<{ sessionId: string; rawRefreshToken: string; expiresAt: Date }> {
  const rawRefreshToken = generateSecureRandomToken();
  const tokenHash = await hashRefreshToken(rawRefreshToken, secret);
  const durationSeconds = parseDurationToSeconds(options.duration ?? "30d");
  const expiresAt = new Date(Date.now() + durationSeconds * 1000);
  const sessionId = crypto.randomUUID();

  await db.insert(sessions).values({
    id: sessionId,
    userId,
    tokenHash,
    userAgent: options.userAgent,
    ipAddress: options.ipAddress,
    expiresAt,
    createdAt: new Date(),
  });

  return { sessionId, rawRefreshToken, expiresAt };
}

export async function validateAndRotateSession(
  db: Database,
  rawRefreshToken: string,
  secret: string,
  options: {
    userAgent?: string;
    ipAddress?: string;
    duration?: string;
  } = {},
): Promise<{ user: User; newRefreshToken: string }> {
  const tokenHash = await hashRefreshToken(rawRefreshToken, secret);
  const now = new Date();

  // Atomically claim and revoke the existing session in a single statement.
  // Concurrency guard: only the single thread that transitions revokedAt from NULL succeeds.
  const [session] = await db
    .update(sessions)
    .set({ revokedAt: now })
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now),
      ),
    )
    .returning();

  if (!session) {
    throw new UnauthorizedError("Invalid or expired refresh token");
  }

  // Find associated user
  const user = await db.query.users.findFirst({
    where: eq(users.id, session.userId),
  });

  if (!user) {
    throw new UnauthorizedError("User account not found");
  }

  // Create new rotated session using the same refresh secret
  const newSession = await createSession(db, user.id, secret, {
    userAgent: options.userAgent ?? session.userAgent ?? undefined,
    ipAddress: options.ipAddress ?? session.ipAddress ?? undefined,
    duration: options.duration,
  });

  return {
    user,
    newRefreshToken: newSession.rawRefreshToken,
  };
}

export async function revokeSession(
  db: Database,
  rawRefreshToken: string,
  secret: string,
): Promise<void> {
  const tokenHash = await hashRefreshToken(rawRefreshToken, secret);
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.tokenHash, tokenHash));
}
