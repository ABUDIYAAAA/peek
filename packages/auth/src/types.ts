import type {
  UserRole,
  User,
  GitHubAccount,
  GitHubInstallation,
} from "@peek/db";

export type { UserRole, User, GitHubAccount, GitHubInstallation };

export interface AuthUser {
  id: string;
  githubId?: string | null;
  username: string;
  email: string;
  name?: string | null;
  avatarUrl?: string | null;
  role: UserRole;
}

export interface JwtPayload {
  sub: string;
  role: UserRole;
  username: string;
  email: string;
  iat: number;
  exp: number;
}

export interface CookieConfig {
  accessName: string;
  refreshName: string;
  domain?: string;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  accessMaxAgeSeconds: number;
  refreshMaxAgeSeconds: number;
}

export interface GitHubUserProfile {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
}

export interface GitHubEmailRecord {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: string | null;
}

export interface GitHubOAuthTokens {
  accessToken: string;
  refreshToken?: string;
  accessTokenExpiresAt?: Date;
  refreshTokenExpiresAt?: Date;
  scope?: string;
  tokenType: string;
}

export interface GitHubRawInstallation {
  id: number;
  account: {
    id: number;
    login: string;
    type: "User" | "Organization" | string;
    avatar_url?: string;
  };
  repository_selection: "all" | "selected";
  permissions: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}
