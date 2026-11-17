import { Hono } from "hono";
import { requireAuth } from "../middleware/auth.js";
import type { AppEnv } from "../types.js";
import {
  initiateGitHubLogin,
  handleGitHubCallback,
  refreshToken,
  logout,
  getMe,
} from "../controllers/auth.controller.js";

export const authRouter = new Hono<AppEnv>();

// GitHub OAuth flow
authRouter.get("/github", initiateGitHubLogin);
authRouter.get("/github/callback", handleGitHubCallback);

// Session management
authRouter.post("/refresh", refreshToken);
authRouter.post("/logout", logout);

// Protected user profile
authRouter.get("/me", requireAuth(), getMe);
