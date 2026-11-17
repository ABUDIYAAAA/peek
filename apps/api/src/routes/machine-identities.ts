import { Hono } from "hono";
import { requireAuth } from "../middleware/auth.js";
import type { AppEnv } from "../types.js";
import {
  getConnectConfigController,
  listIdentitiesController,
  getIdentityDetailsController,
  revokeIdentityController,
  listAllAuditLogsController,
  listIdentityAuditLogsController,
  revertSingleActionController,
  revertAllIdentityActionsController,
} from "../controllers/machine-identities.controller.js";

export const machineIdentitiesRouter = new Hono<AppEnv>();

// Strictly HTTP-only cookie authentication for all human/dashboard Machine Identity management routes
machineIdentitiesRouter.use("*", requireAuth());

// Phase 1 connect configuration snippet
machineIdentitiesRouter.get("/connect-config", getConnectConfigController);

// Global audit log inspection & single-action revert (must precede /:id routes)
machineIdentitiesRouter.get("/audit-logs", listAllAuditLogsController);
machineIdentitiesRouter.post(
  "/audit-logs/:logId/revert",
  revertSingleActionController,
);

// Machine Identity listing, detail, instant revocation & batch rollback
machineIdentitiesRouter.get("/", listIdentitiesController);
machineIdentitiesRouter.get("/:id", getIdentityDetailsController);
machineIdentitiesRouter.post("/:id/revoke", revokeIdentityController);
machineIdentitiesRouter.get("/:id/audit-logs", listIdentityAuditLogsController);
machineIdentitiesRouter.post(
  "/:id/revert-all",
  revertAllIdentityActionsController,
);
