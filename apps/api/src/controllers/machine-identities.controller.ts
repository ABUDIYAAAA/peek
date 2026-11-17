import type { Context } from "hono";
import {
  listMachineIdentities,
  getMachineIdentityDetails,
  revokeMachineIdentity,
  listAuditLogs,
  revertSingleAuditLog,
  revertAllForMachineIdentity,
  defaultCompensationDispatcher,
} from "@peek/auth";
import { getConnectConfig } from "../helpers/connect-config.js";
import type { AuditActionType, AuditStatus } from "@peek/db";
import { UnauthorizedError } from "@peek/core";
import type { AppEnv } from "../types.js";
import { respondSuccess } from "../helpers/respond.js";

/**
 * Phase 1 helper: returns the MCP Server URL and client-specific JSON configuration.
 */
export async function getConnectConfigController(
  c: Context<AppEnv>,
): Promise<Response> {
  const env = c.get("env");
  const client = c.req.query("client");
  const result = getConnectConfig(env.APP_URL, client);
  return respondSuccess(c, result);
}

/**
 * Lists all Machine Identities belonging to the authenticated user.
 */
export async function listIdentitiesController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  if (!user) throw new UnauthorizedError("Authentication required");

  const identities = await listMachineIdentities(db, user.sub);
  return respondSuccess(c, { identities });
}

/**
 * Fetches details and recent audit activity for a single Machine Identity.
 */
export async function getIdentityDetailsController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  if (!user) throw new UnauthorizedError("Authentication required");

  const id = c.req.param("id")!;
  const details = await getMachineIdentityDetails(db, user.sub, id);
  return respondSuccess(c, details);
}

/**
 * Instantly revokes a Machine Identity and all of its active OAuth tokens.
 */
export async function revokeIdentityController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  const logger = c.get("logger");
  if (!user) throw new UnauthorizedError("Authentication required");

  const id = c.req.param("id")!;
  const body = await c.req
    .json<{ reason?: string }>()
    .catch(() => ({ reason: undefined }));

  const revoked = await revokeMachineIdentity(db, user.sub, id, body.reason);

  logger?.warn("Instantly revoked Machine Identity and all associated tokens", {
    userId: user.sub,
    machineIdentityId: id,
    reason: revoked.revokedReason,
  });

  return respondSuccess(c, {
    identity: revoked,
    message: "Machine identity revoked immediately",
  });
}

/**
 * Lists audit logs across all of the user's Machine Identities.
 */
export async function listAllAuditLogsController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  if (!user) throw new UnauthorizedError("Authentication required");

  const actionType = c.req.query("actionType") as AuditActionType | undefined;
  const status = c.req.query("status") as AuditStatus | undefined;
  const machineIdentityId = c.req.query("machineIdentityId");
  const isReversibleParam = c.req.query("isReversible");
  const limitParam = c.req.query("limit");
  const offsetParam = c.req.query("offset");

  const logs = await listAuditLogs(db, user.sub, {
    machineIdentityId,
    actionType,
    status,
    isReversible:
      isReversibleParam === undefined
        ? undefined
        : isReversibleParam === "true",
    limit: limitParam ? parseInt(limitParam, 10) : undefined,
    offset: offsetParam ? parseInt(offsetParam, 10) : undefined,
  });

  return respondSuccess(c, { logs });
}

/**
 * Lists audit logs scoped to a specific Machine Identity.
 */
export async function listIdentityAuditLogsController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  if (!user) throw new UnauthorizedError("Authentication required");

  const machineIdentityId = c.req.param("id")!;
  const actionType = c.req.query("actionType") as AuditActionType | undefined;
  const status = c.req.query("status") as AuditStatus | undefined;
  const limitParam = c.req.query("limit");
  const offsetParam = c.req.query("offset");

  const logs = await listAuditLogs(db, user.sub, {
    machineIdentityId,
    actionType,
    status,
    limit: limitParam ? parseInt(limitParam, 10) : undefined,
    offset: offsetParam ? parseInt(offsetParam, 10) : undefined,
  });

  return respondSuccess(c, { logs });
}

/**
 * Reverts a single reversible action recorded in `machine_audit_logs`.
 */
export async function revertSingleActionController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  const logger = c.get("logger");
  if (!user) throw new UnauthorizedError("Authentication required");

  const logId = c.req.param("logId")!;
  const body = await c.req
    .json<{ reason?: string }>()
    .catch(() => ({ reason: undefined }));

  const result = await revertSingleAuditLog(
    db,
    user.sub,
    logId,
    body.reason,
    defaultCompensationDispatcher,
  );

  logger?.warn("Reverted Machine Identity audit action", {
    userId: user.sub,
    auditLogId: logId,
    strategy: result.strategyApplied,
  });

  return respondSuccess(c, result);
}

/**
 * Batch-reverts all un-reverted reversible actions taken by a Machine Identity in LIFO order.
 */
export async function revertAllIdentityActionsController(
  c: Context<AppEnv>,
): Promise<Response> {
  const db = c.get("db");
  const user = c.get("user");
  const logger = c.get("logger");
  if (!user) throw new UnauthorizedError("Authentication required");

  const machineIdentityId = c.req.param("id")!;
  const body = await c.req
    .json<{ reason?: string }>()
    .catch(() => ({ reason: undefined }));

  const result = await revertAllForMachineIdentity(
    db,
    user.sub,
    machineIdentityId,
    body.reason,
    defaultCompensationDispatcher,
  );

  logger?.warn("Batch-reverted Machine Identity actions", {
    userId: user.sub,
    machineIdentityId,
    revertedCount: result.revertedCount,
  });

  return respondSuccess(c, result);
}
