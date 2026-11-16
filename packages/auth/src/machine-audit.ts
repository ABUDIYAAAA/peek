import {
  eq,
  and,
  desc,
  type Database,
  type AuditActionType,
  type AuditStatus,
  type MachineAuditLog,
} from "@peek/db";
import { machineAuditLogs, machineIdentities } from "@peek/db";
import { BadRequestError, NotFoundError } from "@peek/core";
import {
  defaultCompensationDispatcher,
  type DomainCompensationDispatcher,
  type ReverseActionDescriptor,
  type ReverseActionStrategy,
  type CompensationResult,
} from "./domain-compensation.js";

export * from "./domain-compensation.js";

export interface RecordAuditLogInput {
  machineIdentityId: string;
  userId: string;
  requestId: string;
  toolName: string;
  actionType: AuditActionType;
  scopeUsed?: string;
  resourceType?: string;
  resourceId?: string;
  inputPayload: unknown;
  outputPayload?: unknown;
  beforeState?: unknown;
  afterState?: unknown;
  reverseAction?: ReverseActionDescriptor;
  isReversible?: boolean;
  status: "success" | "failed";
  errorMessage?: string;
  ipAddress?: string;
  userAgent?: string;
  durationMs: number;
}

function safeJsonStringify(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

/**
 * Records an immutable audit log entry for an MCP action taken by a Machine Identity.
 */
export async function recordAuditLog(
  db: Database,
  input: RecordAuditLogInput,
): Promise<MachineAuditLog> {
  const id = crypto.randomUUID();
  const now = new Date();
  const isReversible =
    input.isReversible ??
    Boolean(input.reverseAction && input.reverseAction.strategy !== "none");

  const [created] = await db
    .insert(machineAuditLogs)
    .values({
      id,
      machineIdentityId: input.machineIdentityId,
      userId: input.userId,
      requestId: input.requestId,
      toolName: input.toolName,
      actionType: input.actionType,
      scopeUsed: input.scopeUsed ?? null,
      resourceType: input.resourceType ?? null,
      resourceId: input.resourceId ?? null,
      inputPayload: safeJsonStringify(input.inputPayload) ?? "{}",
      outputPayload: safeJsonStringify(input.outputPayload),
      beforeState: safeJsonStringify(input.beforeState),
      afterState: safeJsonStringify(input.afterState),
      reverseAction: safeJsonStringify(input.reverseAction),
      isReversible,
      status: input.status,
      errorMessage: input.errorMessage ?? null,
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
      durationMs: Math.max(0, Math.round(input.durationMs)),
      createdAt: now,
    })
    .returning();

  if (!created) {
    throw new Error("Failed to persist machine audit log");
  }

  return created;
}

export interface ListAuditLogsFilters {
  machineIdentityId?: string;
  actionType?: AuditActionType;
  status?: AuditStatus;
  isReversible?: boolean;
  limit?: number;
  offset?: number;
}

export async function listAuditLogs(
  db: Database,
  userId: string,
  filters: ListAuditLogsFilters = {},
): Promise<MachineAuditLog[]> {
  const conditions = [eq(machineAuditLogs.userId, userId)];

  if (filters.machineIdentityId) {
    conditions.push(
      eq(machineAuditLogs.machineIdentityId, filters.machineIdentityId),
    );
  }
  if (filters.actionType) {
    conditions.push(eq(machineAuditLogs.actionType, filters.actionType));
  }
  if (filters.status) {
    conditions.push(eq(machineAuditLogs.status, filters.status));
  }
  if (filters.isReversible !== undefined) {
    conditions.push(eq(machineAuditLogs.isReversible, filters.isReversible));
  }

  const limit = Math.min(Math.max(filters.limit ?? 50, 1), 200);
  const offset = Math.max(filters.offset ?? 0, 0);

  return db
    .select()
    .from(machineAuditLogs)
    .where(and(...conditions))
    .orderBy(desc(machineAuditLogs.createdAt))
    .limit(limit)
    .offset(offset);
}

export type CustomRevertExecutor = (
  db: Database,
  log: MachineAuditLog,
  reverseAction: ReverseActionDescriptor,
) => Promise<void>;

export interface RevertExecutionResult {
  auditLog: MachineAuditLog;
  strategyApplied: ReverseActionStrategy;
  note: string;
}

/**
 * Reverts a single reversible Machine Identity audit log action.
 * Validates ownership, reversibility, and executes real compensating domain mutations.
 * If domain compensation fails, the audit log status is NOT changed.
 */
export async function revertSingleAuditLog(
  db: Database,
  userId: string,
  auditLogId: string,
  reason?: string,
  dispatcherOrExecutor?: DomainCompensationDispatcher | CustomRevertExecutor,
): Promise<RevertExecutionResult> {
  const log = await db.query.machineAuditLogs.findFirst({
    where: and(
      eq(machineAuditLogs.id, auditLogId),
      eq(machineAuditLogs.userId, userId),
    ),
  });

  if (!log) {
    throw new NotFoundError("Audit log entry not found");
  }

  if (!log.isReversible) {
    throw new BadRequestError(
      `Audit log "${log.toolName}" (${log.actionType}) is not reversible`,
    );
  }

  if (log.status === "reverted") {
    throw new BadRequestError("Audit log action has already been reverted");
  }

  if (log.status !== "success") {
    throw new BadRequestError(
      `Cannot revert audit log with status "${log.status}"`,
    );
  }

  let reverseAction: ReverseActionDescriptor = { strategy: "none" };
  if (log.reverseAction) {
    try {
      reverseAction = JSON.parse(log.reverseAction) as ReverseActionDescriptor;
    } catch {
      throw new BadRequestError("Corrupted reverse_action descriptor");
    }
  }

  if (reverseAction.strategy === "none") {
    throw new BadRequestError(
      `Audit log "${log.toolName}" has no reversible strategy configured`,
    );
  }

  // Execute real domain compensation before updating audit log status
  let compResult: CompensationResult;
  if (typeof dispatcherOrExecutor === "function") {
    await dispatcherOrExecutor(db, log, reverseAction);
    compResult = {
      strategyApplied: reverseAction.strategy,
      note: `Reverted via custom executor (${reverseAction.strategy})`,
    };
  } else {
    const dispatcher = dispatcherOrExecutor ?? defaultCompensationDispatcher;
    compResult = await dispatcher.execute(db, {
      userId,
      auditLog: log,
      reverseAction,
    });
  }

  const now = new Date();
  const [updated] = await db
    .update(machineAuditLogs)
    .set({
      status: "reverted",
      revertedAt: now,
      revertedByUserId: userId,
      revertReason: reason?.trim() || "Reverted by user",
    })
    .where(
      and(
        eq(machineAuditLogs.id, log.id),
        eq(machineAuditLogs.userId, userId),
      ),
    )
    .returning();

  return {
    auditLog: updated ?? {
      ...log,
      status: "reverted",
      revertedAt: now,
      revertedByUserId: userId,
      revertReason: reason?.trim() || "Reverted by user",
    },
    strategyApplied: compResult.strategyApplied,
    note: compResult.note,
  };
}

export interface BatchRevertResult {
  machineIdentityId: string;
  revertedCount: number;
  results: RevertExecutionResult[];
}

/**
 * Reverts all un-reverted reversible actions taken by a Machine Identity
 * in strict reverse chronological (LIFO) order.
 */
export async function revertAllForMachineIdentity(
  db: Database,
  userId: string,
  machineIdentityId: string,
  reason?: string,
  dispatcherOrExecutor?: DomainCompensationDispatcher | CustomRevertExecutor,
): Promise<BatchRevertResult> {
  const identity = await db.query.machineIdentities.findFirst({
    where: and(
      eq(machineIdentities.id, machineIdentityId),
      eq(machineIdentities.userId, userId),
    ),
  });

  if (!identity) {
    throw new NotFoundError("Machine identity not found");
  }

  const logsToRevert = await db
    .select()
    .from(machineAuditLogs)
    .where(
      and(
        eq(machineAuditLogs.machineIdentityId, machineIdentityId),
        eq(machineAuditLogs.userId, userId),
        eq(machineAuditLogs.status, "success"),
        eq(machineAuditLogs.isReversible, true),
      ),
    )
    .orderBy(desc(machineAuditLogs.createdAt));

  const results: RevertExecutionResult[] = [];
  for (const log of logsToRevert) {
    try {
      const res = await revertSingleAuditLog(
        db,
        userId,
        log.id,
        reason ?? `Batch revert for Machine Identity ${identity.name}`,
        dispatcherOrExecutor,
      );
      results.push(res);
    } catch {
      // Continue best-effort for remaining actions if a single action fails
    }
  }

  return {
    machineIdentityId,
    revertedCount: results.length,
    results,
  };
}
