import {
  type Database,
  type MachineAuditLog,
  journalDrafts,
  engineeringProgress,
  eq,
  and,
} from "@peek/db";
import { BadRequestError, NotFoundError, UnauthorizedError } from "@peek/core";

export type ReverseActionStrategy =
  | "delete_created"
  | "restore_before_state"
  | "reinsert_deleted"
  | "custom"
  | "none";

export interface ReverseActionDescriptor {
  strategy: ReverseActionStrategy;
  table?: string;
  targetId?: string;
  compensatingData?: Record<string, unknown>;
}

export interface CompensationContext {
  userId: string;
  auditLog: MachineAuditLog;
  reverseAction: ReverseActionDescriptor;
}

export interface CompensationResult {
  strategyApplied: ReverseActionStrategy;
  note: string;
}

export type DomainCompensationHandler = (
  db: Database,
  ctx: CompensationContext,
) => Promise<CompensationResult>;

/**
 * Domain Compensation Dispatcher
 *
 * Executes real, verified database mutations to revert actions performed by Machine Identities.
 * Eliminates "placebo" reversibility by guaranteeing:
 * 1. Target entities exist and belong to the calling user (strict tenant isolation).
 * 2. Real table records are deleted, restored, or re-inserted.
 * 3. Audit log status is NEVER marked 'reverted' if domain mutation fails or cannot be executed.
 */
export class DomainCompensationDispatcher {
  private handlers = new Map<string, DomainCompensationHandler>();

  /**
   * Register a custom domain handler for a specific toolName, resourceType, or table.
   */
  public registerHandler(key: string, handler: DomainCompensationHandler): this {
    this.handlers.set(key, handler);
    return this;
  }

  /**
   * Executes compensation for an audit log entry.
   * Throws an error if compensation cannot be performed.
   */
  public async execute(
    db: Database,
    ctx: CompensationContext,
  ): Promise<CompensationResult> {
    const { auditLog, reverseAction, userId } = ctx;

    if (!auditLog.isReversible || reverseAction.strategy === "none") {
      throw new BadRequestError(
        `Audit log action "${auditLog.toolName}" (${auditLog.actionType}) has no reversible strategy configured`,
      );
    }

    // 1. Check for custom-registered handler (matching table, resourceType, or toolName)
    const customKey =
      (reverseAction.table && this.handlers.has(reverseAction.table))
        ? reverseAction.table
        : (auditLog.resourceType && this.handlers.has(auditLog.resourceType))
          ? auditLog.resourceType
          : (auditLog.toolName && this.handlers.has(auditLog.toolName))
            ? auditLog.toolName
            : null;

    if (customKey) {
      const handler = this.handlers.get(customKey)!;
      return await handler(db, ctx);
    }

    // 2. Resolve target table and id
    const table = reverseAction.table || auditLog.resourceType;
    const targetId = reverseAction.targetId || auditLog.resourceId;

    if (!table) {
      throw new BadRequestError(
        `Cannot compensate action "${auditLog.toolName}": target table/resourceType is missing`,
      );
    }

    if (reverseAction.strategy === "delete_created") {
      if (!targetId) {
        throw new BadRequestError(
          `Cannot execute delete_created: targetId is missing`,
        );
      }
      return await this.executeDeleteCreated(db, table, targetId, userId);
    }

    if (reverseAction.strategy === "restore_before_state") {
      if (!targetId) {
        throw new BadRequestError(
          `Cannot execute restore_before_state: targetId is missing`,
        );
      }
      return await this.executeRestoreBeforeState(
        db,
        table,
        targetId,
        userId,
        auditLog.beforeState,
      );
    }

    if (reverseAction.strategy === "custom") {
      throw new BadRequestError(
        `Custom compensation strategy requested for "${auditLog.toolName}", but no custom handler is registered for "${customKey || table}"`,
      );
    }

    throw new BadRequestError(
      `Unsupported compensation strategy "${reverseAction.strategy}" for table "${table}"`,
    );
  }

  private async executeDeleteCreated(
    db: Database,
    table: string,
    targetId: string,
    userId: string,
  ): Promise<CompensationResult> {
    switch (table) {
      case "journal_drafts": {
        const existing = await db.query.journalDrafts.findFirst({
          where: eq(journalDrafts.id, targetId),
        });

        if (!existing) {
          return {
            strategyApplied: "delete_created",
            note: `Journal draft (${targetId}) was already deleted`,
          };
        }

        if (existing.userId !== userId) {
          throw new UnauthorizedError(
            `Target journal draft (${targetId}) does not belong to user`,
          );
        }

        await db
          .delete(journalDrafts)
          .where(and(eq(journalDrafts.id, targetId), eq(journalDrafts.userId, userId)));

        return {
          strategyApplied: "delete_created",
          note: `Deleted created journal draft (${targetId})`,
        };
      }

      case "engineering_progress": {
        const existing = await db.query.engineeringProgress.findFirst({
          where: eq(engineeringProgress.id, targetId),
        });

        if (!existing) {
          return {
            strategyApplied: "delete_created",
            note: `Engineering progress update (${targetId}) was already deleted`,
          };
        }

        if (existing.userId !== userId) {
          throw new UnauthorizedError(
            `Target engineering progress update (${targetId}) does not belong to user`,
          );
        }

        await db
          .delete(engineeringProgress)
          .where(
            and(
              eq(engineeringProgress.id, targetId),
              eq(engineeringProgress.userId, userId),
            ),
          );

        return {
          strategyApplied: "delete_created",
          note: `Deleted created engineering progress update (${targetId})`,
        };
      }

      default:
        throw new BadRequestError(
          `No compensation delete handler registered for table "${table}"`,
        );
    }
  }

  private async executeRestoreBeforeState(
    db: Database,
    table: string,
    targetId: string,
    userId: string,
    beforeStateRaw: string | null,
  ): Promise<CompensationResult> {
    if (!beforeStateRaw) {
      throw new BadRequestError(
        `Cannot execute restore_before_state: beforeState snapshot is missing`,
      );
    }

    let beforeData: Record<string, unknown>;
    try {
      beforeData = JSON.parse(beforeStateRaw);
    } catch {
      throw new BadRequestError("Corrupted beforeState snapshot");
    }

    switch (table) {
      case "journal_drafts": {
        const existing = await db.query.journalDrafts.findFirst({
          where: eq(journalDrafts.id, targetId),
        });

        if (!existing) {
          throw new NotFoundError(
            `Target journal draft (${targetId}) not found to restore`,
          );
        }

        if (existing.userId !== userId) {
          throw new UnauthorizedError(
            `Target journal draft (${targetId}) does not belong to user`,
          );
        }

        const title =
          typeof beforeData.title === "string" ? beforeData.title : existing.title;
        const content =
          typeof beforeData.content === "string" ? beforeData.content : existing.content;
        const tags =
          typeof beforeData.tags === "string" ? beforeData.tags : existing.tags;

        await db
          .update(journalDrafts)
          .set({
            title,
            content,
            tags,
            updatedAt: new Date(),
          })
          .where(and(eq(journalDrafts.id, targetId), eq(journalDrafts.userId, userId)));

        return {
          strategyApplied: "restore_before_state",
          note: `Restored prior state for journal draft (${targetId})`,
        };
      }

      case "engineering_progress": {
        const existing = await db.query.engineeringProgress.findFirst({
          where: eq(engineeringProgress.id, targetId),
        });

        if (!existing) {
          throw new NotFoundError(
            `Target engineering progress update (${targetId}) not found to restore`,
          );
        }

        if (existing.userId !== userId) {
          throw new UnauthorizedError(
            `Target engineering progress update (${targetId}) does not belong to user`,
          );
        }

        const summary =
          typeof beforeData.summary === "string" ? beforeData.summary : existing.summary;
        const details =
          typeof beforeData.details === "string" ? beforeData.details : existing.details;
        const blockers =
          typeof beforeData.blockers === "string" ? beforeData.blockers : existing.blockers;
        const status =
          beforeData.status === "in_progress" ||
          beforeData.status === "completed" ||
          beforeData.status === "blocked"
            ? beforeData.status
            : existing.status;

        await db
          .update(engineeringProgress)
          .set({
            summary,
            details,
            blockers,
            status,
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(engineeringProgress.id, targetId),
              eq(engineeringProgress.userId, userId),
            ),
          );

        return {
          strategyApplied: "restore_before_state",
          note: `Restored prior state for engineering progress update (${targetId})`,
        };
      }

      default:
        throw new BadRequestError(
          `No compensation restore handler registered for table "${table}"`,
        );
    }
  }
}

/**
 * Default singleton instance with standard Peek domain handlers.
 */
export const defaultCompensationDispatcher = new DomainCompensationDispatcher();
