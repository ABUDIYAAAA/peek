import { Hono } from "hono";
import {
  McpServer,
  WebStandardStreamableHTTPServerTransport,
  requireBearerAuth,
  getOAuthProtectedResourceMetadataUrl,
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
} from "@modelcontextprotocol/server";
import type { AppEnv } from "../types.js";
import { z, type BaseEnv, type Logger } from "@peek/core";
import {
  MCP_SCOPES,
  type Database,
  type McpScope,
  type AuditActionType,
  journalDrafts,
  engineeringProgress,
} from "@peek/db";
import {
  verifyMcpBearerToken,
  recordAuditLog,
  type VerifiedMcpSession,
  type ReverseActionDescriptor,
} from "@peek/auth";

/**
 * Builds RFC 9728 Protected Resource Metadata + RFC 8414 Authorization Server Metadata
 * options used by `oauthMetadataResponse`.
 */
export function buildOAuthMetadataOptions(env: BaseEnv) {
  const baseUrl = env.APP_URL.replace(/\/+$/, "");
  const resourceServerUrl = new URL(`${baseUrl}/mcp`);

  return {
    oauthMetadata: {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/api/v1/oauth/authorize`,
      token_endpoint: `${baseUrl}/api/v1/oauth/token`,
      registration_endpoint: `${baseUrl}/api/v1/oauth/register`,
      revocation_endpoint: `${baseUrl}/api/v1/oauth/revoke`,
      scopes_supported: [...MCP_SCOPES],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
    },
    resourceServerUrl,
    scopesSupported: [...MCP_SCOPES],
    resourceName: `${env.APP_NAME ?? "peek"} MCP Server`,
    dangerouslyAllowInsecureIssuerUrl: baseUrl.startsWith("http://"),
  };
}

export interface AuditedToolExecutionOutput {
  content: Array<{ type: "text"; text: string }>;
  resourceType?: string;
  resourceId?: string;
  beforeState?: unknown;
  afterState?: unknown;
  reverseAction?: ReverseActionDescriptor;
  isReversible?: boolean;
}

export interface BuildMcpServerOptions {
  db: Database;
  env: BaseEnv;
  session: VerifiedMcpSession;
  requestId: string;
  logger?: Logger;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Wraps `server.registerTool` with mandatory scope verification, structured logging,
 * and immutable `machine_audit_logs` capture (including before/after snapshots).
 */
function registerAuditedTool<TShape extends Record<string, z.ZodType>>(
  server: McpServer,
  ctx: BuildMcpServerOptions,
  config: {
    name: string;
    description: string;
    inputSchema: TShape;
    actionType: AuditActionType;
    requiredScope?: McpScope;
  },
  handler: (args: z.infer<z.ZodObject<TShape>>) => Promise<AuditedToolExecutionOutput>,
) {
  server.registerTool(
    config.name,
    {
      description: config.description,
      inputSchema: z.object(config.inputSchema),
    },
    async (rawArgs: z.infer<z.ZodObject<TShape>>) => {
      const start = Date.now();
      const args = rawArgs;

      // Enforce granular Machine Identity scope
      if (
        config.requiredScope &&
        !ctx.session.scopes.includes(config.requiredScope)
      ) {
        const errMsg = `Missing required MCP scope "${config.requiredScope}" on Machine Identity "${ctx.session.machineIdentity.name}"`;
        await recordAuditLog(ctx.db, {
          machineIdentityId: ctx.session.machineIdentity.id,
          userId: ctx.session.user.id,
          requestId: ctx.requestId,
          toolName: config.name,
          actionType: config.actionType,
          scopeUsed: config.requiredScope,
          inputPayload: args ?? {},
          status: "failed",
          errorMessage: errMsg,
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
          durationMs: Date.now() - start,
        });

        ctx.logger?.warn("MCP tool denied due to missing scope", {
          toolName: config.name,
          requiredScope: config.requiredScope,
          machineIdentityId: ctx.session.machineIdentity.id,
        });

        return {
          isError: true,
          content: [{ type: "text" as const, text: errMsg }],
        };
      }

      try {
        const result = await handler(args);
        const durationMs = Date.now() - start;

        const auditEntry = await recordAuditLog(ctx.db, {
          machineIdentityId: ctx.session.machineIdentity.id,
          userId: ctx.session.user.id,
          requestId: ctx.requestId,
          toolName: config.name,
          actionType: config.actionType,
          scopeUsed: config.requiredScope,
          resourceType: result.resourceType,
          resourceId: result.resourceId,
          inputPayload: args ?? {},
          outputPayload: result.content,
          beforeState: result.beforeState,
          afterState: result.afterState,
          reverseAction: result.reverseAction,
          isReversible: result.isReversible,
          status: "success",
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
          durationMs,
        });

        ctx.logger?.info("Executed audited MCP tool", {
          toolName: config.name,
          actionType: config.actionType,
          machineIdentityId: ctx.session.machineIdentity.id,
          auditLogId: auditEntry.id,
          durationMs,
        });

        return {
          content: result.content,
        };
      } catch (err) {
        const durationMs = Date.now() - start;
        const errMsg = err instanceof Error ? err.message : "Tool execution failed";

        await recordAuditLog(ctx.db, {
          machineIdentityId: ctx.session.machineIdentity.id,
          userId: ctx.session.user.id,
          requestId: ctx.requestId,
          toolName: config.name,
          actionType: config.actionType,
          scopeUsed: config.requiredScope,
          inputPayload: args ?? {},
          status: "failed",
          errorMessage: errMsg,
          ipAddress: ctx.ipAddress,
          userAgent: ctx.userAgent,
          durationMs,
        });

        ctx.logger?.error("MCP tool execution failed", {
          toolName: config.name,
          machineIdentityId: ctx.session.machineIdentity.id,
          error: errMsg,
          durationMs,
        });

        return {
          isError: true,
          content: [{ type: "text" as const, text: `Error: ${errMsg}` }],
        };
      }
    },
  );
}

export function buildMcpServer(ctx: BuildMcpServerOptions) {
  const appName = ctx.env.APP_NAME ? `${ctx.env.APP_NAME}-mcp` : "peek-mcp";
  const server = new McpServer({
    name: appName,
    version: "0.0.1",
  });

  // Connectivity check tool
  registerAuditedTool(
    server,
    ctx,
    {
      name: "ping",
      description: "Ping the Peek MCP server to test connectivity and audit logging",
      inputSchema: {
        message: z
          .string()
          .optional()
          .describe("Optional message to echo back"),
      },
      actionType: "execute",
    },
    async ({ message }) => {
      return {
        content: [
          {
            type: "text",
            text: message ? `pong: ${message}` : "pong",
          },
        ],
      };
    },
  );

  // Machine Identity & linked account introspection
  registerAuditedTool(
    server,
    ctx,
    {
      name: "whoami_machine",
      description:
        "Inspect the currently authenticated Machine Identity, linked PEEK account, and granted scopes",
      inputSchema: {},
      actionType: "read",
    },
    async () => {
      const payload = {
        machineIdentity: {
          id: ctx.session.machineIdentity.id,
          name: ctx.session.machineIdentity.name,
          clientId: ctx.session.machineIdentity.clientId,
          grantedScopes: ctx.session.scopes,
        },
        linkedUser: {
          id: ctx.session.user.id,
          username: ctx.session.user.username,
          email: ctx.session.user.email,
          role: ctx.session.user.role,
        },
      };

      return {
        resourceType: "machine_identity",
        resourceId: ctx.session.machineIdentity.id,
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
      };
    },
  );

  // Scoped workspace status check
  registerAuditedTool(
    server,
    ctx,
    {
      name: "peek_workspace_status",
      description: "Read high-level workspace status and granted project capabilities",
      inputSchema: {},
      actionType: "read",
      requiredScope: "projects:read",
    },
    async () => {
      return {
        resourceType: "workspace",
        resourceId: ctx.session.user.id,
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                workspaceOwner: ctx.session.user.username,
                machineIdentity: ctx.session.machineIdentity.name,
                status: "connected",
                activeScopes: ctx.session.scopes,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Create journal draft (journals:write) - fully audited and reversible
  registerAuditedTool(
    server,
    ctx,
    {
      name: "create_journal_draft",
      description:
        "Create an engineering journal draft entry in your PEEK workspace",
      inputSchema: {
        title: z.string().describe("Title of the journal entry"),
        content: z.string().describe("Markdown content of the journal draft"),
        tags: z
          .array(z.string())
          .optional()
          .describe("Optional tags to organize the entry"),
      },
      actionType: "create",
      requiredScope: "journals:write",
    },
    async (args) => {
      const draftId = crypto.randomUUID();
      const now = new Date();
      const tagsJson = args.tags ? JSON.stringify(args.tags) : null;

      const [draft] = await ctx.db
        .insert(journalDrafts)
        .values({
          id: draftId,
          userId: ctx.session.user.id,
          machineIdentityId: ctx.session.machineIdentity.id,
          title: args.title,
          content: args.content,
          tags: tagsJson,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      if (!draft) {
        throw new Error("Failed to create journal draft");
      }

      return {
        resourceType: "journal_drafts",
        resourceId: draft.id,
        afterState: draft,
        reverseAction: {
          strategy: "delete_created",
          table: "journal_drafts",
          targetId: draft.id,
        },
        isReversible: true,
        content: [
          {
            type: "text",
            text: `Created journal draft "${draft.title}" with ID ${draft.id}`,
          },
        ],
      };
    },
  );

  // Submit engineering progress (progress:write) - fully audited and reversible
  registerAuditedTool(
    server,
    ctx,
    {
      name: "submit_engineering_progress",
      description: "Log an engineering progress update in your PEEK workspace",
      inputSchema: {
        summary: z.string().describe("Summary of progress made"),
        details: z.string().optional().describe("Additional technical details"),
        blockers: z.string().optional().describe("Any blockers or impediments"),
        status: z
          .enum(["in_progress", "completed", "blocked"])
          .default("in_progress")
          .describe("Current progress status"),
      },
      actionType: "create",
      requiredScope: "progress:write",
    },
    async (args) => {
      const progressId = crypto.randomUUID();
      const now = new Date();

      const [progress] = await ctx.db
        .insert(engineeringProgress)
        .values({
          id: progressId,
          userId: ctx.session.user.id,
          machineIdentityId: ctx.session.machineIdentity.id,
          summary: args.summary,
          details: args.details ?? null,
          blockers: args.blockers ?? null,
          status: args.status,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      if (!progress) {
        throw new Error("Failed to log engineering progress");
      }

      return {
        resourceType: "engineering_progress",
        resourceId: progress.id,
        afterState: progress,
        reverseAction: {
          strategy: "delete_created",
          table: "engineering_progress",
          targetId: progress.id,
        },
        isReversible: true,
        content: [
          {
            type: "text",
            text: `Logged engineering progress update with ID ${progress.id}: "${progress.summary}"`,
          },
        ],
      };
    },
  );

  return server;
}

export function createMcpRouter() {
  const mcpApp = new Hono<AppEnv>();

  mcpApp.all("/", async (c) => {
    const db = c.get("db");
    const env = c.get("env");
    const logger = c.get("logger");
    const requestId = c.get("requestId") ?? crypto.randomUUID();

    if (!db || !env) {
      return c.json({ error: "server_error", error_description: "Server context unavailable" }, 500);
    }

    const baseUrl = env.APP_URL.replace(/\/+$/, "");
    const resourceUrl = new URL(`${baseUrl}/mcp`);
    const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);

    let verifiedSession: VerifiedMcpSession | undefined;
    const ipAddress =
      c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for");
    const userAgent = c.req.header("user-agent");

    const gate = requireBearerAuth({
      resourceMetadataUrl,
      verifier: {
        async verifyAccessToken(token: string): Promise<AuthInfo> {
          try {
            verifiedSession = await verifyMcpBearerToken(
              db,
              env,
              token,
              ipAddress,
            );
          } catch (err) {
            const msg =
              err instanceof Error
                ? err.message
                : "Invalid or revoked MCP token";
            logger?.warn("MCP Bearer authentication failed", { reason: msg });
            throw new OAuthError(OAuthErrorCode.InvalidToken, msg);
          }

          return {
            token,
            clientId: verifiedSession.machineIdentity.clientId,
            scopes: verifiedSession.scopes,
            expiresAt: verifiedSession.expiresAtSeconds,
            extra: {
              machineIdentityId: verifiedSession.machineIdentity.id,
              machineIdentityName: verifiedSession.machineIdentity.name,
              userId: verifiedSession.user.id,
              username: verifiedSession.user.username,
              role: verifiedSession.user.role,
            },
          };
        },
      },
    });

    const authResult = await gate(c.req.raw);
    if (authResult instanceof Response) {
      return authResult;
    }

    if (!verifiedSession) {
      return c.json({ error: "invalid_token" }, 401);
    }

    const server = buildMcpServer({
      db,
      env,
      session: verifiedSession,
      requestId,
      logger,
      ipAddress,
      userAgent,
    });

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    await server.connect(transport);
    return transport.handleRequest(c.req.raw, {
      authInfo: authResult,
    });
  });

  return mcpApp;
}
