import {
  McpServer,
  WebStandardStreamableHTTPServerTransport,
} from "@modelcontextprotocol/server";
import { createMcpHonoApp } from "@modelcontextprotocol/hono";
import { z } from "@peek/core";
import type { Database } from "@peek/db";

export interface CreateMcpServerOptions {
  db?: Database;
  appName?: string;
  version?: string;
}

export function buildMcpServer(options: CreateMcpServerOptions = {}) {
  const { appName = "peek-mcp", version = "1.0.0" } = options;

  const server = new McpServer({
    name: appName,
    version,
  });

  // Example Ping tool to verify MCP protocol communication
  server.registerTool(
    "ping",
    {
      description: "Ping the Peek MCP server to test connectivity",
      inputSchema: {
        message: z
          .string()
          .optional()
          .describe("Optional message to echo back"),
      },
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

  return server;
}

export function createMcpRouter() {
  const mcpApp = createMcpHonoApp();

  mcpApp.all("/", async (c) => {
    const db = (c as any).var?.db as Database | undefined;
    const env = (c as any).var?.env;

    const server = buildMcpServer({
      db,
      appName: env?.APP_NAME ? `${env.APP_NAME}-mcp` : "peek-mcp",
      version: "0.0.1",
    });

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    await server.connect(transport);
    const parsedBody = (c as any).get("parsedBody");
    return transport.handleRequest(c.req.raw, { parsedBody });
  });

  return mcpApp;
}
