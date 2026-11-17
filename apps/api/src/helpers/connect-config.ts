export type SupportedMcpClient =
  | "antigravity"
  | "claude-code"
  | "cursor"
  | "windsurf"
  | "generic";

export interface McpConnectConfigResult {
  client: SupportedMcpClient;
  mcpServerUrl: string;
  configJson: Record<string, unknown>;
}

/**
 * Generates the remote MCP server URL and client-specific configuration snippet
 * for Phase 1 ("Connect coding agent").
 */
export function getConnectConfig(
  appUrl: string,
  rawClient?: string,
): McpConnectConfigResult {
  const normalized = (rawClient ?? "antigravity").toLowerCase();
  const validClients: SupportedMcpClient[] = [
    "antigravity",
    "claude-code",
    "cursor",
    "windsurf",
    "generic",
  ];
  const client: SupportedMcpClient = validClients.includes(
    normalized as SupportedMcpClient,
  )
    ? (normalized as SupportedMcpClient)
    : "generic";

  const baseUrl = appUrl.replace(/\/+$/, "");
  const mcpServerUrl = `${baseUrl}/mcp`;

  let configJson: Record<string, unknown>;

  switch (client) {
    case "antigravity":
      configJson = {
        mcpServers: {
          peek: {
            serverUrl: mcpServerUrl,
          },
        },
      };
      break;
    case "claude-code":
      configJson = {
        mcpServers: {
          peek: {
            type: "http",
            url: mcpServerUrl,
          },
        },
      };
      break;
    case "cursor":
    case "windsurf":
      configJson = {
        mcpServers: {
          peek: {
            url: mcpServerUrl,
          },
        },
      };
      break;
    case "generic":
    default:
      configJson = {
        mcpServers: {
          peek: {
            url: mcpServerUrl,
            transport: "streamable-http",
          },
        },
      };
      break;
  }

  return {
    client,
    mcpServerUrl,
    configJson,
  };
}
