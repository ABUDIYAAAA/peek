import { BadRequestError } from "@peek/core";
import { MCP_SCOPES, type McpScope } from "@peek/db";

export interface McpScopeDefinition {
  scope: McpScope;
  title: string;
  description: string;
}

export const MCP_SCOPE_DEFINITIONS: Record<McpScope, McpScopeDefinition> = {
  "projects:read": {
    scope: "projects:read",
    title: "Read projects and goals",
    description: "View your PEEK workspace projects, metadata, and project goals.",
  },
  "sprints:read": {
    scope: "sprints:read",
    title: "Read sprint information",
    description: "View sprint cycles, velocity, and sprint task assignments.",
  },
  "progress:write": {
    scope: "progress:write",
    title: "Submit engineering progress",
    description: "Log engineering progress updates and status entries on your behalf.",
  },
  "journals:write": {
    scope: "journals:write",
    title: "Create journal drafts",
    description: "Create and edit draft engineering journal entries.",
  },
};

export function isValidMcpScope(value: string): value is McpScope {
  return (MCP_SCOPES as readonly string[]).includes(value);
}

/**
 * Parses a space-delimited OAuth scope string or string array into validated McpScopes.
 * Defaults to all supported MCP scopes when omitted/empty.
 */
export function parseAndValidateScopes(rawScope?: string | string[]): McpScope[] {
  if (!rawScope || (Array.isArray(rawScope) && rawScope.length === 0)) {
    return [...MCP_SCOPES];
  }

  const tokens = Array.isArray(rawScope)
    ? rawScope.flatMap((s) => s.trim().split(/[\s,]+/))
    : rawScope.trim().split(/[\s,]+/);

  const cleaned = tokens.filter(Boolean);
  if (cleaned.length === 0) {
    return [...MCP_SCOPES];
  }

  const invalid = cleaned.filter((s) => !isValidMcpScope(s));
  if (invalid.length > 0) {
    throw new BadRequestError(
      `Unsupported OAuth scope(s): ${invalid.join(", ")}. Supported scopes: ${MCP_SCOPES.join(", ")}`,
    );
  }

  // Deduplicate preserving order
  return Array.from(new Set(cleaned)) as McpScope[];
}

export function getScopeDetailsList(scopes: McpScope[]): McpScopeDefinition[] {
  return scopes.map((scope) => MCP_SCOPE_DEFINITIONS[scope]);
}
