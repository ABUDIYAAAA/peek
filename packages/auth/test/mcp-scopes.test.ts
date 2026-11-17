import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  isValidMcpScope,
  parseAndValidateScopes,
  getScopeDetailsList,
  MCP_SCOPE_DEFINITIONS,
} from "../src/mcp-scopes.ts";
import { MCP_SCOPES } from "@peek/db";

describe("MCP Scopes Validation & Expansion", () => {
  test("isValidMcpScope accurately validates supported scopes", () => {
    assert.equal(isValidMcpScope("projects:read"), true);
    assert.equal(isValidMcpScope("sprints:read"), true);
    assert.equal(isValidMcpScope("progress:write"), true);
    assert.equal(isValidMcpScope("journals:write"), true);

    assert.equal(isValidMcpScope("admin:all"), false);
    assert.equal(isValidMcpScope(""), false);
  });

  test("defaults to all supported scopes when omitted or empty", () => {
    assert.deepEqual(parseAndValidateScopes(undefined), [...MCP_SCOPES]);
    assert.deepEqual(parseAndValidateScopes(""), [...MCP_SCOPES]);
    assert.deepEqual(parseAndValidateScopes([]), [...MCP_SCOPES]);
  });

  test("parses space and comma delimited scope strings", () => {
    const parsed = parseAndValidateScopes("projects:read progress:write");
    assert.deepEqual(parsed, ["projects:read", "progress:write"]);

    const commaParsed = parseAndValidateScopes("projects:read, sprints:read");
    assert.deepEqual(commaParsed, ["projects:read", "sprints:read"]);
  });

  test("deduplicates redundant scopes", () => {
    const parsed = parseAndValidateScopes("projects:read projects:read sprints:read");
    assert.deepEqual(parsed, ["projects:read", "sprints:read"]);
  });

  test("rejects unsupported scopes with informative error", () => {
    assert.throws(
      () => parseAndValidateScopes("projects:read malicious:scope"),
      /Unsupported OAuth scope\(s\): malicious:scope/,
    );
  });

  test("getScopeDetailsList returns rich definitions for scopes", () => {
    const details = getScopeDetailsList(["projects:read", "journals:write"]);
    assert.equal(details.length, 2);
    assert.equal(details[0]?.title, MCP_SCOPE_DEFINITIONS["projects:read"].title);
    assert.equal(details[1]?.title, MCP_SCOPE_DEFINITIONS["journals:write"].title);
  });
});
