import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  validateRedirectUri,
  validateWebUri,
  isRedirectUriAllowed,
} from "../src/mcp-oauth.ts";

describe("RFC 8252 & RFC 6749 URI Validation", () => {
  test("accepts valid loopback HTTP redirect URIs", () => {
    assert.doesNotThrow(() => validateRedirectUri("http://127.0.0.1:45678/callback"));
    assert.doesNotThrow(() => validateRedirectUri("http://[::1]:8080/oauth"));
    assert.doesNotThrow(() => validateRedirectUri("http://localhost:3000/callback"));
  });

  test("accepts custom URI schemes for native desktop apps", () => {
    assert.doesNotThrow(() => validateRedirectUri("cursor://oauth/callback"));
    assert.doesNotThrow(() => validateRedirectUri("antigravity://auth"));
    assert.doesNotThrow(() => validateRedirectUri("com.peek.agent:/oauth2redirect"));
  });

  test("rejects forbidden pseudo-protocols", () => {
    assert.throws(
      () => validateRedirectUri("javascript:alert(1)"),
      /forbidden redirect_uri scheme/i,
    );
    assert.throws(
      () => validateRedirectUri("data:text/html,<script>"),
      /forbidden redirect_uri scheme/i,
    );
    assert.throws(
      () => validateRedirectUri("file:///etc/passwd"),
      /forbidden redirect_uri scheme/i,
    );
    assert.throws(
      () => validateRedirectUri("blob:http://example.com"),
      /forbidden redirect_uri scheme/i,
    );
  });

  test("rejects non-loopback plain HTTP (must use HTTPS or loopback)", () => {
    assert.throws(
      () => validateRedirectUri("http://api.attacker.com/callback"),
      /plain http redirect_uri is only permitted on loopback/i,
    );
  });

  test("rejects URIs with URL fragments per RFC 6749 §3.1.2", () => {
    assert.throws(
      () => validateRedirectUri("http://127.0.0.1:8080/callback#access_token=123"),
      /fragment identifier/i,
    );
    assert.throws(
      () => validateRedirectUri("https://peek.example.com/oauth#state=xyz"),
      /fragment identifier/i,
    );
  });

  test("isRedirectUriAllowed matches exact registered URIs", () => {
    const registered = ["https://client.example.com/callback"];
    assert.equal(
      isRedirectUriAllowed("https://client.example.com/callback", registered),
      true,
    );
    assert.equal(
      isRedirectUriAllowed("https://client.example.com/other", registered),
      false,
    );
  });

  test("isRedirectUriAllowed allows ephemeral loopback port variation per RFC 8252 §7.3", () => {
    const registered = ["http://127.0.0.1/callback"];
    // Any loopback port should be accepted
    assert.equal(
      isRedirectUriAllowed("http://127.0.0.1:49152/callback", registered),
      true,
    );
    assert.equal(
      isRedirectUriAllowed("http://127.0.0.1:54321/callback", registered),
      true,
    );
    // Path mismatch rejected
    assert.equal(
      isRedirectUriAllowed("http://127.0.0.1:49152/wrong-path", registered),
      false,
    );
    // Scheme mismatch rejected
    assert.equal(
      isRedirectUriAllowed("https://127.0.0.1:49152/callback", registered),
      false,
    );
  });

  test("validateWebUri strictly enforces HTTPS", () => {
    assert.doesNotThrow(() => validateWebUri("https://peek.example.com", "client_uri"));
    assert.throws(
      () => validateWebUri("http://peek.example.com", "client_uri"),
      /must use https/i,
    );
    assert.throws(
      () => validateWebUri("javascript:alert(1)", "logo_uri"),
      /forbidden/i,
    );
  });
});
