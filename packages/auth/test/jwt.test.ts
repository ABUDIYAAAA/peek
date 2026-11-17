import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  signAccessToken,
  verifyAccessToken,
  parseDurationToSeconds,
} from "../src/jwt.ts";

describe("JWT Service (Edge Web Crypto)", () => {
  const secret = "jwt-super-secret-access-key-for-testing-123456";
  const user = {
    id: "usr_test_123",
    role: "member" as const,
    username: "alice",
    email: "alice@example.com",
  };

  test("signs and verifies an access token", async () => {
    const token = await signAccessToken(user, secret, "15m");
    assert.ok(typeof token === "string");
    assert.equal(token.split(".").length, 3);

    const payload = await verifyAccessToken(token, secret);
    assert.equal(payload.sub, user.id);
    assert.equal(payload.role, user.role);
    assert.equal(payload.username, user.username);
    assert.equal(payload.email, user.email);
    assert.ok(payload.exp > payload.iat);
  });

  test("rejects token verified with wrong secret", async () => {
    const token = await signAccessToken(user, secret, "15m");
    await assert.rejects(
      async () => {
        await verifyAccessToken(token, "wrong-secret-key-that-does-not-match");
      },
      /signature verification failed|unauthorized/i,
    );
  });

  test("parseDurationToSeconds correctly parses intervals", () => {
    assert.equal(parseDurationToSeconds("15m"), 900);
    assert.equal(parseDurationToSeconds("1h"), 3600);
    assert.equal(parseDurationToSeconds("30d"), 30 * 86400);
    assert.equal(parseDurationToSeconds("60s"), 60);
  });

  test("rejects malformed token strings", async () => {
    await assert.rejects(
      async () => {
        await verifyAccessToken("not.a.valid.jwt.token", secret);
      },
      /invalid|malformed|unauthorized/i,
    );
  });
});
