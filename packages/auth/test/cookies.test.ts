import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  serializeCookie,
  getCookie,
  parseCookies,
  clearAuthCookies,
  getCookieConfig,
} from "../src/cookies.ts";

describe("RFC 6265 Cookie Serializer & Parser", () => {
  test("serializes cookies with HttpOnly, Secure, and SameSite defaults", () => {
    const serialized = serializeCookie("session_token", "abc123xyz", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAgeSeconds: 3600,
      path: "/",
    });

    assert.ok(serialized.includes("session_token=abc123xyz"));
    assert.ok(serialized.includes("HttpOnly"));
    assert.ok(serialized.includes("Secure"));
    assert.ok(serialized.includes("SameSite=Lax"));
    assert.ok(serialized.includes("Max-Age=3600"));
    assert.ok(serialized.includes("Path=/"));
  });

  test("parses cookies accurately from Cookie header", () => {
    const header = "peek_access_token=jwt123; other_cookie=xyz; peek_refresh_token=ref456";
    assert.equal(getCookie(header, "peek_access_token"), "jwt123");
    assert.equal(getCookie(header, "peek_refresh_token"), "ref456");
    assert.equal(getCookie(header, "other_cookie"), "xyz");
    assert.equal(getCookie(header, "missing_cookie"), null);
    assert.equal(getCookie(undefined, "any"), null);
  });

  test("clearAuthCookies sets Max-Age=0 and expired date for both access and refresh cookies", () => {
    const config = getCookieConfig({ ENVIRONMENT: "production" } as any);
    const cleared = clearAuthCookies(config);
    assert.equal(cleared.length, 2);
    assert.ok(cleared[0]?.includes("peek_access_token="));
    assert.ok(cleared[0]?.includes("Max-Age=0"));
    assert.ok(cleared[1]?.includes("peek_refresh_token="));
    assert.ok(cleared[1]?.includes("Max-Age=0"));
  });

  test("parseCookies parses all key-value cookie pairs", () => {
    const header = "a=1; b=hello%20world; c=true";
    const cookies = parseCookies(header);
    assert.equal(cookies["a"], "1");
    assert.equal(cookies["b"], "hello world");
    assert.equal(cookies["c"], "true");
  });

  test("getCookieConfig correctly derives environment flags", () => {
    const devConfig = getCookieConfig({ ENVIRONMENT: "development" } as any);
    assert.equal(devConfig.secure, false);
    assert.equal(devConfig.accessName, "peek_access_token");

    const prodConfig = getCookieConfig({ ENVIRONMENT: "production" } as any);
    assert.equal(prodConfig.secure, true);
  });
});
