import { UnauthorizedError } from "@peek/core";
import type { JwtPayload, UserRole } from "./types.js";

export function parseDurationToSeconds(duration: string): number {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) {
    return 900; // default 15 minutes
  }

  const [, rawVal, unit] = match;
  const value = parseInt(rawVal!, 10);

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 3600;
    case "d":
      return value * 86400;
    default:
      return 900;
  }
}

function base64UrlEncode(data: Uint8Array | string): string {
  let base64: string;
  if (typeof data === "string") {
    const bytes = new TextEncoder().encode(data);
    base64 = btoa(String.fromCharCode(...bytes));
  } else {
    base64 = btoa(String.fromCharCode(...data));
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getHmacKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signAccessToken(
  user: { id: string; role: UserRole; username: string; email: string },
  secret: string,
  duration = "15m",
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expiresInSeconds = parseDurationToSeconds(duration);

  const header = { alg: "HS256", typ: "JWT" };
  const payload: JwtPayload = {
    sub: user.id,
    role: user.role,
    username: user.username,
    email: user.email,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const key = await getHmacKey(secret);
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(dataToSign),
  );

  const encodedSignature = base64UrlEncode(new Uint8Array(signatureBuffer));
  return `${dataToSign}.${encodedSignature}`;
}

export async function verifyAccessToken(
  token: string,
  secret: string,
): Promise<JwtPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new UnauthorizedError("Invalid token format");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts as [
    string,
    string,
    string,
  ];
  const dataToVerify = `${encodedHeader}.${encodedPayload}`;

  const key = await getHmacKey(secret);
  const signatureBytes = base64UrlDecode(encodedSignature);

  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(dataToVerify),
  );

  if (!isValid) {
    throw new UnauthorizedError("Invalid token signature");
  }

  try {
    const payloadJson = new TextDecoder().decode(
      base64UrlDecode(encodedPayload),
    );
    const payload = JSON.parse(payloadJson) as JwtPayload;

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new UnauthorizedError("Token has expired");
    }

    return payload;
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      throw err;
    }
    throw new UnauthorizedError("Invalid token payload");
  }
}
