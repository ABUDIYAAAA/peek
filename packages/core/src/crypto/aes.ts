/**
 * Web Crypto AES-256-GCM authenticated encryption and decryption.
 * Designed for edge runtimes (Cloudflare Workers, Node 18+, Bun, browsers).
 */

/**
 * Derives a 256-bit AES-GCM CryptoKey from a secret string using SHA-256.
 */
async function deriveAesKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyBytes = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

const ENCRYPTED_HEX_PATTERN = /^[0-9a-f]{24}:[0-9a-f]+$/i;

/**
 * Checks if a string matches the encrypted payload format (24-hex-char IV : hex ciphertext).
 */
export function isEncryptedPayload(value: string): boolean {
  return ENCRYPTED_HEX_PATTERN.test(value);
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Output format: `<12-byte IV in hex>:<ciphertext + auth tag in hex>`
 */
export async function encryptString(
  plaintext: string,
  secret: string,
): Promise<string> {
  const key = await deriveAesKey(secret);
  const ivBuffer = new ArrayBuffer(12);
  const iv = new Uint8Array(ivBuffer);
  crypto.getRandomValues(iv);
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    key,
    encoded,
  );

  const ivHex = bytesToHex(iv);
  const cipherHex = bytesToHex(new Uint8Array(ciphertextBuffer));

  return `${ivHex}:${cipherHex}`;
}

/**
 * Decrypts a payload previously encrypted with `encryptString`.
 * Throws an error if the payload was tampered with or if the secret is incorrect.
 */
export async function decryptString(
  payload: string,
  secret: string,
): Promise<string> {
  if (!isEncryptedPayload(payload)) {
    throw new Error(
      "Invalid ciphertext payload format. Expected <iv_hex>:<ciphertext_hex>",
    );
  }

  const [ivHex, cipherHex] = payload.split(":") as [string, string];
  const iv = hexToBytes(ivHex);
  const ciphertext = hexToBytes(cipherHex);

  const key = await deriveAesKey(secret);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      key,
      ciphertext as unknown as BufferSource,
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch {
    throw new Error(
      "Decryption failed: Ciphertext may have been tampered with or invalid encryption secret",
    );
  }
}

/**
 * Safely decrypts a string if it is encrypted; otherwise returns the raw string.
 * Useful for graceful transitions and backward compatibility.
 */
export async function safeDecryptString(
  value: string,
  secret: string,
): Promise<string> {
  if (!isEncryptedPayload(value)) {
    return value;
  }
  return decryptString(value, secret);
}
