import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  encryptString,
  decryptString,
  safeDecryptString,
  isEncryptedPayload,
} from "../src/crypto/aes.ts";

describe("AES-256-GCM Edge Encryption", () => {
  const secret = "test-encryption-secret-minimum-length-for-security";
  const plaintext = "super-secret-mcp-github-token-12345";

  test("encrypts and decrypts round-trip successfully", async () => {
    const encrypted = await encryptString(plaintext, secret);
    assert.ok(isEncryptedPayload(encrypted));
    assert.notEqual(encrypted, plaintext);

    const decrypted = await decryptString(encrypted, secret);
    assert.equal(decrypted, plaintext);
  });

  test("produces non-deterministic ciphertext due to random IV", async () => {
    const enc1 = await encryptString(plaintext, secret);
    const enc2 = await encryptString(plaintext, secret);
    assert.notEqual(enc1, enc2);

    assert.equal(await decryptString(enc1, secret), plaintext);
    assert.equal(await decryptString(enc2, secret), plaintext);
  });

  test("rejects decryption with incorrect secret", async () => {
    const encrypted = await encryptString(plaintext, secret);
    await assert.rejects(
      async () => {
        await decryptString(encrypted, "wrong-secret-which-cannot-decrypt");
      },
      /decryption failed/i,
    );
  });

  test("safeDecryptString returns original value if not encrypted or decryption fails", async () => {
    const plain = "not-encrypted-raw-token";
    const result = await safeDecryptString(plain, secret);
    assert.equal(result, plain);

    const encrypted = await encryptString(plaintext, secret);
    const safeDecrypted = await safeDecryptString(encrypted, secret);
    assert.equal(safeDecrypted, plaintext);
  });

  test("rejects tampered ciphertext", async () => {
    const encrypted = await encryptString(plaintext, secret);
    const [iv, ciphertext] = encrypted.split(":");
    // Tamper with the last hex char
    const tampered = `${iv}:${ciphertext.slice(0, -2)}ff`;

    await assert.rejects(
      async () => {
        await decryptString(tampered, secret);
      },
      /decryption failed/i,
    );
  });

  test("isEncryptedPayload accurately validates format", () => {
    assert.equal(isEncryptedPayload("invalid"), false);
    assert.equal(isEncryptedPayload("abc:123"), false);
    // 24-char hex IV (12 bytes) + ':' + hex ciphertext
    const valid = "0123456789abcdef01234567:abcdef0123456789";
    assert.equal(isEncryptedPayload(valid), true);
  });
});
