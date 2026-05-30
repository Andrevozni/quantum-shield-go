/**
 * QuantumShield JS SDK — integration tests (Vitest).
 *
 * Run against a live server:
 *   go run ./cmd/server &
 *   cd sdk/js && npm test
 *
 * Environment:
 *   QS_URL     server base URL (default http://localhost:8080)
 *   QS_SECRET  bootstrap secret (default "")
 *   QS_SKIP    set to "1" to skip all live tests
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  QuantumShield,
  AuthenticationError,
  AuthorizationError,
  CertVerificationError,
} from "../src/index.js";

const BASE_URL = process.env["QS_URL"]    ?? "http://localhost:8080";
const SECRET   = process.env["QS_SECRET"] ?? "";
const SKIP     = process.env["QS_SKIP"]   === "1";

// Shared client — authenticated once, reused across tests.
let qs: QuantumShield;

beforeAll(async () => {
  if (SKIP) return;
  qs = new QuantumShield({ baseUrl: BASE_URL, bootstrapSecret: SECRET || undefined });
  try {
    await qs.auth("js-sdk-test", ["admin", "write", "read"]);
  } catch (e) {
    console.warn(`⚠  Cannot connect to ${BASE_URL}: ${e}. Skipping live tests.`);
    process.env["QS_SKIP"] = "1";
  }
});

const maybeIt = (name: string, fn: () => Promise<void>) =>
  it(name, async () => {
    if (SKIP || process.env["QS_SKIP"] === "1") return;
    await fn();
  });

// ── Health ────────────────────────────────────────────────────────────────────

describe("health", () => {
  maybeIt("status returns operational", async () => {
    const s = await qs.health.status();
    expect(s.status).toBe("operational");
    expect(s.algorithms).toBeDefined();
  });

  maybeIt("live returns true", async () => {
    expect(await qs.health.live()).toBe(true);
  });

  maybeIt("fips report has probes", async () => {
    const r = await qs.health.fips();
    expect(["pass", "fail"]).toContain(r.overall);
    expect(r.probes.length).toBeGreaterThan(0);
  });
});

// ── Auth ──────────────────────────────────────────────────────────────────────

describe("auth", () => {
  maybeIt("issue and verify token", async () => {
    const tok = await qs.auth_.issue("js-verify-test", ["read"]);
    expect(tok.token).toBeTruthy();
    const r = await qs.auth_.verify(tok.token);
    expect(r).toBeDefined();
  });

  maybeIt("wrong role throws AuthorizationError", async () => {
    const readOnly = new QuantumShield({ baseUrl: BASE_URL });
    await readOnly.auth("readonly", ["read"]);
    await expect(readOnly.keys.generate()).rejects.toBeInstanceOf(AuthorizationError);
  });

  maybeIt("revoked token is rejected", async () => {
    const client2 = new QuantumShield({ baseUrl: BASE_URL });
    const tok = await client2.auth("revoke-js", ["read"]);
    await client2.auth_.revoke(tok.token);
    const stale = new QuantumShield({ baseUrl: BASE_URL, token: tok.token });
    await expect(stale.keys.list()).rejects.toBeInstanceOf(AuthenticationError);
  });
});

// ── Keys ──────────────────────────────────────────────────────────────────────

describe("keys", () => {
  maybeIt("generate ML-KEM-768", async () => {
    const kp = await qs.keys.generate("ML-KEM-768");
    expect(kp.key_id).toBeTruthy();
    expect(kp.public_key).toBeTruthy();
    expect(kp.public_key_size).toBeGreaterThan(0);
  });

  maybeIt("list keys", async () => {
    await qs.keys.generate();
    const ids = await qs.keys.list();
    expect(Array.isArray(ids)).toBe(true);
    expect(ids.length).toBeGreaterThanOrEqual(1);
  });

  maybeIt("get public key", async () => {
    const kp = await qs.keys.generate();
    const pk = await qs.keys.publicKey(kp.key_id);
    expect(pk.key_id).toBe(kp.key_id);
    expect(pk.public_key).toBe(kp.public_key);
  });
});

// ── Crypto ────────────────────────────────────────────────────────────────────

describe("crypto", () => {
  maybeIt("encrypt and decrypt", async () => {
    const kp  = await qs.keys.generate();
    const enc = await qs.crypto.encrypt(kp.key_id, "hello from JS SDK");
    expect(enc.encrypted.kem_ciphertext).toBeTruthy();
    expect(enc.quantum_safe).toBe(true);
    const dec = await qs.crypto.decrypt(kp.key_id, enc.encrypted);
    expect(dec).toBe("hello from JS SDK");
  });

  maybeIt("replay attack is rejected", async () => {
    const kp  = await qs.keys.generate();
    const enc = await qs.crypto.encrypt(kp.key_id, "replay test");
    await qs.crypto.decrypt(kp.key_id, enc.encrypted); // first: ok
    await expect(
      qs.crypto.decrypt(kp.key_id, enc.encrypted),     // second: rejected
    ).rejects.toBeDefined();
  });

  maybeIt("sign and verify", async () => {
    const kp  = await qs.keys.generate();
    const sig = await qs.crypto.sign(kp.key_id, "important document");
    expect(sig.signature).toBeTruthy();
    const r = await qs.crypto.verifySignature(
      "important document", sig.signature, sig.public_key,
    );
    expect(r.valid).toBe(true);
  });

  maybeIt("verify tampered message fails", async () => {
    const kp  = await qs.keys.generate();
    const sig = await qs.crypto.sign(kp.key_id, "original");
    const r   = await qs.crypto.verifySignature("tampered", sig.signature, sig.public_key);
    expect(r.valid).toBe(false);
  });
});

// ── CA ────────────────────────────────────────────────────────────────────────

describe("ca", () => {
  maybeIt("full lifecycle: init → sign → verify → revoke", async () => {
    await qs.ca.init("CN=JS SDK Test Root CA,O=QuantumShield");

    const kp   = await qs.keys.generate();
    const cert = await qs.ca.sign(
      "CN=js-sdk.example.com", kp.public_key, "ML-KEM-768",
    );
    expect(cert.serial).toBeTruthy();
    expect(cert.subject).toBe("CN=js-sdk.example.com");

    const v = await qs.ca.verify(cert);
    expect(v.valid).toBe(true);

    // Revoke and re-verify — must throw.
    await qs.ca.revoke(cert.serial);
    await expect(qs.ca.verify(cert)).rejects.toBeInstanceOf(CertVerificationError);
  });

  maybeIt("forged certificate is rejected", async () => {
    await qs.ca.init("CN=JS Forgery Test CA");
    const fake = {
      version: 1, serial: "DEADBEEF",
      subject: "CN=rogue.example.com",
      issuer:  "CN=JS Forgery Test CA",
      algorithm: "ML-DSA-87",
      public_key: "ZmFrZQ==",
      public_key_type: "ML-KEM-768",
      not_before: "2025-01-01T00:00:00Z",
      not_after:  "2030-01-01T00:00:00Z",
      is_ca: false,
      signature: "ZmFrZXNpZw==",
    };
    await expect(qs.ca.verify(fake)).rejects.toBeDefined();
  });
});

// ── KDF ───────────────────────────────────────────────────────────────────────

describe("kdf", () => {
  maybeIt("hkdf returns 32-byte key", async () => {
    const ikm = btoa("\x00".repeat(32));
    const dk  = await qs.kdf.hkdf(ikm, "test-context", 32);
    expect(dk.key).toBeTruthy();
    expect(dk.key_size).toBe(32);
  });

  maybeIt("generate salt returns 32 bytes", async () => {
    const salt = await qs.kdf.generateSalt(32);
    expect(salt).toBeTruthy();
    expect(atob(salt).length).toBe(32);
  });
});
