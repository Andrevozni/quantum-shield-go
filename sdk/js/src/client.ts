/**
 * QuantumShield JavaScript/TypeScript SDK
 *
 * Works in Node.js ≥ 18, Deno, Bun, and modern browsers (fetch API).
 * Zero runtime dependencies.
 *
 * @example
 * ```ts
 * import { QuantumShield } from "@quantum-shield/client";
 *
 * const qs = new QuantumShield({ baseUrl: "http://localhost:8080" });
 * await qs.auth("alice", ["read", "write"], "my-bootstrap-secret");
 *
 * const key = await qs.keys.generate();
 * const enc = await qs.crypto.encrypt(key.key_id, "hello world");
 * const dec = await qs.crypto.decrypt(key.key_id, enc.encrypted);
 * console.log(dec); // "hello world"
 * ```
 */

import { raiseForStatus, ConnectionError, CertVerificationError } from "./errors.js";
import type {
  CAInitResult, Certificate, CertVerifyResult, ClientOptions,
  DecryptResult, DerivedKey, Encrypted, EncryptResult, FIPSReport,
  HealthStatus, KemLevel, KeyPair, PublicKey, Signature, Token, VerifyResult,
} from "./types.js";

// ── HTTP layer ────────────────────────────────────────────────────────────────

class Http {
  private _token: string | null = null;
  private readonly _fetch: typeof fetch;

  constructor(
    private readonly base: string,
    private readonly timeout: number,
    fetchImpl?: typeof fetch,
  ) {
    this._fetch = fetchImpl ?? globalThis.fetch;
  }

  setToken(token: string | null): void { this._token = token; }
  getToken(): string | null { return this._token; }

  private headers(override?: string): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      "Accept":       "application/json",
    };
    const tok = override ?? this._token;
    if (tok) h["Authorization"] = `Bearer ${tok}`;
    return h;
  }

  async request<T = Record<string, unknown>>(
    method:  string,
    path:    string,
    body?:   unknown,
    tokenOverride?: string,
  ): Promise<T> {
    const url = this.base.replace(/\/$/, "") + path;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let resp: Response;
    try {
      resp = await this._fetch(url, {
        method,
        headers: this.headers(tokenOverride),
        body:    body !== undefined ? JSON.stringify(body) : undefined,
        signal:  controller.signal,
      });
    } catch (err: unknown) {
      throw new ConnectionError(`Connection failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    let json: Record<string, unknown> = {};
    const text = await resp.text();
    if (text.trim()) {
      try { json = JSON.parse(text); } catch { json = { raw: text }; }
    }
    if (!resp.ok) raiseForStatus(resp.status, json);
    return json as T;
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  post<T>(path: string, body?: unknown, tokenOverride?: string): Promise<T> {
    return this.request<T>("POST", path, body, tokenOverride);
  }

  delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }
}

// ── Sub-clients ────────────────────────────────────────────────────────────────

export class AuthClient {
  constructor(private readonly http: Http) {}

  /** Issue a QST token for userId with the given roles. */
  async issue(
    userId:          string,
    roles:           string[],
    bootstrapSecret?: string,
  ): Promise<Token> {
    const d = await this.http.post<Token>(
      "/auth/token",
      { user_id: userId, roles },
      bootstrapSecret,
    );
    this.http.setToken(d.token);
    return d;
  }

  /** Verify a token and return its claims. */
  verify(token: string): Promise<Record<string, unknown>> {
    return this.http.post("/auth/verify", { token });
  }

  /** Revoke a token. */
  async revoke(token: string): Promise<void> {
    await this.http.post("/auth/revoke", { token });
  }
}

export class KeysClient {
  constructor(private readonly http: Http) {}

  /** Generate a new ML-KEM keypair. */
  async generate(level: KemLevel = "ML-KEM-768"): Promise<KeyPair> {
    return this.http.post<KeyPair>("/keys/generate", { level });
  }

  /** List all stored key IDs. */
  async list(): Promise<string[]> {
    const d = await this.http.get<{ key_ids: string[] }>("/keys");
    return d.key_ids ?? [];
  }

  /** Retrieve the public key for a given key ID. */
  publicKey(keyId: string): Promise<PublicKey> {
    return this.http.get<PublicKey>(`/keys/${keyId}/public`);
  }

  /** Export a key wrapped with a password (Argon2id + AES-256-GCM). */
  export(keyId: string, password: string): Promise<Record<string, unknown>> {
    return this.http.post(`/keys/${keyId}/export`, { password });
  }

  /** Import a previously exported key. */
  async importKey(wrapped: Record<string, unknown>, password: string): Promise<KeyPair> {
    return this.http.post<KeyPair>("/keys/import", { wrapped, password });
  }
}

export class CryptoClient {
  constructor(private readonly http: Http) {}

  /**
   * Encrypt plaintext with ML-KEM-768 + AES-256-GCM.
   *
   * @param keyId     Key ID from {@link KeysClient.generate}.
   * @param plaintext String or Uint8Array to encrypt.
   */
  async encrypt(keyId: string, plaintext: string | Uint8Array): Promise<EncryptResult> {
    const pt = typeof plaintext === "string"
      ? plaintext
      : new TextDecoder("latin1").decode(plaintext);
    return this.http.post<EncryptResult>("/encrypt", { key_id: keyId, plaintext: pt });
  }

  /**
   * Decrypt a previously encrypted message.
   *
   * @returns Decoded plaintext string.
   */
  async decrypt(keyId: string, encrypted: Encrypted): Promise<string> {
    const d = await this.http.post<{ plaintext: string }>("/decrypt", {
      key_id:    keyId,
      encrypted,
    });
    // Server returns base64; decode to UTF-8 string.
    return atob(d.plaintext);
  }

  /** Sign a message with ML-DSA-65 (NIST FIPS 204). */
  async sign(keyId: string, message: string | Uint8Array): Promise<Signature> {
    const msgB64 = typeof message === "string"
      ? btoa(message)
      : btoa(String.fromCharCode(...message));
    return this.http.post<Signature>("/sign", { key_id: keyId, message: msgB64 });
  }

  /** Verify an ML-DSA-65 signature. */
  async verifySignature(
    message:   string | Uint8Array,
    signature: string,
    publicKey: string,
  ): Promise<VerifyResult> {
    const msgB64 = typeof message === "string"
      ? btoa(message)
      : btoa(String.fromCharCode(...message));
    return this.http.post<VerifyResult>("/verify-signature", {
      message:    msgB64,
      signature,
      public_key: publicKey,
    });
  }

  /** Sign a message with SLH-DSA (NIST FIPS 205). */
  async slhSign(
    keyId:   string,
    message: string | Uint8Array,
    level:   "128f" | "128s" | "256f" | "256s" = "128f",
  ): Promise<Signature> {
    const msgB64 = typeof message === "string"
      ? btoa(message)
      : btoa(String.fromCharCode(...message));
    return this.http.post<Signature>("/slh-dsa/sign", {
      key_id:  keyId,
      message: msgB64,
      level,
    });
  }
}

export class KDFClient {
  constructor(private readonly http: Http) {}

  /** Derive a key using HKDF-SHA256. */
  hkdf(inputKey: string, info = "", length = 32): Promise<DerivedKey> {
    return this.http.post<DerivedKey>("/kdf/hkdf", {
      input_key: inputKey,
      info,
      length,
    });
  }

  /** Derive a key using Argon2id. */
  argon2(
    password:  string,
    salt?:     string,
    timeCost   = 3,
    memoryKb   = 65536,
  ): Promise<DerivedKey> {
    return this.http.post<DerivedKey>("/kdf/argon2", {
      password,
      salt:       salt ?? "",
      time_cost:  timeCost,
      memory_kb:  memoryKb,
    });
  }

  /** Generate a cryptographically secure random salt (base64). */
  async generateSalt(length = 32): Promise<string> {
    const d = await this.http.post<{ salt: string }>("/kdf/salt", { length });
    return d.salt;
  }
}

export class CAClient {
  constructor(private readonly http: Http) {}

  /** Initialise the root CA (admin role required). */
  init(subject: string): Promise<CAInitResult> {
    return this.http.post<CAInitResult>("/ca/init", { subject });
  }

  /** Issue a leaf certificate. */
  sign(
    subject:       string,
    publicKey:     string,
    publicKeyType: string = "ML-KEM-768",
    ttlDays        = 365,
  ): Promise<Certificate> {
    return this.http.post<Certificate>("/ca/sign", {
      subject,
      public_key:      publicKey,
      public_key_type: publicKeyType,
      ttl_days:        ttlDays,
    });
  }

  /**
   * Verify a certificate.
   * @throws {@link CertVerificationError} if invalid.
   */
  async verify(certificate: Certificate | Record<string, unknown>): Promise<CertVerifyResult> {
    const d = await this.http.post<CertVerifyResult>("/ca/verify", { certificate });
    if (!d.valid) {
      throw new CertVerificationError(d.error ?? "certificate verification failed");
    }
    return d;
  }

  /** Add a serial to the CRL (admin role). */
  async revoke(serial: string): Promise<void> {
    await this.http.post("/ca/revoke", { serial });
  }

  /** Retrieve the root CA certificate (public). */
  getCertificate(): Promise<Certificate> {
    return this.http.get<Certificate>("/ca/certificate");
  }

  /** Retrieve the Certificate Revocation List (public). */
  getCRL(): Promise<Record<string, unknown>> {
    return this.http.get("/ca/crl");
  }

  /** Create an intermediate CA (admin role). */
  async createIntermediate(subject: string, ttlDays = 3650): Promise<Certificate> {
    const d = await this.http.post<{ certificate: Certificate } | Certificate>(
      "/ca/intermediate",
      { subject, ttl_days: ttlDays },
    );
    return "certificate" in d ? (d as { certificate: Certificate }).certificate : d;
  }

  /** Chain-verify a leaf certificate (public). */
  async chainVerify(
    certificate: Certificate,
    chain:       Certificate[],
  ): Promise<boolean> {
    const d = await this.http.post<{ valid: boolean }>("/ca/chain-verify", {
      certificate,
      chain,
    });
    return d.valid;
  }
}

export class HealthClient {
  constructor(private readonly http: Http) {}

  status(): Promise<HealthStatus> { return this.http.get<HealthStatus>("/"); }
  ready():  Promise<Record<string, unknown>> { return this.http.get("/health/ready"); }
  fips():   Promise<FIPSReport>  { return this.http.get<FIPSReport>("/health/fips"); }

  async live(): Promise<boolean> {
    try { await this.http.get("/health/live"); return true; }
    catch { return false; }
  }
}

// ── Main client ────────────────────────────────────────────────────────────────

/**
 * QuantumShield API client.
 *
 * @example Node.js
 * ```ts
 * import { QuantumShield } from "@quantum-shield/client";
 *
 * const qs = new QuantumShield({ baseUrl: "http://localhost:8080" });
 * await qs.auth("alice", ["read", "write"], "bootstrap-secret");
 *
 * const key = await qs.keys.generate();
 * const enc = await qs.crypto.encrypt(key.key_id, "hello");
 * const dec = await qs.crypto.decrypt(key.key_id, enc.encrypted);
 * console.log(dec); // "hello"
 * ```
 *
 * @example Browser (Vite / webpack)
 * ```ts
 * const qs = new QuantumShield({ baseUrl: "/api" }); // proxied to backend
 * await qs.auth("browser-user", ["read"]);
 * const report = await qs.health.fips();
 * console.log(report.overall); // "pass"
 * ```
 */
export class QuantumShield {
  readonly health: HealthClient;
  readonly auth_:  AuthClient;
  readonly keys:   KeysClient;
  readonly crypto: CryptoClient;
  readonly kdf:    KDFClient;
  readonly ca:     CAClient;

  private readonly _http: Http;
  private readonly _bootstrapSecret?: string;

  constructor(options: ClientOptions) {
    this._http = new Http(
      options.baseUrl,
      options.timeout ?? 30_000,
      options.fetch,
    );
    if (options.token) this._http.setToken(options.token);
    this._bootstrapSecret = options.bootstrapSecret;

    this.health = new HealthClient(this._http);
    this.auth_  = new AuthClient(this._http);
    this.keys   = new KeysClient(this._http);
    this.crypto = new CryptoClient(this._http);
    this.kdf    = new KDFClient(this._http);
    this.ca     = new CAClient(this._http);
  }

  /**
   * Issue a token and configure it for all subsequent requests.
   *
   * @param userId          User or service identifier.
   * @param roles           Permission list: "read", "write", "admin".
   * @param bootstrapSecret Overrides the one passed to the constructor.
   */
  async auth(
    userId:          string,
    roles:           string[],
    bootstrapSecret?: string,
  ): Promise<Token> {
    const secret = bootstrapSecret ?? this._bootstrapSecret;
    return this.auth_.issue(userId, roles, secret);
  }

  get token(): string | null { return this._http.getToken(); }
  set token(value: string | null) { this._http.setToken(value); }
}
