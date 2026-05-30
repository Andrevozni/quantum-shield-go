/** QuantumShield SDK — TypeScript types */

// ── Token ─────────────────────────────────────────────────────────────────────

export interface Token {
  token:      string;
  user_id:    string;
  roles:      string[];
  expires_at: string | null;
}

// ── Keys ──────────────────────────────────────────────────────────────────────

export type KemLevel = "ML-KEM-768" | "ML-KEM-1024";

export interface KeyPair {
  key_id:          string;
  public_key:      string;   // base64
  algorithm:       KemLevel;
  public_key_size: number;
  vault_shards:    number;
  vault_threshold: number;
}

export interface PublicKey {
  key_id:     string;
  public_key: string;  // base64
}

// ── Encryption ────────────────────────────────────────────────────────────────

export interface Encrypted {
  kem_ciphertext: string;  // base64
  nonce:          string;  // base64
  data:           string;  // base64
  created_at:     number;  // Unix timestamp
}

export interface EncryptResult {
  encrypted:    Encrypted;
  algorithm:    string;
  quantum_safe: boolean;
}

export interface DecryptResult {
  plaintext: string;   // base64 on wire, decoded to string by SDK
  key_id:    string;
}

// ── Signatures ────────────────────────────────────────────────────────────────

export interface Signature {
  signature:  string;  // base64
  public_key: string;  // base64
  algorithm:  string;
  message:    string;  // base64
}

export interface VerifyResult {
  valid:   boolean;
  message: string;
}

// ── CA ────────────────────────────────────────────────────────────────────────

export interface Certificate {
  version:         number;
  serial:          string;
  subject:         string;
  issuer:          string;
  algorithm:       string;
  public_key:      string;
  public_key_type: string;
  not_before:      string;  // RFC3339
  not_after:       string;  // RFC3339
  is_ca:           boolean;
  signature:       string;
  [key: string]: unknown;   // allow raw passthrough
}

export interface CAInitResult {
  certificate: Certificate;
  message:     string;
}

export interface CertVerifyResult {
  valid:  boolean;
  error?: string;
}

// ── KDF ───────────────────────────────────────────────────────────────────────

export interface DerivedKey {
  key:       string;   // base64
  algorithm: string;
  key_size:  number;
}

// ── Health ────────────────────────────────────────────────────────────────────

export interface HealthStatus {
  status:     string;
  algorithms: Record<string, unknown>;
  version:    string;
}

export interface FIPSProbe {
  algorithm: string;
  standard:  string;
  status:    "pass" | "fail";
  duration:  string;
  error?:    string;
}

export interface FIPSReport {
  overall:    "pass" | "fail";
  probes:     FIPSProbe[];
  timestamp:  string;
  go_version: string;
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface ClientOptions {
  /** Server base URL, e.g. "https://qs.example.com" */
  baseUrl: string;
  /** Pre-issued QST bearer token */
  token?:  string;
  /** Bootstrap secret for POST /auth/token */
  bootstrapSecret?: string;
  /** Request timeout in milliseconds (default 30_000) */
  timeout?: number;
  /** Custom fetch implementation (default: globalThis.fetch) */
  fetch?:   typeof fetch;
}
