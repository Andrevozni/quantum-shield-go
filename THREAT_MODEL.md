# QuantumShield — Threat Model

**Version:** 1.2
**Standard:** STRIDE + LINDDUN
**Last updated:** 2026-05-29

---

## 1. Scope

This document covers all assets, threat actors, attack surfaces, and mitigations for the QuantumShield Go cryptographic platform. It is the primary reference for security auditors, penetration testers, and developers making changes to the system.

Out of scope: infrastructure (cloud provider, OS hardening, network firewalls, HSM provisioning). Those are deployment-environment concerns.

---

## 2. Assets

| ID  | Asset                        | Confidentiality | Integrity | Availability |
|-----|------------------------------|-----------------|-----------|--------------|
| A1  | ML-KEM private keys          | Critical        | Critical  | High         |
| A2  | ML-DSA signing keys          | Critical        | Critical  | High         |
| A3  | Keystore master password     | Critical        | Critical  | Medium       |
| A4  | Plaintext secrets (vault)    | Critical        | Critical  | Medium       |
| A5  | QST tokens in transit        | High            | Critical  | Medium       |
| A6  | Audit log chain              | N/A             | Critical  | High         |
| A7  | Revocation list              | Low             | Critical  | High         |
| A8  | Shared channel session keys  | Critical        | Critical  | Medium       |
| A9  | Threshold signing nonces     | High            | Critical  | Medium       |
| A10 | Prometheus metrics endpoint  | Low             | Low       | Medium       |

---

## 3. Threat Actors

| ID  | Actor                          | Capability                                     | Motivation              |
|-----|--------------------------------|------------------------------------------------|-------------------------|
| T1  | Network passive eavesdropper   | Captures all TLS/cleartext traffic             | Mass surveillance       |
| T2  | Network active attacker (MITM) | Intercepts and modifies traffic                | Targeted interception   |
| T3  | Compromised shard holder       | Has ≤ k-1 valid shards                         | Reconstruct secret      |
| T4  | Byzantine shard holder         | Holds valid shards; submits tampered data      | Corrupt reconstruction  |
| T5  | Stolen token attacker          | Possesses a valid, unexpired QST token         | Privilege escalation    |
| T6  | Insider / rogue signer         | Participates in threshold signing              | Forge authorised sig    |
| T7  | Timing-side-channel attacker   | Measures crypto op latency (microsecond)       | Key extraction          |
| T8  | Quantum computer operator      | Large-scale quantum computation                | Break classical crypto  |
| T9  | Replay attacker                | Captures and re-submits valid ciphertexts      | Double-spend / replay   |
| T10 | Keystore file thief            | Read access to encrypted keystore on disk      | Key material recovery   |

---

## 4. Attack Surface

```
Internet
    │
    ▼
┌──────────────────────────┐
│   HTTP API (:8080)       │  ← RequestID, SecurityHeaders, CORS, RateLimit, RequireJSON
│  /auth, /keys, /encrypt  │
│  /vault, /channel        │
│  /threshold, /keystore   │
│  /kdf, /audit            │
└──────────┬───────────────┘
           │ Bearer QST token (ML-DSA-65 signed)
    ┌──────┴──────┐
    │   Business  │  ← requireAuth + requireRole RBAC middleware
    │    Logic    │
    └──────┬──────┘
           │
    ┌──────┴──────┐
    │   Crypto    │  ← ML-KEM, ML-DSA, AES-256-GCM, Argon2id, Shamir SSS (constant-time)
    │   Core      │
    └──────┬──────┘
           │
    ┌──────┴──────┐
    │   Storage   │  ← keystore.json (AES-GCM), revoked.json, audit log (hash chain + sig)
    │   (Disk)    │
    └─────────────┘
```

External interfaces with attack surface exposure:

- **HTTP API** — unauthenticated endpoints: `/health/*`, `/metrics`, `/auth/token`, `/auth/verify`, `/verify-signature`, `/threshold/verify`. All others require a valid QST Bearer token.
- **Filesystem** — keystore file (AES-GCM encrypted, mode 0600), revocation list (plaintext, mode 0600), audit log (signed, mode 0600). Accessible to any process running as the same OS user.
- **Prometheus** — `/metrics` exposes request counts and latency histograms. No secret material. Restrict to internal network in production.

---

## 5. Attack Scenarios (STRIDE)

### 5.1 Spoofing

#### S1 — Forged QST token
- **Attack:** Attacker constructs a token with elevated roles and signs it with a self-generated key.
- **Mitigation:** ML-DSA-65 signature verified with Authority's public key on every `Verify()` call. Header and payload are both inside the signing input — algorithm confusion is impossible because `hdr.Typ` and `hdr.Alg` are signed.
- **Residual risk:** None at protocol level. Requires compromise of the Authority's private key (A2).

#### S2 — Cross-issuer token presentation
- **Attack:** Token issued by Authority A presented to Authority B.
- **Mitigation:** Each Authority generates an independent ML-DSA-65 keypair at construction. Verification always uses `a.pk` which is never shared.
- **Residual risk:** None.

#### S3 — Stolen token replay (QST)
- **Attack:** Attacker intercepts a valid QST token and uses it before expiry.
- **Mitigation:** TTL enforced on every `Verify()`. Revocation via `Revoke()` persisted atomically to disk — survives service restarts. Immediate revocation via `POST /auth/revoke`.
- **Residual risk:** Window between theft and detection/revocation. Mitigated by short TTLs (default 1 hour; configure 5–15 minutes for sensitive operations).

---

### 5.2 Tampering

#### T1 — Tampered shard value
- **Attack:** Byzantine shard holder (T4) modifies their shard's `Value` bytes.
- **Mitigation:** Every shard carries `HMAC-SHA256(hmacKey, index ‖ value)` where `hmacKey = SHA-256("qs-shard-integrity-v1:" ‖ secret)`. The HMAC key is derived from the secret itself — an attacker who does not know the secret cannot compute a valid checksum for arbitrary shard data, even with full knowledge of the source code. `Reconstruct()` verifies all checksums via `subtle.ConstantTimeCompare` after Lagrange interpolation (post-reconstruction, because the key is not available until the secret is known). If any shard was tampered, interpolation produces an incorrect candidate, the derived HMAC key differs, checksums fail, and the candidate is zeroed before the error is returned.
- **Residual risk:** None — checksum authentication is cryptographically bound to the secret.

#### T2 — Audit log tampering
- **Attack:** Attacker modifies a historical log entry to hide evidence.
- **Mitigation:** Each entry includes `SHA-256(prev_hash ‖ entry_json)` and an ML-DSA-65 signature. Any modification breaks both the chain and the signature. Detected by `GET /audit/verify`.
- **Residual risk:** Chain is only as strong as the signing key (A2). If compromised, historical entries can be re-signed. Mitigate with an offline signing key for high-assurance deployments.

#### T3 — Keystore file tampering
- **Attack:** Attacker with filesystem access modifies the encrypted keystore.
- **Mitigation:** Each entry is encrypted with AES-256-GCM. The GCM authentication tag detects any ciphertext modification — a tampered entry cannot be decrypted.
- **Residual risk:** Denial of service (corrupt entry = key unavailable). No confidentiality loss.

#### T4 — Revocation list deletion
- **Attack:** Attacker deletes the revocation file to un-revoke tokens.
- **Mitigation (partial):** In-memory revocation state is authoritative for the current process lifetime. File deletion only affects the next restart.
- **Residual risk:** If the service restarts after file deletion, previously revoked tokens become valid again until they expire naturally. **Recommended upgrade:** cross-reference revocation with a secondary store (database, distributed cache) for high-security deployments.

#### T5 — Tampered hybrid ciphertext timestamp
- **Attack:** Attacker modifies `created_at` in a captured ciphertext to bypass the freshness window.
- **Mitigation:** `created_at` is bound to the AES-GCM tag as AEAD additional data at encryption time. Any modification causes `gcm.Open` to return an authentication failure before the freshness check is reached.
- **Residual risk:** None — cryptographic guarantee.

---

### 5.3 Repudiation

#### R1 — Deny a key operation occurred
- **Attack:** Principal claims they never requested key generation or signing.
- **Mitigation:** All operations append to a tamper-evident audit log (SHA-256 hash chain + ML-DSA-65 signature). Entries include timestamp, operation type, and subject identifier.
- **Residual risk:** Audit log is co-located with the service. An attacker who can delete files can destroy the log (modifications are detectable, deletion is not). Mitigate by shipping logs to an external SIEM.

---

### 5.4 Information Disclosure

#### I1 — Timing attack on Lagrange interpolation
- **Attack:** Adversary measures response latency of `POST /vault/reconstruct` across many calls to extract polynomial coefficients.
- **Mitigation:** `gfMul` is branchless (fixed 8 iterations, `byte(0)-(b&1)` masking). `gfInv` uses Fermat's theorem via 7 fixed `gfMul` calls. No lookup tables. Timing regression tests in `internal/vault/gfmul_test.go` verify coefficient of variation < 50% across operand classes.
- **Residual risk:** Go runtime scheduling and GC pauses introduce microsecond-scale jitter. This is not controllable at application level. Network RTT noise dwarfs this in practice.

#### I2 — Keystore master key extraction
- **Attack:** Attacker recovers the Argon2id-derived master key from the password.
- **Mitigation:** Argon2id with OWASP 2024 parameters: time=2, memory=64 MB, threads=4. 32-byte random domain-separated salt. Brute-forcing a 128-bit entropy password is computationally infeasible.
- **Residual risk:** Weak passwords. Enforce minimum entropy at the application level. Use `KEYSTORE_PASSWORD_FILE` to load from Docker/Kubernetes Secrets instead of environment variables.

#### I3 — Secret exposure via fewer than k shards
- **Attack:** Attacker collects k-1 shards hoping to learn anything about the secret.
- **Mitigation:** Shamir SSS over GF(256) is information-theoretically secure. k-1 shards reveal zero bits of information about the secret — proved by the perfect secrecy of the scheme.
- **Residual risk:** None — mathematical guarantee.

#### I4 — Quantum attack on classical crypto (Harvest Now, Decrypt Later)
- **Attack:** Adversary stores encrypted traffic now, decrypts when a cryptographically relevant quantum computer exists (Shor's algorithm).
- **Mitigation:** All key agreement uses ML-KEM-768/1024 (NIST FIPS 203, quantum-resistant). All signatures use ML-DSA-44/65/87 (NIST FIPS 204) **and** SLH-DSA-SHA2 (NIST FIPS 205). No RSA or ECC in any cryptographic primitive.
- **Residual risk:** None against Shor's algorithm. Grover's algorithm halves the effective AES key length — AES-256-GCM provides 128-bit post-quantum security, sufficient per NIST guidance.

#### I6 — Cryptanalytic break of lattice assumption (ML-DSA)
- **Attack:** Future cryptanalytic advance breaks the Module-LWE hardness assumption underlying ML-DSA, allowing signature forgery on QST tokens, audit log entries, or channel authentication.
- **Mitigation:** SLH-DSA (NIST FIPS 205) is available as a parallel signature primitive with entirely independent security — its security rests on SHA-256 collision resistance, not lattice hardness. Critical long-lived signatures (e.g. archive documents, regulatory records) can be signed with SLH-DSA via `POST /slh-dsa/sign`.
- **Residual risk:** QST tokens and the in-process audit log currently use ML-DSA-65. If ML-DSA is broken, tokens and log entries from before the break cannot be re-signed retroactively. Mitigate by migrating the authority key and re-issuing tokens; for the audit log, export to an external SIEM before the break event.

#### I5 — Operational data exposure via metrics
- **Attack:** `/metrics` leaks sensitive operational data.
- **Mitigation:** Metrics contain only request counts and latency histograms. No token values, key material, or plaintext secrets appear in metrics or logs.
- **Residual risk:** Request counts reveal usage patterns. Restrict `/metrics` to internal network in production.

---

### 5.5 Denial of Service

#### D1 — Unbounded request rate
- **Attack:** Attacker floods the API with requests to exhaust CPU/memory.
- **Mitigation:** Per-IP sliding-window rate limiter (60 req/min default) with background bucket cleanup every 5 minutes.
- **Residual risk:** Rate limiter is per-process in-memory. Distributed deployments need a shared rate limit store (Redis). IP spoofing can distribute load across many buckets.

#### D2 — Large request body
- **Attack:** Attacker sends a multi-GB body to exhaust memory.
- **Mitigation:** `RequireJSON` middleware caps request bodies at 1 MB via `http.MaxBytesReader`.
- **Residual risk:** None.

#### D3 — Argon2id CPU exhaustion
- **Attack:** Attacker triggers many `POST /kdf/argon2` calls to saturate CPU.
- **Mitigation:** Rate limiter limits calls per IP. Argon2id is intentionally CPU-intensive — this is an inherent tension.
- **Residual risk:** Legitimate users behind NAT share the rate limit bucket. Consider restricting `/kdf/argon2` to authenticated write-role tokens and reducing per-IP limits.

#### D4 — Channel/threshold state exhaustion
- **Attack:** Attacker opens many channel handshakes or signing rounds without completing them, exhausting server memory.
- **Mitigation:** Background `stateCleanup` goroutine evicts stale entries every 5 minutes: incomplete handshakes after 5 min, idle sessions after 1 hour, open signing rounds after 30 min.
- **Residual risk:** Up to 5 minutes of accumulation before eviction. Rate limiter bounds the maximum number of entries an attacker can create.

---

### 5.6 Elevation of Privilege

#### E1 — Threshold signing with fewer than M signers
- **Attack:** Rogue coordinator claims threshold reached with only M-1 valid partials.
- **Mitigation:** Coordinator counts unique signer IDs and cryptographically verifies each partial. Each `PartialSignature` contains `bindingHash = SHA-256("qs-threshold-v1:" ‖ nonce ‖ SHA-256(msg))`. `Verify()` independently re-validates every partial against the trusted signer set.
- **Residual risk:** None — every partial is cryptographically verified.

#### E2 — JTI manipulation to bypass revocation
- **Attack:** Attacker modifies the `jti` field in a token payload to present a revoked token as unrevoked.
- **Mitigation:** JTI is inside the ML-DSA-65 signed payload. Modifying it invalidates the signature, which is checked before the revocation lookup.
- **Residual risk:** None.

#### E3 — Channel session hijacking
- **Attack:** Attacker impersonates a channel participant after key exchange.
- **Mitigation:** ML-KEM ensures only the private-key holder can decapsulate. ML-DSA mutual authentication binds both parties' identities to the key exchange. Sequence numbers in `Seal`/`Open` prevent within-session replay.
- **Residual risk:** If an ML-DSA identity key is compromised, a MITM during key exchange is possible. Per-session ML-KEM ephemeral keys provide forward secrecy — past sessions are not exposed.

#### E4 — Hybrid ciphertext replay (cross-restart)
- **Attack:** Attacker captures a valid hybrid ciphertext and replays it after a server restart (empty in-process replay cache).
- **Mitigation:** `created_at` is bound into the AES-GCM AEAD tag at encryption time. Decryption checks that the authentic timestamp is within 5 minutes of the current time — old ciphertexts are rejected even against a fresh process with an empty cache. Modification of `created_at` fails GCM authentication before the freshness check.
- **Residual risk:** Within the 5-minute window, replay is possible if the in-process cache is empty (after restart). The window is configurable via `Decrypter.maxAge`. For zero-replay tolerance, redirect decryption through a distributed cache keyed on `KEMCiphertext`.

---

## 6. Known Limitations (Accepted Risks)

| ID  | Limitation                                          | Accepted? | Mitigation path                                            |
|-----|-----------------------------------------------------|-----------|------------------------------------------------------------|
| L1  | Revocation file is local (no distributed sync)      | Yes       | Use shared store (Redis/DB) for multi-node deployments     |
| L2  | Audit log signing key is co-located with log        | Yes       | Offline signing key for regulated environments             |
| L3  | No TLS termination in-process                       | Yes       | Deploy behind TLS-terminating reverse proxy (nginx, Caddy) |
| L4  | Rate limiter is per-instance in-memory              | Yes       | Redis-backed rate limiter for cluster deployments          |
| L5  | GC pauses affect timing uniformity                  | Yes       | Unavoidable in Go; network RTT noise dominates in practice |
| L6  | No hardware key storage (HSM/TPM)                   | Yes       | Keystore encrypts in software; HSM integration future work |
| L7  | Hybrid replay window is 5 minutes (not zero)        | Yes       | Configurable `maxAge`; distributed cache for zero-window   |
| L8  | `KEYSTORE_PASSWORD` env var acceptable for dev      | Partial   | Use `KEYSTORE_PASSWORD_FILE` (Docker/K8s Secrets) in prod  |

---

## 7. Security Assumptions

1. **Go runtime safety:** The Go runtime and standard library are free of exploitable memory-safety bugs (upheld by Go's memory-safety guarantees).
2. **NIST PQC algorithms:** ML-KEM-768 and ML-DSA-65 provide 128-bit post-quantum security as specified by NIST FIPS 203/204. SLH-DSA-SHA2-128f provides 128-bit post-quantum security under the SHA-256 collision resistance assumption (NIST FIPS 205).
3. **OS entropy:** `crypto/rand` produces cryptographically secure randomness from the OS CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows).
4. **Deployment TLS:** The service is deployed behind a TLS-terminating proxy. All client traffic is encrypted in transit.
5. **Filesystem confidentiality:** The host applies filesystem access controls. Keystore and revocation files (mode 0600) are readable only by the service process owner.
6. **Administrator trust:** The operator setting the keystore master password is trusted. Compromise of that password equals compromise of all stored keys.
7. **Quantum safety horizon:** Designed for a 20-year security horizon. Cryptographically relevant quantum computers are not assumed to exist before that horizon.

---

## 8. Security Contact

Report vulnerabilities by opening a private security advisory in the project repository. Do not file public issues for unpatched vulnerabilities.
