# QuantumShield — Architecture

**Version:** 1.1
**Last updated:** 2026-05-29

---

## 1. Overview

QuantumShield is a post-quantum cryptographic platform written in Go. It exposes a self-contained HTTP API for key management, authenticated encryption, signing, secret sharing, secure channels, and threshold authorisation — all using NIST-standardised post-quantum algorithms.

Design goals:

- **Zero classical asymmetric crypto** — no RSA, no ECDH, no ECDSA anywhere in the call graph
- **Stdlib-first** — ML-KEM via Go 1.24 `crypto/mlkem`; symmetric crypto via `crypto/cipher`
- **Algorithm diversity** — both ML-DSA (lattice, FIPS 204) and SLH-DSA (hash-based, FIPS 205) are provided with independent security assumptions
- **Audit by default** — every key operation writes a tamper-evident hash-chained log entry
- **Forward secrecy** — PQ Secure Channel uses a fresh ephemeral ML-KEM keypair per session
- **Constant-time crypto** — GF(256) arithmetic is branchless; ML-DSA/ML-KEM libraries are constant-time
- **Replay protection** — hybrid ciphertext timestamps are bound to the AEAD tag; server maintains a persistent per-level replay cache

---

## 2. Package Structure

```
quantum_shield_go/
├── cmd/
│   ├── server/          main.go — HTTP server entry point, graceful shutdown
│   └── scanner/         main.go — RSA/ECDH dependency migration scanner
│
├── internal/            (not importable by external packages)
│   ├── kem/             ML-KEM-768/1024 key encapsulation (FIPS 203)
│   ├── dsa/             ML-DSA-44/65/87 digital signatures (FIPS 204)
│   ├── slhdsa/          SLH-DSA-SHA2 hash-based signatures (FIPS 205, 6 parameter sets)
│   ├── hybrid/          AES-256-GCM encryption with ML-KEM key agreement + replay protection
│   ├── auth/            Quantum Secure Tokens (QST) — JWT-analog, ML-DSA-65 signed
│   ├── audit/           Tamper-evident audit log (SHA-256 hash chain + ML-DSA signatures)
│   ├── channel/         PQ Secure Channel (ephemeral ML-KEM + ML-DSA auth + AES-256-GCM)
│   ├── kdf/             HKDF-SHA256 and Argon2id key derivation
│   ├── keystore/        Encrypted key store (Argon2id master key, AES-GCM entries, atomic writes)
│   ├── threshold/       M-of-N threshold signing (independent ML-DSA-65 per signer)
│   └── vault/           Shamir's Secret Sharing over GF(256), constant-time arithmetic
│
├── pkg/                 (reusable; importable by external packages)
│   ├── api/             HTTP server, routing, all endpoint handlers, state lifecycle
│   ├── logger/          Structured JSON logger (slog), RequestLogger middleware
│   ├── metrics/         Prometheus text format 0.0.4 (Counter, Gauge, Histogram)
│   └── middleware/      RequestID, SecurityHeaders, CORS, RateLimiter, RequireJSON, MaxBodySize
│
├── deploy/
│   └── prometheus.yml   Prometheus scrape configuration
│
├── Dockerfile           Multi-stage build (golang:1.24-alpine → scratch)
├── docker-compose.yml   API + optional Prometheus monitoring profile
└── .github/workflows/
    └── ci.yml           CI: test matrix (Go 1.24 + 1.25), race detector, govulncheck, Docker smoke
```

### Dependency graph (simplified)

```
cmd/server
    └── pkg/api ─────────────────────────────────────────────────────┐
                                                                     │
        pkg/middleware ── pkg/logger ── pkg/metrics                  │
                                                                     │
        internal/kem ──── crypto/mlkem (Go 1.24 stdlib)             │
        internal/dsa ──── cloudflare/circl/sign/mldsa                │
        internal/slhdsa ── trailofbits/go-slh-dsa                   │
        internal/hybrid ── internal/kem + crypto/cipher              │
        internal/auth ──── internal/dsa                              │
        internal/audit ─── internal/dsa + crypto/sha256              │
        internal/channel ── internal/kem + internal/dsa + internal/kdf│
        internal/kdf ────── golang.org/x/crypto/hkdf + argon2        │
        internal/keystore ── internal/kdf + crypto/cipher            │
        internal/threshold ─ internal/dsa + crypto/sha256            │
        internal/vault ───── crypto/hmac + crypto/sha256             │
                                                                     │
        All of the above ────────────────────────────────────────────┘
```

---

## 3. Core Data Flows

### 3.1 Key Encapsulation (ML-KEM)

```
POST /keys/generate → {key_id, public_key}
  Server:  kem.GenerateKey(level) → (dk, ek)
           Store dk encrypted in keystore (or in-memory)
           Return ek (public key) + key_id
           Also split dk via Shamir SSS (5 shards, threshold 3) for backup

POST /encrypt → {encrypted: {kem_ciphertext, nonce, data, created_at}}
  Server:  ek = keystore.GetActive(key_id).EKBytes
           kem.Encapsulate(ek) → (sharedSecret, kemCT)
           aesKey = sharedSecret[:32]
           nonce  = crypto/rand[12]
           created_at = time.Now().Unix()
           ad     = BigEndian64(created_at)            ← AEAD additional data
           data   = AES-256-GCM.Seal(nonce, plaintext, ad)
           Return {kemCT, nonce, data, created_at}

POST /decrypt ← {key_id, encrypted: {kem_ciphertext, nonce, data, created_at}}
  Server:  dk = keystore.GetActive(key_id).DKBytes
           sharedSecret = kem.Decapsulate(dk, kemCT)
           aesKey = sharedSecret[:32]
           ad = BigEndian64(created_at)                ← same AD as at encrypt time
           plaintext = AES-256-GCM.Open(nonce, data, ad)
           if time.Now() - created_at > 5 min → reject (freshness check)
           if kemCT in seen-cache → reject (replay cache)
```

**Replay protection layers:**
1. `created_at` is bound to the AEAD tag — an attacker cannot modify it without breaking authentication
2. Freshness window (5 min, default) — old ciphertexts are rejected even after server restart
3. In-process replay cache per key level — same ciphertext rejected within one process lifetime

Implementation: `internal/hybrid/hybrid.go`, `pkg/api/server.go`

---

### 3.2 QST Token Lifecycle

```
Issue (POST /auth/token):
  1. Validate caller (BOOTSTRAP_SECRET if configured)
  2. Generate 128-bit random JTI
  3. Header{typ:"QST", alg:"ML-DSA-65", ver:1}
  4. Claims{sub, iss, iat, exp, roles, jti, extra}
  5. signingInput = base64url(header) + "." + base64url(claims)
  6. sig = ML-DSA-65.Sign(authority.sk, signingInput)
  7. token = signingInput + "." + base64url(sig)

Verify (POST /auth/verify / Bearer middleware):
  1. Split token → [hdrB64, claimsB64, sigB64]
  2. Decode and validate header fields (typ, ver)
  3. ML-DSA-65.Verify(authority.pk, hdrB64+"."+claimsB64, sig)
  4. Decode claims; check exp > now
  5. Check jti ∉ revocation map
  6. Return claims

Revoke (POST /auth/revoke):
  1. Extract jti + exp from payload (no signature verification)
  2. revoked[jti] = exp
  3. Atomic-write revocation list to disk (JSON → .tmp → rename)
  4. Background pruner removes expired JTIs hourly
```

Security: JTI is inside the ML-DSA-65 signed payload. Modifying it invalidates the signature, so a revoked JTI cannot be presented as a different one.

Implementation: `internal/auth/auth.go`

---

### 3.3 PQ Secure Channel

```
Initiator (Alice)                         Responder (Bob)
  │                                           │
  │  POST /channel/init                       │
  │  Server generates: (initDSA_sk, initDSA_pk)
  │  Server generates: (initKEM_sk, initKEM_ek)
  │  Encapsulate(responderKEM_ek) → (kemCT, sharedSecret)
  │  sig = ML-DSA-65.Sign(initDSA_sk, kemCT)
  │  Store {initiator, initKEM_sk} in server state (5 min TTL)
  │                                           │
  │  ← {session_id, ek_bytes, identity_pk, signature}
  │                                           │
  │  [Alice passes session_id + ek_bytes to Bob out-of-band]
  │                                           │
  │                                           │  POST /channel/complete
  │                                           │  {session_id, kem_ciphertext,
  │                                           │   identity_pk, signature}
  │                                           │
  │                                           │  ML-DSA-65.Verify(identity_pk, kemCT, sig)
  │                                           │  sharedSecret = Decapsulate(initKEM_sk, kemCT)
  │                                           │  sessionKeys = HKDF(sharedSecret, "qs-channel-v1")
  │                                           │  Store session (1h idle TTL)
  │                                           │  ← {session_id, status: "established"}
  │
  │  POST /channel/seal                       │
  │  AES-256-GCM encrypt with seq_num AD      │
  │  → {session_id, seq_num, ciphertext}      │
  │                                           │  POST /channel/open
  │  ──── ciphertext ────────────────────────►│  AES-256-GCM decrypt
  │                                           │  ← {plaintext}
```

Forward secrecy: each session generates a fresh ML-KEM ephemeral keypair. Compromise of long-term ML-DSA identity keys does not expose past session traffic.

Session key derivation (both parties run identically):
```
HKDF-SHA256(sharedSecret, salt="qs-channel-v1", info="send-key")    → sendKey[32]
HKDF-SHA256(sharedSecret, salt="qs-channel-v1", info="recv-key")    → recvKey[32]
HKDF-SHA256(sharedSecret, salt="qs-channel-v1", info="session-nonce") → nonce[12]
```

Implementation: `internal/channel/channel.go`

---

### 3.4 Shamir Secret Sharing (Vault)

```
Split(secret, n, k):
  For each byte i of secret:
    Polynomial: f_i(x) = secret[i] + a₁·x + … + a_{k-1}·x^{k-1}  in GF(256)
    Coefficients a₁…a_{k-1} from crypto/rand
  x-values: {2, 4, 6, …, 2n} — distinct, non-zero, non-consecutive
  Evaluate f_i(x) via Horner's method in GF(256) (branchless arithmetic)
  hmacKey = SHA-256("qs-shard-integrity-v1:" ‖ secret)  ← secret-derived, not fixed
  Each shard: {index=x, value=f(x), checksum=HMAC-SHA256(hmacKey, x||f(x))}

Reconstruct(shards[0..k-1]):
  1. Detect zero / duplicate x-values (structural, no secret needed)
  2. Lagrange interpolation at x=0 in GF(256):
     candidate[i] = Σ_j shard[j].value[i] · ∏_{m≠j} (x_m / (x_j XOR x_m))
  3. Derive hmacKey = SHA-256("qs-shard-integrity-v1:" ‖ candidate)
  4. Verify all shard checksums (subtle.ConstantTimeCompare)
     If any mismatch → zero candidate, return error
  5. Return candidate
```

**Constant-time guarantee:** `gfMul` uses branchless arithmetic — no data-dependent branches, fixed 8 iterations. `gfInv` uses Fermat's theorem (a^254 = a⁻¹) via 7 fixed `gfMul` calls. No lookup tables. Timing regression tests in `internal/vault/gfmul_test.go` verify CV < 50% across operand classes.

**Checksum authentication:** The HMAC key is derived from the secret (`SHA-256("qs-shard-integrity-v1:" ‖ secret)`), not from a fixed string. An attacker who does not know the secret cannot compute valid checksums for arbitrary shard data. Verification happens after reconstruction (post-reconstruction) because the key is not known until the secret is recovered.

Implementation: `internal/vault/vault.go`

---

### 3.5 Threshold Signing

```
Setup:
  Each signer N: NewSigner(id) → ML-DSA-65 keypair (persistent per server lifetime)

Signing round:
  Coordinator: NewCoordinator(msg, nonce, M)

  Each signer i:
    bindingHash = SHA-256("qs-threshold-v1:" ‖ nonce ‖ SHA-256(msg))
    sig_i = ML-DSA-65.Sign(sk_i, msg ‖ bindingHash)
    partial_i = {signerID, publicKey, sig_i, bindingHash}

  Coordinator.Submit(partial_i):
    ML-DSA-65.Verify(pk_i, msg ‖ bindingHash, sig_i)
    Accumulate unique signer IDs until M valid partials
    → AuthorisedSignature{partials[0..M-1], msg_digest, nonce, threshold}

Verify(msg, auth, trustedPKs):
  For each partial: recompute bindingHash, verify ML-DSA-65 sig against trusted pk
  Count unique verified signers ≥ M → accept
```

Binding hash prevents cross-round substitution: a partial from round R cannot be replayed in round R′ with a different message.

Implementation: `internal/threshold/threshold.go`

---

### 3.6 Encrypted Keystore

```
Open(path, password):
  1. masterKey = Argon2id(password, DomainSalt("qs-keystore-master-key-v1"))
                 [time=2, mem=64 MB, threads=4, OWASP 2024]
  2. Load JSON file → decrypt each entry with AES-256-GCM(masterKey)

Put(id, ek_bytes, dk_bytes, ttl):
  1. AES-256-GCM encrypt(masterKey, dk_bytes) → encDK
  2. Store {id, version, encDK, ek_bytes, createdAt, expiresAt, active=true}
  3. Atomic write: path+".tmp" → os.Rename(path)

Rotate(id):
  1. version++; generate new ML-KEM keypair
  2. Previous version stays accessible via GetVersion(id, prev)
  3. GetActive(id) returns highest non-expired version
```

Key isolation: `dk` (private key) is AES-GCM encrypted at rest. `ek` (public key) is stored plaintext — it is by definition public material.

Docker Secrets / Kubernetes Secrets: the keystore password can be read from a file path via `KEYSTORE_PASSWORD_FILE` instead of from the environment variable.

Implementation: `internal/keystore/keystore.go`

---

### 3.7 SLH-DSA Signing (NIST FIPS 205)

```
POST /slh-dsa/sign ← {message, level}
  Server:  params = slh.GetParamSet("SLH-DSA-SHA2-" + level)
           pk, sk = slh.SLHKeygen(params)           ← ephemeral keypair, fresh per request
           sig    = slh.SLHSign(rand.Reader, msg, nil, sk)
                                                     ← hedged (randomized nonce via crypto/rand)
           Return {signature, public_key, algorithm, signature_size}

POST /slh-dsa/verify ← {message, signature, public_key, level}   (public — no auth)
  Server:  pk  = slh.LoadPublicKey(params, pk_bytes)
           sig = slh.LoadSignature(params, sig_bytes)
           ok  = slh.SLHVerify(msg, sig, nil, pk)
           Return {valid, algorithm}
```

**Security properties:**

- **Hash-based security** — rests on SHA-256 collision resistance only; independent of lattice hardness assumptions used by ML-DSA/ML-KEM
- **Stateless** — no per-signer state to synchronise or protect; safe to sign concurrently from multiple goroutines
- **Hedged signing** — each call to `Sign` samples a fresh random nonce from `crypto/rand`; two signatures over the same message are always distinct
- **Parameter set selection** — the `level` string (`128f`, `128s`, `192f`, `192s`, `256f`, `256s`) selects security category (NIST 1/3/5) and speed/size trade-off (`f`=fast+larger, `s`=small+slower)

**Choosing between ML-DSA and SLH-DSA:**

| Property              | ML-DSA                   | SLH-DSA                       |
|-----------------------|--------------------------|-------------------------------|
| Security basis        | Module-LWE (lattice)     | SHA-256 collision resistance  |
| Sign speed            | < 1 ms                   | 1–100 ms (level dependent)    |
| Signature size        | 2.4–4.6 KB               | 7.9–49 KB                     |
| Verify speed          | < 1 ms                   | < 5 ms                        |
| Best for              | Interactive APIs, tokens | Long-term archives, documents |

Implementation: `internal/slhdsa/slhdsa.go` (wraps `github.com/trailofbits/go-slh-dsa`)

---

## 4. HTTP Middleware Chain

Every inbound request passes through this chain in order:

```
Request
  │
  ▼
RequestID                — Generate or propagate X-Request-ID for end-to-end tracing
  │
  ▼
SecurityHeaders          — HSTS, X-Frame-Options, CSP, X-Content-Type-Options, etc.
  │
  ▼
CORS                     — Origin validation, Access-Control-* headers (allowlist from env)
  │
  ▼
metrics.HTTPMiddleware   — Records request count and latency histogram (Prometheus)
  │
  ▼
RateLimiter              — Sliding-window per-IP, 60 req/min default
  │
  ▼
RequireJSON              — Rejects non-JSON Content-Type on POST/PUT/PATCH; 1 MB body cap
  │
  ▼
ServeMux (routing)
  │
  ├─ GET /                     — Service info (public)
  ├─ GET /health/live          — Liveness probe (public)
  ├─ GET /health/ready         — Readiness probe (public)
  ├─ GET /metrics              — Prometheus scrape (public — restrict in prod)
  │
  ├─ POST /auth/token          — Issue QST (public; gated by BOOTSTRAP_SECRET if set)
  ├─ POST /auth/verify         — Verify QST (public)
  ├─ POST /auth/revoke         — Revoke QST (write role)
  │
  ├─ POST /verify-signature    — ML-DSA verify (public)
  ├─ POST /threshold/verify    — Threshold verify (public)
  │
  ├─ POST /keys/generate       — Generate ML-KEM keypair (write)
  ├─ GET  /keys/{key_id}/public — Retrieve public key (read)
  ├─ POST /encrypt             — Hybrid encrypt (write)
  ├─ POST /decrypt             — Hybrid decrypt (write)
  ├─ POST /sign                — ML-DSA sign (write)
  │
  ├─ POST /vault/split         — Shamir split (write)
  ├─ POST /vault/reconstruct   — Shamir reconstruct (write)
  │
  ├─ POST /channel/init        — Channel initiate (write)
  ├─ POST /channel/complete    — Channel complete (write)
  ├─ POST /channel/seal        — Channel seal (write)
  ├─ POST /channel/open        — Channel open (write)
  │
  ├─ POST /threshold/round     — Open signing round (write)
  ├─ POST /threshold/sign      — Submit partial signature (write)
  ├─ POST /threshold/submit    — Collect partials (write)
  │
  ├─ POST /kdf/hkdf            — HKDF-SHA256 derivation (write)
  ├─ POST /kdf/argon2          — Argon2id derivation (write)
  ├─ POST /kdf/salt            — Random 32-byte salt (write)
  │
  ├─ GET  /audit/entries       — List audit log (read)
  ├─ GET  /audit/verify        — Verify audit chain (read)
  │
  ├─ POST /keystore/generate   — Generate + store ML-KEM keypair (admin)
  ├─ GET  /keystore            — List key IDs (admin)
  ├─ GET  /keystore/{key_id}   — Key metadata (admin)
  ├─ POST /keystore/{key_id}/rotate  — Rotate key (admin)
  ├─ POST /keystore/{key_id}/expire  — Expire version (admin)
  └─ DELETE /keystore/{key_id}       — Delete key (admin)
```

Role check order: `requireRole(role) = requireAuth() → hasRole(role)`. Returns 401 if unauthenticated, 403 if authenticated but role absent.

---

## 5. Key Management Lifecycle

```
Generation
  kem.GenerateKey() → (dk, ek)
        │
        ▼
Storage
  If KEYSTORE_PATH set:
    keystore.Put(id, dk_bytes, ek_bytes, ttl)
    → AES-256-GCM(dk_bytes, masterKey) on disk
  Else:
    In-memory map (ephemeral — lost on restart)
        │
        ▼
Active use
  keystore.GetActive(id) → decrypt → return
        │
        ├─ Rotation (POST /keystore/{id}/rotate)
        │   New ML-KEM keypair; previous version stays accessible
        │   Old version for decryption of existing ciphertexts during transition
        │
        └─ Expiry
            keystore.Expire(id) or TTL auto-expiry
            GetActive rejects expired versions
```

### Key rotation policy

| Key type            | Scheduled interval | Emergency action                                          |
|---------------------|--------------------|-----------------------------------------------------------|
| ML-DSA signing keys | 90 days            | Rotate immediately; revoke all tokens signed with old key |
| ML-KEM long-term    | 180 days           | Rotate; redistribute new public key out-of-band           |
| ML-KEM session keys | Per session        | Automatic (ephemeral, never reused)                       |
| Keystore master key | On suspicion only  | Re-encrypt all entries with new Argon2id-derived key      |

Backward compatibility: `GetVersion(id, v)` retrieves historical versions for decrypting messages encrypted with a rotated key.

---

## 6. In-Memory State Lifecycle

The server holds in-memory state for active channels and threshold rounds. A background goroutine (`stateCleanup`) prunes stale entries every 5 minutes to prevent unbounded memory growth.

| State bucket              | TTL          | Eviction trigger                      |
|---------------------------|--------------|---------------------------------------|
| `channelInitiators`       | 5 minutes    | Incomplete handshake (responder absent) |
| `channelSessions`         | 1 hour idle  | Session not used for 1 hour           |
| `thresholdRounds`         | 30 minutes   | Round not reaching threshold          |
| `thresholdSigners`        | 24 hours idle| Signer identity not used              |
| Hybrid replay cache       | Process lifetime | Per-level LRU, max 100k entries    |

`Server.Close()` is idempotent (via `sync.Once`) and stops both the state cleanup goroutine and the revocation pruner goroutine. Called by `main.go` after `http.Server.Shutdown` drains connections.

---

## 7. Audit Log Structure

```json
{
  "seq":       42,
  "timestamp": "2026-05-29T14:30:00Z",
  "operation": "KEY_GENERATE",
  "subject":   "user-001",
  "details":   {"algorithm": "ML-KEM-768", "key_id": "k-abc123"},
  "prev_hash": "sha256:aabbcc...",
  "hash":      "sha256:ddeeff...",
  "signature": "base64url(ML-DSA-65(sk, entry_json))"
}
```

Hash chain: `entry.hash = SHA-256(entry.prev_hash ‖ entry_json_without_hash_and_sig)`

Verification: `GET /audit/verify` replays every hash and re-verifies every ML-DSA signature. Any gap or modification is detected.

---

## 8. Security Boundaries

```
Trust zone: PROCESS
  ┌─────────────────────────────────────────────────────┐
  │  All internal/* packages share the same process.    │
  │  No IPC boundary — they share memory.               │
  │  Trust boundary is the HTTP API surface.            │
  └─────────────────────────────────────────────────────┘

Trust zone: FILESYSTEM
  ┌─────────────────────────────────────────────────────┐
  │  keystore.json   — AES-256-GCM encrypted (mode 0600)│
  │  revoked.json    — plaintext JTI list (low value)   │
  │  audit.log       — hash-chained + ML-DSA signed     │
  │                                                     │
  │  Docker Secrets: /run/secrets/qs_*                  │
  └─────────────────────────────────────────────────────┘

Trust zone: NETWORK (untrusted)
  ┌─────────────────────────────────────────────────────┐
  │  All HTTP clients are untrusted.                    │
  │  Authentication via QST Bearer token.               │
  │  Transport security via TLS-terminating proxy.      │
  └─────────────────────────────────────────────────────┘
```

---

## 9. Concurrency Model

- All state-holding types use `sync.RWMutex` for reader-writer separation.
- `Authority` (auth): RWMutex covers pk/sk and revoked map. File I/O occurs outside the lock (snapshot → release → atomic write).
- `Keystore`: RWMutex covers in-memory entry map. Atomic file writes prevent partial disk state.
- `RateLimiter`: per-IP `sync.Mutex`; background cleanup goroutine every 5 minutes.
- `Audit`: `sync.Mutex` serialises append (hash chain requires strict ordering).
- `Decrypter` (hybrid replay cache): `sync.Mutex` on the seen-map; shared across requests via `Server.decryptors[level]`.
- HTTP server: each request runs in its own goroutine (`net/http` default). All shared state protected by the above.
- Race detector (`go test -race`) runs on every CI push.

---

## 10. Configuration

All configuration via environment variables (12-factor). Secrets support a `_FILE` suffix to read from a Docker/Kubernetes Secrets file instead of the environment.

| Variable                  | Default   | Description                                                  |
|---------------------------|-----------|--------------------------------------------------------------|
| `LISTEN_ADDR`             | `:8080`   | TCP address to listen on                                     |
| `LOG_LEVEL`               | `INFO`    | Minimum log level: DEBUG, INFO, WARN, ERROR                  |
| `ALLOWED_ORIGINS`         | `""`      | Comma-separated CORS origins; empty = CORS disabled          |
| `BOOTSTRAP_SECRET`        | `""`      | Protects `POST /auth/token`; empty = open (dev only)         |
| `BOOTSTRAP_SECRET_FILE`   | `""`      | File path for bootstrap secret (Docker Secrets preferred)    |
| `REVOCATION_FILE`         | `""`      | Path to persistent revocation list JSON; empty = in-memory   |
| `KEYSTORE_PATH`           | `""`      | Path to encrypted keystore; empty = ephemeral in-memory      |
| `KEYSTORE_PASSWORD`       | `""`      | Argon2id master key password for keystore                    |
| `KEYSTORE_PASSWORD_FILE`  | `""`      | File path for keystore password (Docker Secrets preferred)   |

---

## 11. Build and Deployment

### Container image

```
Stage 1 (builder): golang:1.24-alpine
  CGO_ENABLED=0, GOFLAGS="-trimpath", ldflags="-s -w"
  go build ./cmd/server

Stage 2 (runtime): scratch
  COPY /etc/passwd (non-root UID 65534)
  COPY /etc/ssl/certs (CA bundle for outbound TLS if needed)
  COPY binary
  USER 65534:65534
  EXPOSE 8080
```

Container security properties:
- No shell, no package manager, no OS utilities — minimal attack surface
- Non-root user — privilege escalation requires escaping the container
- Read-only root filesystem (`read_only: true` in docker-compose)
- No new privileges (`security_opt: no-new-privileges:true`)
- All Linux capabilities dropped (`cap_drop: ALL`)
- `/tmp` as tmpfs for temporary files

### CI pipeline

| Job       | Matrix          | Checks                                                                |
|-----------|-----------------|-----------------------------------------------------------------------|
| test      | Go 1.24 + 1.25  | `go vet`, `go build`, `go test -race -count=1 -timeout=300s ./...`   |
| benchmark | Go 1.24         | `go test -bench=.` across all internal packages                       |
| security  | Go 1.24         | `govulncheck ./...`, RSA migration scanner                            |
| docker    | —               | `docker build`, smoke test `/health/live` + `/health/ready`           |
