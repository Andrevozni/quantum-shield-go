# QuantumShield

**Post-quantum cryptography platform built in Go.**

A self-hosted API server that replaces RSA/ECDSA/ECDH with NIST-standardised
post-quantum algorithms — ready for the quantum computing era.

**No RSA. No ECDH. No ECDSA. Anywhere.**

```bash
# Start in 30 seconds
docker run -p 8080:8080 ghcr.io/quantum-shield/quantum-shield:latest

# Generate a post-quantum keypair
curl -X POST http://localhost:8080/keys/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"level":"ML-KEM-768"}'
```

---

## Why

Harvest-now-decrypt-later attacks are real. Organisations are already
collecting encrypted traffic today to decrypt it once a sufficiently powerful
quantum computer exists. NIST finalised its post-quantum standards in 2024
(FIPS 203/204/205). Most production systems still use RSA and ECDSA.

QuantumShield is a drop-in cryptography service that lets you migrate your
stack to post-quantum algorithms without rewriting every service from scratch.

---

## Algorithms

| Primitive | Algorithm | Standard | Implementation |
|-----------|-----------|----------|----------------|
| Key encapsulation | ML-KEM-768 / ML-KEM-1024 | NIST FIPS 203 | Go stdlib `crypto/mlkem` |
| Digital signatures | ML-DSA-44 / 65 / 87 | NIST FIPS 204 | `cloudflare/circl` |
| Hash-based signatures | SLH-DSA-SHA2 128/192/256 f/s | NIST FIPS 205 | `trailofbits/go-slh-dsa` |
| Authenticated encryption | AES-256-GCM | NIST FIPS 197 | Go stdlib `crypto/cipher` |
| Key derivation | HKDF-SHA256 | RFC 5869 | `golang.org/x/crypto` |
| Password hashing | Argon2id | RFC 9106 | `golang.org/x/crypto` |
| Secret sharing | Shamir SSS over GF(256) | — | Constant-time custom |
| Auth tokens | QST (ML-DSA-65 signed JWT-analog) | — | Custom |

---

## Features

### 🔑 Key Management
- Generate ML-KEM-768/1024 keypairs
- Encrypted keystore (Argon2id + AES-256-GCM)
- Key rotation, expiry, secure export/import
- Automatic Shamir secret-sharing of every private key (5-of-3)

### 🔐 Cryptography API
- **Hybrid encryption**: ML-KEM-768 key encapsulation + AES-256-GCM
- **Replay protection**: in-process ciphertext cache rejects replayed ciphertext
- **Signatures**: ML-DSA-65 (default) and SLH-DSA (stateless, HSM-friendly)
- **KDF**: HKDF-SHA256, Argon2id, random salt generation

### 🏛️ Post-Quantum CA
- ML-DSA-87 signed certificates (JSON format, no ASN.1)
- Root CA + intermediate CAs
- Certificate Revocation List (CRL)
- Full chain verification
- Encrypted persistence (survives restarts)

### 🛡️ Security
- JWT-analog tokens signed with ML-DSA-65
- Role-based access control (read / write / admin)
- Sliding-window rate limiting (per-IP + per-subject)
- Tamper-evident audit log (SHA-256 hash-chained)
- **54 automated penetration tests** covering JWT forgery, replay attacks,
  path traversal, CORS bypass, timing oracles, cert forgery, and more
- **Go race detector clean** — zero data races under concurrent load

### 🔐 HSM Support
- PKCS#11 integration (SoftHSM2, Thales Luna, AWS CloudHSM, nCipher)
- Build with `-tags pkcs11` to enable

### 🌐 High Availability
- 3-node Raft cluster via `hashicorp/raft`
- Automatic leader election (< 150 ms failover)
- Write replication: all key/CA mutations replicated before response
- Follower read serving (eventually consistent)

### 📦 SDKs
- **Python** — zero dependencies, sync + async (`httpx`)
- **JavaScript/TypeScript** — zero dependencies, works in Node, Deno, Bun, browser

---

## Quick Start

### Standalone (single node)

```bash
docker run -p 8080:8080 \
  -e BOOTSTRAP_SECRET=my-secret \
  ghcr.io/quantum-shield/quantum-shield:latest
```

### 3-node cluster

```bash
git clone https://github.com/quantum-shield/quantum-shield-go
cd quantum-shield-go
docker compose --profile cluster up
```

Nodes listen on ports 8081, 8082, 8083. Nginx load balancer on port 80.

### Build from source

```bash
git clone https://github.com/quantum-shield/quantum-shield-go
cd quantum-shield-go
go build ./cmd/server
./server
```

Requires Go 1.25+.

---

## API

### Authentication

```bash
# Issue a token
TOKEN=$(curl -s -X POST http://localhost:8080/auth/token \
  -H "Authorization: Bearer my-secret" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","roles":["read","write"]}' | jq -r .token)
```

### Key Management

```bash
# Generate ML-KEM-768 keypair
KEY=$(curl -s -X POST http://localhost:8080/keys/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"level":"ML-KEM-768"}')

KEY_ID=$(echo $KEY | jq -r .key_id)
```

### Encrypt / Decrypt

```bash
# Encrypt
ENC=$(curl -s -X POST http://localhost:8080/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key_id\":\"$KEY_ID\",\"plaintext\":\"hello world\"}")

# Decrypt
curl -s -X POST http://localhost:8080/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key_id\":\"$KEY_ID\",\"encrypted\":$(echo $ENC | jq .encrypted)}"
```

### Sign / Verify

```bash
# Sign
SIG=$(curl -s -X POST http://localhost:8080/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key_id\":\"$KEY_ID\",\"message\":\"$(echo -n 'hello' | base64)\"}")

# Verify (public — no token needed)
curl -s -X POST http://localhost:8080/verify-signature \
  -H "Content-Type: application/json" \
  -d "{
    \"message\":\"$(echo -n 'hello' | base64)\",
    \"signature\":$(echo $SIG | jq .signature),
    \"public_key\":$(echo $SIG | jq .public_key)
  }"
```

### Certificate Authority

```bash
# Initialise CA (admin role required)
curl -s -X POST http://localhost:8080/ca/init \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"CN=My Root CA,O=Example Corp"}'

# Issue a certificate
CERT=$(curl -s -X POST http://localhost:8080/ca/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"subject\":\"CN=service.example.com\",
    \"public_key\":$(echo $KEY | jq .public_key),
    \"public_key_type\":\"ML-KEM-768\"
  }")

# Verify (public — no token needed)
curl -s -X POST http://localhost:8080/ca/verify \
  -H "Content-Type: application/json" \
  -d "{\"certificate\":$CERT}"
```

---

## Python SDK

```bash
pip install quantum-shield
```

```python
from quantum_shield import QuantumShield

qs = QuantumShield("http://localhost:8080", bootstrap_secret="my-secret")
qs.auth("alice", ["read", "write"])

# Encrypt
key = qs.keys.generate("ML-KEM-768")
enc = qs.crypto.encrypt(key.key_id, b"secret message")
dec = qs.crypto.decrypt(key.key_id, enc.encrypted)
assert dec.plaintext == b"secret message"

# Sign
sig = qs.crypto.sign(key.key_id, b"document")
result = qs.crypto.verify_signature(b"document", sig.signature, sig.public_key)
assert result.valid

# CA
qs.ca.init("CN=My Root CA,O=Example Corp")
cert = qs.ca.sign("CN=service.example.com", key.public_key, "ML-KEM-768")
qs.ca.verify(cert)  # raises CertificateVerificationError if invalid
```

**Async:**

```python
from quantum_shield.async_client import AsyncQuantumShield

async with AsyncQuantumShield("http://localhost:8080") as qs:
    await qs.auth("alice", ["write"])
    key  = await qs.keys.generate()
    enc  = await qs.crypto.encrypt(key.key_id, b"hello")
    dec  = await qs.crypto.decrypt(key.key_id, enc.encrypted)
```

---

## JavaScript / TypeScript SDK

```bash
npm install @quantum-shield/client
```

```typescript
import { QuantumShield } from "@quantum-shield/client";

const qs = new QuantumShield({ baseUrl: "http://localhost:8080" });
await qs.auth("alice", ["read", "write"], "my-bootstrap-secret");

// Encrypt / decrypt
const key = await qs.keys.generate("ML-KEM-768");
const enc = await qs.crypto.encrypt(key.key_id, "hello world");
const dec = await qs.crypto.decrypt(key.key_id, enc.encrypted);
console.log(dec); // "hello world"

// Sign / verify
const sig = await qs.crypto.sign(key.key_id, "document");
const ok  = await qs.crypto.verifySignature("document", sig.signature, sig.public_key);

// CA
await qs.ca.init("CN=My Root CA");
const cert = await qs.ca.sign("CN=service.example.com", key.public_key);
await qs.ca.verify(cert);
```

Works in Node.js ≥ 18, Deno, Bun, and modern browsers. Zero dependencies.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `BOOTSTRAP_SECRET` | — | Bearer secret for `/auth/token` |
| `LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARN` \| `ERROR` |
| `TLS_CERT_FILE` | — | PEM certificate (enables HTTPS) |
| `TLS_KEY_FILE` | — | PEM private key |
| `TLS_AUTO_SELF_SIGNED` | `false` | Generate self-signed cert (dev only) |
| `TLS_CLIENT_CA_FILE` | — | Enable mTLS |
| `KEYSTORE_PATH` | — | Encrypted key store path |
| `KEYSTORE_PASSWORD` | — | Key store password |
| `CA_STORE_PATH` | — | Encrypted CA hierarchy path |
| `CA_STORE_PASSWORD` | — | CA store password |
| `REVOCATION_FILE` | — | Persistent JWT revocation list |
| `QS_CLUSTER_ENABLED` | `false` | Enable Raft cluster |
| `QS_CLUSTER_NODE_ID` | hostname | Unique node identifier |
| `QS_CLUSTER_BIND_ADDR` | `127.0.0.1:7000` | Raft TCP address |
| `QS_CLUSTER_DATA_DIR` | `./data/raft` | Raft log + snapshot directory |
| `QS_CLUSTER_BOOTSTRAP` | `false` | Bootstrap new cluster (first node only) |
| `QS_CLUSTER_JOIN_ADDR` | — | Leader Raft address to join |

---

## Health & Observability

```bash
GET /health/live   # liveness probe
GET /health/ready  # readiness probe + FIPS status
GET /health/fips   # detailed FIPS algorithm probe report
GET /metrics       # Prometheus metrics
```

FIPS probe runs 11 live algorithm tests at startup (ML-KEM, ML-DSA, SLH-DSA,
AES-256-GCM, HKDF, Argon2id, CSPRNG) and caches the result.

---

## Security

### Threat model

QuantumShield assumes:
- Network between clients and server is **untrusted** → use TLS
- Network between cluster nodes is **trusted** → use mTLS or VPN
- Server memory is **trusted** — private keys live unencrypted in RAM during use
- Disk is **untrusted** → all persisted state is encrypted (AES-256-GCM + Argon2id)

### Security tests

8 levels of red team attacks — 148 security tests total:

```
L1  API auth, RBAC, CA boundaries              12 attacks   PASS
L2  Type confusion, panic, DoS vectors         12 attacks   PASS
L3  Crypto guarantees, side-channel            14 attacks   PASS
L4  Nonce uniqueness, replay, GF(256)          15 attacks   PASS
L5  Timing oracles, race conditions            11 attacks   PASS  ← 2 real bugs found & fixed
L6  Fault injection (software), Module-LWE     11 attacks   PASS
L7  FO-Transform, NTT coefficients, Keccak      6 attacks   PASS
L8  Infrastructure, concurrent safety          13 attacks   PASS  ← 1 real bug found & fixed
```

Real vulnerabilities found and fixed during testing:
- **Timing oracle** — bootstrap secret compared with `==` instead of `subtle.ConstantTimeCompare`
- **TOCTOU race** — channel handshake check-then-act without atomic lock
- **Content-Type bypass** — empty header bypassed `RequireJSON` middleware (CSRF vector)

```bash
# Standard pentest (54 attacks)
go test ./test/security/... -v

# Red team attacks (8 levels, 94 attacks)
go test ./test/redteam/... -v

# Race detector
go test -race ./...
```

### Reporting vulnerabilities

Please open a GitHub Security Advisory rather than a public issue.

---

## Kubernetes

```bash
# Deploy 3-node cluster
kubectl apply -k deploy/k8s/
```

The manifests include:
- `StatefulSet` (3 replicas, ordered rolling updates)
- `Headless Service` (stable DNS for Raft peer discovery)
- `PodDisruptionBudget` (maxUnavailable: 1 — preserves quorum during node drain)
- `PersistentVolumeClaim` (1 Gi per node for Raft log + CA store + keystore)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   REST API (port 8080/8443)         │
│  Auth · Keys · Encrypt · Sign · CA · Vault · KDF   │
└──────────────┬──────────────────────────────────────┘
               │ write operations
               ▼
┌─────────────────────────────────────────────────────┐
│              Raft Consensus (port 7000)             │
│   Leader election · Log replication · Snapshots    │
└──────────────┬──────────────────────────────────────┘
               │ committed log entries
               ▼
┌─────────────────────────────────────────────────────┐
│                   FSM (local state)                 │
│     keys map · CA root snapshot · intermediates    │
└─────────────────────────────────────────────────────┘
```

---

## Project structure

```
cmd/
  server/        — HTTP server entrypoint
  healthcheck/   — Docker HEALTHCHECK probe binary
  scanner/       — FIPS compliance scanner CLI

internal/
  ca/            — Post-quantum CA (ML-DSA-87 signed certs)
  castore/       — Encrypted CA persistence
  cluster/       — Raft FSM, node lifecycle, HTTP handlers
  auth/          — QST token issuance and verification
  kem/           — ML-KEM-768/1024 wrapper
  dsa/           — ML-DSA-44/65/87 wrapper
  slhdsa/        — SLH-DSA-SHA2 wrapper
  hybrid/        — ML-KEM + AES-256-GCM hybrid encryption
  keystore/      — Encrypted key store
  vault/         — Shamir secret sharing over GF(256)
  threshold/     — k-of-n threshold signatures
  channel/       — Post-quantum secure channel (ML-KEM handshake)
  fips/          — Live FIPS algorithm probes
  hsm/           — HSM abstraction (EnvProvider + PKCS#11)
  kdf/           — HKDF + Argon2id

pkg/
  api/           — HTTP handlers (50+ endpoints)
  middleware/    — Rate limiting, CORS, security headers
  metrics/       — Prometheus metrics
  logger/        — Structured logging

sdk/
  python/        — Python SDK (sync + async)
  js/            — TypeScript SDK

test/
  integration/   — End-to-end tests
  security/      — 54 automated penetration tests
  redteam/       — Adversarial red team attacks

deploy/
  k8s/           — Kubernetes manifests
  nginx/         — Nginx load balancer config
```

---

## Tests

```bash
go test ./...                    # all tests
go test -race ./...              # with race detector
go test ./test/security/... -v   # penetration tests
go test ./test/redteam/... -v    # red team attacks
go test -short ./...             # skip slow tests
```

**25 packages, 0 data races. 148 security tests (94 red team + 54 pentest).**

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

Issues and PRs welcome. For security vulnerabilities please use GitHub Security Advisories.
