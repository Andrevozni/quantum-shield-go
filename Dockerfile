# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# For PKCS#11 support add: gcc musl-dev pkgconfig opensc  and set CGO_ENABLED=1
RUN apk add --no-cache ca-certificates

ENV CGO_ENABLED=0
WORKDIR /src

# Fetch dependencies first — cached as long as go.mod / go.sum unchanged.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown

# Build the main server binary.
RUN go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
      -o /out/quantum-shield \
      ./cmd/server

# Build the healthcheck probe (used by Docker HEALTHCHECK in scratch image).
RUN go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/healthcheck \
      ./cmd/healthcheck

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
# scratch = no shell, no package manager, minimal attack surface (~10 MB image).
FROM scratch

# TLS root certificates (for outbound HTTPS: ACME, cloud KMS, etc.).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Server and healthcheck binaries.
COPY --from=builder /out/quantum-shield  /quantum-shield
COPY --from=builder /out/healthcheck     /healthcheck

# Non-root numeric UID (scratch has no /etc/passwd).
USER 65534:65534

# ── Ports ─────────────────────────────────────────────────────────────────────
# 8080 — HTTP  (plain; dev only)
# 8443 — HTTPS (TLS 1.3; production)
# 7000 — Raft  inter-node TCP transport
EXPOSE 8080 8443 7000

# ── Health check ──────────────────────────────────────────────────────────────
# The /healthcheck binary reads HEALTH_URL or derives the port from LISTEN_ADDR.
# Adjust start-period for slower hardware or large Argon2id keystore unlocks.
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/healthcheck"]

# ── Runtime environment (full docs in cmd/server/main.go) ─────────────────────
# LISTEN_ADDR              :8080 (HTTP) | :8443 (HTTPS)
# TLS_CERT_FILE            /tls/tls.crt
# TLS_KEY_FILE             /tls/tls.key
# TLS_AUTO_SELF_SIGNED     true (dev only)
# TLS_CLIENT_CA_FILE       /tls/client-ca.crt  (enables mTLS)
# TLS_MIN_VERSION          1.3 (default) | 1.2
# LOG_LEVEL                INFO | DEBUG | WARN | ERROR
# BOOTSTRAP_SECRET         <random secret>
# KEYSTORE_PATH            /data/keystore.qsk
# KEYSTORE_PASSWORD        <strong password>
# CA_STORE_PATH            /data/ca.qsc
# CA_STORE_PASSWORD        <strong password>
# QS_CLUSTER_ENABLED       true
# QS_CLUSTER_NODE_ID       node-1
# QS_CLUSTER_BIND_ADDR     qs-node1:7000
# QS_CLUSTER_DATA_DIR      /data/raft
# QS_CLUSTER_BOOTSTRAP     true (first node only)
# QS_CLUSTER_JOIN_ADDR     qs-node1:7000 (non-bootstrap nodes)
# QS_CLUSTER_HTTP_ADDR     http://qs-node1:8080

ENTRYPOINT ["/quantum-shield"]
