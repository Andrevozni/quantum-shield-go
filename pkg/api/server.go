// Package api is the QuantumShield REST API server.
//
// All cryptographic primitives are production-grade:
//   - ML-KEM-768:    crypto/mlkem (Go stdlib, Go team maintained)
//   - ML-DSA-65:     cloudflare/circl (production, Cloudflare-audited)
//   - SLH-DSA-SHA2:  Trail of Bits go-slh-dsa (NIST FIPS 205)
//   - AES-256-GCM:   crypto/cipher stdlib
//   - Randomness:    crypto/rand (OS CSPRNG)
//
// # Configuration (environment variables)
//
//	LISTEN_ADDR        TCP address to listen on (default: ":8080")
//	LOG_LEVEL          Minimum log level: DEBUG|INFO|WARN|ERROR (default: INFO)
//	ALLOWED_ORIGINS    Comma-separated CORS origins; empty = no CORS
//	BOOTSTRAP_SECRET   If set, POST /auth/token requires "Authorization: Bearer <secret>"
//	REVOCATION_FILE    Path to the persistent revocation list JSON file
//	KEYSTORE_PATH      Path to the encrypted keystore JSON file
//	KEYSTORE_PASSWORD  Password for the keystore master key (Argon2id-derived)
//	CA_STORE_PATH      Path to the encrypted CA store file (Argon2id + AES-256-GCM)
//	CA_STORE_PASSWORD  Password for the CA store; required when CA_STORE_PATH is set
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"

	"github.com/quantum-shield/quantum-shield-go/internal/audit"
	"github.com/quantum-shield/quantum-shield-go/internal/auth"
	"github.com/quantum-shield/quantum-shield-go/internal/ca"
	"github.com/quantum-shield/quantum-shield-go/internal/castore"
	"github.com/quantum-shield/quantum-shield-go/internal/channel"
	"github.com/quantum-shield/quantum-shield-go/internal/cluster"
	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
	"github.com/quantum-shield/quantum-shield-go/internal/fips"
	"github.com/quantum-shield/quantum-shield-go/internal/hybrid"
	"github.com/quantum-shield/quantum-shield-go/internal/kdf"
	"github.com/quantum-shield/quantum-shield-go/internal/kem"
	"github.com/quantum-shield/quantum-shield-go/internal/keystore"
	"github.com/quantum-shield/quantum-shield-go/internal/slhdsa"
	"github.com/quantum-shield/quantum-shield-go/internal/threshold"
	"github.com/quantum-shield/quantum-shield-go/internal/vault"
	mw "github.com/quantum-shield/quantum-shield-go/pkg/middleware"
	"github.com/quantum-shield/quantum-shield-go/pkg/metrics"
)

// ── TTL constants for in-memory session state ─────────────────────────────────

const (
	// channelHandshakeTTL is how long an incomplete channel init is kept.
	// If the responder never calls /channel/complete, the slot is reclaimed.
	channelHandshakeTTL = 5 * time.Minute

	// channelSessionTTL is the idle timeout for an established channel session.
	channelSessionTTL = 1 * time.Hour

	// thresholdRoundTTL is how long an open signing round lives without reaching threshold.
	thresholdRoundTTL = 30 * time.Minute

	// thresholdSignerTTL is how long an idle signer identity is cached.
	thresholdSignerTTL = 24 * time.Hour

	// stateCleanupInterval is how often the background cleaner runs.
	stateCleanupInterval = 5 * time.Minute
)

// ── State entry types ─────────────────────────────────────────────────────────

type channelInitEntry struct {
	initiator *channel.Initiator
	req       *channel.InitRequest
	createdAt time.Time
}

type channelSessEntry struct {
	sess     *channel.Session
	lastUsed time.Time
}

type thresholdRoundEntry struct {
	coord     *threshold.Coordinator
	msg       []byte
	nonce     []byte
	createdAt time.Time
}

type signerEntry struct {
	signer   *threshold.Signer
	lastUsed time.Time
}

// ── Server ────────────────────────────────────────────────────────────────────

// Server holds all service instances and the HTTP mux.
// Safe for concurrent use. Call Close when done.
type Server struct {
	mux     *http.ServeMux
	auth    *auth.Authority
	audit   *audit.Logger
	enc     *hybrid.Encrypter
	rl      *mw.RateLimiter // global per-IP rate limit (applied to every request)
	srl     *mw.RateLimiter // per-subject rate limit  (applied after JWT verification)
	metrics *metrics.Registry

	// bootstrapSecret protects POST /auth/token in production.
	// Empty string = open (development / test mode only).
	bootstrapSecret string

	// ks is the optional encrypted key store.
	// nil = fall back to in-memory keypairs map.
	ks  *keystore.Store
	kmu sync.RWMutex
	keypairs map[string]keyEntry // fallback when ks == nil

	// decryptors holds persistent per-level Decrypter instances so that the
	// in-process replay cache survives across individual HTTP requests.
	// Creating a new Decrypter per request (old behaviour) discards the cache
	// and makes replay protection ineffective within the same process lifetime.
	decryptors map[kem.Level]*hybrid.Decrypter

	// ── Channel state ──────────────────────────────────────────────────────────
	// All channel entries carry timestamps; a background goroutine prunes
	// entries that exceed their TTL (prevents unbounded memory growth).
	channelMu         sync.RWMutex
	channelInitiators map[string]*channelInitEntry // sessionID → pending init
	channelSessions   map[string]*channelSessEntry // sessionID → active session

	// ── Threshold state ────────────────────────────────────────────────────────
	thresholdMu      sync.RWMutex
	thresholdSigners map[string]*signerEntry        // signerID → signer + last-used
	thresholdRounds  map[string]*thresholdRoundEntry // roundID  → open round

	// ── Post-quantum CA ────────────────────────────────────────────────────────
	// caMu protects caInstance, caIntermediates, and caStore.
	// caInstance is nil until POST /ca/init is called.
	// caIntermediates maps serial number → subordinate CA; populated by
	// POST /ca/intermediate.  The root CA's private key signs the intermediate
	// certificate; the intermediate's private key signs leaf certificates
	// issued through POST /ca/intermediate/{serial}/sign.
	// caStore is non-nil when CA_STORE_PATH is configured; every mutation
	// (init, revoke, new intermediate) triggers an atomic encrypted save.
	caMu            sync.RWMutex
	caInstance      *ca.CA
	caIntermediates map[string]*ca.CA // serial → sub-CA
	caStore         *castore.Store    // non-nil when CA_STORE_PATH is set
	caStorePath     string            // path from CA_STORE_PATH env var
	caStorePassword string            // password from CA_STORE_PASSWORD env var

	// ── FIPS compliance cache ──────────────────────────────────────────────────
	// fipsReport caches the most recent fips.Check() result so /health/ready
	// can include a quick status without re-running all probes on every request.
	// nil = not yet computed.
	fipsMu     sync.Mutex
	fipsReport *fips.Report

	// ── Raft cluster (optional) ───────────────────────────────────────────────
	// clusterNode is non-nil when QS_CLUSTER_ENABLED=true.
	// All state-mutating operations are routed through Raft when active.
	// Reads are served from the local FSM (eventually consistent on followers).
	//
	// clusterHTTPAddr is the HTTP address to redirect clients to when this node
	// is not the leader.  Derived from QS_CLUSTER_HTTP_ADDR env var.
	clusterNode     *cluster.Node
	clusterHTTPAddr string // e.g. "http://qs-node1:8080"

	// ── Lifecycle ──────────────────────────────────────────────────────────────
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

type keyEntry struct {
	ekBytes []byte
	dkBytes []byte
	level   kem.Level
}

// Option is a functional option for configuring a Server.
type Option func(*Server)

// WithIPRateLimit overrides the global per-IP rate limit.
// The default is 60 requests per 60-second window.
// Primarily intended for testing; production code should use the default.
func WithIPRateLimit(limit int, window time.Duration) Option {
	return func(s *Server) {
		s.rl = mw.NewRateLimiter(limit, window)
	}
}

// WithSubjectRateLimit overrides the per-JWT-subject rate limit.
// The default is 120 requests per 60-second window.
// Primarily intended for testing; production code should use the default.
func WithSubjectRateLimit(limit int, window time.Duration) Option {
	return func(s *Server) {
		s.srl = mw.NewRateLimiter(limit, window)
	}
}

// WithClusterNode attaches a Raft cluster node to the server.
//
// When set, all state-mutating operations (key generation, CA init, revocation)
// are routed through the Raft log before being committed to local state.
// Follower nodes redirect write requests to the current leader via HTTP 307.
//
// httpAddr is the full HTTP base URL of THIS node
// (e.g. "http://qs-node1:8080") — used to construct leader-redirect URLs.
func WithClusterNode(node *cluster.Node, httpAddr string) Option {
	return func(s *Server) {
		s.clusterNode     = node
		s.clusterHTTPAddr = httpAddr
	}
}

// New creates a Server with all components initialised.
//
// Environment variables are read once at startup:
//   - BOOTSTRAP_SECRET  — if non-empty, /auth/token requires this as Bearer token
//   - REVOCATION_FILE   — if non-empty, revocation list is persisted to this path
//   - KEYSTORE_PATH     — if non-empty, keys are stored in encrypted keystore
//   - KEYSTORE_PASSWORD — required when KEYSTORE_PATH is set
func New(opts ...Option) (*Server, error) {
	authority, err := auth.NewAuthority("QuantumShield-API", 3600*time.Second, dsa.Level65)
	if err != nil {
		return nil, err
	}

	// Wire persistent revocation if configured.
	if revFile := os.Getenv("REVOCATION_FILE"); revFile != "" {
		if err := authority.SetRevocationFile(revFile); err != nil {
			return nil, fmt.Errorf("api.New: open revocation file: %w", err)
		}
	}

	logger, err := audit.NewLogger("QuantumShield-API")
	if err != nil {
		return nil, err
	}

	reg := metrics.New()
	metrics.RegisterHTTPMetrics(reg)
	metrics.RegisterCryptoMetrics(reg)
	// Normalize path-param segments so metrics don't get unbounded label cardinality.
	// e.g. /keys/Xk9aB3m/public → /keys/{id}/public
	reg.SetPathNormalizer(normalizeAPIPath)

	s := &Server{
		mux:     http.NewServeMux(),
		auth:    authority,
		audit:   logger,
		enc:     hybrid.NewEncrypter(kem.Level768),
		keypairs: make(map[string]keyEntry),
		rl:      mw.NewRateLimiter(60, 60*time.Second),   // 60 req/min per IP
		srl:     mw.NewRateLimiter(120, 60*time.Second),  // 120 req/min per JWT subject
		metrics: reg,
		// secretFromEnv supports BOOTSTRAP_SECRET or BOOTSTRAP_SECRET_FILE (Docker Secrets)
		bootstrapSecret: secretFromEnv("BOOTSTRAP_SECRET"),
		// Persistent per-level decrypters: the in-process replay cache must survive
		// across requests within the same process.  A fresh Decrypter per request
		// (old behaviour) discarded the cache and provided no same-session protection.
		decryptors: map[kem.Level]*hybrid.Decrypter{
			kem.Level768:  hybrid.NewDecrypter(kem.Level768),
			kem.Level1024: hybrid.NewDecrypter(kem.Level1024),
		},
		caIntermediates:   make(map[string]*ca.CA),
		channelInitiators: make(map[string]*channelInitEntry),
		channelSessions:   make(map[string]*channelSessEntry),
		thresholdSigners:  make(map[string]*signerEntry),
		thresholdRounds:   make(map[string]*thresholdRoundEntry),
		stopCleanup:       make(chan struct{}),
	}

	// Apply functional options — may override defaults set above.
	for _, opt := range opts {
		opt(s)
	}

	// Wire encrypted keystore if configured.
	if ksPath := os.Getenv("KEYSTORE_PATH"); ksPath != "" {
		// secretFromEnv supports KEYSTORE_PASSWORD or KEYSTORE_PASSWORD_FILE (Docker Secrets)
		ksPwd := secretFromEnv("KEYSTORE_PASSWORD")
		if ksPwd == "" {
			return nil, fmt.Errorf("api.New: KEYSTORE_PATH set but KEYSTORE_PASSWORD is empty")
		}
		ks, err := keystore.Open(ksPath, ksPwd)
		if err != nil {
			return nil, fmt.Errorf("api.New: open keystore: %w", err)
		}
		s.ks = ks
	}

	// Wire encrypted CA store if configured.
	// If the file already exists it is loaded on startup, restoring the CA
	// hierarchy (root + intermediates + CRL) from a previous run.
	if caPath := secretFromEnv("CA_STORE_PATH"); caPath != "" {
		caPwd := secretFromEnv("CA_STORE_PASSWORD")
		if caPwd == "" {
			return nil, fmt.Errorf("api.New: CA_STORE_PATH set but CA_STORE_PASSWORD is empty")
		}
		s.caStorePath = caPath
		s.caStorePassword = caPwd

		if _, err := os.Stat(caPath); err == nil {
			// File exists — restore from disk.
			cs, err := castore.Load(caPath, caPwd)
			if err != nil {
				return nil, fmt.Errorf("api.New: load CA store %q: %w", caPath, err)
			}
			s.caStore = cs
			if root := cs.Root(); root != nil {
				s.caInstance = root
				for serial, sub := range cs.Intermediates() {
					s.caIntermediates[serial] = sub
				}
			}
		} else {
			// File doesn't exist yet — create an empty store; CA will be
			// written the first time POST /ca/init is called.
			s.caStore = castore.New()
		}
	}

	// Start background cleaner for in-memory session state.
	go s.stateCleanup()

	s.routes()
	return s, nil
}

// Close releases all resources held by the server.
//
// Sequence (order matters — no in-flight request can touch these after Close):
//  1. Stop background goroutines (state cleanup, auth pruner)
//  2. Close the encrypted keystore (flushes pending writes)
//
// Safe to call multiple times; subsequent calls are no-ops.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		// Stop background goroutines first.
		close(s.stopCleanup)
		s.auth.Close()

		// Close encrypted keystore — flushes any pending writes.
		if s.ks != nil {
			s.ks.Close() //nolint:errcheck
		}
	})
}

// ── Cluster helpers ───────────────────────────────────────────────────────────

// clusterEnabled reports whether this server is running as part of a Raft cluster.
func (s *Server) clusterEnabled() bool { return s.clusterNode != nil }

// isLeader reports whether this node can accept write requests.
// Always true in standalone mode.
func (s *Server) isLeader() bool {
	return s.clusterNode == nil || s.clusterNode.IsLeader()
}

// requireLeader writes a 307 redirect to the current leader if this node is
// a follower.  Returns false if the request was redirected (caller must return).
func (s *Server) requireLeader(w http.ResponseWriter, r *http.Request) bool {
	if s.isLeader() {
		return true
	}
	leaderAddr := s.clusterNode.LeaderAddr()
	if leaderAddr == "" {
		mw.JSONError(w, "cluster has no leader — election in progress, retry shortly",
			http.StatusServiceUnavailable)
		return false
	}
	// Build redirect URL: replace Raft transport address with HTTP address.
	// The leader HTTP URL is derived from QS_CLUSTER_HTTP_ADDR on each node;
	// since we only know our own HTTP addr here, we embed the leader's Raft
	// address so the client can use /cluster/leader to look up the HTTP addr.
	w.Header().Set("X-Raft-Leader", s.clusterNode.LeaderID())
	w.Header().Set("X-Raft-Leader-Addr", leaderAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, `{"error":"not the leader","leader_id":%q,"leader_raft_addr":%q}`,
		s.clusterNode.LeaderID(), leaderAddr)
	return false
}

// clusterApply applies a command to the Raft log when cluster mode is active.
// In standalone mode it is a no-op.
func (s *Server) clusterApply(op cluster.OpType, payload any) error {
	if !s.clusterEnabled() {
		return nil
	}
	return s.clusterNode.ApplyJSON(op, payload)
}

// Handler returns the root HTTP handler with all middleware applied.
// Chain (outer → inner): RequestID → SecurityHeaders → CORS → Metrics → IP-RateLimit → RequireJSON → mux
// An additional per-subject rate limit is enforced inside requireAuth for authenticated endpoints.
func (s *Server) Handler() http.Handler {
	return mw.RequestID(
		mw.SecurityHeaders(
			mw.CORS(
				s.metrics.HTTPMiddleware(
					s.rl.Limit(
						mw.RequireJSON(s.mux),
					),
				),
			),
		),
	)
}

// routes registers all API endpoints.
func (s *Server) routes() {
	// ── Public ──────────────────────────────────────────────────────────────────
	s.mux.HandleFunc("GET /", s.handleHealth)
	s.mux.Handle("GET /metrics", s.metrics.Handler())
	s.mux.HandleFunc("GET /health/live", s.handleLive)
	s.mux.HandleFunc("GET /health/ready", s.handleReady)
	s.mux.HandleFunc("GET /health/fips", s.handleFIPS)

	// ── Auth (token issuance protected by bootstrap secret) ──────────────────────
	s.mux.HandleFunc("POST /auth/token", s.handleIssueToken)
	s.mux.HandleFunc("POST /auth/verify", s.handleVerifyToken)
	s.mux.HandleFunc("POST /auth/revoke", s.requireAuth(s.handleRevokeToken))

	// ── Signature verification is intentionally public ───────────────────────────
	s.mux.HandleFunc("POST /verify-signature", s.handleVerifySignature)
	s.mux.HandleFunc("POST /slh-dsa/verify", s.handleSLHDSAVerify)
	s.mux.HandleFunc("POST /threshold/verify", s.handleThresholdVerify)

	// ── Authenticated: write role required ───────────────────────────────────────
	s.mux.HandleFunc("GET /keys", s.requireRole("read", s.handleListKeys))
	s.mux.HandleFunc("POST /keys/generate", s.requireRole("write", s.handleGenerateKey))
	s.mux.HandleFunc("GET /keys/{key_id}/public", s.requireRole("read", s.handleGetPublicKey))
	s.mux.HandleFunc("POST /encrypt", s.requireRole("write", s.handleEncrypt))
	s.mux.HandleFunc("POST /decrypt", s.requireRole("write", s.handleDecrypt))
	s.mux.HandleFunc("POST /sign", s.requireRole("write", s.handleSign))
	s.mux.HandleFunc("POST /slh-dsa/sign", s.requireRole("write", s.handleSLHDSASign))

	s.mux.HandleFunc("POST /vault/split", s.requireRole("write", s.handleVaultSplit))
	s.mux.HandleFunc("POST /vault/reconstruct", s.requireRole("write", s.handleVaultReconstruct))

	s.mux.HandleFunc("POST /channel/init", s.requireRole("write", s.handleChannelInit))
	s.mux.HandleFunc("POST /channel/complete", s.requireRole("write", s.handleChannelComplete))
	s.mux.HandleFunc("POST /channel/seal", s.requireRole("write", s.handleChannelSeal))
	s.mux.HandleFunc("POST /channel/open", s.requireRole("write", s.handleChannelOpen))

	s.mux.HandleFunc("POST /threshold/round", s.requireRole("write", s.handleThresholdRound))
	s.mux.HandleFunc("POST /threshold/sign", s.requireRole("write", s.handleThresholdSign))
	s.mux.HandleFunc("POST /threshold/submit", s.requireRole("write", s.handleThresholdSubmit))

	// ── KDF — write role ─────────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /kdf/hkdf", s.requireRole("write", s.handleKDFHKDF))
	s.mux.HandleFunc("POST /kdf/argon2", s.requireRole("write", s.handleKDFArgon2))
	s.mux.HandleFunc("POST /kdf/salt", s.requireRole("write", s.handleKDFSalt))

	// ── Audit — read role ────────────────────────────────────────────────────────
	s.mux.HandleFunc("GET /audit/entries", s.requireRole("read", s.handleAuditEntries))
	s.mux.HandleFunc("GET /audit/verify", s.requireRole("read", s.handleAuditVerify))

	// ── Encrypted keystore — admin role ─────────────────────────────────────────
	s.mux.HandleFunc("POST /keystore/generate", s.requireRole("admin", s.handleKeystoreGenerate))
	s.mux.HandleFunc("GET /keystore", s.requireRole("admin", s.handleKeystoreList))
	s.mux.HandleFunc("GET /keystore/{key_id}", s.requireRole("admin", s.handleKeystoreGet))
	s.mux.HandleFunc("POST /keystore/{key_id}/rotate", s.requireRole("admin", s.handleKeystoreRotate))
	s.mux.HandleFunc("POST /keystore/{key_id}/expire", s.requireRole("admin", s.handleKeystoreExpire))
	s.mux.HandleFunc("DELETE /keystore/{key_id}", s.requireRole("admin", s.handleKeystoreDelete))

	// ── Key export/import — admin role ───────────────────────────────────────────
	// Export wraps the private key with Argon2id+AES-256-GCM so it can be
	// transported or backed up securely.  Import unwraps and stores the key.
	s.mux.HandleFunc("POST /keys/{key_id}/export", s.requireRole("admin", s.handleKeyExport))
	s.mux.HandleFunc("POST /keys/import", s.requireRole("admin", s.handleKeyImport))

	// ── Post-quantum CA — ML-DSA-87 ─────────────────────────────────────────────
	// CA certificate and issued leaf certificates are JSON documents (not X.509).
	// Signature coverage: all fields except "signature" (canonical Go JSON).
	s.mux.HandleFunc("POST /ca/init", s.requireRole("admin", s.handleCAInit))
	s.mux.HandleFunc("POST /ca/sign", s.requireRole("write", s.handleCASign))
	s.mux.HandleFunc("POST /ca/revoke", s.requireRole("admin", s.handleCARevoke))
	s.mux.HandleFunc("POST /ca/verify", s.handleCAVerify)          // public
	s.mux.HandleFunc("GET /ca/certificate", s.handleCACertificate) // public
	s.mux.HandleFunc("GET /ca/crl", s.handleCACRL)                 // public

	// ── Hybrid PKI — intermediate CA support ────────────────────────────────────
	// POST /ca/intermediate  — create an intermediate CA signed by the root CA.
	// POST /ca/intermediate/{serial}/sign  — issue leaf cert via an intermediate.
	// POST /ca/chain-verify  — verify a full certificate chain against the root CA.
	s.mux.HandleFunc("POST /ca/intermediate", s.requireRole("admin", s.handleCAIntermediate))
	s.mux.HandleFunc("POST /ca/intermediate/{serial}/sign", s.requireRole("write", s.handleCAIntermediateSign))
	s.mux.HandleFunc("POST /ca/chain-verify", s.handleCAChainVerify) // public

	// ── Raft cluster management (only registered when cluster is enabled) ────────
	// GET  /cluster/status  — node state, leader, peers (public within cluster)
	// GET  /cluster/leader  — current leader address  (public within cluster)
	// POST /cluster/join    — add a voter             (admin role)
	// POST /cluster/remove  — remove a voter          (admin role)
	if s.clusterNode != nil {
		n := s.clusterNode // capture
		s.mux.HandleFunc("GET /cluster/status",  func(w http.ResponseWriter, r *http.Request) { n.Handler().ServeHTTP(w, r) })
		s.mux.HandleFunc("GET /cluster/leader",  func(w http.ResponseWriter, r *http.Request) { n.Handler().ServeHTTP(w, r) })
		s.mux.HandleFunc("POST /cluster/join",   s.requireRole("admin", func(w http.ResponseWriter, r *http.Request) { n.Handler().ServeHTTP(w, r) }))
		s.mux.HandleFunc("POST /cluster/remove", s.requireRole("admin", func(w http.ResponseWriter, r *http.Request) { n.Handler().ServeHTTP(w, r) }))
	}
}

// ── Background cleanup ────────────────────────────────────────────────────────

// stateCleanup runs every stateCleanupInterval and removes expired in-memory
// channel and threshold entries. Without this, a flood of abandoned handshakes
// or signing rounds would cause unbounded memory growth.
func (s *Server) stateCleanup() {
	ticker := time.NewTicker(stateCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.pruneChannelState()
			s.pruneThresholdState()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *Server) pruneChannelState() {
	now := time.Now()
	s.channelMu.Lock()
	defer s.channelMu.Unlock()
	for id, e := range s.channelInitiators {
		if now.Sub(e.createdAt) > channelHandshakeTTL {
			delete(s.channelInitiators, id)
		}
	}
	for id, e := range s.channelSessions {
		if now.Sub(e.lastUsed) > channelSessionTTL {
			delete(s.channelSessions, id)
		}
	}
}

func (s *Server) pruneThresholdState() {
	now := time.Now()
	s.thresholdMu.Lock()
	defer s.thresholdMu.Unlock()
	for id, e := range s.thresholdRounds {
		if now.Sub(e.createdAt) > thresholdRoundTTL {
			delete(s.thresholdRounds, id)
		}
	}
	for id, e := range s.thresholdSigners {
		if now.Sub(e.lastUsed) > thresholdSignerTTL {
			delete(s.thresholdSigners, id)
		}
	}
}

// ── Auth middleware ────────────────────────────────────────────────────────────

// requireAuth verifies the Bearer QST token in the Authorization header.
// On success it stores subject and roles in the request context and enforces
// the per-subject rate limit (distinct from the global per-IP limit).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		token := strings.TrimPrefix(bearer, "Bearer ")
		if token == "" {
			mw.JSONError(w, "Authentication failed", http.StatusUnauthorized)
			return
		}
		tok, err := s.auth.Verify(token)
		if err != nil {
			mw.JSONError(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// Per-subject rate limit: a single JWT subject cannot exceed 120 req/min
		// regardless of how many IP addresses it originates from.  This bounds
		// the blast radius of a stolen credential used from multiple hosts.
		if !s.srl.Allow(tok.Claims.Subject) {
			w.Header().Set("Retry-After", "60")
			mw.JSONError(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		ctx := context.WithValue(r.Context(), mw.SubjectKey, tok.Claims.Subject)
		ctx = context.WithValue(ctx, mw.RolesKey, tok.Claims.Roles)
		next(w, r.WithContext(ctx))
	}
}

// requireRole verifies authentication AND that the token contains the given role.
// Returns 401 if unauthenticated, 403 if authenticated but role is absent.
func (s *Server) requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !hasRole(r, role) {
			mw.JSONError(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func hasRole(r *http.Request, role string) bool {
	roles, _ := r.Context().Value(mw.RolesKey).([]string)
	for _, tr := range roles {
		if tr == role {
			return true
		}
	}
	return false
}

func subject(r *http.Request) string {
	if s, ok := r.Context().Value(mw.SubjectKey).(string); ok {
		return s
	}
	return "anonymous"
}

// ── Key store helpers ─────────────────────────────────────────────────────────

func (s *Server) storeKey(keyID string, level kem.Level, ekBytes, dkBytes []byte) error {
	if s.ks != nil {
		return s.ks.Put(keyID, level, ekBytes, dkBytes, 0)
	}
	s.kmu.Lock()
	s.keypairs[keyID] = keyEntry{ekBytes: ekBytes, dkBytes: dkBytes, level: level}
	s.kmu.Unlock()
	return nil
}

func (s *Server) lookupKey(keyID string) (ekBytes, dkBytes []byte, level kem.Level, ok bool) {
	if s.ks != nil {
		kv, err := s.ks.GetActive(keyID)
		if err != nil {
			return nil, nil, 0, false
		}
		return kv.EKBytes, kv.DKBytes, kv.Level, true
	}
	s.kmu.RLock()
	entry, found := s.keypairs[keyID]
	s.kmu.RUnlock()
	if !found {
		return nil, nil, 0, false
	}
	return entry.ekBytes, entry.dkBytes, entry.level, true
}

func (s *Server) keystoreRequired(w http.ResponseWriter) bool {
	if s.ks == nil {
		mw.JSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "keystore not configured — set KEYSTORE_PATH and KEYSTORE_PASSWORD",
		})
		return false
	}
	return true
}

func (s *Server) keyCount() int {
	if s.ks != nil {
		return len(s.ks.List())
	}
	s.kmu.RLock()
	n := len(s.keypairs)
	s.kmu.RUnlock()
	return n
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		mw.JSONError(w, "Not found", http.StatusNotFound)
		return
	}
	mw.JSON(w, map[string]any{
		"service":   "QuantumShield API",
		"version":   "2.0.0",
		"language":  "Go",
		"standards": []string{"NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"},
		"algorithms": map[string]string{
			"kem":       "ML-KEM-768 (crypto/mlkem — Go stdlib)",
			"signature": "ML-DSA-65 (cloudflare/circl)",
			"slh_dsa":   "SLH-DSA-SHA2 (Trail of Bits go-slh-dsa)",
			"symmetric": "AES-256-GCM (crypto/cipher — Go stdlib)",
		},
		"status":    "operational",
		"timestamp": time.Now().Unix(),
	})
}

// handleIssueToken issues a QST token.
// When BOOTSTRAP_SECRET is set the request must carry that secret as Bearer token.
func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if s.bootstrapSecret != "" {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != s.bootstrapSecret {
			mw.JSONError(w, "Authentication failed", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		UserID string         `json:"user_id"`
		Roles  []string       `json:"roles"`
		Extra  map[string]any `json:"extra"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		mw.JSONError(w, "user_id required", http.StatusBadRequest)
		return
	}
	if len(req.Roles) == 0 {
		req.Roles = []string{"read"}
	}
	// Cap roles to prevent JWT memory bombs: a token with 10,000 roles would
	// be carried in every authenticated request, amplifying memory usage.
	const maxRoles = 16
	if len(req.Roles) > maxRoles {
		mw.JSONError(w, fmt.Sprintf("too many roles (max %d)", maxRoles), http.StatusBadRequest)
		return
	}
	if len(req.UserID) > 64 || !isValidUserID(req.UserID) {
		mw.JSONError(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	token, err := s.auth.Issue(req.UserID, req.Roles, req.Extra)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	s.metrics.Counter("qs_crypto_token_issue_total").Inc()
	s.audit.Log(req.UserID, "issue_token", "ok", "")
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"token":      token,
		"expires_in": 3600,
		"algorithm":  "ML-DSA-65",
		"type":       "QST",
	})
}

func (s *Server) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	tok, err := s.auth.Verify(req.Token)
	s.metrics.Counter("qs_crypto_token_verify_total").Inc()
	if err != nil {
		mw.JSONStatus(w, http.StatusUnauthorized, map[string]any{
			"valid": false,
			"error": "Authentication failed",
		})
		return
	}
	mw.JSON(w, map[string]any{
		"valid":   true,
		"subject": tok.Claims.Subject,
		"roles":   tok.Claims.Roles,
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.auth.Revoke(req.Token)
	s.metrics.Counter("qs_crypto_token_revoke_total").Inc()
	s.audit.Log(subject(r), "revoke_token", "ok", "")
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]bool{"revoked": true})
}

// handleListKeys returns the IDs of all keys currently held by the server.
//
// When an encrypted keystore is configured the list is read from it.
// Otherwise the in-memory map is used.  Public keys are not returned here;
// use GET /keys/{key_id}/public for that.
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	var ids []string
	backend := "in-memory"

	if s.ks != nil {
		ids = s.ks.List()
		backend = "encrypted-keystore"
	} else {
		s.kmu.RLock()
		ids = make([]string, 0, len(s.keypairs))
		for id := range s.keypairs {
			ids = append(ids, id)
		}
		s.kmu.RUnlock()
	}

	mw.JSON(w, map[string]any{
		"keys":    ids,
		"count":   len(ids),
		"backend": backend,
	})
}

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Accept canonical NIST names ("ML-KEM-768", "ML-KEM-1024") and the
	// legacy "high" alias.  Anything else defaults to ML-KEM-768.
	var lvl kem.Level
	switch strings.ToUpper(strings.TrimSpace(req.Level)) {
	case "ML-KEM-1024", "HIGH":
		lvl = kem.Level1024
	default:
		lvl = kem.Level768
	}

	dk, err := kem.GenerateKey(lvl)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	dkBytes := dk.Bytes()

	keyID := randomID()

	// ── Cluster: replicate through Raft before storing locally ────────────────
	// In standalone mode clusterApply is a no-op.
	// In cluster mode the leader applies the command; followers would have
	// already been redirected by requireLeader (called in handleCAInit etc.).
	// Key-generation is special: we generate on the leader, then replicate the
	// key bytes so all followers store identical material.
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.clusterApply(cluster.OpGenerateKey, cluster.GenerateKeyPayload{
		KeyID:   keyID,
		Level:   lvl.String(),
		EKBytes: ekBytes,
		DKBytes: dkBytes,
	}); err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Cluster replication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.storeKey(keyID, lvl, ekBytes, dkBytes); err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Failed to store key", http.StatusInternalServerError)
		return
	}

	shards, _ := vault.Split(dkBytes, 5, 3)

	s.metrics.Counter("qs_crypto_keygen_total").Inc()
	s.metrics.Gauge("qs_keystore_keys_total").Set(float64(s.keyCount()))
	s.audit.Log(subject(r), "generate_key", "ok", keyID)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"key_id":          keyID,
		"public_key":      base64.StdEncoding.EncodeToString(ekBytes),
		"algorithm":       lvl.String(),
		"public_key_size": len(ekBytes),
		"vault_shards":    len(shards),
		"vault_threshold": 3,
	})
}

func (s *Server) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("key_id")
	ekBytes, _, _, ok := s.lookupKey(keyID)
	if !ok {
		mw.JSONError(w, "Key not found", http.StatusNotFound)
		return
	}
	mw.JSON(w, map[string]string{
		"key_id":     keyID,
		"public_key": base64.StdEncoding.EncodeToString(ekBytes),
	})
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	var ekBytes []byte
	if req.KeyID != "" {
		var ok bool
		ekBytes, _, _, ok = s.lookupKey(req.KeyID)
		if !ok {
			mw.JSONError(w, "Key not found", http.StatusBadRequest)
			return
		}
	} else if req.PublicKey != "" {
		var err error
		ekBytes, err = base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			mw.JSONError(w, "Invalid public_key encoding", http.StatusBadRequest)
			return
		}
	} else {
		mw.JSONError(w, "key_id or public_key required", http.StatusBadRequest)
		return
	}

	encrypted, err := s.enc.Encrypt(ekBytes, []byte(req.Plaintext))
	if err != nil {
		mw.JSONError(w, "Encryption failed", http.StatusBadRequest)
		return
	}

	s.metrics.Counter("qs_crypto_encrypt_total").Inc()
	s.audit.Log(subject(r), "encrypt", "ok", req.KeyID)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	// created_at is returned so the caller can include it verbatim in /decrypt.
	// It is bound into the AEAD tag — omitting or altering it causes auth failure.
	mw.JSON(w, map[string]any{
		"encrypted": map[string]any{
			"kem_ciphertext": base64.StdEncoding.EncodeToString(encrypted.KEMCiphertext),
			"nonce":          base64.StdEncoding.EncodeToString(encrypted.Nonce),
			"data":           base64.StdEncoding.EncodeToString(encrypted.Data),
			"created_at":     encrypted.CreatedAt,
		},
		"algorithm":    "ML-KEM-768 + AES-256-GCM",
		"quantum_safe": true,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		Encrypted struct {
			KEMCiphertext string `json:"kem_ciphertext"`
			Nonce         string `json:"nonce"`
			Data          string `json:"data"`
			// CreatedAt is required: it was bound into the AEAD tag by /encrypt.
			// Omitting or altering it causes authentication failure.
			CreatedAt int64 `json:"created_at"`
		} `json:"encrypted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	_, dkBytes, level, ok := s.lookupKey(req.KeyID)
	if !ok {
		mw.JSONError(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	kemCT, _ := base64.StdEncoding.DecodeString(req.Encrypted.KEMCiphertext)
	nonce, _ := base64.StdEncoding.DecodeString(req.Encrypted.Nonce)
	data, _ := base64.StdEncoding.DecodeString(req.Encrypted.Data)

	// Use the persistent per-level decrypter so the in-process replay cache
	// is shared across all requests within this server's lifetime.
	dec, hasDec := s.decryptors[level]
	if !hasDec {
		dec = hybrid.NewDecrypter(level)
	}
	plaintext, err := dec.Decrypt(dkBytes, &hybrid.Encrypted{
		KEMCiphertext: kemCT,
		Nonce:         nonce,
		Data:          data,
		CreatedAt:     req.Encrypted.CreatedAt,
	})
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		s.audit.Log(subject(r), "decrypt", "failed", req.KeyID)
		mw.JSONError(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	s.metrics.Counter("qs_crypto_decrypt_total").Inc()
	s.audit.Log(subject(r), "decrypt", "ok", req.KeyID)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"plaintext": string(plaintext),
		"verified":  true,
	})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	lvl := dsa.Level65
	switch req.Level {
	case "light":
		lvl = dsa.Level44
	case "high":
		lvl = dsa.Level87
	}

	pk, sk, err := dsa.GenerateKey(lvl)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	sig, err := dsa.Sign(sk, []byte(req.Message))
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	pkBytes, _ := pk.Bytes()
	s.metrics.Counter("qs_crypto_sign_total").Inc()
	mw.JSON(w, map[string]any{
		"signature":    base64.StdEncoding.EncodeToString(sig),
		"public_key":   base64.StdEncoding.EncodeToString(pkBytes),
		"algorithm":    "ML-DSA-65",
		"quantum_safe": true,
	})
}

func (s *Server) handleVerifySignature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
		Level     string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	lvl := dsa.Level65
	pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		mw.JSONError(w, "Invalid public_key", http.StatusBadRequest)
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		mw.JSONError(w, "Invalid signature", http.StatusBadRequest)
		return
	}
	pk, err := dsa.ParsePublicKey(lvl, pkBytes)
	if err != nil {
		mw.JSONError(w, "Invalid public_key", http.StatusBadRequest)
		return
	}
	valid := dsa.Verify(pk, []byte(req.Message), sigBytes)
	s.metrics.Counter("qs_crypto_verify_total").Inc()
	mw.JSON(w, map[string]any{"valid": valid, "algorithm": "ML-DSA-65"})
}

// ── SLH-DSA (NIST FIPS 205) ───────────────────────────────────────────────────

// handleSLHDSASign generates an ephemeral SLH-DSA keypair and signs the
// provided message.
//
// Request:
//
//	{
//	  "message": "<string>",
//	  "level":   "128f|128s|192f|192s|256f|256s"   // optional, default "128f"
//	}
//
// Response includes the signature, public key (base64), parameter set name,
// and signature size in bytes.
func (s *Server) handleSLHDSASign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Message == "" {
		mw.JSONError(w, "message is required", http.StatusBadRequest)
		return
	}

	lvl, err := slhdsa.ParseLevel(req.Level)
	if err != nil {
		mw.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	pk, sk, err := slhdsa.GenerateKey(lvl)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	sig, err := slhdsa.Sign(sk, []byte(req.Message))
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	s.metrics.Counter("qs_crypto_sign_total").Inc()
	mw.JSON(w, map[string]any{
		"signature":      base64.StdEncoding.EncodeToString(sig),
		"public_key":     base64.StdEncoding.EncodeToString(pk.Bytes()),
		"algorithm":      lvl.AlgorithmName(),
		"signature_size": len(sig),
		"quantum_safe":   true,
	})
}

// handleSLHDSAVerify verifies an SLH-DSA signature.  This endpoint is public
// (no authentication required) so anyone with the public key can verify.
//
// Request:
//
//	{
//	  "message":    "<string>",
//	  "signature":  "<base64>",
//	  "public_key": "<base64>",
//	  "level":      "128f|128s|192f|192s|256f|256s"  // must match signing level
//	}
func (s *Server) handleSLHDSAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
		Level     string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	lvl, err := slhdsa.ParseLevel(req.Level)
	if err != nil {
		mw.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		mw.JSONError(w, "Invalid public_key encoding", http.StatusBadRequest)
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		mw.JSONError(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}

	pk, err := slhdsa.ParsePublicKey(lvl, pkBytes)
	if err != nil {
		mw.JSONError(w, "Invalid public_key", http.StatusBadRequest)
		return
	}

	valid := slhdsa.Verify(pk, []byte(req.Message), sigBytes)
	s.metrics.Counter("qs_crypto_verify_total").Inc()
	mw.JSON(w, map[string]any{
		"valid":     valid,
		"algorithm": lvl.AlgorithmName(),
	})
}

func (s *Server) handleVaultSplit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret    string `json:"secret"`
		N         int    `json:"n"`
		Threshold int    `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil || len(secret) == 0 {
		mw.JSONError(w, "secret must be non-empty base64", http.StatusBadRequest)
		return
	}
	if req.N < 2 || req.Threshold < 2 || req.Threshold > req.N || req.N > 255 {
		mw.JSONError(w, "invalid n/threshold parameters", http.StatusBadRequest)
		return
	}

	shards, err := vault.Split(secret, req.N, req.Threshold)
	if err != nil {
		mw.JSONError(w, "Split failed", http.StatusBadRequest)
		return
	}

	type shardResp struct {
		Index    int    `json:"index"`
		Value    string `json:"value"`
		Checksum string `json:"checksum"`
	}
	resp := make([]shardResp, len(shards))
	for i, sh := range shards {
		resp[i] = shardResp{
			Index:    int(sh.Index),
			Value:    base64.StdEncoding.EncodeToString(sh.Value),
			Checksum: base64.StdEncoding.EncodeToString(sh.Checksum),
		}
	}

	s.metrics.Counter("qs_crypto_vault_split_total").Inc()
	s.audit.Log(subject(r), "vault_split", "ok", "")
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"shards":    resp,
		"n":         req.N,
		"threshold": req.Threshold,
	})
}

func (s *Server) handleVaultReconstruct(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Shards []struct {
			Index    int    `json:"index"`
			Value    string `json:"value"`
			Checksum string `json:"checksum"`
		} `json:"shards"`
		Threshold int `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Shards) == 0 {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	shards := make([]vault.Shard, len(req.Shards))
	for i, sh := range req.Shards {
		val, err1 := base64.StdEncoding.DecodeString(sh.Value)
		chk, err2 := base64.StdEncoding.DecodeString(sh.Checksum)
		if err1 != nil || err2 != nil {
			mw.JSONError(w, "Invalid shard encoding", http.StatusBadRequest)
			return
		}
		shards[i] = vault.Shard{Index: byte(sh.Index), Value: val, Checksum: chk}
	}

	secret, err := vault.Reconstruct(shards, req.Threshold)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		s.audit.Log(subject(r), "vault_reconstruct", "failed", "")
		mw.JSONError(w, "Reconstruction failed", http.StatusBadRequest)
		return
	}

	s.metrics.Counter("qs_crypto_vault_reconstruct_total").Inc()
	s.audit.Log(subject(r), "vault_reconstruct", "ok", "")
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]string{
		"secret": base64.StdEncoding.EncodeToString(secret),
	})
}

func (s *Server) handleAuditEntries(w http.ResponseWriter, r *http.Request) {
	mw.JSON(w, map[string]any{
		"entries": s.audit.Entries(),
		"count":   s.audit.Count(),
	})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	result := s.audit.VerifyChain()
	mw.JSON(w, result)
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	mw.JSON(w, map[string]string{"status": "alive"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	result := s.audit.VerifyChain()
	if !result.Valid {
		mw.JSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not ready",
			"reason": "audit chain invalid",
		})
		return
	}
	mw.JSON(w, map[string]any{
		"status":        "ready",
		"audit_entries": result.Entries,
		"fips_status":   s.fipsOverall(),
	})
}

// fipsOverall returns the cached FIPS overall status string.
// We run the check once at startup (expensive) and cache the result.
// The cache is invalidated when this method is called on a fresh server
// by running the check on first call.
func (s *Server) fipsOverall() string {
	s.fipsMu.Lock()
	defer s.fipsMu.Unlock()
	if s.fipsReport == nil {
		r := fips.Check()
		s.fipsReport = &r
	}
	return string(s.fipsReport.Overall)
}

// handleFIPS returns a full FIPS compliance report for all algorithm components.
// Runs live probes on every call — use for operational monitoring.
//
// Response: { "overall": "pass"|"fail", "timestamp": "...", "probes": [...] }
func (s *Server) handleFIPS(w http.ResponseWriter, _ *http.Request) {
	report := fips.Check()

	// Cache the latest result for /health/ready's summary field.
	s.fipsMu.Lock()
	s.fipsReport = &report
	s.fipsMu.Unlock()

	if report.Overall == fips.StatusFail {
		mw.JSONStatus(w, http.StatusServiceUnavailable, report)
		return
	}
	mw.JSON(w, report)
}

// ── KDF handlers ──────────────────────────────────────────────────────────────

func (s *Server) handleKDFHKDF(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret string `json:"secret"`
		Salt   string `json:"salt"`
		Info   string `json:"info"`
		KeyLen int    `json:"key_len"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.KeyLen <= 0 || req.KeyLen > 512 {
		mw.JSONError(w, "key_len must be 1-512", http.StatusBadRequest)
		return
	}
	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil || len(secret) == 0 {
		mw.JSONError(w, "secret must be non-empty base64", http.StatusBadRequest)
		return
	}
	var salt []byte
	if req.Salt != "" {
		salt, err = base64.StdEncoding.DecodeString(req.Salt)
		if err != nil {
			mw.JSONError(w, "invalid salt encoding", http.StatusBadRequest)
			return
		}
	}
	derived, err := kdf.DeriveHKDF(secret, salt, []byte(req.Info), req.KeyLen)
	if err != nil {
		mw.JSONError(w, "HKDF failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(subject(r), "kdf_hkdf", "ok", "")
	mw.JSON(w, map[string]any{
		"key":       base64.StdEncoding.EncodeToString(derived),
		"key_len":   len(derived),
		"algorithm": "HKDF-SHA256",
	})
}

func (s *Server) handleKDFArgon2(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Salt     string `json:"salt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	password, err := base64.StdEncoding.DecodeString(req.Password)
	if err != nil || len(password) == 0 {
		mw.JSONError(w, "password must be non-empty base64", http.StatusBadRequest)
		return
	}
	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil || len(salt) < 16 {
		mw.JSONError(w, "salt must be base64-encoded and at least 16 bytes", http.StatusBadRequest)
		return
	}
	derived, err := kdf.DeriveArgon2id(password, salt)
	if err != nil {
		mw.JSONError(w, "Argon2id failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(subject(r), "kdf_argon2id", "ok", "")
	mw.JSON(w, map[string]any{
		"key":       base64.StdEncoding.EncodeToString(derived),
		"key_len":   len(derived),
		"algorithm": "Argon2id",
		"params":    map[string]int{"time": 2, "memory_kb": 65536, "threads": 4},
	})
}

func (s *Server) handleKDFSalt(w http.ResponseWriter, _ *http.Request) {
	salt, err := kdf.NewSalt()
	if err != nil {
		mw.JSONError(w, "Failed to generate salt", http.StatusInternalServerError)
		return
	}
	mw.JSON(w, map[string]any{
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"size":     len(salt),
		"encoding": "base64",
	})
}

// ── Encrypted keystore handlers ───────────────────────────────────────────────

func (s *Server) handleKeystoreGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	var req struct {
		KeyID string `json:"key_id"`
		Level string `json:"level"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.KeyID == "" || !isValidUserID(req.KeyID) {
		mw.JSONError(w, "key_id required (alphanumeric, max 64 chars)", http.StatusBadRequest)
		return
	}
	var lvl kem.Level
	switch strings.ToUpper(strings.TrimSpace(req.Level)) {
	case "ML-KEM-1024", "HIGH":
		lvl = kem.Level1024
	default:
		lvl = kem.Level768
	}
	dk, err := kem.GenerateKey(lvl)
	if err != nil {
		mw.JSONError(w, "Key generation failed", http.StatusInternalServerError)
		return
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	dkBytes := dk.Bytes()
	if err := s.ks.Put(req.KeyID, lvl, ekBytes, dkBytes, 0); err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Failed to store key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.metrics.Counter("qs_crypto_keygen_total").Inc()
	s.metrics.Gauge("qs_keystore_keys_total").Set(float64(len(s.ks.List())))
	s.audit.Log(subject(r), "keystore_generate", "ok", req.KeyID)
	mw.JSON(w, map[string]any{
		"key_id":     req.KeyID,
		"public_key": base64.StdEncoding.EncodeToString(ekBytes),
		"algorithm":  "ML-KEM-768",
		"stored":     "encrypted-keystore",
	})
}

func (s *Server) handleKeystoreList(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	ids := s.ks.List()
	mw.JSON(w, map[string]any{"keys": ids, "count": len(ids)})
}

func (s *Server) handleKeystoreGet(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	keyID := r.PathValue("key_id")
	kv, err := s.ks.GetActive(keyID)
	if err != nil {
		mw.JSONError(w, "Key not found", http.StatusNotFound)
		return
	}
	mw.JSON(w, map[string]any{
		"key_id":     keyID,
		"version":    kv.Version,
		"public_key": base64.StdEncoding.EncodeToString(kv.EKBytes),
		"created_at": kv.CreatedAt,
		"expires_at": kv.ExpiresAt,
		"active":     kv.Active,
	})
}

func (s *Server) handleKeystoreRotate(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	keyID := r.PathValue("key_id")
	newEK, err := s.ks.Rotate(keyID)
	if err != nil {
		mw.JSONError(w, "Rotation failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.metrics.Counter("qs_crypto_keygen_total").Inc()
	s.audit.Log(subject(r), "keystore_rotate", "ok", keyID)
	mw.JSON(w, map[string]any{
		"key_id":         keyID,
		"new_public_key": base64.StdEncoding.EncodeToString(newEK),
		"rotated":        true,
	})
}

func (s *Server) handleKeystoreExpire(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	keyID := r.PathValue("key_id")
	if err := s.ks.Expire(keyID); err != nil {
		mw.JSONError(w, "Expire failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(subject(r), "keystore_expire", "ok", keyID)
	mw.JSON(w, map[string]bool{"expired": true})
}

func (s *Server) handleKeystoreDelete(w http.ResponseWriter, r *http.Request) {
	if !s.keystoreRequired(w) {
		return
	}
	keyID := r.PathValue("key_id")
	if err := s.ks.Delete(keyID); err != nil {
		mw.JSONError(w, "Delete failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.metrics.Gauge("qs_keystore_keys_total").Set(float64(len(s.ks.List())))
	s.audit.Log(subject(r), "keystore_delete", "ok", keyID)
	mw.JSON(w, map[string]bool{"deleted": true})
}

// ── Key export / import ───────────────────────────────────────────────────────

// wrappedKeyEnvelope is the JSON format produced by /keys/{key_id}/export
// and consumed by /keys/import.
//
// The private key (dk) is wrapped with AES-256-GCM using a key derived from
// the caller-supplied password via Argon2id (time=2, mem=64 MiB, threads=4).
// The salt is random per export; nonce is random per encryption.
type wrappedKeyEnvelope struct {
	Version     int    `json:"version"`      // always 1
	Algorithm   string `json:"algorithm"`    // "ML-KEM-768" or "ML-KEM-1024"
	Level       int    `json:"level"`        // 768 or 1024
	KDF         string `json:"kdf"`          // "argon2id"
	Salt        string `json:"salt"`         // base64 random 32-byte salt
	Nonce       string `json:"nonce"`        // base64 random 12-byte GCM nonce
	WrappedKey  string `json:"wrapped_key"`  // base64 AES-256-GCM(dk)
	PublicKey   string `json:"public_key"`   // base64 encapsulation key (plaintext)
}

// handleKeyExport wraps the private key identified by key_id with a
// password-derived AES-256-GCM wrapping key and returns the envelope JSON.
//
// Request:  { "password": "<string>" }
// Response: wrappedKeyEnvelope JSON
func (s *Server) handleKeyExport(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("key_id")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		mw.JSONError(w, "password is required", http.StatusBadRequest)
		return
	}

	ekBytes, dkBytes, level, ok := s.lookupKey(keyID)
	if !ok {
		mw.JSONError(w, "Key not found", http.StatusNotFound)
		return
	}

	// Generate random 32-byte salt and 12-byte nonce.
	salt := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if _, err := rand.Read(nonce); err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Derive wrapping key via Argon2id.
	wrapKey, err := kdf.DeriveArgon2id([]byte(req.Password), salt)
	if err != nil {
		mw.JSONError(w, "Key derivation failed", http.StatusInternalServerError)
		return
	}

	// Wrap the private key with AES-256-GCM.
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	wrapped := gcm.Seal(nil, nonce, dkBytes, nil)

	algoName := "ML-KEM-768"
	if level == kem.Level1024 {
		algoName = "ML-KEM-1024"
	}
	env := wrappedKeyEnvelope{
		Version:    1,
		Algorithm:  algoName,
		Level:      int(level),
		KDF:        "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
		PublicKey:  base64.StdEncoding.EncodeToString(ekBytes),
	}

	s.audit.Log(subject(r), "key_export", "ok", keyID)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, env)
}

// handleKeyImport unwraps a previously exported key envelope and stores the
// key under the provided key_id.
//
// Request:
//
//	{
//	  "key_id":   "<string>",
//	  "password": "<string>",
//	  "wrapped":  { ...wrappedKeyEnvelope... }
//	}
func (s *Server) handleKeyImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID    string             `json:"key_id"`
		Password string             `json:"password"`
		Wrapped  wrappedKeyEnvelope `json:"wrapped"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.KeyID == "" || !isValidUserID(req.KeyID) {
		mw.JSONError(w, "key_id required (alphanumeric, max 64 chars)", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		mw.JSONError(w, "password is required", http.StatusBadRequest)
		return
	}
	if req.Wrapped.Version != 1 {
		mw.JSONError(w, "unsupported wrapped key version", http.StatusBadRequest)
		return
	}

	salt, err := base64.StdEncoding.DecodeString(req.Wrapped.Salt)
	if err != nil || len(salt) == 0 {
		mw.JSONError(w, "invalid salt encoding", http.StatusBadRequest)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Wrapped.Nonce)
	if err != nil {
		mw.JSONError(w, "invalid nonce encoding", http.StatusBadRequest)
		return
	}
	wrappedBytes, err := base64.StdEncoding.DecodeString(req.Wrapped.WrappedKey)
	if err != nil {
		mw.JSONError(w, "invalid wrapped_key encoding", http.StatusBadRequest)
		return
	}

	// Derive the unwrapping key.
	wrapKey, err := kdf.DeriveArgon2id([]byte(req.Password), salt)
	if err != nil {
		mw.JSONError(w, "Key derivation failed", http.StatusInternalServerError)
		return
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	dkBytes, err := gcm.Open(nil, nonce, wrappedBytes, nil)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Unwrap failed: invalid password or corrupted envelope", http.StatusBadRequest)
		return
	}

	// Determine level from the envelope.
	level := kem.Level768
	if req.Wrapped.Level == int(kem.Level1024) {
		level = kem.Level1024
	}

	// Reconstruct the full keypair from the decapsulation key seed.
	dk, err := kem.ParseDecapsulationKey(level, dkBytes)
	if err != nil {
		mw.JSONError(w, "Invalid key material in envelope", http.StatusBadRequest)
		return
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	if err := s.storeKey(req.KeyID, level, ekBytes, dkBytes); err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Failed to store key", http.StatusInternalServerError)
		return
	}

	s.metrics.Counter("qs_crypto_keygen_total").Inc()
	s.metrics.Gauge("qs_keystore_keys_total").Set(float64(s.keyCount()))
	s.audit.Log(subject(r), "key_import", "ok", req.KeyID)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"key_id":     req.KeyID,
		"public_key": base64.StdEncoding.EncodeToString(ekBytes),
		"algorithm":  req.Wrapped.Algorithm,
		"imported":   true,
	})
}

// ── Post-quantum CA ────────────────────────────────────────────────────────────

// caStoreSave persists the current CA hierarchy to disk when a CA store is
// configured.  It must be called while holding caMu (at least RLock).
// Errors are logged but not propagated — a save failure must never abort a
// cryptographic operation that has already succeeded in memory.
func (s *Server) caStoreSave() {
	if s.caStore == nil {
		return // persistence not configured
	}
	// Snapshot the current state into the castore.Store so Save sees it.
	s.caStore.SetRoot(s.caInstance)
	for serial, sub := range s.caIntermediates {
		s.caStore.SetIntermediate(serial, sub)
	}
	if err := s.caStore.Save(s.caStorePath, s.caStorePassword); err != nil {
		// Non-fatal: the operation already succeeded in memory; log and continue.
		// In production, operator should alert on this via metrics/audit.
		s.audit.Log("system", "ca_store_save_failed", "error", err.Error())
	}
}

// handleCAInit initialises the server's built-in CA with a fresh ML-DSA-87
// keypair and a self-signed root certificate.
//
// Request:  { "subject": "CN=..." }
// Response: root certificate JSON
func (s *Server) handleCAInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		mw.JSONError(w, "subject is required", http.StatusBadRequest)
		return
	}

	// Fast pre-check: avoid expensive ML-DSA-87 keygen if CA already exists.
	// A concurrent init may still slip through; the double-checked lock below
	// guarantees only one writer wins.
	s.caMu.RLock()
	alreadyExists := s.caInstance != nil
	s.caMu.RUnlock()
	if alreadyExists {
		mw.JSONError(w, "CA already initialised — use POST /ca/reinit to replace", http.StatusConflict)
		return
	}

	// Expensive: generate ML-DSA-87 keypair outside the write lock to avoid
	// blocking other operations.  Multiple concurrent requests may reach this
	// point; only one will successfully commit below.
	authority, err := ca.Init(req.Subject)
	if err != nil {
		mw.JSONError(w, "CA initialisation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Double-checked lock: a concurrent init that completed during our keygen
	// must not be silently overwritten.
	// ── Cluster: must be leader; replicate CA snapshot via Raft ─────────────
	if !s.requireLeader(w, r) {
		return
	}
	if s.clusterEnabled() {
		snap, err := authority.Export()
		if err != nil {
			mw.JSONError(w, "CA export failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		snapJSON, _ := json.Marshal(snap)
		if err := s.clusterApply(cluster.OpCAInit, cluster.CAInitPayload{Snapshot: snapJSON}); err != nil {
			mw.JSONError(w, "Cluster replication failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s.caMu.Lock()
	if s.caInstance != nil {
		s.caMu.Unlock()
		// Discard the CA we just generated — another goroutine won the race.
		mw.JSONError(w, "CA already initialised", http.StatusConflict)
		return
	}
	s.caInstance = authority
	s.caStoreSave()
	s.caMu.Unlock()

	s.audit.Log(subject(r), "ca_init", "ok", req.Subject)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"status":      "initialised",
		"certificate": authority.Certificate(),
	})
}

// handleCASign issues a leaf certificate for the given subject, binding their
// public key to their identity.
//
// Request:
//
//	{
//	  "subject":          "CN=...",
//	  "public_key":       "<base64>",
//	  "public_key_type":  "ML-KEM-768",   // or "ML-DSA-65", "ML-DSA-87", etc.
//	  "ttl_days":         365              // optional; default 365
//	}
func (s *Server) handleCASign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject       string `json:"subject"`
		PublicKey     string `json:"public_key"`
		PublicKeyType string `json:"public_key_type"`
		TTLDays       int    `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		mw.JSONError(w, "subject is required", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		mw.JSONError(w, "public_key is required", http.StatusBadRequest)
		return
	}
	if req.PublicKeyType == "" {
		mw.JSONError(w, "public_key_type is required", http.StatusBadRequest)
		return
	}

	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised — call POST /ca/init first", http.StatusServiceUnavailable)
		return
	}

	pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pkBytes) == 0 {
		mw.JSONError(w, "invalid public_key encoding", http.StatusBadRequest)
		return
	}

	// Validate TTL: negative values produce already-expired certs; extreme
	// values (> 25 years) exceed reasonable CA policy.
	const maxTTLDays = 25 * 365
	if req.TTLDays < 0 {
		mw.JSONError(w, "ttl_days must not be negative", http.StatusBadRequest)
		return
	}
	if req.TTLDays > maxTTLDays {
		mw.JSONError(w, fmt.Sprintf("ttl_days exceeds maximum of %d days", maxTTLDays), http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour
	cert, err := authority.Issue(req.Subject, req.PublicKeyType, pkBytes, ttl)
	if err != nil {
		mw.JSONError(w, "Certificate issuance failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.metrics.Counter("qs_crypto_sign_total").Inc()
	s.audit.Log(subject(r), "ca_sign", "ok", req.Subject)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, cert)
}

// handleCAVerify verifies a leaf certificate against the server's CA.
// This endpoint is public — any holder of a certificate can verify it.
//
// Request:  { "certificate": { ...Certificate JSON... } }
// Response: { "valid": true|false, "error": "..." }
func (s *Server) handleCAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certificate ca.Certificate `json:"certificate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}

	s.metrics.Counter("qs_crypto_verify_total").Inc()
	if err := authority.Verify(&req.Certificate); err != nil {
		mw.JSON(w, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	mw.JSON(w, map[string]any{"valid": true})
}

// handleCACertificate returns the server CA's root certificate.
// This endpoint is public — clients can retrieve it to verify issued certs.
func (s *Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised — call POST /ca/init first", http.StatusServiceUnavailable)
		return
	}
	mw.JSON(w, authority.Certificate())
}

// handleCARevoke adds a certificate serial number to the CA's revocation list.
// Subsequent Verify calls for a certificate with this serial will fail.
//
// Request:  { "serial": "<hex serial>" }
// Response: { "revoked": true, "serial": "..." }
func (s *Server) handleCARevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Serial == "" {
		mw.JSONError(w, "serial is required", http.StatusBadRequest)
		return
	}

	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}

	// ── Cluster: replicate revocation through Raft ───────────────────────────
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.clusterApply(cluster.OpCARevoke, cluster.CARevokePayload{Serial: req.Serial}); err != nil {
		mw.JSONError(w, "Cluster replication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := authority.Revoke(req.Serial); err != nil {
		mw.JSONError(w, "Revocation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Persist the updated CRL immediately.
	s.caMu.RLock()
	s.caStoreSave()
	s.caMu.RUnlock()

	s.audit.Log(subject(r), "ca_revoke", "ok", req.Serial)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, map[string]any{
		"revoked": true,
		"serial":  req.Serial,
	})
}

// handleCACRL returns the current Certificate Revocation List.
// This endpoint is public — any holder of a certificate can check its status.
func (s *Server) handleCACRL(w http.ResponseWriter, r *http.Request) {
	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}
	mw.JSON(w, authority.CRL())
}

// ── Hybrid PKI handlers ───────────────────────────────────────────────────────

// handleCAIntermediate issues a new intermediate CA certificate signed by the
// server's root CA.  The subordinate CA is stored in memory; it can later
// issue leaf certificates via POST /ca/intermediate/{serial}/sign.
//
// Request:  { "subject": "CN=Intermediate CA,O=Example Corp", "ttl_days": 3650 }
// Response: { "certificate": {...}, "serial": "..." }
func (s *Server) handleCAIntermediate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject string `json:"subject"`
		TTLDays int    `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		mw.JSONError(w, "subject is required", http.StatusBadRequest)
		return
	}

	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised — call POST /ca/init first", http.StatusServiceUnavailable)
		return
	}

	if req.TTLDays < 0 {
		mw.JSONError(w, "ttl_days must not be negative", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour
	subCA, cert, err := authority.IssueIntermediate(req.Subject, ttl)
	if err != nil {
		mw.JSONError(w, "Intermediate CA creation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.caMu.Lock()
	s.caIntermediates[cert.Serial] = subCA
	s.caStoreSave()
	s.caMu.Unlock()

	s.audit.Log(subject(r), "ca_intermediate", "ok", req.Subject)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSONStatus(w, http.StatusCreated, map[string]any{
		"certificate": cert,
		"serial":      cert.Serial,
	})
}

// handleCAIntermediateSign issues a leaf certificate signed by one of the
// server's intermediate CAs (identified by serial number in the URL path).
//
// Request:  { "subject": "CN=...", "public_key": "<base64>", "public_key_type": "ML-KEM-768", "ttl_days": 365 }
// Response: leaf Certificate JSON
func (s *Server) handleCAIntermediateSign(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")

	s.caMu.RLock()
	subCA, ok := s.caIntermediates[serial]
	s.caMu.RUnlock()
	if !ok {
		mw.JSONError(w, "intermediate CA not found", http.StatusNotFound)
		return
	}

	var req struct {
		Subject       string `json:"subject"`
		PublicKey     string `json:"public_key"`
		PublicKeyType string `json:"public_key_type"`
		TTLDays       int    `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		mw.JSONError(w, "subject is required", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		mw.JSONError(w, "public_key is required", http.StatusBadRequest)
		return
	}
	if req.PublicKeyType == "" {
		mw.JSONError(w, "public_key_type is required", http.StatusBadRequest)
		return
	}

	pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pkBytes) == 0 {
		mw.JSONError(w, "invalid public_key encoding", http.StatusBadRequest)
		return
	}

	if req.TTLDays < 0 {
		mw.JSONError(w, "ttl_days must not be negative", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour
	cert, err := subCA.Issue(req.Subject, req.PublicKeyType, pkBytes, ttl)
	if err != nil {
		mw.JSONError(w, "Certificate issuance failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.metrics.Counter("qs_crypto_sign_total").Inc()
	s.audit.Log(subject(r), "ca_intermediate_sign", "ok", req.Subject)
	s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
	mw.JSON(w, cert)
}

// handleCAChainVerify verifies a certificate chain against the server's root CA.
// This endpoint is public — any client can verify a chain.
//
// Request:
//
//	{
//	  "certificate": { ...Certificate JSON... },
//	  "chain":        [ ...intermediate Certificate JSON objects, direct issuer first... ]
//	}
//
// Response: { "valid": true|false, "error": "..." }
func (s *Server) handleCAChainVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certificate ca.Certificate   `json:"certificate"`
		Chain       []ca.Certificate `json:"chain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.caMu.RLock()
	authority := s.caInstance
	s.caMu.RUnlock()
	if authority == nil {
		mw.JSONError(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}

	// Build chain pointer slice.
	chain := make([]*ca.Certificate, len(req.Chain))
	for i := range req.Chain {
		c := req.Chain[i] // capture
		chain[i] = &c
	}

	s.metrics.Counter("qs_crypto_verify_total").Inc()
	if err := ca.VerifyChain(&req.Certificate, chain, authority.Certificate()); err != nil {
		mw.JSON(w, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	mw.JSON(w, map[string]any{"valid": true})
}

// ── Channel API ───────────────────────────────────────────────────────────────

func (s *Server) handleChannelInit(w http.ResponseWriter, r *http.Request) {
	pk, sk, err := dsa.GenerateKey(dsa.Level65)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	initiator, err := channel.NewInitiator(sk, pk)
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	req, err := initiator.Begin()
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Guard against channel session flooding: cap total pending initiators.
	// A single unauthenticated write-role user could otherwise exhaust memory
	// by creating thousands of abandoned handshakes within the 5-minute TTL.
	const maxPendingChannels = 256
	s.channelMu.Lock()
	if len(s.channelInitiators) >= maxPendingChannels {
		s.channelMu.Unlock()
		mw.JSONError(w, "too many pending channel sessions — complete or wait for expiry",
			http.StatusTooManyRequests)
		return
	}
	s.channelInitiators[req.SessionID] = &channelInitEntry{
		initiator: initiator,
		req:       req,
		createdAt: time.Now(),
	}
	s.channelMu.Unlock()

	s.metrics.Counter("qs_crypto_channel_handshake_total").Inc()
	s.audit.Log(subject(r), "channel_init", "ok", req.SessionID)
	mw.JSON(w, map[string]any{
		"session_id":  req.SessionID,
		"ek_bytes":    base64.StdEncoding.EncodeToString(req.EKBytes),
		"identity_pk": base64.StdEncoding.EncodeToString(req.IdentityPK),
		"signature":   base64.StdEncoding.EncodeToString(req.Signature),
	})
}

func (s *Server) handleChannelComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID     string `json:"session_id"`
		KEMCiphertext string `json:"kem_ciphertext"`
		IdentityPK    string `json:"identity_pk"`
		Signature     string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.channelMu.RLock()
	entry, ok := s.channelInitiators[req.SessionID]
	s.channelMu.RUnlock()
	if !ok {
		mw.JSONError(w, "Session not found", http.StatusNotFound)
		return
	}

	kemCT, _ := base64.StdEncoding.DecodeString(req.KEMCiphertext)
	idPK, _ := base64.StdEncoding.DecodeString(req.IdentityPK)
	sig, _ := base64.StdEncoding.DecodeString(req.Signature)

	resp := &channel.InitResponse{
		SessionID:     req.SessionID,
		KEMCiphertext: kemCT,
		IdentityPK:    idPK,
		Signature:     sig,
	}
	sess, err := entry.initiator.Complete(resp)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Handshake failed", http.StatusBadRequest)
		return
	}

	s.channelMu.Lock()
	delete(s.channelInitiators, req.SessionID)
	s.channelSessions[req.SessionID] = &channelSessEntry{
		sess:     sess,
		lastUsed: time.Now(),
	}
	s.channelMu.Unlock()

	s.audit.Log(subject(r), "channel_complete", "ok", req.SessionID)
	mw.JSON(w, map[string]string{"session_id": req.SessionID, "status": "established"})
}

func (s *Server) handleChannelSeal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.channelMu.RLock()
	entry, ok := s.channelSessions[req.SessionID]
	s.channelMu.RUnlock()
	if !ok {
		mw.JSONError(w, "Session not found", http.StatusNotFound)
		return
	}

	msg, err := entry.sess.Seal([]byte(req.Plaintext))
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Seal failed", http.StatusInternalServerError)
		return
	}

	// Touch last-used timestamp.
	s.channelMu.Lock()
	if e, exists := s.channelSessions[req.SessionID]; exists {
		e.lastUsed = time.Now()
	}
	s.channelMu.Unlock()

	s.metrics.Counter("qs_crypto_encrypt_total").Inc()
	mw.JSON(w, map[string]any{
		"session_id": msg.SessionID,
		"seq_num":    msg.SeqNum,
		"ciphertext": base64.StdEncoding.EncodeToString(msg.Ciphertext),
	})
}

func (s *Server) handleChannelOpen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID  string `json:"session_id"`
		MsgNonce   string `json:"msg_nonce"`
		SeqNum     uint64 `json:"seq_num"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.channelMu.RLock()
	entry, ok := s.channelSessions[req.SessionID]
	s.channelMu.RUnlock()
	if !ok {
		mw.JSONError(w, "Session not found", http.StatusNotFound)
		return
	}

	nonce, _ := base64.StdEncoding.DecodeString(req.MsgNonce)
	ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
	plain, err := entry.sess.Open(&channel.Message{
		SessionID:  nonce,
		SeqNum:     req.SeqNum,
		Ciphertext: ct,
	})
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Touch last-used timestamp.
	s.channelMu.Lock()
	if e, exists := s.channelSessions[req.SessionID]; exists {
		e.lastUsed = time.Now()
	}
	s.channelMu.Unlock()

	s.metrics.Counter("qs_crypto_decrypt_total").Inc()
	mw.JSON(w, map[string]string{"plaintext": string(plain)})
}

// ── Threshold API ─────────────────────────────────────────────────────────────

func (s *Server) handleThresholdRound(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message   string   `json:"message"`
		SignerIDs []string `json:"signer_ids"`
		Threshold int      `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Threshold < 1 {
		mw.JSONError(w, "threshold must be ≥ 1", http.StatusBadRequest)
		return
	}

	msg := []byte(req.Message)
	nonce, err := threshold.NewNonce()
	if err != nil {
		mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	coord, err := threshold.NewCoordinator(msg, nonce, req.Threshold)
	if err != nil {
		mw.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	roundID := threshold.RoundID(nonce)
	s.thresholdMu.Lock()
	s.thresholdRounds[roundID] = &thresholdRoundEntry{
		coord:     coord,
		msg:       msg,
		nonce:     nonce,
		createdAt: time.Now(),
	}
	s.thresholdMu.Unlock()

	s.audit.Log(subject(r), "threshold_round_open", "ok", roundID)
	mw.JSON(w, map[string]any{
		"round_id":  roundID,
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"threshold": req.Threshold,
	})
}

func (s *Server) handleThresholdSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SignerID string `json:"signer_id"`
		RoundID  string `json:"round_id"`
		Nonce    string `json:"nonce"`
		Message  string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SignerID == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.thresholdMu.Lock()
	se, ok := s.thresholdSigners[req.SignerID]
	if !ok {
		sgn, err := threshold.NewSigner(req.SignerID)
		if err != nil {
			s.thresholdMu.Unlock()
			mw.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		se = &signerEntry{signer: sgn, lastUsed: time.Now()}
		s.thresholdSigners[req.SignerID] = se
	}
	se.lastUsed = time.Now()
	sgn := se.signer
	s.thresholdMu.Unlock()

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		mw.JSONError(w, "Invalid nonce encoding", http.StatusBadRequest)
		return
	}
	partial, err := sgn.Sign([]byte(req.Message), nonce)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Sign failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.metrics.Counter("qs_crypto_threshold_partial_total").Inc()
	mw.JSON(w, map[string]any{
		"signer_id":  partial.SignerID,
		"public_key": base64.StdEncoding.EncodeToString(partial.PublicKey),
		"signature":  base64.StdEncoding.EncodeToString(partial.Signature),
		"nonce":      base64.StdEncoding.EncodeToString(partial.Nonce),
	})
}

func (s *Server) handleThresholdSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoundID   string `json:"round_id"`
		SignerID  string `json:"signer_id"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
		Nonce     string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoundID == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.thresholdMu.RLock()
	round, ok := s.thresholdRounds[req.RoundID]
	s.thresholdMu.RUnlock()
	if !ok {
		mw.JSONError(w, "Round not found", http.StatusNotFound)
		return
	}

	pk, _ := base64.StdEncoding.DecodeString(req.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(req.Signature)
	nc, _ := base64.StdEncoding.DecodeString(req.Nonce)

	partial := &threshold.PartialSignature{
		SignerID:  req.SignerID,
		PublicKey: pk,
		Signature: sig,
		Nonce:     nc,
	}
	done, auth, err := round.coord.Submit(partial)
	if err != nil {
		s.metrics.Counter("qs_crypto_errors_total").Inc()
		mw.JSONError(w, "Submit failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	if done && auth != nil {
		s.metrics.Counter("qs_crypto_threshold_authorised_total").Inc()
		s.audit.Log(subject(r), "threshold_authorised", "ok", req.RoundID)
		s.metrics.Gauge("qs_audit_log_entries").Set(float64(s.audit.Count()))
		s.thresholdMu.Lock()
		delete(s.thresholdRounds, req.RoundID)
		s.thresholdMu.Unlock()
		mw.JSON(w, map[string]any{
			"done":       true,
			"round_id":   req.RoundID,
			"authorised": threshold.AuthorisedSignatureToMap(auth),
		})
		return
	}
	mw.JSON(w, map[string]any{
		"done":      false,
		"round_id":  req.RoundID,
		"collected": round.coord.Count(),
	})
}

func (s *Server) handleThresholdVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string            `json:"message"`
		Auth    map[string]any    `json:"authorised"`
		Trusted map[string]string `json:"trusted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		mw.JSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	trusted := make(map[string][]byte, len(req.Trusted))
	for id, pkB64 := range req.Trusted {
		pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			mw.JSONError(w, "Invalid trusted pk for "+id, http.StatusBadRequest)
			return
		}
		trusted[id] = pkBytes
	}

	auth, err := authFromMap(req.Auth)
	if err != nil {
		mw.JSONError(w, "Invalid authorised signature: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.metrics.Counter("qs_crypto_verify_total").Inc()
	if err := threshold.Verify([]byte(req.Message), auth, trusted); err != nil {
		mw.JSON(w, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	mw.JSON(w, map[string]any{"valid": true, "threshold": auth.Threshold})
}

// authFromMap reconstructs an AuthorisedSignature from the JSON map produced
// by AuthorisedSignatureToMap.
func authFromMap(m map[string]any) (*threshold.AuthorisedSignature, error) {
	if m == nil {
		return nil, fmt.Errorf("nil map")
	}
	thresh, _ := m["threshold"].(float64)
	digestB64, _ := m["msg_digest"].(string)
	nonceB64, _ := m["nonce"].(string)
	partialsRaw, _ := m["partials"].([]any)

	digest, err := base64.StdEncoding.DecodeString(digestB64)
	if err != nil {
		return nil, fmt.Errorf("decode msg_digest: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	partials := make([]threshold.PartialSignature, 0, len(partialsRaw))
	for _, pr := range partialsRaw {
		pm, ok := pr.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid partial entry")
		}
		pk, _ := base64.StdEncoding.DecodeString(pm["public_key"].(string))
		sig, _ := base64.StdEncoding.DecodeString(pm["signature"].(string))
		pn, _ := base64.StdEncoding.DecodeString(pm["nonce"].(string))
		partials = append(partials, threshold.PartialSignature{
			SignerID:  pm["signer_id"].(string),
			PublicKey: pk,
			Signature: sig,
			Nonce:     pn,
		})
	}

	return &threshold.AuthorisedSignature{
		Threshold: int(thresh),
		MsgDigest: digest,
		Nonce:     nonce,
		Partials:  partials,
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// normalizeAPIPath collapses path-parameter segments to "{id}" so that the
// metrics path label has bounded cardinality.  Only segments that are NOT known
// API keywords are replaced — this prevents unbounded growth from user-supplied
// key IDs appearing in Prometheus label sets.
//
// Examples:
//
//	/keys/Xk9aB3m/public  →  /keys/{id}/public
//	/keystore/prod-key/rotate  →  /keystore/{id}/rotate
//	/auth/token  →  /auth/token  (unchanged — all segments are known)
func normalizeAPIPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if !knownAPISegment[p] {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// knownAPISegment lists all literal path segments used in the QuantumShield API.
// Any segment NOT in this map is treated as a path parameter and replaced with
// "{id}" in metrics labels.  Update this map when adding new routes.
var knownAPISegment = map[string]bool{
	"":                 true, // leading slash produces an empty first segment
	"health":           true,
	"live":             true,
	"ready":            true,
	"fips":             true,
	"metrics":          true,
	"auth":             true,
	"token":            true,
	"verify":           true,
	"revoke":           true,
	"keys":             true,
	"generate":         true,
	"public":           true,
	"encrypt":          true,
	"decrypt":          true,
	"sign":             true,
	"verify-signature": true,
	"slh-dsa":          true,
	"vault":            true,
	"split":            true,
	"reconstruct":      true,
	"channel":          true,
	"init":             true,
	"complete":         true,
	"seal":             true,
	"open":             true,
	"threshold":        true,
	"round":            true,
	"submit":           true,
	"keystore":         true,
	"rotate":           true,
	"expire":           true,
	"kdf":              true,
	"hkdf":             true,
	"argon2":           true,
	"salt":             true,
	"audit":            true,
	"entries":          true,
	"export":           true,
	"import":           true,
	"ca":               true,
	"certificate":      true,
	"crl":              true,
	"intermediate":     true,
	"chain-verify":     true,
}

// secretFromEnv reads a secret from an env var.
// If name+"_FILE" is set, the file at that path is read instead (Docker Secrets,
// Kubernetes Secrets, etc.).  Trailing newlines are stripped from file content.
// Example: KEYSTORE_PASSWORD_FILE=/run/secrets/qs_keystore_password
func secretFromEnv(name string) string {
	if path := os.Getenv(name + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimRight(string(data), "\r\n")
		}
	}
	return os.Getenv(name)
}

func isValidUserID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '@' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

func randomID() string {
	b := make([]byte, 9)
	rand.Read(b) //nolint:errcheck — crypto/rand.Read never fails on modern OS
	return base64.RawURLEncoding.EncodeToString(b)
}
