// Package auth implements Quantum Secure Tokens (QST) —
// a JWT-analog signed with ML-DSA (NIST FIPS 204).
//
// Token format:  base64url(header) . base64url(payload) . base64url(signature)
//
// Security properties:
//   - Signature covers header+payload — any field tampering breaks verification
//   - jti (JWT ID) is inside the signed payload — revocation bypass impossible
//   - Constant-time signature verification via cloudflare/circl
//   - Persistent revocation list (JSON file, atomic writes) — survives restarts
//   - Expired JTIs pruned automatically (background goroutine, hourly)
//   - Expiry enforced on every Verify call
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

const (
	tokenVersion    = "QST-1"
	defaultTTL      = 3600 * time.Second
	jtiBytes        = 16 // 128-bit random token ID
	pruneInterval   = 1 * time.Hour
	revocationPerms = 0o600 // owner read/write only
)

// revokedEntry is one record persisted in the on-disk revocation file.
// Entries whose ExpiresAt is in the past are pruned on load and hourly.
type revokedEntry struct {
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"exp"` // Unix timestamp; entry is prunable after this
}

// Header is the token header (algorithm metadata).
type Header struct {
	Typ string `json:"typ"` // always "QST"
	Alg string `json:"alg"` // e.g. "ML-DSA-65"
	Ver string `json:"ver"` // token format version
}

// Claims holds the token payload fields.
type Claims struct {
	Subject   string         `json:"sub"`             // user/entity identifier
	Issuer    string         `json:"iss"`             // authority name
	IssuedAt  int64          `json:"iat"`             // Unix timestamp
	ExpiresAt int64          `json:"exp"`             // Unix timestamp
	Roles     []string       `json:"roles"`           // authorised actions
	JTI       string         `json:"jti"`             // unique token ID (signed — immutable)
	Extra     map[string]any `json:"extra,omitempty"` // application-specific fields
}

// Token is a parsed, verified QST token.
type Token struct {
	Header Header
	Claims Claims
}

// Authority issues and verifies Quantum Secure Tokens.
// Safe for concurrent use.
// Call Close when the Authority is no longer needed to stop the background pruner.
type Authority struct {
	issuer string
	ttl    time.Duration
	dsaLvl dsa.Level

	mu             sync.RWMutex
	pk             *dsa.PublicKey
	sk             *dsa.PrivateKey
	revoked        map[string]int64 // jti → expiresAt Unix (0 = no expiry info)
	revocationPath string           // empty = in-memory only

	stopPrune chan struct{}
	pruneOnce sync.Once
}

// NewAuthority creates an Authority that signs with ML-DSA at the given level.
// A fresh signing keypair is generated on construction.
func NewAuthority(issuer string, ttl time.Duration, level dsa.Level) (*Authority, error) {
	if ttl == 0 {
		ttl = defaultTTL
	}
	pk, sk, err := dsa.GenerateKey(level)
	if err != nil {
		return nil, fmt.Errorf("auth.NewAuthority: %w", err)
	}
	return &Authority{
		issuer:    issuer,
		ttl:       ttl,
		dsaLvl:    level,
		pk:        pk,
		sk:        sk,
		revoked:   make(map[string]int64),
		stopPrune: make(chan struct{}),
	}, nil
}

// SetRevocationFile configures persistent revocation storage.
// If the file already exists its entries are loaded (expired ones discarded).
// From this point every Revoke call atomically rewrites the file.
// A background goroutine prunes expired entries from memory and disk hourly.
// Returns an error only if the existing file cannot be parsed.
func (a *Authority) SetRevocationFile(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Load existing entries, discarding expired ones.
	if err := a.loadRevocationLocked(path); err != nil {
		return err
	}
	a.revocationPath = path

	// Start the hourly pruner exactly once.
	a.pruneOnce.Do(func() {
		go a.pruneLoop()
	})
	return nil
}

// Close stops the background pruner goroutine.
// Safe to call multiple times or even if SetRevocationFile was never called.
func (a *Authority) Close() {
	a.pruneOnce.Do(func() {}) // ensure the channel init path has run
	select {
	case <-a.stopPrune: // already closed
	default:
		close(a.stopPrune)
	}
}

// PublicKeyBytes returns the serialised ML-DSA public key (for distribution).
func (a *Authority) PublicKeyBytes() ([]byte, error) {
	return a.pk.Bytes()
}

// Issue creates and signs a new token for the given subject.
func (a *Authority) Issue(subject string, roles []string, extra map[string]any) (string, error) {
	if subject == "" {
		return "", errors.New("auth.Issue: subject must not be empty")
	}
	if len(roles) == 0 {
		return "", errors.New("auth.Issue: at least one role required")
	}

	// Generate a cryptographically random token ID.
	jtiRaw := make([]byte, jtiBytes)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", fmt.Errorf("auth.Issue: generate jti: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiRaw)

	now := time.Now()
	hdr := Header{
		Typ: "QST",
		Alg: algName(a.dsaLvl),
		Ver: tokenVersion,
	}
	payload := Claims{
		Subject:   subject,
		Issuer:    a.issuer,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(a.ttl).Unix(),
		Roles:     roles,
		JTI:       jti,
		Extra:     extra,
	}

	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("auth.Issue: marshal header: %w", err)
	}
	payJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("auth.Issue: marshal payload: %w", err)
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64

	a.mu.RLock()
	sig, err := dsa.Sign(a.sk, []byte(signingInput))
	a.mu.RUnlock()
	if err != nil {
		return "", fmt.Errorf("auth.Issue: sign: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// Verify parses, verifies, and validates a token string.
// Returns the token claims on success.
// All error messages are generic to prevent oracle attacks.
func (a *Authority) Verify(tokenStr string) (*Token, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("authentication failed")
	}
	hdrB64, payB64, sigB64 := parts[0], parts[1], parts[2]

	// 1. Decode header
	hdrJSON, err := base64.RawURLEncoding.DecodeString(hdrB64)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	var hdr Header
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, errors.New("authentication failed")
	}
	if hdr.Typ != "QST" || hdr.Ver != tokenVersion {
		return nil, errors.New("authentication failed")
	}

	// 2. Decode payload
	payJSON, err := base64.RawURLEncoding.DecodeString(payB64)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	var claims Claims
	if err := json.Unmarshal(payJSON, &claims); err != nil {
		return nil, errors.New("authentication failed")
	}

	// 3. Decode signature
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	// 4. Verify ML-DSA signature (covers header+payload — any tampering fails here)
	signingInput := hdrB64 + "." + payB64
	a.mu.RLock()
	valid := dsa.Verify(a.pk, []byte(signingInput), sig)
	a.mu.RUnlock()
	if !valid {
		return nil, errors.New("authentication failed")
	}

	// 5. Check expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("authentication failed")
	}

	// 6. Check revocation (jti is inside the signed payload — cannot be forged)
	if claims.JTI == "" {
		return nil, errors.New("authentication failed")
	}
	a.mu.RLock()
	_, isRevoked := a.revoked[claims.JTI]
	a.mu.RUnlock()
	if isRevoked {
		return nil, errors.New("authentication failed")
	}

	return &Token{Header: hdr, Claims: claims}, nil
}

// Revoke adds a token's jti to the revocation list.
// Subsequent Verify calls for this token will fail.
// If a revocation file was configured, it is atomically updated.
// No-op if the token is malformed or already revoked.
func (a *Authority) Revoke(tokenStr string) {
	jti, exp := extractJTIAndExp(tokenStr)
	if jti == "" {
		return
	}

	a.mu.Lock()
	a.revoked[jti] = exp
	snapshot := a.snapshotLocked()
	path := a.revocationPath
	a.mu.Unlock()

	if path != "" {
		_ = persistRevocation(path, snapshot) // best-effort; in-memory revocation already applied
	}
}

// IsRevoked reports whether the token identified by tokenStr has been revoked.
func (a *Authority) IsRevoked(tokenStr string) bool {
	jti, _ := extractJTIAndExp(tokenStr)
	if jti == "" {
		return false
	}
	a.mu.RLock()
	_, ok := a.revoked[jti]
	a.mu.RUnlock()
	return ok
}

// ── Persistence helpers ───────────────────────────────────────────────────────

// loadRevocationLocked reads the revocation file at path and populates a.revoked.
// Expired entries are silently discarded. Must be called with a.mu held for write.
func (a *Authority) loadRevocationLocked(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // first run — no file yet
	}
	if err != nil {
		return fmt.Errorf("auth: read revocation file %q: %w", path, err)
	}

	var entries []revokedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("auth: parse revocation file %q: %w", path, err)
	}

	now := time.Now().Unix()
	for _, e := range entries {
		if e.ExpiresAt > 0 && e.ExpiresAt < now {
			continue // expired — skip
		}
		a.revoked[e.JTI] = e.ExpiresAt
	}
	return nil
}

// snapshotLocked returns a copy of the revocation map. Must be called with a.mu held.
func (a *Authority) snapshotLocked() []revokedEntry {
	entries := make([]revokedEntry, 0, len(a.revoked))
	for jti, exp := range a.revoked {
		entries = append(entries, revokedEntry{JTI: jti, ExpiresAt: exp})
	}
	return entries
}

// persistRevocation atomically writes entries to path.
// Writes to a .tmp file, then renames — guarantees no partial writes.
func persistRevocation(path string, entries []revokedEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("auth: marshal revocation list: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, revocationPerms); err != nil {
		return fmt.Errorf("auth: write revocation tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("auth: rename revocation file: %w", err)
	}
	return nil
}

// pruneLoop runs hourly, removing expired JTI entries from memory and disk.
func (a *Authority) pruneLoop() {
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.pruneExpired()
		case <-a.stopPrune:
			return
		}
	}
}

// pruneExpired removes entries whose expiry is in the past, then rewrites the file.
func (a *Authority) pruneExpired() {
	now := time.Now().Unix()

	a.mu.Lock()
	for jti, exp := range a.revoked {
		if exp > 0 && exp < now {
			delete(a.revoked, jti)
		}
	}
	snapshot := a.snapshotLocked()
	path := a.revocationPath
	a.mu.Unlock()

	if path != "" {
		_ = persistRevocation(path, snapshot)
	}
}

// ── Token parsing helpers ─────────────────────────────────────────────────────

// extractJTIAndExp parses jti and exp from the payload WITHOUT verifying the signature.
// Used for revocation only — a revoked-but-tampered token will fail signature
// verification in Verify() regardless.
func extractJTIAndExp(tokenStr string) (jti string, exp int64) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", 0
	}
	payJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0
	}
	var claims struct {
		JTI       string `json:"jti"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(payJSON, &claims); err != nil {
		return "", 0
	}
	return claims.JTI, claims.ExpiresAt
}

func algName(level dsa.Level) string {
	switch level {
	case dsa.Level44:
		return "ML-DSA-44"
	case dsa.Level65:
		return "ML-DSA-65"
	case dsa.Level87:
		return "ML-DSA-87"
	}
	return "ML-DSA-65"
}
