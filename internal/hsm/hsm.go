// Package hsm provides the MasterKeyProvider abstraction for supplying the
// AES-256 master key used to protect the QuantumShield keystore.
//
// Built-in implementations
//
//   - EnvProvider — derives the master key from a password via Argon2id
//     (time=2, memory=64 MiB, threads=4, key=32 bytes).  This is the default
//     when no hardware module is configured.
//   - PKCS11Provider — wraps a PKCS#11 hardware security module.
//     Only compiled when built with -tags pkcs11.
//
// Future implementations may target cloud KMS services (AWS KMS, Google Cloud
// KMS, Azure Key Vault) by following the same interface.
//
// # Thread safety
//
// All implementations must be safe for concurrent use from multiple goroutines.
package hsm

import (
	"errors"
	"fmt"
	"sync"

	"github.com/quantum-shield/quantum-shield-go/internal/kdf"
)

// MasterKeyProvider supplies the 32-byte AES-256 symmetric key used to encrypt
// and decrypt private key material in the QuantumShield keystore.
//
// Implementations MUST be safe for concurrent use.
type MasterKeyProvider interface {
	// MasterKey returns the 32-byte AES-256 encryption key.
	// The returned slice must not be modified by the caller.
	// After Close has been called, MasterKey must return an error.
	MasterKey() ([]byte, error)

	// Close releases all resources held by the provider (e.g. HSM sessions,
	// file handles, network connections).  After Close returns, MasterKey must
	// return an error on every subsequent call.
	//
	// Implementations should zero any in-memory key material on Close.
	Close() error
}

// ── EnvProvider ───────────────────────────────────────────────────────────────

// EnvProvider derives the master key from a password using Argon2id with a
// caller-specified domain salt.  The derived key is computed once on the first
// call to MasterKey and cached for the lifetime of the provider.
//
// This avoids paying Argon2id's intentional latency on every keystore
// operation while still protecting the key material in memory between calls.
//
// Use NewEnvProvider to create an instance.
type EnvProvider struct {
	password   []byte
	domainSalt string

	mu      sync.Mutex
	derived []byte // nil until first MasterKey() call
	closed  bool
	err     error // sticky error from first failed derivation
}

// NewEnvProvider returns an EnvProvider that derives a 32-byte AES-256 master
// key from password using Argon2id keyed with domainSalt.
//
// To produce the same key as the default keystore.Open behaviour, pass
//
//	domainSalt = "qs-keystore-master-key-v1"
//
// Both password and domainSalt must be non-empty.
func NewEnvProvider(password, domainSalt string) (*EnvProvider, error) {
	if password == "" {
		return nil, errors.New("hsm.NewEnvProvider: password must not be empty")
	}
	if domainSalt == "" {
		return nil, errors.New("hsm.NewEnvProvider: domainSalt must not be empty")
	}
	return &EnvProvider{
		password:   []byte(password),
		domainSalt: domainSalt,
	}, nil
}

// MasterKey returns the 32-byte Argon2id-derived AES-256 master key.
//
// The first call runs Argon2id (≈ 100–300 ms depending on hardware) and caches
// the result.  Subsequent calls return the cached key in O(1).
func (p *EnvProvider) MasterKey() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, errors.New("hsm.EnvProvider: provider is closed")
	}
	if p.err != nil {
		return nil, p.err // sticky: don't retry a failed derivation
	}
	if p.derived != nil {
		return p.derived, nil
	}

	derived, err := kdf.DeriveArgon2id(p.password, kdf.DomainSalt(p.domainSalt))
	if err != nil {
		p.err = fmt.Errorf("hsm.EnvProvider: derive master key: %w", err)
		return nil, p.err
	}
	if len(derived) != 32 {
		p.err = fmt.Errorf("hsm.EnvProvider: Argon2id returned %d bytes, want 32", len(derived))
		return nil, p.err
	}
	p.derived = derived
	return p.derived, nil
}

// Close zeroes all in-memory key material and prevents further calls to
// MasterKey from returning useful data.
//
// Safe to call multiple times; subsequent calls are no-ops.
func (p *EnvProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	for i := range p.password {
		p.password[i] = 0
	}
	for i := range p.derived {
		p.derived[i] = 0
	}
	p.password = nil
	p.derived = nil
	return nil
}
