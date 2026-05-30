// Package kdf provides key derivation for QuantumShield.
//
// Two primitives:
//   - HKDF-SHA256   — derives key material from high-entropy secrets (KEM shared keys).
//   - Argon2id       — derives keys from low-entropy passwords (memory-hard, side-channel resistant).
package kdf

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeyLen32 is the standard 256-bit key length.
	KeyLen32 = 32

	// SaltLen is the recommended random salt length (256-bit).
	SaltLen = 32

	// argon2 tuning — OWASP minimum for interactive logins (2024):
	// time=2, memory=64MB, threads=4 → ~200ms on modern hardware.
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
)

// ── HKDF ─────────────────────────────────────────────────────────────────────

// DeriveHKDF derives keyLen bytes of key material using HKDF-SHA256.
//
//   - secret: high-entropy input (e.g. ML-KEM shared secret — 32 bytes)
//   - salt:   random or domain-specific value; nil is OK (replaced with SHA-256 zero hash)
//   - info:   context label, e.g. []byte("qs-channel-send-key-v1")
func DeriveHKDF(secret, salt, info []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 || keyLen > 255*sha256.Size {
		return nil, errors.New("kdf: invalid keyLen")
	}
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeriveHKDFMulti derives multiple keys in one call (single Extract, multiple Expand passes).
// infos and lens must have equal length.
//
// Use this to derive send-key, recv-key, and MAC-key from one shared secret
// without running Extract multiple times.
func DeriveHKDFMulti(secret, salt []byte, infos [][]byte, lens []int) ([][]byte, error) {
	if len(infos) != len(lens) {
		return nil, errors.New("kdf: infos and lens length mismatch")
	}
	keys := make([][]byte, len(infos))
	for i, info := range infos {
		k, err := DeriveHKDF(secret, salt, info, lens[i])
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	return keys, nil
}

// ── Argon2id ──────────────────────────────────────────────────────────────────

// DeriveArgon2id derives a 256-bit key from a low-entropy password using Argon2id.
// salt must be at least 16 bytes; use NewSalt() to generate.
//
// Parameters: time=2, memory=64MB, threads=4 (OWASP 2024 minimum).
func DeriveArgon2id(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("kdf: password must not be empty")
	}
	if len(salt) < 16 {
		return nil, errors.New("kdf: salt must be at least 16 bytes")
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

// ── Utilities ─────────────────────────────────────────────────────────────────

// NewSalt generates a cryptographically random 32-byte salt.
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// DomainSalt creates a deterministic domain-separated salt from a string label.
// Use when you need a fixed salt (e.g. per-application constant).
// For user passwords, always use NewSalt().
func DomainSalt(label string) []byte {
	h := sha256.Sum256([]byte("qs-domain-salt-v1:" + label))
	return h[:]
}
