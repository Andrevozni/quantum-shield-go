// Package hybrid implements ML-KEM + AES-256-GCM hybrid encryption.
//
// Security properties:
//   - Nonce: 12 bytes from crypto/rand, zero nonce rejected
//   - Key: 32-byte shared secret from ML-KEM (FIPS 203)
//   - AEAD: AES-256-GCM — authenticated encryption, 16-byte tag
//   - Replay (in-process): ciphertext deduplication via LRU cache
//   - Replay (cross-restart): CreatedAt timestamp bound into AEAD additional data;
//     maxAge (default 5 min) prevents old ciphertexts from decrypting after restart
//
// Cross-restart replay protection design:
//
//	Encrypt sets CreatedAt = time.Now().Unix() and passes it as 8-byte
//	big-endian additional data (AD) to AES-GCM Seal.  Any modification to
//	CreatedAt causes authentication failure in gcm.Open.  Decrypt checks that
//	the authentic CreatedAt is within the maxAge window.  An attacker who
//	captures a valid ciphertext cannot replay it after maxAge seconds even if
//	the server restarts (empty cache) because the timestamp check rejects it.
package hybrid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/kem"
)

const (
	nonceSize   = 12
	keySize     = 32
	seenCacheMax = 100_000

	// defaultMaxAge is the maximum age of a ciphertext accepted by Decrypt.
	// After this duration, a ciphertext is rejected even if cryptographically valid.
	// This bounds the replay window to the lifetime of the ciphertext — a server
	// restart with an empty in-process cache does not re-open the replay window
	// for ciphertexts older than defaultMaxAge.
	defaultMaxAge = 5 * time.Minute
)

// Encrypted is the wire-format ciphertext produced by Encrypt.
//
// CreatedAt is a Unix timestamp (seconds) set by Encrypt and authenticated
// by the AES-GCM tag via AEAD additional data.  It must be included verbatim
// when calling Decrypt — altering it causes authentication failure.
type Encrypted struct {
	KEMCiphertext []byte // ML-KEM encapsulated key
	Nonce         []byte // AES-GCM nonce (12 bytes)
	Data          []byte // AES-GCM ciphertext + 16-byte tag
	CreatedAt     int64  // Unix seconds; authenticated via AEAD additional data
}

// Encrypter encrypts data under a recipient's ML-KEM public key.
// Safe for concurrent use; holds no mutable state.
type Encrypter struct {
	level kem.Level
}

// NewEncrypter returns an Encrypter for the given ML-KEM security level.
func NewEncrypter(level kem.Level) *Encrypter {
	return &Encrypter{level: level}
}

// Encrypt encrypts plaintext for the given encapsulation key bytes.
// A fresh ML-KEM shared secret, AES-GCM nonce, and CreatedAt timestamp are
// generated per call. The timestamp is cryptographically bound to the ciphertext.
func (e *Encrypter) Encrypt(ekBytes []byte, plaintext []byte) (*Encrypted, error) {
	// 1. Parse public key
	ek, err := kem.ParseEncapsulationKey(e.level, ekBytes)
	if err != nil {
		return nil, fmt.Errorf("hybrid.Encrypt: parse public key: %w", err)
	}

	// 2. ML-KEM encapsulate → (shared_secret, ciphertext)
	sharedSecret, kemCT, err := kem.Encapsulate(ek)
	if err != nil {
		return nil, fmt.Errorf("hybrid.Encrypt: encapsulate: %w", err)
	}

	// 3. Derive AES-256 key from first 32 bytes of shared secret.
	//    shared_secret is already 32 bytes of uniform keying material per FIPS 203.
	aesKey := sharedSecret[:keySize]

	// 4. Generate nonce from crypto/rand — never reuse.
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("hybrid.Encrypt: generate nonce: %w", err)
	}
	// Paranoia: reject all-zero nonce (weak RNG indicator)
	if subtle.ConstantTimeCompare(nonce, make([]byte, nonceSize)) == 1 {
		return nil, errors.New("hybrid.Encrypt: zero nonce generated — RNG failure")
	}

	// 5. AES-256-GCM encrypt with CreatedAt bound as additional data.
	//    The timestamp is authenticated by the GCM tag: any modification to
	//    CreatedAt (by the caller or an attacker) causes gcm.Open to fail.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("hybrid.Encrypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("hybrid.Encrypt: cipher.NewGCM: %w", err)
	}

	createdAt := time.Now().Unix()
	ad := encodeTimestamp(createdAt)
	ciphertext := gcm.Seal(nil, nonce, plaintext, ad)

	return &Encrypted{
		KEMCiphertext: kemCT,
		Nonce:         nonce,
		Data:          ciphertext,
		CreatedAt:     createdAt,
	}, nil
}

// Decrypter decrypts data under a ML-KEM private key.
//
// It provides two layers of replay protection:
//
//  1. Freshness window (cross-restart): CreatedAt is verified to be within maxAge
//     of the current time. Since CreatedAt is bound by the AEAD tag, an attacker
//     cannot modify it without causing authentication failure. A server restart
//     does not reset this protection — old ciphertexts outside the window are
//     rejected even if the in-process cache is empty.
//
//  2. In-process LRU cache (same-session): ciphertexts seen within the same
//     process lifetime are rejected on the second attempt.
//
// Safe for concurrent use.
type Decrypter struct {
	level  kem.Level
	maxAge time.Duration // 0 = freshness check disabled (test/dev only)

	// nowFn returns the current time. Nil → time.Now().
	// Override in tests via WithNowFunc to simulate time passing without sleeping.
	nowFn func() time.Time

	mu      sync.Mutex
	seen    map[string]struct{} // KEM ciphertext → seen
	seenSeq []string            // insertion order for LRU eviction
}

// NewDecrypter returns a Decrypter with the default maxAge (5 minutes).
func NewDecrypter(level kem.Level) *Decrypter {
	return &Decrypter{
		level:  level,
		maxAge: defaultMaxAge,
		seen:   make(map[string]struct{}),
	}
}

// NewDecrypterWithMaxAge returns a Decrypter with the specified maxAge.
// Pass 0 to disable the freshness check (development / testing only).
func NewDecrypterWithMaxAge(level kem.Level, maxAge time.Duration) *Decrypter {
	return &Decrypter{
		level:  level,
		maxAge: maxAge,
		seen:   make(map[string]struct{}),
	}
}

// WithNowFunc overrides the clock used for freshness checks.
// Intended for tests only — allows simulating future times without sleeping.
// Returns the same Decrypter so calls can be chained.
func (d *Decrypter) WithNowFunc(fn func() time.Time) *Decrypter {
	d.nowFn = fn
	return d
}

func (d *Decrypter) now() time.Time {
	if d.nowFn != nil {
		return d.nowFn()
	}
	return time.Now()
}

// Decrypt decrypts an Encrypted message using the given decapsulation key bytes.
//
// Order of operations is chosen for timing uniformity:
//  1. ML-KEM decapsulate (always, regardless of subsequent checks)
//  2. AES-GCM open with CreatedAt as additional data (authenticates timestamp)
//  3. Freshness check (CreatedAt within maxAge window)
//  4. In-process replay cache check
//
// All error paths return the same sentinel to prevent oracle attacks.
func (d *Decrypter) Decrypt(dkBytes []byte, enc *Encrypted) ([]byte, error) {
	if enc == nil || len(enc.KEMCiphertext) == 0 || len(enc.Nonce) == 0 || len(enc.Data) == 0 {
		return nil, errors.New("decryption failed")
	}

	// 1. Parse private key
	dk, err := kem.ParseDecapsulationKey(d.level, dkBytes)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	// 2. ML-KEM decapsulate — constant-time per FIPS 203 implicit rejection.
	//    Always executed before freshness/replay checks so timing is uniform
	//    regardless of whether the ciphertext is stale or replayed.
	sharedSecret, err := kem.Decapsulate(dk, enc.KEMCiphertext)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	aesKey := sharedSecret[:keySize]

	// 3. AES-256-GCM decrypt — CreatedAt is bound as additional data.
	//    An attacker who modifies CreatedAt (to bypass the freshness check)
	//    gets an authentication failure here, not a freshness failure.
	//    Both return the same opaque error.
	if len(enc.Nonce) != nonceSize {
		return nil, errors.New("decryption failed")
	}
	if subtle.ConstantTimeCompare(enc.Nonce, make([]byte, nonceSize)) == 1 {
		return nil, errors.New("decryption failed")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	ad := encodeTimestamp(enc.CreatedAt)
	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Data, ad)
	if err != nil {
		// Authentication failure — wrong key, tampered ciphertext, or tampered CreatedAt.
		return nil, errors.New("decryption failed")
	}

	// 4. Freshness check — runs after GCM so we only reach here for authentic ciphertexts.
	//    Prevents cross-restart replay: after a restart the in-process cache is empty,
	//    but an attacker cannot replay a 6-minute-old (authentic) ciphertext.
	if d.maxAge > 0 {
		nowT := d.now()
		nowSec := nowT.Unix()
		age := nowT.Sub(time.Unix(enc.CreatedAt, 0))
		if enc.CreatedAt <= 0 || age > d.maxAge {
			return nil, errors.New("decryption failed")
		}
		if enc.CreatedAt > nowSec+60 { // tolerate up to 1 minute of clock skew
			return nil, errors.New("decryption failed")
		}
	}

	// 5. In-process replay cache — AFTER crypto to equalise timing across all paths.
	cacheKey := string(enc.KEMCiphertext)
	d.mu.Lock()
	_, seen := d.seen[cacheKey]
	if !seen {
		d.seen[cacheKey] = struct{}{}
		d.seenSeq = append(d.seenSeq, cacheKey)
		// Evict oldest half when cache is full
		if len(d.seen) > seenCacheMax {
			evict := d.seenSeq[:seenCacheMax/2]
			for _, k := range evict {
				delete(d.seen, k)
			}
			d.seenSeq = d.seenSeq[seenCacheMax/2:]
		}
	}
	d.mu.Unlock()

	if seen {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// encodeTimestamp encodes a Unix timestamp as an 8-byte big-endian slice
// suitable for use as AES-GCM additional data (AD).
func encodeTimestamp(ts int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(ts))
	return b
}
