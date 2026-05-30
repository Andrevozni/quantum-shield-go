// Package fips provides runtime compliance probes for the NIST post-quantum
// algorithms used by QuantumShield.
//
// None of this constitutes a formal FIPS 140-3 validation.  The checks
// verify that each algorithm implementation is:
//   - importable and linked into the binary
//   - able to generate keys
//   - able to complete a round-trip (sign+verify or encapsulate+decapsulate)
//
// Run Check() at startup or via GET /health/fips to confirm that all
// required primitives are operational before serving production traffic.
package fips

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
	"github.com/quantum-shield/quantum-shield-go/internal/kem"
	"github.com/quantum-shield/quantum-shield-go/internal/slhdsa"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Status represents the outcome of a single algorithm probe.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
)

// AlgorithmProbe is the result of one algorithm compliance probe.
type AlgorithmProbe struct {
	Algorithm string    `json:"algorithm"`
	Standard  string    `json:"standard"`   // e.g. "NIST FIPS 203"
	Status    Status    `json:"status"`
	Error     string    `json:"error,omitempty"`
	DurationMs float64  `json:"duration_ms"`
}

// Report is the full FIPS compliance report returned by Check.
type Report struct {
	Overall   Status           `json:"overall"`   // "pass" if all probes pass, else "fail"
	Timestamp time.Time        `json:"timestamp"`
	GoVersion string           `json:"go_version"`
	Probes    []AlgorithmProbe `json:"probes"`
}

// Check runs compliance probes for every algorithm used by QuantumShield.
// It never panics — any failure is captured as a StatusFail probe entry.
func Check() Report {
	probes := []AlgorithmProbe{
		probe("ML-KEM-768",         "NIST FIPS 203", checkMLKEM768),
		probe("ML-KEM-1024",        "NIST FIPS 203", checkMLKEM1024),
		probe("ML-DSA-44",          "NIST FIPS 204", func() error { return checkMLDSA(dsa.Level44) }),
		probe("ML-DSA-65",          "NIST FIPS 204", func() error { return checkMLDSA(dsa.Level65) }),
		probe("ML-DSA-87",          "NIST FIPS 204", func() error { return checkMLDSA(dsa.Level87) }),
		probe("SLH-DSA-SHA2-128f",  "NIST FIPS 205", func() error { return checkSLHDSA(slhdsa.Level128f) }),
		probe("SLH-DSA-SHA2-256f",  "NIST FIPS 205", func() error { return checkSLHDSA(slhdsa.Level256f) }),
		probe("AES-256-GCM",        "NIST SP 800-38D", checkAES256GCM),
		probe("HKDF-SHA256",        "RFC 5869",       checkHKDF),
		probe("Argon2id",           "RFC 9106",       checkArgon2id),
		probe("CSPRNG",             "NIST SP 800-90A", checkCSPRNG),
	}

	overall := StatusPass
	for _, p := range probes {
		if p.Status == StatusFail {
			overall = StatusFail
		}
	}
	return Report{
		Overall:   overall,
		Timestamp: time.Now().UTC(),
		GoVersion: runtime.Version(),
		Probes:    probes,
	}
}

// probe runs f, captures panics, and returns a timed AlgorithmProbe.
func probe(algorithm, standard string, f func() error) (result AlgorithmProbe) {
	result.Algorithm = algorithm
	result.Standard = standard
	defer func() {
		if r := recover(); r != nil {
			result.Status = StatusFail
			result.Error = fmt.Sprintf("panic: %v", r)
		}
	}()

	start := time.Now()
	err := f()
	result.DurationMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		result.Status = StatusFail
		result.Error = err.Error()
	} else {
		result.Status = StatusPass
	}
	return result
}

// ── Algorithm probes ──────────────────────────────────────────────────────────

func checkMLKEM768() error {
	return checkMLKEM(kem.Level768)
}

func checkMLKEM1024() error {
	return checkMLKEM(kem.Level1024)
}

func checkMLKEM(level kem.Level) error {
	dk, err := kem.GenerateKey(level)
	if err != nil {
		return fmt.Errorf("GenerateKey(%v): %w", level, err)
	}
	ek := dk.EncapsulationKey()
	sharedKey, ct, err := kem.Encapsulate(ek)
	if err != nil {
		return fmt.Errorf("Encapsulate: %w", err)
	}
	sharedKey2, err := kem.Decapsulate(dk, ct)
	if err != nil {
		return fmt.Errorf("Decapsulate: %w", err)
	}
	if !bytes.Equal(sharedKey, sharedKey2) {
		return fmt.Errorf("ML-KEM-%v shared key mismatch after encapsulate/decapsulate", level)
	}
	return nil
}

func checkMLDSA(level dsa.Level) error {
	pk, sk, err := dsa.GenerateKey(level)
	if err != nil {
		return fmt.Errorf("GenerateKey(%v): %w", level, err)
	}
	msg := []byte("fips-probe-message")
	sig, err := dsa.Sign(sk, msg)
	if err != nil {
		return fmt.Errorf("Sign: %w", err)
	}
	if !dsa.Verify(pk, msg, sig) {
		return fmt.Errorf("ML-DSA-%v signature verification failed", level)
	}
	// Ensure a tampered message fails.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0xFF
	if dsa.Verify(pk, tampered, sig) {
		return fmt.Errorf("ML-DSA-%v accepted tampered message", level)
	}
	return nil
}

func checkSLHDSA(level slhdsa.Level) error {
	pk, sk, err := slhdsa.GenerateKey(level)
	if err != nil {
		return fmt.Errorf("SLH-DSA GenerateKey: %w", err)
	}
	msg := []byte("fips-probe-slh-dsa")
	sig, err := slhdsa.Sign(sk, msg)
	if err != nil {
		return fmt.Errorf("SLH-DSA Sign: %w", err)
	}
	if !slhdsa.Verify(pk, msg, sig) {
		return fmt.Errorf("SLH-DSA signature verification failed")
	}
	return nil
}

func checkAES256GCM() error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("read random key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}
	plaintext := []byte("fips-probe-aes-gcm")
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("GCM Open: %w", err)
	}
	if !bytes.Equal(plaintext, pt) {
		return fmt.Errorf("AES-256-GCM plaintext mismatch after decrypt")
	}
	return nil
}

func checkHKDF() error {
	secret := []byte("fips-probe-hkdf-secret")
	salt   := []byte("fips-probe-hkdf-salt")
	info   := []byte("fips-probe-hkdf-info")

	h := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return fmt.Errorf("HKDF Expand: %w", err)
	}
	// Deterministic — derive again and verify equality.
	h2 := hkdf.New(sha256.New, secret, salt, info)
	key2 := make([]byte, 32)
	io.ReadFull(h2, key2) //nolint:errcheck — same inputs, same HKDF stream
	if !hmac.Equal(key, key2) {
		return fmt.Errorf("HKDF is not deterministic")
	}
	if bytes.Equal(key, make([]byte, 32)) {
		return fmt.Errorf("HKDF produced all-zero output")
	}
	return nil
}

func checkArgon2id() error {
	password := []byte("fips-probe-argon2id-password")
	salt     := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("read salt: %w", err)
	}
	// Minimal parameters — just verify the function is wired and produces output.
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	if len(key) != 32 {
		return fmt.Errorf("Argon2id output length %d (want 32)", len(key))
	}
	if bytes.Equal(key, make([]byte, 32)) {
		return fmt.Errorf("Argon2id produced all-zero output")
	}
	return nil
}

func checkCSPRNG() error {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Errorf("crypto/rand.Read: %w", err)
	}
	// Sanity: not all zeros (probability 2^-256).
	if bytes.Equal(buf, make([]byte, 32)) {
		return fmt.Errorf("CSPRNG produced all-zero output")
	}
	return nil
}
