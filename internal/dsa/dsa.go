// Package dsa wraps ML-DSA (CRYSTALS-Dilithium) from cloudflare/circl.
// ML-DSA is the NIST FIPS 204 post-quantum signature scheme.
//
// Randomness: GenerateKey uses crypto/rand via circl.
// Signing: deterministic per FIPS 204 (no per-signature randomness needed).
package dsa

import (
	"errors"
	"fmt"

	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Level selects the ML-DSA parameter set (NIST security categories 2/3/5).
type Level int

const (
	Level44 Level = 44 // Security category 2 — IoT, embedded
	Level65 Level = 65 // Security category 3 — default
	Level87 Level = 87 // Security category 5 — government, defence
)

func schemeFor(level Level) (circlsign.Scheme, error) {
	switch level {
	case Level44:
		return mldsa44.Scheme(), nil
	case Level65:
		return mldsa65.Scheme(), nil
	case Level87:
		return mldsa87.Scheme(), nil
	}
	return nil, fmt.Errorf("dsa: unsupported level %d", level)
}

// PrivateKey holds the ML-DSA signing key.
type PrivateKey struct {
	level Level
	sch   circlsign.Scheme
	sk    circlsign.PrivateKey
}

// PublicKey holds the ML-DSA verification key.
type PublicKey struct {
	level Level
	sch   circlsign.Scheme
	pk    circlsign.PublicKey
}

// Bytes serialises the private key.
func (sk *PrivateKey) Bytes() ([]byte, error) {
	return sk.sk.MarshalBinary()
}

// Bytes serialises the public key.
func (pk *PublicKey) Bytes() ([]byte, error) {
	return pk.pk.MarshalBinary()
}

// Level returns the parameter set.
func (sk *PrivateKey) Level() Level { return sk.level }
func (pk *PublicKey) Level() Level  { return pk.level }

// GenerateKey generates a fresh ML-DSA keypair using crypto/rand.
func GenerateKey(level Level) (*PublicKey, *PrivateKey, error) {
	sch, err := schemeFor(level)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := sch.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("dsa.GenerateKey(%d): %w", level, err)
	}
	return &PublicKey{level: level, sch: sch, pk: pub},
		&PrivateKey{level: level, sch: sch, sk: priv},
		nil
}

// Sign signs msg with the private key.
// Signing is deterministic (FIPS 204 §6).
func Sign(sk *PrivateKey, msg []byte) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("dsa.Sign: nil private key")
	}
	sig := sk.sch.Sign(sk.sk, msg, nil)
	return sig, nil
}

// Verify verifies a signature. Returns true iff valid.
func Verify(pk *PublicKey, msg, sig []byte) bool {
	if pk == nil || len(sig) == 0 {
		return false
	}
	return pk.sch.Verify(pk.pk, msg, sig, nil)
}

// ParsePrivateKey deserialises a private key from bytes.
func ParsePrivateKey(level Level, b []byte) (*PrivateKey, error) {
	sch, err := schemeFor(level)
	if err != nil {
		return nil, err
	}
	sk, err := sch.UnmarshalBinaryPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("dsa.ParsePrivateKey: %w", err)
	}
	return &PrivateKey{level: level, sch: sch, sk: sk}, nil
}

// ParsePublicKey deserialises a public key from bytes.
func ParsePublicKey(level Level, b []byte) (*PublicKey, error) {
	sch, err := schemeFor(level)
	if err != nil {
		return nil, err
	}
	pk, err := sch.UnmarshalBinaryPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("dsa.ParsePublicKey: %w", err)
	}
	return &PublicKey{level: level, sch: sch, pk: pk}, nil
}
