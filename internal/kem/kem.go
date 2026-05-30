// Package kem wraps Go 1.24 stdlib crypto/mlkem (NIST FIPS 203).
//
// Available parameter sets: ML-KEM-768 (default) and ML-KEM-1024.
// ML-KEM-512 is not in the Go 1.24 stdlib; use Level768 for most applications.
//
// Randomness: crypto/rand via the stdlib GenerateKey* functions.
// Constant-time: guaranteed by the Go team for Decapsulate per FIPS 203 §6.4
// (implicit rejection — always returns pseudorandom key on bad input).
package kem

import (
	"crypto/mlkem"
	"errors"
	"fmt"
)

// Level selects the ML-KEM parameter set.
type Level int

const (
	Level768  Level = 768  // NIST security category 3 — default
	Level1024 Level = 1024 // NIST security category 5 — government, defence
)

// String returns the canonical NIST algorithm name for the level.
func (l Level) String() string {
	switch l {
	case Level1024:
		return "ML-KEM-1024"
	default:
		return "ML-KEM-768"
	}
}

// EncapsulationKey is the public key (used to encrypt / encapsulate).
type EncapsulationKey struct {
	level Level
	k768  *mlkem.EncapsulationKey768
	k1024 *mlkem.EncapsulationKey1024
}

// DecapsulationKey is the private key (used to decrypt / decapsulate).
type DecapsulationKey struct {
	level Level
	k768  *mlkem.DecapsulationKey768
	k1024 *mlkem.DecapsulationKey1024
}

// Bytes returns the serialised encapsulation key (public key bytes).
func (ek *EncapsulationKey) Bytes() []byte {
	switch ek.level {
	case Level768:
		return ek.k768.Bytes()
	case Level1024:
		return ek.k1024.Bytes()
	}
	panic("kem: invalid level")
}

// Bytes returns the seed bytes of the decapsulation key.
// These 64 bytes are sufficient to reconstruct the full key via ParseDecapsulationKey.
func (dk *DecapsulationKey) Bytes() []byte {
	switch dk.level {
	case Level768:
		return dk.k768.Bytes()
	case Level1024:
		return dk.k1024.Bytes()
	}
	panic("kem: invalid level")
}

// Level returns the parameter set.
func (ek *EncapsulationKey) Level() Level { return ek.level }
func (dk *DecapsulationKey) Level() Level { return dk.level }

// EncapsulationKey returns the corresponding public key.
func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	ek := &EncapsulationKey{level: dk.level}
	switch dk.level {
	case Level768:
		ek.k768 = dk.k768.EncapsulationKey()
	case Level1024:
		ek.k1024 = dk.k1024.EncapsulationKey()
	}
	return ek
}

// GenerateKey generates a fresh ML-KEM keypair.
// Randomness: crypto/rand (OS CSPRNG — BCryptGenRandom on Windows, getrandom on Linux).
func GenerateKey(level Level) (*DecapsulationKey, error) {
	dk := &DecapsulationKey{level: level}
	var err error
	switch level {
	case Level768:
		dk.k768, err = mlkem.GenerateKey768()
	case Level1024:
		dk.k1024, err = mlkem.GenerateKey1024()
	default:
		return nil, fmt.Errorf("kem.GenerateKey: unsupported level %d (use 768 or 1024)", level)
	}
	if err != nil {
		return nil, fmt.Errorf("kem.GenerateKey%d: %w", level, err)
	}
	return dk, nil
}

// Encapsulate produces a shared secret and a ciphertext from a public key.
// Returns: sharedSecret (32 bytes), ciphertext.
// Randomness: crypto/rand inside stdlib.
func Encapsulate(ek *EncapsulationKey) (sharedSecret, ciphertext []byte, err error) {
	if ek == nil {
		return nil, nil, errors.New("kem.Encapsulate: nil encapsulation key")
	}
	switch ek.level {
	case Level768:
		ss, ct := ek.k768.Encapsulate() // returns (sharedKey, ciphertext)
		return ss, ct, nil
	case Level1024:
		ss, ct := ek.k1024.Encapsulate()
		return ss, ct, nil
	}
	return nil, nil, errors.New("kem.Encapsulate: nil key")
}

// Decapsulate recovers the shared secret from a ciphertext.
// Constant-time: the stdlib always returns a pseudorandom key on bad input
// (FIPS 203 implicit rejection) — no timing or error oracle is possible.
// The returned error message is always generic.
func Decapsulate(dk *DecapsulationKey, ciphertext []byte) (sharedSecret []byte, err error) {
	if dk == nil {
		return nil, errors.New("decapsulation failed")
	}
	switch dk.level {
	case Level768:
		ss, err := dk.k768.Decapsulate(ciphertext)
		if err != nil {
			return nil, errors.New("decapsulation failed")
		}
		return ss, nil
	case Level1024:
		ss, err := dk.k1024.Decapsulate(ciphertext)
		if err != nil {
			return nil, errors.New("decapsulation failed")
		}
		return ss, nil
	}
	return nil, errors.New("decapsulation failed")
}

// ParseEncapsulationKey deserialises a public key from its byte representation.
func ParseEncapsulationKey(level Level, b []byte) (*EncapsulationKey, error) {
	ek := &EncapsulationKey{level: level}
	var err error
	switch level {
	case Level768:
		ek.k768, err = mlkem.NewEncapsulationKey768(b)
	case Level1024:
		ek.k1024, err = mlkem.NewEncapsulationKey1024(b)
	default:
		return nil, fmt.Errorf("kem.ParseEncapsulationKey: unsupported level %d", level)
	}
	if err != nil {
		return nil, fmt.Errorf("kem.ParseEncapsulationKey: %w", err)
	}
	return ek, nil
}

// ParseDecapsulationKey reconstructs a private key from the seed bytes
// returned by DecapsulationKey.Bytes().
func ParseDecapsulationKey(level Level, seed []byte) (*DecapsulationKey, error) {
	dk := &DecapsulationKey{level: level}
	var err error
	switch level {
	case Level768:
		dk.k768, err = mlkem.NewDecapsulationKey768(seed)
	case Level1024:
		dk.k1024, err = mlkem.NewDecapsulationKey1024(seed)
	default:
		return nil, fmt.Errorf("kem.ParseDecapsulationKey: unsupported level %d", level)
	}
	if err != nil {
		return nil, fmt.Errorf("kem.ParseDecapsulationKey: %w", err)
	}
	return dk, nil
}
