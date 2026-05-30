// Package slhdsa wraps the Trail of Bits SLH-DSA implementation.
// SLH-DSA is the NIST FIPS 205 stateless hash-based signature scheme — the
// third NIST-standardised post-quantum signature algorithm alongside ML-DSA
// (FIPS 204) and ML-KEM (FIPS 203).
//
// Security properties:
//   - Hash-based: security relies solely on the collision resistance of
//     SHA-256; no structured algebraic assumptions (contrast with ML-DSA's
//     lattice hardness).
//   - Conservative choice: even if lattice cryptanalysis advances, SLH-DSA
//     signatures remain valid as long as SHA-256 is not broken.
//   - Stateless: unlike XMSS/LMS, no signer state to manage or synchronise.
//
// Parameter set selection:
//
//	Level128f — SLH-DSA-SHA2-128f: NIST Category 1 (128-bit PQ), fast signing (sig ≈ 17 KB)
//	Level128s — SLH-DSA-SHA2-128s: NIST Category 1, small signatures       (sig ≈  7.9 KB)
//	Level192f — SLH-DSA-SHA2-192f: NIST Category 3 (192-bit PQ), fast signing (sig ≈ 35 KB)
//	Level192s — SLH-DSA-SHA2-192s: NIST Category 3, small signatures       (sig ≈ 16 KB)
//	Level256f — SLH-DSA-SHA2-256f: NIST Category 5 (256-bit PQ), fast signing (sig ≈ 49 KB)
//	Level256s — SLH-DSA-SHA2-256s: NIST Category 5, small signatures       (sig ≈ 29 KB)
//
// "f" (fast) variants produce larger signatures in exchange for faster signing.
// "s" (small) variants produce smaller signatures at the cost of slower signing.
// For server-side signing of transient messages the "f" variant is preferred.
// Choose "s" for long-term archive signatures or certificate chains where
// on-wire size is the bottleneck.
//
// All variants use SHA-2 for their internal hash function.
package slhdsa

import (
	"crypto/rand"
	"errors"
	"fmt"

	slh "github.com/trailofbits/go-slh-dsa/slh_dsa"
)

// Level identifies the SLH-DSA parameter set.
//
// Naming convention: Level<security-bits><variant>
//   - security bits: 128, 192, 256 → NIST categories 1/3/5
//   - variant: f = fast signing, larger signatures
//              s = small signatures, slower signing
type Level int

const (
	Level128f Level = iota // SLH-DSA-SHA2-128f — default: NIST Cat 1, fast
	Level128s              // SLH-DSA-SHA2-128s — NIST Cat 1, small
	Level192f              // SLH-DSA-SHA2-192f — NIST Cat 3, fast
	Level192s              // SLH-DSA-SHA2-192s — NIST Cat 3, small
	Level256f              // SLH-DSA-SHA2-256f — NIST Cat 5, fast
	Level256s              // SLH-DSA-SHA2-256s — NIST Cat 5, small
)

// paramSetName returns the string name accepted by slh.GetParamSet.
func paramSetName(level Level) (string, error) {
	switch level {
	case Level128f:
		return "SLH-DSA-SHA2-128f", nil
	case Level128s:
		return "SLH-DSA-SHA2-128s", nil
	case Level192f:
		return "SLH-DSA-SHA2-192f", nil
	case Level192s:
		return "SLH-DSA-SHA2-192s", nil
	case Level256f:
		return "SLH-DSA-SHA2-256f", nil
	case Level256s:
		return "SLH-DSA-SHA2-256s", nil
	}
	return "", fmt.Errorf("slhdsa: unsupported level %d", level)
}

// AlgorithmName returns the FIPS 205 canonical parameter set name.
func (l Level) AlgorithmName() string {
	name, err := paramSetName(l)
	if err != nil {
		return "unknown"
	}
	return name
}

// ParseLevel converts an API-level string to a Level constant.
//
// Accepted values:
//
//	""    or "128f" → Level128f (default)
//	"128s"          → Level128s
//	"192f"          → Level192f
//	"192s"          → Level192s
//	"256f"          → Level256f
//	"256s"          → Level256s
func ParseLevel(s string) (Level, error) {
	switch s {
	case "", "128f":
		return Level128f, nil
	case "128s":
		return Level128s, nil
	case "192f":
		return Level192f, nil
	case "192s":
		return Level192s, nil
	case "256f":
		return Level256f, nil
	case "256s":
		return Level256s, nil
	}
	return Level128f, fmt.Errorf("slhdsa: unknown level %q (accepted: 128f|128s|192f|192s|256f|256s)", s)
}

// PrivateKey holds an SLH-DSA signing key.
type PrivateKey struct {
	level Level
	name  string // FIPS 205 parameter set name
	sk    slh.SecretKey
}

// PublicKey holds an SLH-DSA verification key.
type PublicKey struct {
	level Level
	name  string
	pk    slh.PublicKey
}

// Level returns the parameter set used for this key.
func (sk *PrivateKey) Level() Level { return sk.level }

// Level returns the parameter set used for this key.
func (pk *PublicKey) Level() Level { return pk.level }

// Bytes serialises the private key to its FIPS 205 binary representation.
func (sk *PrivateKey) Bytes() []byte { return sk.sk.Bytes() }

// Bytes serialises the public key to its FIPS 205 binary representation.
func (pk *PublicKey) Bytes() []byte { return pk.pk.Bytes() }

// Public derives the public key from the private key.
func (sk *PrivateKey) Public() *PublicKey {
	p := sk.sk.Public()
	pub, ok := p.(*slh.PublicKey)
	if !ok {
		panic("slhdsa: unexpected type from SecretKey.Public()")
	}
	return &PublicKey{level: sk.level, name: sk.name, pk: *pub}
}

// GenerateKey generates a fresh SLH-DSA keypair using crypto/rand.
//
// Keygen is fast across all parameter sets (microseconds).
func GenerateKey(level Level) (*PublicKey, *PrivateKey, error) {
	name, err := paramSetName(level)
	if err != nil {
		return nil, nil, err
	}
	params, err := slh.GetParamSet(name)
	if err != nil {
		return nil, nil, fmt.Errorf("slhdsa.GenerateKey: %w", err)
	}
	sk, pk, err := slh.SLHKeygen(params)
	if err != nil {
		return nil, nil, fmt.Errorf("slhdsa.GenerateKey(%s): %w", name, err)
	}
	return &PublicKey{level: level, name: name, pk: pk},
		&PrivateKey{level: level, name: name, sk: sk},
		nil
}

// Sign signs msg using the hedged (randomized) variant of SLH-DSA signing.
//
// Randomised signing is preferred over the deterministic variant because
// it eliminates catastrophic failures under fault-injection attacks on
// the signer side-channel.
//
// Approximate signing cost (single core):
//
//	Level128f: ~1 ms    Level128s: ~20 ms
//	Level192f: ~3 ms    Level192s: ~50 ms
//	Level256f: ~6 ms    Level256s: ~100 ms
func Sign(sk *PrivateKey, msg []byte) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("slhdsa.Sign: nil private key")
	}
	// Pass crypto/rand.Reader explicitly — SLHSign panics on nil rand.
	sig, err := slh.SLHSign(rand.Reader, msg, nil, sk.sk)
	if err != nil {
		return nil, fmt.Errorf("slhdsa.Sign: %w", err)
	}
	return sig.Bytes(), nil
}

// Verify verifies a signature. Returns true iff the signature is valid.
//
// Verification is fast across all parameter sets (~few ms).
func Verify(pk *PublicKey, msg, sigBytes []byte) bool {
	if pk == nil || len(sigBytes) == 0 {
		return false
	}
	params, err := slh.GetParamSet(pk.name)
	if err != nil {
		return false
	}
	sig, err := slh.LoadSignature(params, sigBytes)
	if err != nil {
		return false
	}
	return slh.SLHVerify(msg, sig, nil, pk.pk)
}

// ParsePrivateKey deserialises a private key from its FIPS 205 binary form.
func ParsePrivateKey(level Level, b []byte) (*PrivateKey, error) {
	name, err := paramSetName(level)
	if err != nil {
		return nil, err
	}
	params, err := slh.GetParamSet(name)
	if err != nil {
		return nil, fmt.Errorf("slhdsa.ParsePrivateKey: %w", err)
	}
	sk, err := slh.LoadSecretKey(params, b)
	if err != nil {
		return nil, fmt.Errorf("slhdsa.ParsePrivateKey: %w", err)
	}
	return &PrivateKey{level: level, name: name, sk: sk}, nil
}

// ParsePublicKey deserialises a public key from its FIPS 205 binary form.
func ParsePublicKey(level Level, b []byte) (*PublicKey, error) {
	name, err := paramSetName(level)
	if err != nil {
		return nil, err
	}
	params, err := slh.GetParamSet(name)
	if err != nil {
		return nil, fmt.Errorf("slhdsa.ParsePublicKey: %w", err)
	}
	pk, err := slh.LoadPublicKey(params, b)
	if err != nil {
		return nil, fmt.Errorf("slhdsa.ParsePublicKey: %w", err)
	}
	return &PublicKey{level: level, name: name, pk: pk}, nil
}
