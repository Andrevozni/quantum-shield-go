// Package threshold implements M-of-N threshold signing using ML-DSA-65.
//
// # Model
//
// Each of N signers holds their own ML-DSA-65 keypair. A message is
// considered authorised only when at least M signers provide a valid signature.
// This is NOT a threshold signature scheme in the cryptographic sense (no
// key-splitting or aggregation); instead it is a multi-signature committee:
//
//   - Each signer signs independently.
//   - A Coordinator collects partial signatures and verifies them.
//   - The final AuthorisedSignature bundles M verified (sig, pubkey) pairs.
//   - Any verifier can re-verify the bundle with just the public keys.
//
// # Use cases
//
//   - Multi-party approval: EUR > 500,000 transfers require 3-of-5 directors
//   - Key ceremonies: root CA key generation requires 4-of-7 custodians
//   - Governance actions: smart contract upgrades require M-of-N council
package threshold

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Signer holds one participant's ML-DSA-65 keypair.
type Signer struct {
	id string
	pk *dsa.PublicKey
	sk *dsa.PrivateKey
}

// PartialSignature is one signer's contribution to a threshold signature.
type PartialSignature struct {
	SignerID  string
	PublicKey []byte // ML-DSA-65 pk bytes
	Signature []byte // ML-DSA-65 sig over bindingHash(nonce, msg)
	Nonce     []byte // 32-byte random (prevents cross-round replay)
}

// AuthorisedSignature is the final output of a completed threshold round.
// It bundles M verified (sig, pk) pairs and the original message digest.
type AuthorisedSignature struct {
	Threshold int
	MsgDigest []byte             // SHA-256(msg)
	Nonce     []byte             // round nonce (same for all partials)
	Partials  []PartialSignature // exactly Threshold valid signatures
}

// ── Signer ────────────────────────────────────────────────────────────────────

// NewSigner creates a Signer with a fresh ML-DSA-65 keypair.
func NewSigner(id string) (*Signer, error) {
	if id == "" {
		return nil, errors.New("threshold: signer id must not be empty")
	}
	pk, sk, err := dsa.GenerateKey(dsa.Level65)
	if err != nil {
		return nil, fmt.Errorf("threshold: keygen for %q: %w", id, err)
	}
	return &Signer{id: id, pk: pk, sk: sk}, nil
}

// ParseSigner recreates a Signer from serialised key bytes.
func ParseSigner(id string, pkBytes, skBytes []byte) (*Signer, error) {
	pk, err := dsa.ParsePublicKey(dsa.Level65, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("threshold: parse pk for %q: %w", id, err)
	}
	sk, err := dsa.ParsePrivateKey(dsa.Level65, skBytes)
	if err != nil {
		return nil, fmt.Errorf("threshold: parse sk for %q: %w", id, err)
	}
	return &Signer{id: id, pk: pk, sk: sk}, nil
}

// ID returns the signer's identifier.
func (s *Signer) ID() string { return s.id }

// PublicKeyBytes returns the serialised ML-DSA-65 public key.
func (s *Signer) PublicKeyBytes() ([]byte, error) { return s.pk.Bytes() }

// Sign produces a PartialSignature for msg using the provided round nonce.
// All signers in a round must use the same nonce (distributed by Coordinator).
func (s *Signer) Sign(msg, nonce []byte) (*PartialSignature, error) {
	if len(msg) == 0 {
		return nil, errors.New("threshold: message must not be empty")
	}
	if len(nonce) != 32 {
		return nil, errors.New("threshold: nonce must be 32 bytes")
	}

	pkBytes, err := s.pk.Bytes()
	if err != nil {
		return nil, fmt.Errorf("threshold: marshal pk: %w", err)
	}

	// Sign the binding hash: prevents cross-round and cross-message substitution.
	bh := bindingHash(nonce, msg)
	sig, err := dsa.Sign(s.sk, bh)
	if err != nil {
		return nil, fmt.Errorf("threshold: sign: %w", err)
	}

	return &PartialSignature{
		SignerID:  s.id,
		PublicKey: pkBytes,
		Signature: sig,
		Nonce:     nonce,
	}, nil
}

// ── Coordinator ───────────────────────────────────────────────────────────────

// Coordinator collects partial signatures and assembles the final bundle.
// A Coordinator is single-use per round.
type Coordinator struct {
	mu        sync.Mutex
	msg       []byte
	nonce     []byte
	threshold int
	partials  []PartialSignature
	done      bool
	authorised *AuthorisedSignature
}

// NewCoordinator starts a new signing round.
// threshold is the minimum number of valid signatures required.
// nonce is a 32-byte random value distributed to all signers; use NewNonce() to generate.
func NewCoordinator(msg []byte, nonce []byte, threshold int) (*Coordinator, error) {
	if len(msg) == 0 {
		return nil, errors.New("threshold: message must not be empty")
	}
	if len(nonce) != 32 {
		return nil, errors.New("threshold: nonce must be 32 bytes")
	}
	if threshold < 1 {
		return nil, errors.New("threshold: threshold must be ≥ 1")
	}
	return &Coordinator{
		msg:       msg,
		nonce:     nonce,
		threshold: threshold,
	}, nil
}

// Submit adds a partial signature to the round.
// Returns (true, *AuthorisedSignature) when the threshold is reached.
// Returns an error if the partial signature is invalid or the nonce mismatches.
func (c *Coordinator) Submit(p *PartialSignature) (bool, *AuthorisedSignature, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.done {
		return true, c.authorised, nil
	}

	// Verify nonce matches
	if subtle.ConstantTimeCompare(p.Nonce, c.nonce) != 1 {
		return false, nil, fmt.Errorf("threshold: nonce mismatch from signer %q", p.SignerID)
	}

	// Prevent duplicate signer submissions
	for _, existing := range c.partials {
		if existing.SignerID == p.SignerID {
			return false, nil, fmt.Errorf("threshold: duplicate submission from signer %q", p.SignerID)
		}
	}

	// Verify the partial signature
	pk, err := dsa.ParsePublicKey(dsa.Level65, p.PublicKey)
	if err != nil {
		return false, nil, fmt.Errorf("threshold: invalid public key from %q: %w", p.SignerID, err)
	}
	bh := bindingHash(c.nonce, c.msg)
	if !dsa.Verify(pk, bh, p.Signature) {
		return false, nil, fmt.Errorf("threshold: invalid signature from signer %q", p.SignerID)
	}

	c.partials = append(c.partials, *p)

	if len(c.partials) >= c.threshold {
		digest := sha256.Sum256(c.msg)
		c.authorised = &AuthorisedSignature{
			Threshold: c.threshold,
			MsgDigest: digest[:],
			Nonce:     c.nonce,
			Partials:  c.partials[:c.threshold],
		}
		c.done = true
		return true, c.authorised, nil
	}
	return false, nil, nil
}

// Count returns the number of valid partial signatures collected so far.
func (c *Coordinator) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.partials)
}

// ── Verification ──────────────────────────────────────────────────────────────

// Verify checks an AuthorisedSignature against a message and a set of trusted public keys.
//
//   - msg: the original message
//   - trusted: map[signerID]pkBytes of all authorised signers (the "registry")
//   - All partials must appear in trusted and all signatures must be valid.
func Verify(msg []byte, auth *AuthorisedSignature, trusted map[string][]byte) error {
	if auth == nil {
		return errors.New("threshold: nil AuthorisedSignature")
	}
	if len(auth.Partials) < auth.Threshold {
		return fmt.Errorf("threshold: only %d partials, need %d",
			len(auth.Partials), auth.Threshold)
	}

	// Verify message digest
	digest := sha256.Sum256(msg)
	if subtle.ConstantTimeCompare(digest[:], auth.MsgDigest) != 1 {
		return errors.New("threshold: message digest mismatch")
	}

	seen := map[string]struct{}{}
	for _, p := range auth.Partials {
		// Must be in trusted registry
		trustedPKBytes, ok := trusted[p.SignerID]
		if !ok {
			return fmt.Errorf("threshold: signer %q not in trusted registry", p.SignerID)
		}
		// Public key in partial must match registry
		if subtle.ConstantTimeCompare(trustedPKBytes, p.PublicKey) != 1 {
			return fmt.Errorf("threshold: public key mismatch for signer %q", p.SignerID)
		}
		// No duplicate signer in bundle
		if _, dup := seen[p.SignerID]; dup {
			return fmt.Errorf("threshold: duplicate signer %q in bundle", p.SignerID)
		}
		seen[p.SignerID] = struct{}{}

		// Verify nonce matches
		if subtle.ConstantTimeCompare(p.Nonce, auth.Nonce) != 1 {
			return fmt.Errorf("threshold: nonce mismatch for signer %q", p.SignerID)
		}

		// Re-verify signature
		pk, err := dsa.ParsePublicKey(dsa.Level65, p.PublicKey)
		if err != nil {
			return fmt.Errorf("threshold: parse pk for %q: %w", p.SignerID, err)
		}
		bh := bindingHash(auth.Nonce, msg)
		if !dsa.Verify(pk, bh, p.Signature) {
			return fmt.Errorf("threshold: invalid signature for signer %q", p.SignerID)
		}
	}
	return nil
}

// ── Utilities ─────────────────────────────────────────────────────────────────

// NewNonce generates a 32-byte cryptographic random nonce for a signing round.
func NewNonce() ([]byte, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// RoundID returns a hex string identifying a round (for logging/audit).
func RoundID(nonce []byte) string {
	h := sha256.Sum256(nonce)
	return hex.EncodeToString(h[:8])
}

// bindingHash prevents cross-round and cross-message substitution.
// bh = SHA-256("qs-threshold-v1" || nonce || SHA-256(msg))
func bindingHash(nonce, msg []byte) []byte {
	msgDigest := sha256.Sum256(msg)
	h := sha256.New()
	h.Write([]byte("qs-threshold-v1:"))
	h.Write(nonce)
	h.Write(msgDigest[:])
	return h.Sum(nil)
}

// ── Serialisation helpers ─────────────────────────────────────────────────────

// AuthorisedSignatureToMap converts an AuthorisedSignature to a map for JSON marshalling.
func AuthorisedSignatureToMap(a *AuthorisedSignature) map[string]any {
	partials := make([]map[string]string, len(a.Partials))
	for i, p := range a.Partials {
		partials[i] = map[string]string{
			"signer_id":  p.SignerID,
			"public_key": base64.StdEncoding.EncodeToString(p.PublicKey),
			"signature":  base64.StdEncoding.EncodeToString(p.Signature),
			"nonce":      base64.StdEncoding.EncodeToString(p.Nonce),
		}
	}
	return map[string]any{
		"threshold":  a.Threshold,
		"msg_digest": base64.StdEncoding.EncodeToString(a.MsgDigest),
		"nonce":      base64.StdEncoding.EncodeToString(a.Nonce),
		"partials":   partials,
	}
}
