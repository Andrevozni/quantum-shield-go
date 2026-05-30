// Package ca implements a minimal post-quantum certificate authority.
//
// Certificates are JSON documents signed with ML-DSA-87 (NIST FIPS 204).
// The format avoids ASN.1 complexity while providing: serial number,
// subject/issuer binding, validity window, public-key embedding, and an
// ML-DSA-87 digital signature that covers all fields except "signature".
//
// # Certificate lifecycle
//
//  1. Init("CN=Root CA") → fresh ML-DSA-87 keypair + self-signed root cert.
//  2. Issue(subject, keyType, keyBytes, ttl) → signed leaf certificate.
//  3. IssueIntermediate(subject, ttl) → a subordinate CA signed by this CA.
//  4. Verify(cert) → checks time validity, ML-DSA-87 signature, and CRL.
//  5. Revoke(serial) → adds the serial to the in-memory CRL.
//  6. CRL() → returns the current revocation list.
//  7. VerifyChain(cert, chain, trustAnchor) → verifies a full certificate chain.
//
// # Wire format
//
// Certificates are JSON objects. All fields except "signature" are covered
// by the issuer's ML-DSA-87 signature. The signature is computed over the
// canonical JSON of those fields (Go's encoding/json — sorted keys, no
// trailing spaces). Consumers MUST NOT add or reorder fields before verifying.
package ca

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

const (
	schemeAlgorithm = "ML-DSA-87"
	defaultCATTL    = 10 * 365 * 24 * time.Hour // 10 years
	defaultLeafTTL  = 365 * 24 * time.Hour       // 1 year
)

// ── CRL types ─────────────────────────────────────────────────────────────────

// CRLEntry records a single revoked certificate.
type CRLEntry struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
}

// CRL is a snapshot of the Certificate Revocation List at a point in time.
type CRL struct {
	Version    int        `json:"version"`
	Issuer     string     `json:"issuer"`
	ThisUpdate time.Time  `json:"this_update"`
	Entries    []CRLEntry `json:"entries"` // sorted by serial
}

// ── Wire types ────────────────────────────────────────────────────────────────

// Certificate is a post-quantum certificate signed with ML-DSA-87.
//
// All fields except Signature are covered by the issuer's signature.
// To verify authenticity, use CA.Verify — do not inspect individual fields
// before the signature is confirmed.
type Certificate struct {
	Version       int       `json:"version"`
	Serial        string    `json:"serial"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	Algorithm     string    `json:"algorithm"`        // always "ML-DSA-87"
	PublicKey     string    `json:"public_key"`       // base64 — the subject's public key
	PublicKeyType string    `json:"public_key_type"`  // e.g. "ML-KEM-768", "ML-DSA-87"
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsCA          bool      `json:"is_ca"`
	Signature     string    `json:"signature,omitempty"` // base64 ML-DSA-87 sig over body
}

// signingBody is the subset of Certificate fields that are signed.
// It must exactly mirror the non-Signature fields of Certificate.
type signingBody struct {
	Version       int       `json:"version"`
	Serial        string    `json:"serial"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	Algorithm     string    `json:"algorithm"`
	PublicKey     string    `json:"public_key"`
	PublicKeyType string    `json:"public_key_type"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsCA          bool      `json:"is_ca"`
}

// signingBytes returns the canonical JSON encoding of all fields that are
// covered by the certificate's ML-DSA-87 signature (everything except
// "signature").  Verification must use the same encoding.
func (c *Certificate) signingBytes() ([]byte, error) {
	return json.Marshal(signingBody{
		Version:       c.Version,
		Serial:        c.Serial,
		Subject:       c.Subject,
		Issuer:        c.Issuer,
		Algorithm:     c.Algorithm,
		PublicKey:     c.PublicKey,
		PublicKeyType: c.PublicKeyType,
		NotBefore:     c.NotBefore,
		NotAfter:      c.NotAfter,
		IsCA:          c.IsCA,
	})
}

// ── CA ────────────────────────────────────────────────────────────────────────

// CA is a post-quantum certificate authority backed by an ML-DSA-87 keypair.
// It is safe for concurrent use from multiple goroutines.
type CA struct {
	pk   *dsa.PublicKey
	sk   *dsa.PrivateKey
	cert *Certificate

	// mu protects revoked.
	mu      sync.RWMutex
	revoked map[string]time.Time // serial → revocation time
}

// Init creates a new CA with a fresh ML-DSA-87 keypair and a self-signed root
// certificate.
//
// subject identifies the CA (e.g. "CN=QuantumShield Root CA,O=Example Corp").
// The CA certificate is valid for 10 years from the moment of creation.
func Init(subject string) (*CA, error) {
	if subject == "" {
		return nil, errors.New("ca.Init: subject must not be empty")
	}

	pk, sk, err := dsa.GenerateKey(dsa.Level87)
	if err != nil {
		return nil, fmt.Errorf("ca.Init: keygen: %w", err)
	}
	pkBytes, err := pk.Bytes()
	if err != nil {
		return nil, fmt.Errorf("ca.Init: marshal public key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca.Init: generate serial: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cert := &Certificate{
		Version:       1,
		Serial:        serial,
		Subject:       subject,
		Issuer:        subject, // self-signed
		Algorithm:     schemeAlgorithm,
		PublicKey:     base64.StdEncoding.EncodeToString(pkBytes),
		PublicKeyType: schemeAlgorithm,
		NotBefore:     now,
		NotAfter:      now.Add(defaultCATTL),
		IsCA:          true,
	}
	if err := attachSignature(cert, sk); err != nil {
		return nil, fmt.Errorf("ca.Init: sign root cert: %w", err)
	}
	return &CA{pk: pk, sk: sk, cert: cert, revoked: make(map[string]time.Time)}, nil
}

// Certificate returns the CA's self-signed root certificate.
// The returned pointer must not be modified.
func (ca *CA) Certificate() *Certificate { return ca.cert }

// Issue signs a new leaf certificate binding subject to the given public key.
//
//   - subject: human-readable name for the certificate holder.
//   - publicKeyType: algorithm of the subject's key (e.g. "ML-KEM-768", "ML-DSA-65").
//   - publicKeyBytes: raw bytes of the subject's public key (encoded as base64
//     in the certificate).
//   - ttl: certificate lifetime; ≤ 0 uses the default (1 year).
func (ca *CA) Issue(subject, publicKeyType string, publicKeyBytes []byte, ttl time.Duration) (*Certificate, error) {
	if subject == "" {
		return nil, errors.New("ca.Issue: subject must not be empty")
	}
	if publicKeyType == "" {
		return nil, errors.New("ca.Issue: publicKeyType must not be empty")
	}
	if len(publicKeyBytes) == 0 {
		return nil, errors.New("ca.Issue: publicKeyBytes must not be empty")
	}
	if ttl <= 0 {
		ttl = defaultLeafTTL
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca.Issue: generate serial: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cert := &Certificate{
		Version:       1,
		Serial:        serial,
		Subject:       subject,
		Issuer:        ca.cert.Subject,
		Algorithm:     schemeAlgorithm,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKeyBytes),
		PublicKeyType: publicKeyType,
		NotBefore:     now,
		NotAfter:      now.Add(ttl),
		IsCA:          false,
	}
	if err := attachSignature(cert, ca.sk); err != nil {
		return nil, fmt.Errorf("ca.Issue: sign cert: %w", err)
	}
	return cert, nil
}

// IssueIntermediate creates a new subordinate CA signed by this CA.
//
// The subordinate CA gets its own fresh ML-DSA-87 keypair and a CA certificate
// (IsCA=true) signed by the current CA's private key. The returned *CA can
// sign leaf certificates and further intermediate CAs. The returned
// *Certificate is the proof that this CA delegated authority; it should be
// included in the certificate chain presented to relying parties.
//
// ttl ≤ 0 uses the default (10 years).
func (ca *CA) IssueIntermediate(subject string, ttl time.Duration) (*CA, *Certificate, error) {
	if subject == "" {
		return nil, nil, errors.New("ca.IssueIntermediate: subject must not be empty")
	}
	if ttl <= 0 {
		ttl = defaultCATTL
	}

	// Generate a fresh keypair for the intermediate CA.
	subPK, subSK, err := dsa.GenerateKey(dsa.Level87)
	if err != nil {
		return nil, nil, fmt.Errorf("ca.IssueIntermediate: keygen: %w", err)
	}
	subPKBytes, err := subPK.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("ca.IssueIntermediate: marshal public key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("ca.IssueIntermediate: generate serial: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cert := &Certificate{
		Version:       1,
		Serial:        serial,
		Subject:       subject,
		Issuer:        ca.cert.Subject,
		Algorithm:     schemeAlgorithm,
		PublicKey:     base64.StdEncoding.EncodeToString(subPKBytes),
		PublicKeyType: schemeAlgorithm,
		NotBefore:     now,
		NotAfter:      now.Add(ttl),
		IsCA:          true, // intermediate is a CA
	}
	// Sign with the issuing CA's private key.
	if err := attachSignature(cert, ca.sk); err != nil {
		return nil, nil, fmt.Errorf("ca.IssueIntermediate: sign cert: %w", err)
	}

	subCA := &CA{pk: subPK, sk: subSK, cert: cert, revoked: make(map[string]time.Time)}
	return subCA, cert, nil
}

// VerifyChain verifies cert against an ordered chain of intermediate CA
// certificates and a self-signed trust anchor.
//
// chain is ordered from the direct issuer of cert (chain[0]) toward the
// issuer of the trust anchor (chain[len-1]).  If chain is empty, cert must
// have been signed directly by trustAnchor.
//
// Verification rules applied for each link:
//   - the signing certificate must have IsCA=true
//   - the issued certificate's Issuer must match the signing certificate's Subject
//   - the signing certificate's ML-DSA-87 public key must verify the issued
//     certificate's signature
//   - all certificates must be within their validity windows at the current time
//   - trustAnchor must be self-signed (Issuer == Subject)
//
// VerifyChain does NOT check CRLs — callers that need revocation checking
// should call CA.Verify instead of (or in addition to) VerifyChain.
func VerifyChain(cert *Certificate, chain []*Certificate, trustAnchor *Certificate) error {
	if cert == nil {
		return errors.New("ca.VerifyChain: cert must not be nil")
	}
	if trustAnchor == nil {
		return errors.New("ca.VerifyChain: trustAnchor must not be nil")
	}
	if trustAnchor.Issuer != trustAnchor.Subject {
		return fmt.Errorf("ca.VerifyChain: trust anchor is not self-signed (Issuer=%q Subject=%q)",
			trustAnchor.Issuer, trustAnchor.Subject)
	}
	if !trustAnchor.IsCA {
		return errors.New("ca.VerifyChain: trust anchor does not have IsCA=true")
	}
	for i, c := range chain {
		if c == nil {
			return fmt.Errorf("ca.VerifyChain: chain[%d] is nil", i)
		}
		if !c.IsCA {
			return fmt.Errorf("ca.VerifyChain: chain[%d] (subject=%q) does not have IsCA=true", i, c.Subject)
		}
	}

	// Build the ordered list of signers: trustAnchor signs chain[last], …,
	// chain[0] signs cert.
	// signerFor[i] signs certs[i].
	certs := make([]*Certificate, 0, 1+len(chain))
	certs = append(certs, cert)
	certs = append(certs, chain...)
	signers := make([]*Certificate, 0, 1+len(chain))
	signers = append(signers, chain...)
	signers = append(signers, trustAnchor)

	// Verify the trust anchor itself (self-signed).
	if err := verifySingleLink(trustAnchor, trustAnchor); err != nil {
		return fmt.Errorf("ca.VerifyChain: trust anchor self-signature invalid: %w", err)
	}

	// Walk the chain: certs[i] signed by signers[i].
	for i, issued := range certs {
		signer := signers[i]
		if err := verifySingleLink(issued, signer); err != nil {
			return fmt.Errorf("ca.VerifyChain: link %d (issued=%q, signer=%q): %w",
				i, issued.Subject, signer.Subject, err)
		}
	}
	return nil
}

// verifySingleLink checks that issued was signed by signer.
// It checks validity windows, issuer/subject binding, and the ML-DSA-87 signature.
func verifySingleLink(issued, signer *Certificate) error {
	now := time.Now().UTC()
	// Check issued validity.
	if now.Before(issued.NotBefore) {
		return fmt.Errorf("not yet valid (valid from %s)", issued.NotBefore.Format(time.RFC3339))
	}
	if now.After(issued.NotAfter) {
		return fmt.Errorf("expired at %s", issued.NotAfter.Format(time.RFC3339))
	}
	// Check signer validity.
	if now.Before(signer.NotBefore) {
		return fmt.Errorf("signer not yet valid (valid from %s)", signer.NotBefore.Format(time.RFC3339))
	}
	if now.After(signer.NotAfter) {
		return fmt.Errorf("signer expired at %s", signer.NotAfter.Format(time.RFC3339))
	}
	// Issuer/subject binding.
	if issued.Issuer != signer.Subject {
		return fmt.Errorf("issued.Issuer=%q does not match signer.Subject=%q",
			issued.Issuer, signer.Subject)
	}
	// Decode signer's public key.
	pkBytes, err := base64.StdEncoding.DecodeString(signer.PublicKey)
	if err != nil {
		return fmt.Errorf("decode signer public key: %w", err)
	}
	signerPK, err := dsa.ParsePublicKey(dsa.Level87, pkBytes)
	if err != nil {
		return fmt.Errorf("parse signer public key: %w", err)
	}
	// Decode issued's signature.
	sigBytes, err := base64.StdEncoding.DecodeString(issued.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	// Recompute signing bytes.
	msg, err := issued.signingBytes()
	if err != nil {
		return fmt.Errorf("build signing bytes: %w", err)
	}
	if !dsa.Verify(signerPK, msg, sigBytes) {
		return errors.New("ML-DSA-87 signature verification failed")
	}
	return nil
}

// Verify checks that cert was issued by this CA and is currently valid.
//
// It verifies:
//  1. The validity window (NotBefore ≤ now ≤ NotAfter).
//  2. That cert.Issuer matches this CA's subject.
//  3. The ML-DSA-87 signature with the CA's public key.
//  4. That the certificate serial is not on the revocation list (CRL).
func (ca *CA) Verify(cert *Certificate) error {
	if cert == nil {
		return errors.New("ca.Verify: nil certificate")
	}
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("ca.Verify: certificate not yet valid (valid from %s)",
			cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("ca.Verify: certificate expired at %s",
			cert.NotAfter.Format(time.RFC3339))
	}
	// End-entity certificates must not have the CA flag set.
	// Accepting CA certificates (is_ca:true) as leaf certs violates PKI
	// semantics and allows CA cert holders to impersonate any leaf entity.
	if cert.IsCA {
		return errors.New("ca.Verify: certificate has is_ca=true — CA certificates cannot be used as end-entity certificates")
	}
	if cert.Issuer != ca.cert.Subject {
		return fmt.Errorf("ca.Verify: issuer %q does not match CA subject %q",
			cert.Issuer, ca.cert.Subject)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return fmt.Errorf("ca.Verify: decode signature: %w", err)
	}
	msg, err := cert.signingBytes()
	if err != nil {
		return fmt.Errorf("ca.Verify: build signing bytes: %w", err)
	}
	if !dsa.Verify(ca.pk, msg, sigBytes) {
		return errors.New("ca.Verify: signature verification failed")
	}
	// CRL check — after signature verification so the serial is trustworthy.
	ca.mu.RLock()
	revokedAt, isRevoked := ca.revoked[cert.Serial]
	ca.mu.RUnlock()
	if isRevoked {
		return fmt.Errorf("ca.Verify: certificate %s was revoked at %s",
			cert.Serial, revokedAt.Format(time.RFC3339))
	}
	return nil
}

// Revoke adds the given serial number to the CA's in-memory revocation list.
// Subsequent calls to Verify for a certificate with this serial will fail.
//
// serial must be a non-empty string.  Revoking an already-revoked serial is
// a no-op (returns nil).
func (ca *CA) Revoke(serial string) error {
	// Reject empty, whitespace-only, or control-character serials.
	// These can never match a real cert serial and would pollute the CRL.
	trimmed := strings.TrimSpace(serial)
	if trimmed == "" {
		return errors.New("ca.Revoke: serial must not be empty or whitespace-only")
	}
	// Use the trimmed form as the canonical serial for CRL storage.
	serial = trimmed
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if _, already := ca.revoked[serial]; !already {
		ca.revoked[serial] = time.Now().UTC()
	}
	return nil
}

// IsRevoked reports whether the given serial number appears on the CRL.
func (ca *CA) IsRevoked(serial string) bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	_, ok := ca.revoked[serial]
	return ok
}

// CRL returns a snapshot of the current revocation list, sorted by serial.
// The returned value is a copy — safe to read after the call returns.
func (ca *CA) CRL() CRL {
	ca.mu.RLock()
	entries := make([]CRLEntry, 0, len(ca.revoked))
	for serial, revokedAt := range ca.revoked {
		entries = append(entries, CRLEntry{Serial: serial, RevokedAt: revokedAt})
	}
	ca.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial < entries[j].Serial
	})
	return CRL{
		Version:    1,
		Issuer:     ca.cert.Subject,
		ThisUpdate: time.Now().UTC(),
		Entries:    entries,
	}
}

// ── Snapshot — serialisation for persistence ──────────────────────────────────

// Snapshot is a portable, JSON-serialisable representation of a CA's full state.
// It contains the private key bytes — store it only in encrypted form.
type Snapshot struct {
	Version     int                  `json:"version"`
	Certificate *Certificate         `json:"certificate"`
	PrivKey     string               `json:"priv_key"` // base64 ML-DSA-87 private key
	Revoked     map[string]time.Time `json:"revoked"`  // serial → revocation time
}

// Export serialises the CA's full state into a Snapshot.
// The returned Snapshot contains the private key — callers MUST encrypt it
// before writing to disk.
func (ca *CA) Export() (Snapshot, error) {
	skBytes, err := ca.sk.Bytes()
	if err != nil {
		return Snapshot{}, fmt.Errorf("ca.Export: marshal private key: %w", err)
	}
	ca.mu.RLock()
	revoked := make(map[string]time.Time, len(ca.revoked))
	for k, v := range ca.revoked {
		revoked[k] = v
	}
	ca.mu.RUnlock()
	return Snapshot{
		Version:     1,
		Certificate: ca.cert,
		PrivKey:     base64.StdEncoding.EncodeToString(skBytes),
		Revoked:     revoked,
	}, nil
}

// Restore reconstructs a CA from a Snapshot produced by Export.
// The restored CA can sign and verify certificates exactly as the original.
func Restore(snap Snapshot) (*CA, error) {
	if snap.Certificate == nil {
		return nil, errors.New("ca.Restore: nil certificate in snapshot")
	}
	if snap.PrivKey == "" {
		return nil, errors.New("ca.Restore: empty priv_key in snapshot")
	}
	skBytes, err := base64.StdEncoding.DecodeString(snap.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("ca.Restore: decode priv_key: %w", err)
	}
	sk, err := dsa.ParsePrivateKey(dsa.Level87, skBytes)
	if err != nil {
		return nil, fmt.Errorf("ca.Restore: parse private key: %w", err)
	}
	// Derive the public key from the private key bytes embedded in the certificate.
	pkBytes, err := base64.StdEncoding.DecodeString(snap.Certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca.Restore: decode public key from cert: %w", err)
	}
	pk, err := dsa.ParsePublicKey(dsa.Level87, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("ca.Restore: parse public key: %w", err)
	}
	revoked := snap.Revoked
	if revoked == nil {
		revoked = make(map[string]time.Time)
	}
	return &CA{pk: pk, sk: sk, cert: snap.Certificate, revoked: revoked}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// attachSignature signs cert with sk and stores the base64 signature in
// cert.Signature.
func attachSignature(cert *Certificate, sk *dsa.PrivateKey) error {
	msg, err := cert.signingBytes()
	if err != nil {
		return err
	}
	sig, err := dsa.Sign(sk, msg)
	if err != nil {
		return err
	}
	cert.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// randomSerial returns a 32-hex-char (16-byte) random serial number.
func randomSerial() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
