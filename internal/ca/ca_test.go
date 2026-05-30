package ca_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/ca"
)

// ── Init ──────────────────────────────────────────────────────────────────────

func TestInit_CreatesCA(t *testing.T) {
	authority, err := ca.Init("CN=Test Root CA,O=Example Corp")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cert := authority.Certificate()
	if cert == nil {
		t.Fatal("Certificate() returned nil")
	}
	if cert.Subject != "CN=Test Root CA,O=Example Corp" {
		t.Errorf("Subject: %q", cert.Subject)
	}
	if cert.Issuer != cert.Subject {
		t.Errorf("self-signed: Issuer %q != Subject %q", cert.Issuer, cert.Subject)
	}
	if !cert.IsCA {
		t.Error("IsCA should be true for root cert")
	}
	if cert.Algorithm != "ML-DSA-87" {
		t.Errorf("Algorithm: %q", cert.Algorithm)
	}
	if cert.Signature == "" {
		t.Error("root cert has no signature")
	}
	if cert.Version != 1 {
		t.Errorf("Version: %d", cert.Version)
	}
}

func TestInit_EmptySubject(t *testing.T) {
	_, err := ca.Init("")
	if err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestInit_ValidityWindow(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)
	cert := authority.Certificate()
	if cert.NotBefore.Before(before) || cert.NotBefore.After(after) {
		t.Errorf("NotBefore %v not within expected range [%v, %v]", cert.NotBefore, before, after)
	}
	// CA cert should be valid for ~10 years
	expectedExpiry := time.Now().UTC().Add(9 * 365 * 24 * time.Hour)
	if cert.NotAfter.Before(expectedExpiry) {
		t.Errorf("NotAfter %v is less than 9 years from now", cert.NotAfter)
	}
}

// ── Issue ─────────────────────────────────────────────────────────────────────

func TestIssue_LeafCert(t *testing.T) {
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	fakeKey := []byte("fake-ml-kem-768-public-key-bytes-1234")
	cert, err := authority.Issue("CN=client.example.com", "ML-KEM-768", fakeKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if cert.Subject != "CN=client.example.com" {
		t.Errorf("Subject: %q", cert.Subject)
	}
	if cert.Issuer != "CN=Root CA" {
		t.Errorf("Issuer: %q", cert.Issuer)
	}
	if cert.IsCA {
		t.Error("leaf cert should not be a CA")
	}
	if cert.PublicKeyType != "ML-KEM-768" {
		t.Errorf("PublicKeyType: %q", cert.PublicKeyType)
	}
	got, err := base64.StdEncoding.DecodeString(cert.PublicKey)
	if err != nil {
		t.Fatalf("decode PublicKey: %v", err)
	}
	if string(got) != string(fakeKey) {
		t.Errorf("PublicKey mismatch")
	}
	if cert.Signature == "" {
		t.Error("leaf cert has no signature")
	}
	if len(cert.Serial) != 32 { // 16 bytes hex = 32 chars
		t.Errorf("Serial length: %d (want 32)", len(cert.Serial))
	}
}

func TestIssue_CustomTTL(t *testing.T) {
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	ttl := 30 * 24 * time.Hour
	cert, err := authority.Issue("CN=short-lived.example.com", "ML-DSA-65", []byte("pk"), ttl)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	// allow ±2 seconds tolerance for clock
	if lifetime < ttl-2*time.Second || lifetime > ttl+2*time.Second {
		t.Errorf("lifetime %v, want ~%v", lifetime, ttl)
	}
}

func TestIssue_EmptySubject(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	_, err := authority.Issue("", "ML-KEM-768", []byte("pk"), 0)
	if err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestIssue_EmptyPublicKey(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	_, err := authority.Issue("CN=test", "ML-KEM-768", nil, 0)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

// ── Verify ────────────────────────────────────────────────────────────────────

func TestVerify_ValidLeafCert(t *testing.T) {
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cert, err := authority.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk-bytes"), 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := authority.Verify(cert); err != nil {
		t.Errorf("Verify valid cert: %v", err)
	}
}

func TestVerify_SelfSignedRootCert_IsRejected(t *testing.T) {
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// The root cert has is_ca:true — Verify must reject it as an end-entity cert.
	// Accepting CA certs as leaf certs would violate PKI semantics and allow
	// CA cert holders to impersonate any leaf entity (red-team finding).
	if err := authority.Verify(authority.Certificate()); err == nil {
		t.Error("Verify(root CA cert) should fail — CA certs must not pass as leaf certs")
	}
}

func TestVerify_TamperedSubject(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	cert, _ := authority.Issue("CN=legitimate.example.com", "ML-KEM-768", []byte("pk"), 0)

	// Tamper with the subject.
	cert.Subject = "CN=attacker.example.com"
	if err := authority.Verify(cert); err == nil {
		t.Error("expected verification failure for tampered subject")
	}
}

func TestVerify_TamperedPublicKey(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	cert, _ := authority.Issue("CN=server.example.com", "ML-KEM-768", []byte("real-pk"), 0)

	cert.PublicKey = base64.StdEncoding.EncodeToString([]byte("attacker-pk"))
	if err := authority.Verify(cert); err == nil {
		t.Error("expected verification failure for tampered public key")
	}
}

func TestVerify_WrongCA(t *testing.T) {
	ca1, _ := ca.Init("CN=CA One")
	ca2, _ := ca.Init("CN=CA Two")

	// cert issued by CA1, verified against CA2 — must fail.
	cert, _ := ca1.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	if err := ca2.Verify(cert); err == nil {
		t.Error("expected verification failure for wrong CA")
	}
}

func TestVerify_NilCert(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	if err := authority.Verify(nil); err == nil {
		t.Error("expected error for nil cert")
	}
}

// ── JSON serialisation ────────────────────────────────────────────────────────

func TestCertificate_JSONRoundtrip(t *testing.T) {
	authority, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	orig, err := authority.Issue("CN=roundtrip.example.com", "ML-KEM-768", []byte("pk-data"), 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var parsed ca.Certificate
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if parsed.Subject != orig.Subject {
		t.Errorf("Subject: %q vs %q", parsed.Subject, orig.Subject)
	}
	if parsed.Serial != orig.Serial {
		t.Errorf("Serial: %q vs %q", parsed.Serial, orig.Serial)
	}
	if parsed.Signature != orig.Signature {
		t.Errorf("Signature mismatch after roundtrip")
	}

	// Verify the deserialized cert — signature must still be valid.
	if err := authority.Verify(&parsed); err != nil {
		t.Errorf("Verify after JSON roundtrip: %v", err)
	}
}

// ── CRL ───────────────────────────────────────────────────────────────────────

func TestRevoke_RevokedCertFailsVerify(t *testing.T) {
	authority, err := ca.Init("CN=Revoke CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cert, err := authority.Issue("CN=will-be-revoked.example.com", "ML-KEM-768", []byte("pk"), 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Verify before revocation — must succeed.
	if err := authority.Verify(cert); err != nil {
		t.Fatalf("Verify before revocation: %v", err)
	}

	// Revoke.
	if err := authority.Revoke(cert.Serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Verify after revocation — must fail.
	if err := authority.Verify(cert); err == nil {
		t.Error("expected Verify to fail for revoked certificate")
	}
}

func TestRevoke_EmptySerialFails(t *testing.T) {
	authority, _ := ca.Init("CN=Revoke CA")
	if err := authority.Revoke(""); err == nil {
		t.Error("expected error for empty serial")
	}
}

func TestRevoke_Idempotent(t *testing.T) {
	authority, _ := ca.Init("CN=Revoke CA")
	cert, _ := authority.Issue("CN=revoke-twice.example.com", "ML-KEM-768", []byte("pk"), 0)

	if err := authority.Revoke(cert.Serial); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := authority.Revoke(cert.Serial); err != nil {
		t.Fatalf("second Revoke (idempotent): %v", err)
	}
}

func TestIsRevoked(t *testing.T) {
	authority, _ := ca.Init("CN=IsRevoked CA")
	cert, _ := authority.Issue("CN=check.example.com", "ML-KEM-768", []byte("pk"), 0)

	if authority.IsRevoked(cert.Serial) {
		t.Error("certificate should not be revoked before Revoke is called")
	}
	authority.Revoke(cert.Serial)
	if !authority.IsRevoked(cert.Serial) {
		t.Error("certificate should be revoked after Revoke is called")
	}
}

func TestCRL_EmptyInitially(t *testing.T) {
	authority, _ := ca.Init("CN=CRL CA")
	crl := authority.CRL()
	if len(crl.Entries) != 0 {
		t.Errorf("expected empty CRL, got %d entries", len(crl.Entries))
	}
	if crl.Issuer != "CN=CRL CA" {
		t.Errorf("issuer: %q", crl.Issuer)
	}
	if crl.Version != 1 {
		t.Errorf("version: %d", crl.Version)
	}
}

func TestCRL_ContainsRevokedSerials(t *testing.T) {
	authority, _ := ca.Init("CN=CRL CA")

	c1, _ := authority.Issue("CN=one.example.com", "ML-KEM-768", []byte("pk1"), 0)
	c2, _ := authority.Issue("CN=two.example.com", "ML-KEM-768", []byte("pk2"), 0)
	authority.Revoke(c1.Serial)
	authority.Revoke(c2.Serial)

	crl := authority.CRL()
	if len(crl.Entries) != 2 {
		t.Fatalf("expected 2 CRL entries, got %d", len(crl.Entries))
	}

	serials := map[string]bool{crl.Entries[0].Serial: true, crl.Entries[1].Serial: true}
	if !serials[c1.Serial] || !serials[c2.Serial] {
		t.Errorf("CRL does not contain expected serials")
	}

	// Entries must be sorted by serial.
	if crl.Entries[0].Serial > crl.Entries[1].Serial {
		t.Errorf("CRL entries not sorted: %q > %q", crl.Entries[0].Serial, crl.Entries[1].Serial)
	}
}

func TestCRL_UnrevokedCertStillValid(t *testing.T) {
	authority, _ := ca.Init("CN=CRL CA")
	c1, _ := authority.Issue("CN=revoked.example.com", "ML-KEM-768", []byte("pk1"), 0)
	c2, _ := authority.Issue("CN=valid.example.com", "ML-KEM-768", []byte("pk2"), 0)

	authority.Revoke(c1.Serial)

	// c2 not revoked — must still verify.
	if err := authority.Verify(c2); err != nil {
		t.Errorf("Verify for non-revoked cert: %v", err)
	}
}

// ── IssueIntermediate ─────────────────────────────────────────────────────────

func TestIssueIntermediate_Basic(t *testing.T) {
	root, err := ca.Init("CN=Root CA")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub, cert, err := root.IssueIntermediate("CN=Intermediate CA", 0)
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	if sub == nil {
		t.Fatal("returned sub-CA is nil")
	}
	if cert == nil {
		t.Fatal("returned cert is nil")
	}
	if !cert.IsCA {
		t.Error("intermediate cert must have IsCA=true")
	}
	if cert.Subject != "CN=Intermediate CA" {
		t.Errorf("Subject: %q", cert.Subject)
	}
	if cert.Issuer != "CN=Root CA" {
		t.Errorf("Issuer: %q", cert.Issuer)
	}
	if cert.Algorithm != "ML-DSA-87" {
		t.Errorf("Algorithm: %q", cert.Algorithm)
	}
	if cert.Signature == "" {
		t.Error("intermediate cert has no signature")
	}
}

func TestIssueIntermediate_CACertRejectedByVerify(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	_, intCert, _ := root.IssueIntermediate("CN=Intermediate CA", 0)

	// Intermediate CA cert has is_ca:true — root.Verify must reject it.
	// Use VerifyChain for CA chain validation instead.
	if err := root.Verify(intCert); err == nil {
		t.Error("root.Verify(intermediate cert) should fail — CA certs must not pass as leaf certs")
	}
}

func TestIssueIntermediate_ChainVerifiable(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	sub, intCert, _ := root.IssueIntermediate("CN=Intermediate CA", 0)

	// Issue a leaf via the intermediate.
	leaf, _ := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	// VerifyChain validates the full chain: leaf → intermediate → root.
	if err := ca.VerifyChain(leaf, []*ca.Certificate{intCert}, root.Certificate()); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
}

func TestIssueIntermediate_CanIssueLeaf(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	sub, _, _ := root.IssueIntermediate("CN=Intermediate CA", 0)

	leaf, err := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	if err != nil {
		t.Fatalf("sub.Issue: %v", err)
	}
	if leaf.Issuer != "CN=Intermediate CA" {
		t.Errorf("leaf issuer: %q", leaf.Issuer)
	}
	// Root cannot verify a leaf issued by sub (different keypair).
	if err := root.Verify(leaf); err == nil {
		t.Error("root.Verify should fail for leaf issued by intermediate")
	}
	// Sub can verify its own leaf.
	if err := sub.Verify(leaf); err != nil {
		t.Errorf("sub.Verify(leaf): %v", err)
	}
}

func TestIssueIntermediate_EmptySubject(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	_, _, err := root.IssueIntermediate("", 0)
	if err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestIssueIntermediate_CustomTTL(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	ttl := 365 * 24 * time.Hour
	_, cert, _ := root.IssueIntermediate("CN=Short-lived Intermediate", ttl)

	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime < ttl-2*time.Second || lifetime > ttl+2*time.Second {
		t.Errorf("lifetime %v, want ~%v", lifetime, ttl)
	}
}

// ── VerifyChain ───────────────────────────────────────────────────────────────

func TestVerifyChain_DirectLeaf(t *testing.T) {
	// No intermediates: leaf → root.
	root, _ := ca.Init("CN=Root CA")
	leaf, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	if err := ca.VerifyChain(leaf, nil, root.Certificate()); err != nil {
		t.Errorf("VerifyChain with no intermediates: %v", err)
	}
}

func TestVerifyChain_OneIntermediate(t *testing.T) {
	// Leaf → Intermediate → Root.
	root, _ := ca.Init("CN=Root CA")
	sub, intCert, _ := root.IssueIntermediate("CN=Intermediate CA", 0)
	leaf, _ := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	// chain = [intCert] (one intermediate, signed by root)
	if err := ca.VerifyChain(leaf, []*ca.Certificate{intCert}, root.Certificate()); err != nil {
		t.Errorf("VerifyChain with 1 intermediate: %v", err)
	}
}

func TestVerifyChain_TwoIntermediates(t *testing.T) {
	// Leaf → Sub2 → Sub1 → Root.
	root, _ := ca.Init("CN=Root CA")
	sub1, int1Cert, _ := root.IssueIntermediate("CN=Intermediate CA 1", 0)
	sub2, int2Cert, _ := sub1.IssueIntermediate("CN=Intermediate CA 2", 0)
	leaf, _ := sub2.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	// chain = [int2Cert, int1Cert] — direct issuer of leaf first
	if err := ca.VerifyChain(leaf, []*ca.Certificate{int2Cert, int1Cert}, root.Certificate()); err != nil {
		t.Errorf("VerifyChain with 2 intermediates: %v", err)
	}
}

func TestVerifyChain_TamperedLeaf(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	sub, intCert, _ := root.IssueIntermediate("CN=Intermediate CA", 0)
	leaf, _ := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	leaf.Subject = "CN=attacker.example.com" // tamper

	err := ca.VerifyChain(leaf, []*ca.Certificate{intCert}, root.Certificate())
	if err == nil {
		t.Error("expected VerifyChain to fail for tampered leaf")
	}
}

func TestVerifyChain_WrongTrustAnchor(t *testing.T) {
	root1, _ := ca.Init("CN=Root CA 1")
	root2, _ := ca.Init("CN=Root CA 2")
	sub, intCert, _ := root1.IssueIntermediate("CN=Intermediate CA", 0)
	leaf, _ := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	// Use root2 as trust anchor — must fail.
	err := ca.VerifyChain(leaf, []*ca.Certificate{intCert}, root2.Certificate())
	if err == nil {
		t.Error("expected VerifyChain to fail with wrong trust anchor")
	}
}

func TestVerifyChain_NilCert(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	if err := ca.VerifyChain(nil, nil, root.Certificate()); err == nil {
		t.Error("expected error for nil cert")
	}
}

func TestVerifyChain_NilTrustAnchor(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	leaf, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	if err := ca.VerifyChain(leaf, nil, nil); err == nil {
		t.Error("expected error for nil trust anchor")
	}
}

func TestVerifyChain_NonCATrustAnchor(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	// Use a leaf cert as trust anchor — must fail.
	leaf, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	if err := ca.VerifyChain(leaf, nil, leaf); err == nil {
		t.Error("expected error when trust anchor has IsCA=false")
	}
}

func TestVerifyChain_NonCAInChain(t *testing.T) {
	root, _ := ca.Init("CN=Root CA")
	leaf1, _ := root.Issue("CN=leaf1.example.com", "ML-KEM-768", []byte("pk"), 0)
	leaf2, _ := root.Issue("CN=leaf2.example.com", "ML-KEM-768", []byte("pk"), 0)

	// Use a leaf cert (IsCA=false) as chain member — must fail.
	err := ca.VerifyChain(leaf2, []*ca.Certificate{leaf1}, root.Certificate())
	if err == nil {
		t.Error("expected error when chain contains non-CA cert")
	}
}

func TestCertificate_JSONContainsExpectedFields(t *testing.T) {
	authority, _ := ca.Init("CN=Root CA")
	cert, _ := authority.Issue("CN=check.example.com", "ML-KEM-768", []byte("pk"), 0)

	b, _ := json.Marshal(cert)
	s := string(b)

	for _, field := range []string{"version", "serial", "subject", "issuer", "algorithm",
		"public_key", "public_key_type", "not_before", "not_after", "is_ca", "signature"} {
		if !strings.Contains(s, `"`+field+`"`) {
			t.Errorf("JSON missing field %q: %s", field, s)
		}
	}
}
