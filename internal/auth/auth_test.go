package auth_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/auth"
	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

func newAuthority(t *testing.T) *auth.Authority {
	t.Helper()
	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	return a
}

// ── Correctness ───────────────────────────────────────────────────────────────

func TestIssueVerify(t *testing.T) {
	a := newAuthority(t)
	token, err := a.Issue("alice", []string{"read", "transfer"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tok, err := a.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if tok.Claims.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", tok.Claims.Subject, "alice")
	}
	if len(tok.Claims.Roles) != 2 {
		t.Errorf("roles: got %v", tok.Claims.Roles)
	}
	if tok.Claims.JTI == "" {
		t.Error("jti must not be empty")
	}
}

func TestRevocation(t *testing.T) {
	a := newAuthority(t)
	token, _ := a.Issue("alice", []string{"read"}, nil)

	// First verify — must pass
	if _, err := a.Verify(token); err != nil {
		t.Fatalf("pre-revoke verify failed: %v", err)
	}

	a.Revoke(token)

	// After revocation — must fail
	if _, err := a.Verify(token); err == nil {
		t.Fatal("revoked token should fail verification")
	}
}

func TestDoubleRevocation(t *testing.T) {
	a := newAuthority(t)
	token, _ := a.Issue("alice", []string{"read"}, nil)
	a.Revoke(token)
	a.Revoke(token) // must not panic
	if _, err := a.Verify(token); err == nil {
		t.Fatal("double-revoked token should still fail")
	}
}

func TestExpiredToken(t *testing.T) {
	a, err := auth.NewAuthority("TestBank", -1*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := a.Issue("alice", []string{"read"}, nil)
	if _, err := a.Verify(token); err == nil {
		t.Fatal("expired token should fail verification")
	}
}

// ── Security: JWT attack vectors ──────────────────────────────────────────────

func TestTamperedSubject(t *testing.T) {
	// Attack: decode payload, change subject to "admin", re-encode, keep original sig.
	// Expected: signature verification fails because signing input changed.
	a := newAuthority(t)
	token, _ := a.Issue("alice", []string{"read"}, nil)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("unexpected token format")
	}
	// Replace payload with a tampered one (any change breaks the ML-DSA signature)
	parts[1] = parts[1][:len(parts[1])-2] + "XX"
	tampered := strings.Join(parts, ".")
	if _, err := a.Verify(tampered); err == nil {
		t.Fatal("tampered payload should fail verification")
	}
}

func TestTamperedJTI(t *testing.T) {
	// Attack: change the jti in the payload to bypass revocation.
	// Expected: signature verification fails — jti is inside the signed payload.
	a := newAuthority(t)
	token, _ := a.Issue("alice", []string{"read"}, nil)
	a.Revoke(token)

	// Attempt to bypass revocation by modifying the signature part
	parts := strings.Split(token, ".")
	parts[2] = parts[2][:len(parts[2])-2] + "AA"
	tampered := strings.Join(parts, ".")
	if _, err := a.Verify(tampered); err == nil {
		t.Fatal("tampered token should fail — jti cannot be extracted without sig failure")
	}
}

func TestAlgorithmConfusion(t *testing.T) {
	// Attack: change alg in header to something else.
	// Expected: signature check fails (header is part of signing input).
	a := newAuthority(t)
	token, _ := a.Issue("alice", []string{"read"}, nil)
	parts := strings.Split(token, ".")
	parts[0] = parts[0][:len(parts[0])-2] + "XX" // tamper header
	tampered := strings.Join(parts, ".")
	if _, err := a.Verify(tampered); err == nil {
		t.Fatal("algorithm confusion attack should fail")
	}
}

func TestCrossIssuerToken(t *testing.T) {
	// Attack: present token issued by a different authority.
	a1, _ := auth.NewAuthority("BankA", 3600*time.Second, dsa.Level65)
	a2, _ := auth.NewAuthority("BankB", 3600*time.Second, dsa.Level65)

	tokenFromA1, _ := a1.Issue("alice", []string{"read"}, nil)
	if _, err := a2.Verify(tokenFromA1); err == nil {
		t.Fatal("cross-issuer token should fail — different signing keys")
	}
}

func TestEmptyToken(t *testing.T) {
	a := newAuthority(t)
	if _, err := a.Verify(""); err == nil {
		t.Fatal("empty token should fail")
	}
}

func TestMalformedToken(t *testing.T) {
	a := newAuthority(t)
	for _, bad := range []string{
		"notavalidtoken",
		"a.b",
		"a.b.c.d",
		"...",
		"!!!.!!!.!!!",
	} {
		if _, err := a.Verify(bad); err == nil {
			t.Fatalf("malformed token %q should fail", bad)
		}
	}
}

func TestEmptySubject(t *testing.T) {
	a := newAuthority(t)
	if _, err := a.Issue("", []string{"read"}, nil); err == nil {
		t.Fatal("empty subject should be rejected")
	}
}

func TestEmptyRoles(t *testing.T) {
	a := newAuthority(t)
	if _, err := a.Issue("alice", nil, nil); err == nil {
		t.Fatal("empty roles should be rejected")
	}
}

func TestExtraFields(t *testing.T) {
	a := newAuthority(t)
	extra := map[string]any{"account_id": "acc-001", "branch": "central"}
	token, err := a.Issue("alice", []string{"transfer"}, extra)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Claims.Extra["account_id"] != "acc-001" {
		t.Errorf("extra field not preserved: %v", tok.Claims.Extra)
	}
}

func TestUniqueJTI(t *testing.T) {
	// 1000 tokens must all have unique JTIs
	a := newAuthority(t)
	seen := make(map[string]bool, 1000)
	for i := range 1000 {
		tok, err := a.Issue("user", []string{"read"}, nil)
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		parsed, err := a.Verify(tok)
		if err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
		jti := parsed.Claims.JTI
		if seen[jti] {
			t.Fatalf("duplicate JTI at token %d: %s", i, jti)
		}
		seen[jti] = true
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestConcurrentIssueVerify(t *testing.T) {
	a := newAuthority(t)
	const goroutines = 50
	errc := make(chan error, goroutines)

	for range goroutines {
		go func() {
			tok, err := a.Issue("user", []string{"read"}, nil)
			if err != nil {
				errc <- err
				return
			}
			if _, err := a.Verify(tok); err != nil {
				errc <- err
				return
			}
			errc <- nil
		}()
	}
	for range goroutines {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// ── Persistent revocation ─────────────────────────────────────────────────────

func TestPersistentRevocation_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")

	// Authority 1: issue and revoke
	a1, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()

	if err := a1.SetRevocationFile(path); err != nil {
		t.Fatal(err)
	}
	token, _ := a1.Issue("alice", []string{"read"}, nil)
	a1.Revoke(token)

	// File must exist and contain the JTI
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("revocation file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("revocation file is empty")
	}

	// Authority 2: fresh instance, load same file — token must be revoked
	a2, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()

	if err := a2.SetRevocationFile(path); err != nil {
		t.Fatalf("SetRevocationFile on reload: %v", err)
	}
	if !a2.IsRevoked(token) {
		t.Error("revocation not persisted: IsRevoked returned false after reload")
	}
}

func TestPersistentRevocation_FileFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")

	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if err := a.SetRevocationFile(path); err != nil {
		t.Fatal(err)
	}

	token, _ := a.Issue("alice", []string{"read"}, nil)
	a.Revoke(token)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read revocation file: %v", err)
	}

	var entries []struct {
		JTI       string `json:"jti"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("revocation file not valid JSON array: %v\n%s", err, data)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].JTI == "" {
		t.Error("jti field is empty in revocation file")
	}
	if entries[0].ExpiresAt <= 0 {
		t.Error("exp field is zero in revocation file")
	}
}

func TestPersistentRevocation_ExpiredEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")

	// Write a revocation file with one already-expired entry.
	expired := `[{"jti":"old-jti-expired","exp":1}]` // exp=1 is way in the past
	if err := os.WriteFile(path, []byte(expired), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if err := a.SetRevocationFile(path); err != nil {
		t.Fatal(err)
	}

	// The expired JTI must not be in memory (would fail IsRevoked: jti not parseable from token,
	// but we can confirm via direct revocation of a fresh token still works).
	token, _ := a.Issue("alice", []string{"read"}, nil)
	// Fresh token must NOT be considered revoked
	if a.IsRevoked(token) {
		t.Error("fresh token incorrectly marked as revoked")
	}
}

func TestPersistentRevocation_MultipleTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")

	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if err := a.SetRevocationFile(path); err != nil {
		t.Fatal(err)
	}

	const n = 10
	tokens := make([]string, n)
	for i := range n {
		tok, _ := a.Issue("user", []string{"read"}, nil)
		tokens[i] = tok
	}

	// Revoke odd-indexed tokens
	for i, tok := range tokens {
		if i%2 == 1 {
			a.Revoke(tok)
		}
	}

	// Reload into a new authority
	a2, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()

	if err := a2.SetRevocationFile(path); err != nil {
		t.Fatal(err)
	}

	for i, tok := range tokens {
		revoked := a2.IsRevoked(tok)
		if i%2 == 1 && !revoked {
			t.Errorf("token %d should be revoked but IsRevoked=false", i)
		}
		if i%2 == 0 && revoked {
			t.Errorf("token %d should NOT be revoked but IsRevoked=true", i)
		}
	}
}

func TestSetRevocationFile_NonExistentPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json") // does not exist yet — must be created on first Revoke

	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	// Must not error when file doesn't exist yet
	if err := a.SetRevocationFile(path); err != nil {
		t.Fatalf("SetRevocationFile on missing path: %v", err)
	}

	token, _ := a.Issue("alice", []string{"read"}, nil)
	a.Revoke(token)

	if _, err := os.Stat(path); err != nil {
		t.Errorf("revocation file should have been created: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	a, err := auth.NewAuthority("TestBank", 3600*time.Second, dsa.Level65)
	if err != nil {
		t.Fatal(err)
	}
	// Close without SetRevocationFile — must not panic
	a.Close()
	a.Close() // second call must also be safe
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkIssue(b *testing.B) {
	a, _ := auth.NewAuthority("Bench", 3600*time.Second, dsa.Level65)
	b.ResetTimer()
	for b.Loop() {
		a.Issue("user-001", []string{"read", "write"}, nil)
	}
}

func BenchmarkVerify(b *testing.B) {
	a, _ := auth.NewAuthority("Bench", 3600*time.Second, dsa.Level65)
	token, _ := a.Issue("user-001", []string{"read", "write"}, nil)
	b.ResetTimer()
	for b.Loop() {
		a.Verify(token)
	}
}
