// Package redteam_test is an adversarial red-team suite that attacks the
// QuantumShield API at a deeper level than the standard penetration tests.
//
// Each test targets a specific class of attack that exploits implementation
// assumptions, protocol design flaws, or business-logic gaps.  Tests that
// reveal real vulnerabilities are marked with the comment "EXPLOIT".
//
// Run:
//
//	go test ./test/redteam/... -v
//
// All tests must PASS (either the attack is blocked → confirmed secure, or the
// attack exposes a vulnerability that was then fixed → also passes).
package redteam_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/pkg/api"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func srv(t *testing.T, opts ...api.Option) (*httptest.Server, func()) {
	t.Helper()
	s, err := api.New(opts...)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	return ts, func() { ts.Close(); s.Close() }
}

func jreq(t *testing.T, ts *httptest.Server, method, path string, body any, tok string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck
	return resp.StatusCode, m
}

func token(t *testing.T, ts *httptest.Server, uid string, roles []string) string {
	t.Helper()
	code, body := jreq(t, ts, "POST", "/auth/token", map[string]any{
		"user_id": uid, "roles": roles,
	}, "")
	if code != 200 {
		t.Fatalf("issue token: %d %v", code, body)
	}
	return body["token"].(string)
}

func initCA(t *testing.T, ts *httptest.Server, adminTok, subject string) map[string]any {
	t.Helper()
	code, body := jreq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": subject}, adminTok)
	if code != 200 {
		t.Fatalf("ca/init: %d %v", code, body)
	}
	return body
}

func genKey(t *testing.T, ts *httptest.Server, tok, level string) (string, string) {
	t.Helper()
	code, body := jreq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": level}, tok)
	if code != 200 {
		t.Fatalf("keys/generate: %d %v", code, body)
	}
	return body["key_id"].(string), body["public_key"].(string)
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 1: ML-KEM Level Confusion
//
// EXPLOIT: sending "ML-KEM-1024" as level silently falls back to ML-KEM-768
// because handleGenerateKey only checks `level == "high"`.
// A developer who trusts the API docs gets 768-bit security while believing
// they have 1024-bit security.
// ══════════════════════════════════════════════════════════════════════════════

// TestRedTeam_LevelConfusion_1024FallsBackTo768 confirms the bug:
// posting "ML-KEM-1024" must produce a key of ML-KEM-1024 size (1568 bytes
// for the public key), NOT ML-KEM-768 (1184 bytes).
func TestRedTeam_LevelConfusion_1024FallsBackTo768(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "attacker", []string{"write", "read"})

	// ML-KEM-768 public key size = 1184 bytes
	// ML-KEM-1024 public key size = 1568 bytes
	const pk768size  = 1184
	const pk1024size = 1568

	// Ask for 1024 using the documented API value.
	_, pk1024 := genKey(t, ts, tok, "ML-KEM-1024")
	decoded, err := base64.StdEncoding.DecodeString(pk1024)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	if len(decoded) == pk768size {
		t.Errorf("VULNERABILITY CONFIRMED: level='ML-KEM-1024' produced a "+
			"ML-KEM-768 key (%d bytes). "+
			"Developers requesting 1024-bit security silently get 768-bit.",
			len(decoded))
	}
	if len(decoded) != pk1024size {
		t.Errorf("unexpected public key size: got %d, want %d",
			len(decoded), pk1024size)
	}
}

// TestRedTeam_LevelConfusion_HighKeyword checks that the undocumented "high"
// keyword correctly produces an ML-KEM-1024 key.
func TestRedTeam_LevelConfusion_HighKeywordWorks(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "user", []string{"write"})
	_, pk := genKey(t, ts, tok, "high")
	decoded, _ := base64.StdEncoding.DecodeString(pk)
	// "high" must produce 1024-bit key (1568-byte public key).
	if len(decoded) != 1568 {
		t.Errorf("'high' level: got %d-byte key, want 1568 (ML-KEM-1024)", len(decoded))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 2: CA Certificate Accepted as Leaf Certificate
//
// EXPLOIT: ca.Verify() does not check cert.IsCA == false.
// An attacker who obtains an intermediate CA certificate can present it to
// /ca/verify and receive valid:true, violating PKI semantics.
// In a real deployment this allows a CA cert holder to impersonate any leaf.
// ══════════════════════════════════════════════════════════════════════════════

// TestRedTeam_CACertAcceptedAsLeaf checks whether the ROOT CA certificate
// itself passes /ca/verify (it should NOT — IsCA:true means it is a CA, not
// an end-entity cert).
func TestRedTeam_CACertAcceptedAsLeaf(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})

	initCA(t, ts, adminTok, "CN=RedTeam Root CA")

	// Retrieve the root CA certificate.
	code, caCert := jreq(t, ts, "GET", "/ca/certificate", nil, "")
	if code != 200 {
		t.Fatalf("GET /ca/certificate: %d", code)
	}

	// Submit the CA cert itself to /ca/verify.
	code, body := jreq(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": caCert}, "")

	valid, _ := body["valid"].(bool)
	if valid {
		t.Errorf("VULNERABILITY CONFIRMED: root CA certificate (is_ca:true) "+
			"accepted as valid leaf cert by /ca/verify (status=%d body=%v). "+
			"A CA cert holder can impersonate any leaf entity.", code, body)
	}
	t.Logf("CA cert verify result: status=%d valid=%v error=%v", code, valid, body["error"])
}

// TestRedTeam_IntermediateCACertAcceptedAsLeaf submits an intermediate CA cert
// (is_ca:true) to the root CA's /ca/verify endpoint.
func TestRedTeam_IntermediateCACertAcceptedAsLeaf(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})

	initCA(t, ts, adminTok, "CN=RedTeam Root CA 2")

	// Create an intermediate CA.
	code, intResp := jreq(t, ts, "POST", "/ca/intermediate",
		map[string]any{"subject": "CN=Intermediate CA", "ttl_days": 3650}, adminTok)
	if code != 200 && code != 201 {
		t.Fatalf("ca/intermediate: %d %v", code, intResp)
	}

	// Extract the intermediate CA certificate.
	intCert, ok := intResp["certificate"].(map[string]any)
	if !ok {
		t.Fatalf("no certificate in intermediate response: %v", intResp)
	}

	// Submit the intermediate CA cert to /ca/verify.
	code, body := jreq(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": intCert}, "")

	valid, _ := body["valid"].(bool)
	if valid {
		t.Errorf("VULNERABILITY CONFIRMED: intermediate CA certificate "+
			"(is_ca:true) accepted as valid leaf cert. "+
			"Intermediate CA holders can bypass leaf-cert trust checks.", )
	}
	t.Logf("Intermediate cert verify result: status=%d valid=%v error=%v",
		code, valid, body["error"])
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 3: Negative / Zero TTL Certificate Issuance
//
// EXPLOIT: handleCASign accepts ttl_days: -1, which produces a certificate
// with not_after = yesterday.  The cert is issued successfully but is
// immediately expired.  A CA that issues expired certs has a broken lifecycle.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_NegativeTTLCertIssued(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	writeTok := token(t, ts, "writer", []string{"write", "read"})

	initCA(t, ts, adminTok, "CN=NegTTL Test CA")

	_, pubKey := genKey(t, ts, writeTok, "ML-KEM-768")

	// Issue a certificate with negative TTL.
	code, body := jreq(t, ts, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=already-expired.example.com",
		"public_key":      pubKey,
		"public_key_type": "ML-KEM-768",
		"ttl_days":        -1,
	}, writeTok)

	if code == 200 {
		notAfter, _ := body["not_after"].(string)
		t.Errorf("VULNERABILITY CONFIRMED: certificate issued with ttl_days=-1. "+
			"not_after=%q (should be rejected, cert is already expired).", notAfter)
	} else {
		t.Logf("Negative TTL correctly rejected: status=%d error=%v", code, body["error"])
	}
}

func TestRedTeam_ZeroTTLCertDefaulted(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	writeTok := token(t, ts, "writer", []string{"write", "read"})
	initCA(t, ts, adminTok, "CN=ZeroTTL Test CA")
	_, pubKey := genKey(t, ts, writeTok, "ML-KEM-768")

	// ttl_days: 0 should default to 1 year (not a zero-duration cert).
	code, body := jreq(t, ts, "POST", "/ca/sign", map[string]any{
		"subject": "CN=zero-ttl.example.com", "public_key": pubKey,
		"public_key_type": "ML-KEM-768", "ttl_days": 0,
	}, writeTok)
	if code != 200 {
		t.Errorf("ttl_days=0 should default to 1 year, got status %d: %v", code, body)
		return
	}
	notAfter, _ := body["not_after"].(string)
	// Must be at least 1 day in the future.
	parsed, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		t.Errorf("invalid not_after: %v", notAfter)
		return
	}
	if time.Until(parsed) < 23*time.Hour {
		t.Errorf("ttl_days=0 produced cert expiring in < 23h: not_after=%v", notAfter)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 4: Subject Impersonation / Proof-of-Possession Gap
//
// The server does not verify that the requester owns the private key matching
// the public_key submitted to /ca/sign.  Any "write"-role user can:
//   1. Get another user's public key from /keys/{id}/public (read endpoint)
//   2. Issue a cert with a privileged subject (e.g. CN=admin) bound to
//      their own key (not the admin's key)  — or vice versa.
//
// This is a fundamental PKI design issue: without proof-of-possession, the
// CA is simply a "trusted stamping service" — it attests whatever it's told.
// Whether this is a vulnerability depends on the threat model, but it should
// be documented and tested.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_SubjectImpersonation_AdminCertForAttackersKey(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok  := token(t, ts, "admin",    []string{"admin", "write", "read"})
	attackerTok := token(t, ts, "attacker", []string{"write", "read"})

	initCA(t, ts, adminTok, "CN=Impersonation Test CA")

	// Attacker generates their own keypair.
	_, attackerPubKey := genKey(t, ts, attackerTok, "ML-KEM-768")

	// Attacker issues a cert with subject "CN=CEO,O=Company" bound to THEIR key.
	code, cert := jreq(t, ts, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=CEO,O=Company",
		"public_key":      attackerPubKey,
		"public_key_type": "ML-KEM-768",
	}, attackerTok)

	if code == 200 {
		subject, _ := cert["subject"].(string)
		t.Logf("DESIGN GAP: Attacker issued a cert with subject=%q bound to "+
			"their own key — no proof-of-possession check. "+
			"Whether this is acceptable depends on the threat model. "+
			"The CA trusts the requester to assert the correct subject.", subject)
		// This is not necessarily a bug (depends on deployment model),
		// but it MUST be documented. The test passes to confirm this behaviour is known.
	} else {
		t.Logf("Server rejected subject impersonation (status=%d) — good.", code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 5: Concurrent CA Initialisation Race
//
// Send 30 concurrent POST /ca/init.  Only ONE should succeed;
// if the mutex is broken, multiple CAs could be created.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_ConcurrentCAInit_OnlyOneWins(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	const goroutines = 30
	results := make([]int, goroutines)
	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := token(t, ts, fmt.Sprintf("admin-%d", i), []string{"admin"})
			code, _ := jreq(t, ts, "POST", "/ca/init",
				map[string]any{"subject": fmt.Sprintf("CN=Race CA %d", i)}, tok)
			results[i] = code
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, code := range results {
		if code == 200 {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("RACE CONDITION: %d concurrent CA inits produced %d successes, want exactly 1",
			goroutines, successes)
	} else {
		t.Logf("Concurrent CA init: %d goroutines, 1 success — mutex correct.", goroutines)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 6: Memory DoS via Channel Session Flooding
//
// A "write"-role user can POST /channel/init repeatedly without completing
// the handshake.  Each pending session lives for up to channelHandshakeTTL
// (5 minutes).  Within one TTL window an attacker can create thousands of
// entries and exhaust server memory.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_ChannelSessionFlooding(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "flooder", []string{"write", "read"})

	const flood = 500

	// Generate one keypair to use as "initiator key" for all inits.
	_, pubKey := genKey(t, ts, tok, "ML-KEM-768")

	var wg sync.WaitGroup
	created := 0
	var mu sync.Mutex

	for range flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Use raw HTTP to avoid t.Fatalf from inside a goroutine.
			body, _ := json.Marshal(map[string]any{
				"initiator_public_key": pubKey,
				"level":                "ML-KEM-768",
			})
			req, _ := http.NewRequest("POST", ts.URL+"/channel/init",
				bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := ts.Client().Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	t.Logf("Channel flooding: %d/%d sessions created before rate limit or OOM",
		created, flood)
	if created == flood {
		t.Logf("DESIGN GAP: All %d abandoned channel sessions accepted. "+
			"Consider per-user session limits in addition to the global cleanup TTL.", flood)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 7: JWT Subject Explosion (Rate Limit Bypass)
//
// The per-subject rate limiter uses the JWT `sub` claim as the bucket key.
// An attacker who controls token issuance can mint tokens with unique subjects
// (e.g. "user-1", "user-2", …) to get a fresh rate-limit bucket for each
// request, effectively bypassing the per-subject limit.
//
// The per-IP limit still applies, but in cloud/proxy deployments where many
// clients share an IP, this degrades to per-IP throttling only.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_SubjectExplosionBypassesSubjectRateLimit(t *testing.T) {
	// Use a tiny subject-level rate limit so the bypass is observable.
	ts, cleanup := srv(t,
		api.WithSubjectRateLimit(2, 10*time.Second), // 2 req/10s per subject
		api.WithIPRateLimit(1000, 10*time.Second),   // high IP limit to isolate
	)
	defer cleanup()

	const requests = 20
	successes := 0

	for i := range requests {
		// New unique subject for every request → fresh bucket.
		tok := token(t, ts, fmt.Sprintf("unique-subject-%d", i), []string{"read"})
		code, _ := jreq(t, ts, "GET", "/keys", nil, tok)
		if code == 200 {
			successes++
		}
	}

	if successes == requests {
		t.Logf("DESIGN GAP: Subject explosion bypasses per-subject rate limit. "+
			"%d/%d requests succeeded despite 2 req/10s per-subject limit. "+
			"Consider per-IP OR per-user-identity limits that cannot be forged.",
			successes, requests)
	} else {
		t.Logf("Subject rate limit held: %d/%d succeeded", successes, requests)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 8: Empty / Whitespace Serial Revocation
//
// Revoking an empty serial or whitespace serial must not corrupt CA state
// or silently succeed without effect.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_EmptySerialRevocation(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin"})
	initCA(t, ts, adminTok, "CN=EmptySerial Test CA")

	for _, serial := range []string{"", "   ", "\t", "\n"} {
		code, body := jreq(t, ts, "POST", "/ca/revoke",
			map[string]any{"serial": serial}, adminTok)
		if code == 200 {
			t.Errorf("VULNERABILITY: empty/whitespace serial %q was accepted for revocation "+
				"(status=200). This could cause undefined CRL state.", serial)
		} else {
			t.Logf("Serial %q correctly rejected: status=%d error=%v",
				serial, code, body["error"])
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 9: Huge Subject DN (Cert Bomb)
//
// Issue a certificate with a subject DN that is 1 MB of data.
// The server should reject it before allocating unbounded memory.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_HugeSubjectDN(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	writeTok := token(t, ts, "writer", []string{"write", "read"})
	initCA(t, ts, adminTok, "CN=HugeSubject Test CA")
	_, pubKey := genKey(t, ts, writeTok, "ML-KEM-768")

	hugeSubject := "CN=" + strings.Repeat("A", 1<<20) // 1 MB

	// The body limit (1 MB) should reject this before the handler runs.
	body := map[string]any{
		"subject":         hugeSubject,
		"public_key":      pubKey,
		"public_key_type": "ML-KEM-768",
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/ca/sign", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+writeTok)

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Logf("Request rejected at transport level: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Errorf("VULNERABILITY: 1 MB subject DN accepted — server should reject oversized body")
	} else {
		t.Logf("Huge subject DN rejected: status=%d", resp.StatusCode)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 10: Token Algorithm Field Confusion
//
// Change the `alg` field in the JWT header to "none", "ML-DSA-44", etc.
// The server must still reject these tokens because the signature is verified
// against the fixed ML-DSA-65 key — the `alg` field must be validated too.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_JWTAlgorithmFieldConfusion(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	// Get a genuine valid token.
	realTok := token(t, ts, "user", []string{"read"})
	parts := strings.Split(realTok, ".")
	if len(parts) != 3 {
		t.Fatal("token not 3 parts")
	}

	// Decode header, change alg, re-encode — keep original payload + signature.
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	json.Unmarshal(hdrRaw, &hdr) //nolint:errcheck

	algMutations := []string{"none", "ML-DSA-44", "ML-DSA-87", "HS256", "RS256", ""}

	for _, badAlg := range algMutations {
		hdr["alg"] = badAlg
		newHdrJSON, _ := json.Marshal(hdr)
		newHdr := base64.RawURLEncoding.EncodeToString(newHdrJSON)
		forgedTok := newHdr + "." + parts[1] + "." + parts[2]

		code, _ := jreq(t, ts, "GET", "/keys", nil, forgedTok)
		if code == 200 {
			t.Errorf("VULNERABILITY: token with alg=%q accepted (status=200). "+
				"Algorithm field must be validated.", badAlg)
		} else {
			t.Logf("alg=%q correctly rejected (status=%d)", badAlg, code)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 11: Vault Split with k > n (Impossible Threshold)
//
// Requesting more shards than threshold (e.g. n=2, k=5) must be rejected.
// If accepted, reconstruction would be impossible and keys permanently lost.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_VaultImpossibleThreshold(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "user", []string{"write", "read"})

	_, pubKey := genKey(t, ts, tok, "ML-KEM-768")

	cases := []struct{ n, k int }{
		{2, 5},    // k > n
		{0, 1},    // n = 0
		{1, 0},    // k = 0
		{-1, -1},  // negative
		{1000, 999}, // valid but extreme
	}
	for _, tc := range cases {
		code, body := jreq(t, ts, "POST", "/vault/split", map[string]any{
			"secret":    pubKey,
			"shares":    tc.n,
			"threshold": tc.k,
		}, tok)
		if tc.k > tc.n && code == 200 {
			t.Errorf("VULNERABILITY: vault split n=%d k=%d (impossible) accepted. "+
				"Keys split this way can never be reconstructed.", tc.n, tc.k)
		} else {
			t.Logf("split n=%d k=%d: status=%d %v", tc.n, tc.k, code, body["error"])
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 12: Raft Log Flooding (Write Amplification DoS)
//
// Apply thousands of tiny operations to flood the Raft log.
// The server should rate-limit writes even to authenticated clients.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam_WriteFlood_KeyGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping write flood test in short mode")
	}
	ts, cleanup := srv(t,
		api.WithSubjectRateLimit(1000, time.Minute),
		api.WithIPRateLimit(1000, time.Minute),
	)
	defer cleanup()
	tok := token(t, ts, "flooder", []string{"write"})

	const ops    = 200
	start       := time.Now()
	successes   := 0

	for range ops {
		code, _ := jreq(t, ts, "POST", "/keys/generate",
			map[string]any{"level": "ML-KEM-768"}, tok)
		if code == 200 {
			successes++
		}
	}
	elapsed := time.Since(start)

	rps := float64(successes) / elapsed.Seconds()
	t.Logf("Write flood: %d/%d ops in %v (%.1f ops/sec)", successes, ops, elapsed, rps)

	// The server should survive (not OOM, not panic).
	code, body := jreq(t, ts, "GET", "/health/live", nil, "")
	if code != 200 {
		t.Errorf("Server unhealthy after write flood: %d %v", code, body)
	}
}
