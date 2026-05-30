// Package integration_test contains end-to-end tests for the QuantumShield API.
//
// Tests in this package create a real httptest.Server (TCP listener, full
// middleware stack) and exercise complete user flows rather than individual
// handlers in isolation.
//
// Run with:
//
//	go test ./test/integration/...
//
// To skip slow tests (SLH-DSA keygen, Argon2id KDF):
//
//	go test -short ./test/integration/...
package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/pkg/api"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

// srv starts a new QuantumShield HTTP server backed by httptest.NewServer.
// The test server uses the real TCP stack (unlike httptest.NewRecorder) so
// middleware like request-ID injection and security headers is fully exercised.
func srv(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	s, err := api.New()
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	cleanup := func() {
		ts.Close()
		s.Close()
	}
	return ts, cleanup
}

// call performs an HTTP request against the test server and returns the
// decoded response body as map[string]any.
func call(t *testing.T, ts *httptest.Server, method, path string, body any, token string) (int, map[string]any) {
	t.Helper()
	var bodyR io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		bodyR = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyR)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result) //nolint:errcheck — errors surface via assertions
	return resp.StatusCode, result
}

// issueToken obtains a QST token with the requested roles.
// Fails the test if the token endpoint returns a non-200 response.
func issueToken(t *testing.T, ts *httptest.Server, userID string, roles []string) string {
	t.Helper()
	code, body := call(t, ts, "POST", "/auth/token", map[string]any{
		"user_id": userID,
		"roles":   roles,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("issue token: status %d body %v", code, body)
	}
	tok, ok := body["token"].(string)
	if !ok || tok == "" {
		t.Fatalf("issue token: no token in response: %v", body)
	}
	return tok
}

// ── Health ────────────────────────────────────────────────────────────────────

func TestIntegration_Health(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	code, body := call(t, ts, "GET", "/", nil, "")
	if code != http.StatusOK {
		t.Fatalf("GET /: status %d", code)
	}
	if body["status"] != "operational" {
		t.Errorf("status: %v", body["status"])
	}
	algos, ok := body["algorithms"].(map[string]any)
	if !ok {
		t.Fatalf("algorithms field missing or not a map: %v", body)
	}
	for _, algo := range []string{"kem", "signature", "slh_dsa"} {
		if _, exists := algos[algo]; !exists {
			t.Errorf("algorithms missing key %q", algo)
		}
	}
}

func TestIntegration_LiveAndReady(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	for _, path := range []string{"/health/live", "/health/ready"} {
		code, body := call(t, ts, "GET", path, nil, "")
		if code != http.StatusOK {
			t.Errorf("GET %s: status %d body %v", path, code, body)
		}
	}
}

// ── Auth flow ─────────────────────────────────────────────────────────────────

func TestIntegration_TokenIssueVerifyRevoke(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "alice", []string{"read", "write"})

	// Verify the issued token.
	code, body := call(t, ts, "POST", "/auth/verify", map[string]string{"token": token}, "")
	if code != http.StatusOK {
		t.Fatalf("verify: status %d body %v", code, body)
	}
	if body["valid"] != true {
		t.Errorf("valid: %v", body["valid"])
	}

	// Revoke.
	code, _ = call(t, ts, "POST", "/auth/revoke", map[string]string{"token": token}, token)
	if code != http.StatusOK {
		t.Fatalf("revoke: status %d", code)
	}

	// Verify after revocation — handleVerifyToken returns 401 for invalid/revoked tokens.
	code, body = call(t, ts, "POST", "/auth/verify", map[string]string{"token": token}, "")
	if code != http.StatusUnauthorized {
		t.Errorf("revoked token: expected 401, got %d body %v", code, body)
	}
	if body["valid"] != false {
		t.Errorf("token should be invalid after revocation, got %v", body["valid"])
	}
}

func TestIntegration_AuthRequired(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	// Protected endpoints must reject requests without a token.
	for _, ep := range []struct{ method, path string }{
		{"POST", "/keys/generate"},
		{"POST", "/encrypt"},
		{"POST", "/decrypt"},
		{"POST", "/sign"},
	} {
		code, _ := call(t, ts, ep.method, ep.path, map[string]any{}, "")
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d", ep.method, ep.path, code)
		}
	}
}

// ── Key generation, encrypt, decrypt ─────────────────────────────────────────

func TestIntegration_GenerateEncryptDecrypt(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "bob", []string{"read", "write"})

	// Generate a key pair.
	code, body := call(t, ts, "POST", "/keys/generate", map[string]string{"level": "standard"}, token)
	if code != http.StatusOK {
		t.Fatalf("generate: status %d body %v", code, body)
	}
	keyID, ok := body["key_id"].(string)
	if !ok || keyID == "" {
		t.Fatalf("no key_id: %v", body)
	}

	// Get public key.
	code, pubBody := call(t, ts, "GET", "/keys/"+keyID+"/public", nil, token)
	if code != http.StatusOK {
		t.Fatalf("get public key: status %d", code)
	}
	if pubBody["key_id"] != keyID {
		t.Errorf("key_id mismatch: %v", pubBody)
	}

	// Encrypt.
	plaintext := "integration-test-secret-2026"
	code, encBody := call(t, ts, "POST", "/encrypt", map[string]any{
		"key_id":    keyID,
		"plaintext": plaintext,
	}, token)
	if code != http.StatusOK {
		t.Fatalf("encrypt: status %d body %v", code, encBody)
	}
	enc, ok := encBody["encrypted"].(map[string]any)
	if !ok {
		t.Fatalf("no encrypted field: %v", encBody)
	}

	// Decrypt.
	code, decBody := call(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    keyID,
		"encrypted": enc,
	}, token)
	if code != http.StatusOK {
		t.Fatalf("decrypt: status %d body %v", code, decBody)
	}
	if decBody["plaintext"] != plaintext {
		t.Errorf("plaintext: got %q, want %q", decBody["plaintext"], plaintext)
	}
	if decBody["verified"] != true {
		t.Errorf("verified: %v", decBody["verified"])
	}
}

// ── ML-DSA sign / verify ──────────────────────────────────────────────────────

func TestIntegration_SignAndVerify(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "signer", []string{"write"})

	msg := "post-quantum signature integration test"
	code, body := call(t, ts, "POST", "/sign", map[string]string{"message": msg}, token)
	if code != http.StatusOK {
		t.Fatalf("sign: status %d body %v", code, body)
	}
	sig, _ := body["signature"].(string)
	pk, _ := body["public_key"].(string)
	if sig == "" || pk == "" {
		t.Fatalf("missing signature or public_key: %v", body)
	}

	// Verify (public endpoint — no auth).
	code, vbody := call(t, ts, "POST", "/verify-signature", map[string]string{
		"message":    msg,
		"signature":  sig,
		"public_key": pk,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("verify-signature: status %d", code)
	}
	if vbody["valid"] != true {
		t.Errorf("valid: %v", vbody["valid"])
	}

	// Tampered message must fail.
	code, vbody = call(t, ts, "POST", "/verify-signature", map[string]string{
		"message":    msg + "-tampered",
		"signature":  sig,
		"public_key": pk,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("verify-tampered: status %d", code)
	}
	if vbody["valid"] != false {
		t.Errorf("tampered message should not verify, got valid=%v", vbody["valid"])
	}
}

// ── SLH-DSA (FIPS 205) ────────────────────────────────────────────────────────

func TestIntegration_SLHDSASignVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("SLH-DSA keygen is slow; skipping in short mode")
	}
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "slh-user", []string{"write"})

	msg := "SLH-DSA FIPS 205 integration test"
	code, body := call(t, ts, "POST", "/slh-dsa/sign", map[string]string{
		"message": msg,
		"level":   "128f",
	}, token)
	if code != http.StatusOK {
		t.Fatalf("slh-dsa/sign: status %d body %v", code, body)
	}
	sig, _ := body["signature"].(string)
	pk, _ := body["public_key"].(string)
	if sig == "" || pk == "" {
		t.Fatalf("missing signature or public_key in SLH-DSA response: %v", body)
	}

	// Verify (public endpoint).
	code, vbody := call(t, ts, "POST", "/slh-dsa/verify", map[string]string{
		"message":    msg,
		"signature":  sig,
		"public_key": pk,
		"level":      "128f",
	}, "")
	if code != http.StatusOK {
		t.Fatalf("slh-dsa/verify: status %d", code)
	}
	if vbody["valid"] != true {
		t.Errorf("valid: %v", vbody["valid"])
	}
}

// ── Vault split / reconstruct ─────────────────────────────────────────────────

func TestIntegration_VaultSplitReconstruct(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "vault-user", []string{"write"})

	secret := base64.StdEncoding.EncodeToString([]byte("top-secret-payload-to-protect"))
	code, body := call(t, ts, "POST", "/vault/split", map[string]any{
		"secret":    secret,
		"n":         5,
		"threshold": 3,
	}, token)
	if code != http.StatusOK {
		t.Fatalf("vault/split: status %d body %v", code, body)
	}
	shardsRaw, ok := body["shards"].([]any)
	if !ok || len(shardsRaw) != 5 {
		t.Fatalf("expected 5 shards, got %v", body["shards"])
	}

	// Use first 3 shards to reconstruct.
	shards := shardsRaw[:3]
	code, rBody := call(t, ts, "POST", "/vault/reconstruct", map[string]any{
		"shards":    shards,
		"threshold": 3,
	}, token)
	if code != http.StatusOK {
		t.Fatalf("vault/reconstruct: status %d body %v", code, rBody)
	}
	recovered, _ := rBody["secret"].(string)
	if recovered != secret {
		t.Errorf("reconstructed secret mismatch: got %q, want %q", recovered, secret)
	}
}

// ── Key export / import ───────────────────────────────────────────────────────

func TestIntegration_KeyExportImport(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id in export/import is slow; skipping in short mode")
	}
	ts, cleanup := srv(t)
	defer cleanup()

	adminToken := issueToken(t, ts, "admin", []string{"read", "write", "admin"})

	// Generate a key.
	code, body := call(t, ts, "POST", "/keys/generate", map[string]string{"level": "standard"}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("generate: status %d body %v", code, body)
	}
	keyID := body["key_id"].(string)

	// Export with a password.
	exportPw := "export-integration-test-password-2026"
	code, exportBody := call(t, ts, "POST", "/keys/"+keyID+"/export",
		map[string]string{"password": exportPw}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("export: status %d body %v", code, exportBody)
	}
	if exportBody["version"] == nil {
		t.Fatalf("export response missing version: %v", exportBody)
	}
	if exportBody["wrapped_key"] == nil {
		t.Fatalf("export response missing wrapped_key: %v", exportBody)
	}

	// Import under a new key ID.
	newKeyID := "imported-integration-key"
	code, importBody := call(t, ts, "POST", "/keys/import", map[string]any{
		"key_id":   newKeyID,
		"password": exportPw,
		"wrapped":  exportBody,
	}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("import: status %d body %v", code, importBody)
	}
	if importBody["imported"] != true {
		t.Errorf("imported: %v", importBody["imported"])
	}

	// Encrypt with original key, decrypt with imported key (same underlying key).
	plaintext := "cross-key-roundtrip"
	code, encBody := call(t, ts, "POST", "/encrypt", map[string]any{
		"key_id":    keyID,
		"plaintext": plaintext,
	}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("encrypt with original key: status %d", code)
	}
	enc := encBody["encrypted"]

	code, decBody := call(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    newKeyID,
		"encrypted": enc,
	}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("decrypt with imported key: status %d body %v", code, decBody)
	}
	if decBody["plaintext"] != plaintext {
		t.Errorf("plaintext after import roundtrip: got %q, want %q", decBody["plaintext"], plaintext)
	}
}

func TestIntegration_KeyImport_WrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id is slow; skipping in short mode")
	}
	ts, cleanup := srv(t)
	defer cleanup()

	adminToken := issueToken(t, ts, "admin", []string{"read", "write", "admin"})

	// Generate + export.
	code, body := call(t, ts, "POST", "/keys/generate", map[string]string{}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("generate: %d", code)
	}
	keyID := body["key_id"].(string)

	code, exportBody := call(t, ts, "POST", "/keys/"+keyID+"/export",
		map[string]string{"password": "correct-password"}, adminToken)
	if code != http.StatusOK {
		t.Fatalf("export: %d %v", code, exportBody)
	}

	// Import with wrong password — must fail.
	code, _ = call(t, ts, "POST", "/keys/import", map[string]any{
		"key_id":   "should-not-be-created",
		"password": "wrong-password",
		"wrapped":  exportBody,
	}, adminToken)
	if code != http.StatusBadRequest {
		t.Errorf("wrong password: expected 400, got %d", code)
	}
}

// ── Post-quantum CA ───────────────────────────────────────────────────────────

func TestIntegration_CALifecycle(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	adminToken := issueToken(t, ts, "admin", []string{"read", "write", "admin"})
	writeToken := issueToken(t, ts, "writer", []string{"read", "write"})

	// GET /ca/certificate before init — must fail (503).
	code, _ := call(t, ts, "GET", "/ca/certificate", nil, "")
	if code != http.StatusServiceUnavailable {
		t.Errorf("certificate before init: expected 503, got %d", code)
	}

	// Init CA.
	code, body := call(t, ts, "POST", "/ca/init",
		map[string]string{"subject": "CN=Integration Test Root CA,O=Example Corp"},
		adminToken)
	if code != http.StatusOK {
		t.Fatalf("ca/init: status %d body %v", code, body)
	}
	if body["status"] != "initialised" {
		t.Errorf("status: %v", body["status"])
	}

	// GET the CA certificate (public, no auth).
	code, caCert := call(t, ts, "GET", "/ca/certificate", nil, "")
	if code != http.StatusOK {
		t.Fatalf("ca/certificate: status %d", code)
	}
	if caCert["subject"] != "CN=Integration Test Root CA,O=Example Corp" {
		t.Errorf("ca cert subject: %v", caCert["subject"])
	}
	if caCert["is_ca"] != true {
		t.Errorf("is_ca: %v", caCert["is_ca"])
	}

	// Issue a leaf certificate.
	// Use a dummy ML-KEM-768 public key (random bytes — CA doesn't validate the key material).
	fakeKey := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%0100d", 0))) // 100 zero-char string
	code, leafCert := call(t, ts, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=server.example.com,O=Example Corp",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
		"ttl_days":        90,
	}, writeToken)
	if code != http.StatusOK {
		t.Fatalf("ca/sign: status %d body %v", code, leafCert)
	}
	if leafCert["subject"] != "CN=server.example.com,O=Example Corp" {
		t.Errorf("leaf subject: %v", leafCert["subject"])
	}
	if leafCert["signature"] == "" || leafCert["signature"] == nil {
		t.Error("leaf cert has no signature")
	}

	// Verify the leaf certificate (public endpoint).
	code, verBody := call(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": leafCert}, "")
	if code != http.StatusOK {
		t.Fatalf("ca/verify: status %d body %v", code, verBody)
	}
	if verBody["valid"] != true {
		t.Errorf("valid: %v verr: %v", verBody["valid"], verBody["error"])
	}

	// Tamper with the leaf cert — verification must fail.
	leafCert["subject"] = "CN=attacker.example.com"
	code, verBody = call(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": leafCert}, "")
	if code != http.StatusOK {
		t.Fatalf("ca/verify tampered: status %d", code)
	}
	if verBody["valid"] != false {
		t.Errorf("tampered cert should not verify, got valid=%v", verBody["valid"])
	}
}

// ── GET /keys ─────────────────────────────────────────────────────────────────

func TestIntegration_ListKeys(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "lister", []string{"read", "write"})

	// Empty at start.
	code, body := call(t, ts, "GET", "/keys", nil, token)
	if code != http.StatusOK {
		t.Fatalf("GET /keys: status %d", code)
	}
	if body["count"].(float64) != 0 {
		t.Errorf("count before generate: %v", body["count"])
	}

	// Generate two keys.
	call(t, ts, "POST", "/keys/generate", map[string]string{}, token)
	call(t, ts, "POST", "/keys/generate", map[string]string{}, token)

	code, body = call(t, ts, "GET", "/keys", nil, token)
	if code != http.StatusOK {
		t.Fatalf("GET /keys: status %d", code)
	}
	if body["count"].(float64) != 2 {
		t.Errorf("count after generate: %v (want 2)", body["count"])
	}
}

// ── CA CRL ────────────────────────────────────────────────────────────────────

func TestIntegration_CACRLRevocation(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	adminToken := issueToken(t, ts, "admin", []string{"read", "write", "admin"})
	writeToken := issueToken(t, ts, "writer", []string{"read", "write"})

	// Init CA.
	call(t, ts, "POST", "/ca/init",
		map[string]string{"subject": "CN=CRL Integration CA,O=Example Corp"}, adminToken)

	// Issue a cert.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("crl-integration-test-pk"))
	_, leafCert := call(t, ts, "POST", "/ca/sign", map[string]any{
		"subject": "CN=revocable.example.com", "public_key": fakeKey,
		"public_key_type": "ML-KEM-768",
	}, writeToken)
	serial := leafCert["serial"].(string)

	// Verify before revocation — must pass.
	code, verBody := call(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": leafCert}, "")
	if code != http.StatusOK || verBody["valid"] != true {
		t.Fatalf("pre-revoke verify: code=%d valid=%v", code, verBody["valid"])
	}

	// Check CRL — empty.
	_, crlBody := call(t, ts, "GET", "/ca/crl", nil, "")
	if len(crlBody["entries"].([]any)) != 0 {
		t.Errorf("CRL should be empty before revocation")
	}

	// Revoke.
	code, rBody := call(t, ts, "POST", "/ca/revoke",
		map[string]string{"serial": serial}, adminToken)
	if code != http.StatusOK || rBody["revoked"] != true {
		t.Fatalf("revoke: code=%d body=%v", code, rBody)
	}

	// CRL now has one entry.
	_, crlBody = call(t, ts, "GET", "/ca/crl", nil, "")
	entries := crlBody["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("CRL entries after revoke: %d (want 1)", len(entries))
	}

	// Verify after revocation — must fail.
	code, verBody = call(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": leafCert}, "")
	if code != http.StatusOK || verBody["valid"] != false {
		t.Errorf("post-revoke verify: code=%d valid=%v", code, verBody["valid"])
	}
}

// ── KDF ───────────────────────────────────────────────────────────────────────

func TestIntegration_KDF(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "kdf-user", []string{"write"})

	// Get a random salt.
	code, saltBody := call(t, ts, "POST", "/kdf/salt", nil, token)
	if code != http.StatusOK {
		t.Fatalf("kdf/salt: status %d", code)
	}
	salt, _ := saltBody["salt"].(string)
	if salt == "" {
		t.Fatal("no salt in response")
	}

	// Derive via HKDF.
	secretB64 := base64.StdEncoding.EncodeToString([]byte("test-secret-material"))
	code, hkdfBody := call(t, ts, "POST", "/kdf/hkdf", map[string]any{
		"secret":  secretB64,
		"salt":    salt,
		"info":    "integration-test-2026",
		"key_len": 32,
	}, token)
	if code != http.StatusOK {
		t.Fatalf("kdf/hkdf: status %d body %v", code, hkdfBody)
	}
	derived, _ := hkdfBody["key"].(string)
	if derived == "" {
		t.Fatal("no derived key in HKDF response")
	}
	keyLen := int(hkdfBody["key_len"].(float64))
	if keyLen != 32 {
		t.Errorf("key_len: %d, want 32", keyLen)
	}
}

// ── Audit log ─────────────────────────────────────────────────────────────────

func TestIntegration_AuditChain(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	token := issueToken(t, ts, "audit-user", []string{"read", "write"})

	// Perform a few operations to populate the audit log.
	call(t, ts, "POST", "/keys/generate", map[string]string{}, token) //nolint:errcheck
	call(t, ts, "POST", "/sign", map[string]string{"message": "hello"}, token)

	// Verify audit chain integrity.
	code, body := call(t, ts, "GET", "/audit/verify", nil, token)
	if code != http.StatusOK {
		t.Fatalf("audit/verify: status %d", code)
	}
	if body["valid"] != true {
		t.Errorf("audit chain invalid: %v", body)
	}

	// Retrieve entries.
	code, body = call(t, ts, "GET", "/audit/entries", nil, token)
	if code != http.StatusOK {
		t.Fatalf("audit/entries: status %d", code)
	}
	count, _ := body["count"].(float64)
	if count == 0 {
		t.Error("expected non-zero audit log entries")
	}
}

// ── Metrics endpoint ──────────────────────────────────────────────────────────

func TestIntegration_MetricsEndpoint(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	// Perform a request so there is something to observe.
	call(t, ts, "GET", "/health/live", nil, "") //nolint:errcheck

	// The metrics endpoint returns Prometheus text format, not JSON.
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("metrics response is empty")
	}
	text := string(body)
	for _, metric := range []string{"qs_http_requests_total", "qs_http_request_duration_seconds"} {
		if !contains(text, metric) {
			t.Errorf("metrics response missing %q", metric)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
