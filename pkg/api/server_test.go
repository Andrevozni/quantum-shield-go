package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/pkg/api"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*api.Server, http.Handler) {
	t.Helper()
	srv, err := api.New()
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv, srv.Handler()
}

func do(t *testing.T, h http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getToken(t *testing.T, h http.Handler) string {
	t.Helper()
	rr := do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "test-user",
		"roles":   []string{"read", "write"},
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("issue token: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	tok, ok := resp["token"].(string)
	if !ok || tok == "" {
		t.Fatal("no token in response")
	}
	return tok
}

// ── Health ────────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("health: status %d", rr.Code)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "operational" {
		t.Errorf("status: %v", resp["status"])
	}
}

func TestLive(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/health/live", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("live: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "alive" {
		t.Errorf("live status: %v", resp["status"])
	}
}

func TestReady_IncludesFIPSStatus(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/health/ready", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ready: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ready" {
		t.Errorf("ready status: %v", resp["status"])
	}
	fipsStatus, ok := resp["fips_status"].(string)
	if !ok || fipsStatus == "" {
		t.Errorf("fips_status missing or empty in /health/ready: %v", resp)
	}
}

func TestFIPS_ReturnsReport(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/health/fips", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("health/fips: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	// Top-level fields.
	if resp["overall"] == nil {
		t.Error("fips report missing 'overall' field")
	}
	if resp["overall"] != "pass" {
		t.Errorf("fips overall: %v (all algorithms should be operational)", resp["overall"])
	}
	if resp["timestamp"] == nil {
		t.Error("fips report missing 'timestamp' field")
	}
	if resp["go_version"] == nil {
		t.Error("fips report missing 'go_version' field")
	}

	// Probes array must be non-empty.
	probes, ok := resp["probes"].([]any)
	if !ok || len(probes) == 0 {
		t.Fatalf("fips report 'probes' missing or empty: %v", resp["probes"])
	}

	// Every probe must have algorithm, standard, status, duration_ms.
	for i, raw := range probes {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("probe[%d] is not an object", i)
			continue
		}
		if p["algorithm"] == nil {
			t.Errorf("probe[%d] missing 'algorithm'", i)
		}
		if p["standard"] == nil {
			t.Errorf("probe[%d] missing 'standard'", i)
		}
		if p["status"] == nil {
			t.Errorf("probe[%d] missing 'status'", i)
		}
		if p["status"] != "pass" {
			t.Errorf("probe[%d] (%v) failed: %v", i, p["algorithm"], p["error"])
		}
	}
}

func TestFIPS_IsPublic(t *testing.T) {
	_, h := newTestServer(t)
	// No token — must still return a response (public endpoint).
	rr := do(t, h, "GET", "/health/fips", nil, "")
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Errorf("GET /health/fips should be public, got %d", rr.Code)
	}
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func TestIssueAndVerifyToken(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "POST", "/auth/verify", map[string]string{"token": token}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["valid"] != true {
		t.Errorf("valid: %v", resp["valid"])
	}
}

func TestRevokeToken(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "POST", "/auth/revoke", map[string]string{"token": token}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status %d", rr.Code)
	}

	// Revoked token must fail verification
	rr = do(t, h, "POST", "/auth/verify", map[string]string{"token": token}, "")
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["valid"] != false {
		t.Fatal("revoked token should not be valid")
	}
}

func TestInvalidUserID(t *testing.T) {
	_, h := newTestServer(t)
	for _, bad := range []string{"", "a b", "../../etc/passwd", "x@y;z"} {
		rr := do(t, h, "POST", "/auth/token", map[string]any{
			"user_id": bad, "roles": []string{"read"},
		}, "")
		if rr.Code == http.StatusOK {
			t.Errorf("bad user_id %q should be rejected", bad)
		}
	}
}

// ── Keys + Encrypt/Decrypt ────────────────────────────────────────────────────

func TestGenerateKeyAndEncryptDecrypt(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	// Generate key
	rr := do(t, h, "POST", "/keys/generate", map[string]string{"level": "standard"}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("generate_key: status %d body %s", rr.Code, rr.Body)
	}
	var keyResp map[string]any
	json.NewDecoder(rr.Body).Decode(&keyResp)
	keyID := keyResp["key_id"].(string)

	// Encrypt
	plaintext := "Transfer EUR 500,000 — classified"
	rr = do(t, h, "POST", "/encrypt", map[string]any{
		"key_id":    keyID,
		"plaintext": plaintext,
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("encrypt: status %d body %s", rr.Code, rr.Body)
	}
	// encrypted object now contains created_at (int64) alongside base64 strings.
	var encResp struct {
		Encrypted map[string]any `json:"encrypted"`
	}
	json.NewDecoder(rr.Body).Decode(&encResp)

	// Decrypt — pass the encrypted object back verbatim; created_at is required
	// because it is bound into the AEAD tag.
	rr = do(t, h, "POST", "/decrypt", map[string]any{
		"key_id":    keyID,
		"encrypted": encResp.Encrypted,
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("decrypt: status %d body %s", rr.Code, rr.Body)
	}
	var decResp map[string]any
	json.NewDecoder(rr.Body).Decode(&decResp)
	if decResp["plaintext"] != plaintext {
		t.Errorf("plaintext mismatch: got %q", decResp["plaintext"])
	}
}

// ── Sign / Verify signature ───────────────────────────────────────────────────

func TestSignAndVerify(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	// Sign
	msg := "Legal document — signed with ML-DSA"
	rr := do(t, h, "POST", "/sign", map[string]string{"message": msg}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign: status %d", rr.Code)
	}
	var signResp map[string]string
	json.NewDecoder(rr.Body).Decode(&signResp)

	// Verify
	rr = do(t, h, "POST", "/verify-signature", map[string]string{
		"message":    msg,
		"signature":  signResp["signature"],
		"public_key": signResp["public_key"],
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("verify_sig: status %d", rr.Code)
	}
	var verResp map[string]any
	json.NewDecoder(rr.Body).Decode(&verResp)
	if verResp["valid"] != true {
		t.Errorf("valid: %v", verResp["valid"])
	}
}

// ── Vault ─────────────────────────────────────────────────────────────────────

func TestVaultSplitReconstruct(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	secret := []byte("top-secret-private-key-material-32b")
	secretB64 := base64.StdEncoding.EncodeToString(secret)

	// Split
	rr := do(t, h, "POST", "/vault/split", map[string]any{
		"secret":    secretB64,
		"n":         5,
		"threshold": 3,
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("vault_split: status %d body %s", rr.Code, rr.Body)
	}
	var splitResp map[string]any
	json.NewDecoder(rr.Body).Decode(&splitResp)
	shards := splitResp["shards"].([]any)
	if len(shards) != 5 {
		t.Fatalf("expected 5 shards, got %d", len(shards))
	}

	// Reconstruct with 3 of 5
	rr = do(t, h, "POST", "/vault/reconstruct", map[string]any{
		"shards":    shards[:3],
		"threshold": 3,
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("vault_reconstruct: status %d body %s", rr.Code, rr.Body)
	}
	var recResp map[string]string
	json.NewDecoder(rr.Body).Decode(&recResp)
	recovered, _ := base64.StdEncoding.DecodeString(recResp["secret"])
	if string(recovered) != string(secret) {
		t.Errorf("secret mismatch: got %q", recovered)
	}
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func TestAuditVerify(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	// Perform a few operations to populate the audit log
	do(t, h, "POST", "/keys/generate", map[string]string{"level": "standard"}, token)

	rr := do(t, h, "GET", "/audit/verify", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit_verify: status %d", rr.Code)
	}
	var result map[string]any
	json.NewDecoder(rr.Body).Decode(&result)
	if result["valid"] != true {
		t.Errorf("audit chain invalid: %v", result)
	}
}

// ── Security: middleware ──────────────────────────────────────────────────────

func TestNoAuthReturns401(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "POST", "/keys/generate", map[string]string{"level": "standard"}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: expected 401, got %d", rr.Code)
	}
}

func TestFormPostRejected(t *testing.T) {
	_, h := newTestServer(t)
	req := httptest.NewRequest("POST", "/auth/token", bytes.NewBufferString("user_id=alice&roles=admin"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form POST: expected 415, got %d", rr.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/", nil, "")
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store, no-cache, must-revalidate",
		"Server":                 "QuantumShield",
	}
	for k, want := range headers {
		if got := rr.Header().Get(k); got != want {
			t.Errorf("header %s: got %q, want %q", k, got, want)
		}
	}
}

func TestNotFound(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/redirect?url=https://evil.example.com", nil, "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("open redirect path: expected 404, got %d", rr.Code)
	}
}

// ── Request ID ────────────────────────────────────────────────────────────────

func TestRequestID_GeneratedWhenAbsent(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/", nil, "")
	id := rr.Header().Get("X-Request-ID")
	if id == "" {
		t.Error("X-Request-ID header must be set in response")
	}
}

func TestRequestID_PropagatedFromClient(t *testing.T) {
	_, h := newTestServer(t)
	req := httptest.NewRequest("GET", "/health/live", nil)
	req.Header.Set("X-Request-ID", "client-trace-001")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("X-Request-ID"); got != "client-trace-001" {
		t.Errorf("X-Request-ID not propagated: got %q", got)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	_, h := newTestServer(t)
	ids := make(map[string]bool, 10)
	for range 10 {
		rr := do(t, h, "GET", "/health/live", nil, "")
		id := rr.Header().Get("X-Request-ID")
		if id == "" {
			t.Fatal("missing X-Request-ID")
		}
		if ids[id] {
			t.Fatalf("duplicate X-Request-ID: %s", id)
		}
		ids[id] = true
	}
}

// ── RBAC ──────────────────────────────────────────────────────────────────────

func getTokenWithRoles(t *testing.T, h http.Handler, roles []string) string {
	t.Helper()
	rr := do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "rbac-test",
		"roles":   roles,
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("issue token: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	return resp["token"].(string)
}

func TestRBAC_ReadTokenCannotWrite(t *testing.T) {
	_, h := newTestServer(t)
	readToken := getTokenWithRoles(t, h, []string{"read"})

	// "read" role cannot generate keys (requires "write")
	rr := do(t, h, "POST", "/keys/generate", map[string]string{"level": "standard"}, readToken)
	if rr.Code != http.StatusForbidden {
		t.Errorf("read token on write endpoint: expected 403, got %d — body: %s", rr.Code, rr.Body)
	}
}

func TestRBAC_WriteTokenCanWrite(t *testing.T) {
	_, h := newTestServer(t)
	writeToken := getTokenWithRoles(t, h, []string{"write"})

	rr := do(t, h, "POST", "/keys/generate", map[string]string{"level": "standard"}, writeToken)
	if rr.Code != http.StatusOK {
		t.Errorf("write token on write endpoint: expected 200, got %d — body: %s", rr.Code, rr.Body)
	}
}

func TestRBAC_ReadTokenCanReadAudit(t *testing.T) {
	_, h := newTestServer(t)
	readToken := getTokenWithRoles(t, h, []string{"read"})

	rr := do(t, h, "GET", "/audit/verify", nil, readToken)
	if rr.Code != http.StatusOK {
		t.Errorf("read token on audit: expected 200, got %d — body: %s", rr.Code, rr.Body)
	}
}

func TestRBAC_NonAdminCannotAccessKeystore(t *testing.T) {
	_, h := newTestServer(t)
	writeToken := getTokenWithRoles(t, h, []string{"read", "write"})

	// No "admin" role → 503 (keystore not configured) or 403 (no admin role)
	// Since keystore isn't configured in test server, we get 503 after RBAC passes for admin.
	// But write token doesn't have admin → should get 403 before even checking keystore.
	rr := do(t, h, "GET", "/keystore", nil, writeToken)
	if rr.Code != http.StatusForbidden {
		t.Errorf("non-admin on keystore: expected 403, got %d — body: %s", rr.Code, rr.Body)
	}
}

func TestRBAC_AdminTokenCanAccessKeystore(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	// Admin role passes RBAC, but keystore is not configured → 503
	rr := do(t, h, "GET", "/keystore", nil, adminToken)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("admin on keystore (not configured): expected 503, got %d — body: %s", rr.Code, rr.Body)
	}
}

// ── Bootstrap secret ──────────────────────────────────────────────────────────

func TestBootstrapSecret_OpenWhenNotSet(t *testing.T) {
	// Default test server has no bootstrap secret — /auth/token must be open
	_, h := newTestServer(t)
	rr := do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "alice", "roles": []string{"read"},
	}, "")
	if rr.Code != http.StatusOK {
		t.Errorf("no bootstrap secret: expected 200, got %d", rr.Code)
	}
}

func TestBootstrapSecret_ProtectedWhenSet(t *testing.T) {
	t.Setenv("BOOTSTRAP_SECRET", "super-secret-bootstrap-key")
	srv, err := api.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	// Without secret → 401
	rr := do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "alice", "roles": []string{"read"},
	}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("without bootstrap secret: expected 401, got %d", rr.Code)
	}

	// With wrong secret → 401
	rr = do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "alice", "roles": []string{"read"},
	}, "wrong-secret")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("with wrong bootstrap secret: expected 401, got %d", rr.Code)
	}

	// With correct secret → 200
	req := httptest.NewRequest("POST", "/auth/token", mustJSON(t, map[string]any{
		"user_id": "alice", "roles": []string{"read"},
	}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-bootstrap-key")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("with correct bootstrap secret: expected 200, got %d — body: %s", rr.Code, rr.Body)
	}
}

// ── KDF endpoints ─────────────────────────────────────────────────────────────

func TestKDFSalt(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "POST", "/kdf/salt", map[string]any{}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("kdf/salt: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	saltB64, ok := resp["salt"].(string)
	if !ok || saltB64 == "" {
		t.Error("salt field missing or empty")
	}
	saltBytes, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil || len(saltBytes) != 32 {
		t.Errorf("salt must be 32 bytes, got %d", len(saltBytes))
	}
}

func TestKDFHKDF(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	secret := base64.StdEncoding.EncodeToString(make([]byte, 32))
	salt := base64.StdEncoding.EncodeToString(make([]byte, 32))

	rr := do(t, h, "POST", "/kdf/hkdf", map[string]any{
		"secret":  secret,
		"salt":    salt,
		"info":    "test-context",
		"key_len": 32,
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("kdf/hkdf: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	keyB64, ok := resp["key"].(string)
	if !ok || keyB64 == "" {
		t.Error("key field missing")
	}
	keyBytes, _ := base64.StdEncoding.DecodeString(keyB64)
	if len(keyBytes) != 32 {
		t.Errorf("derived key must be 32 bytes, got %d", len(keyBytes))
	}
}

func TestKDFHKDF_Deterministic(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	req := map[string]any{
		"secret":  base64.StdEncoding.EncodeToString([]byte("fixed-secret-material")),
		"salt":    base64.StdEncoding.EncodeToString([]byte("fixed-salt-value-here")),
		"info":    "test",
		"key_len": 32,
	}

	rr1 := do(t, h, "POST", "/kdf/hkdf", req, token)
	rr2 := do(t, h, "POST", "/kdf/hkdf", req, token)

	var r1, r2 map[string]any
	json.NewDecoder(rr1.Body).Decode(&r1)
	json.NewDecoder(rr2.Body).Decode(&r2)

	if r1["key"] != r2["key"] {
		t.Error("HKDF must be deterministic for same inputs")
	}
}

func TestKDFArgon2(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	salt := make([]byte, 32)
	rr := do(t, h, "POST", "/kdf/argon2", map[string]any{
		"password": base64.StdEncoding.EncodeToString([]byte("test-password")),
		"salt":     base64.StdEncoding.EncodeToString(salt),
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("kdf/argon2: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	keyB64, ok := resp["key"].(string)
	if !ok || keyB64 == "" {
		t.Error("key field missing")
	}
	keyBytes, _ := base64.StdEncoding.DecodeString(keyB64)
	if len(keyBytes) != 32 {
		t.Errorf("Argon2id key must be 32 bytes, got %d", len(keyBytes))
	}
}

func TestKDFArgon2_ShortSaltRejected(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "POST", "/kdf/argon2", map[string]any{
		"password": base64.StdEncoding.EncodeToString([]byte("password")),
		"salt":     base64.StdEncoding.EncodeToString([]byte("short")), // < 16 bytes
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("short salt: expected 400, got %d", rr.Code)
	}
}

// ── SLH-DSA (NIST FIPS 205) ──────────────────────────────────────────────────

func TestSLHDSASignAndVerify(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	msg := "Authorised by SLH-DSA (hash-based post-quantum signature)"

	// Sign with default level (128f).
	rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{"message": msg}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("slh-dsa/sign: status %d body %s", rr.Code, rr.Body)
	}
	var signResp map[string]any
	json.NewDecoder(rr.Body).Decode(&signResp)

	alg, _ := signResp["algorithm"].(string)
	if alg != "SLH-DSA-SHA2-128f" {
		t.Errorf("algorithm: got %q, want SLH-DSA-SHA2-128f", alg)
	}
	sig, _ := signResp["signature"].(string)
	pk, _ := signResp["public_key"].(string)
	if sig == "" || pk == "" {
		t.Fatalf("missing signature or public_key in response")
	}

	// Verify — public endpoint, no token.
	rr = do(t, h, "POST", "/slh-dsa/verify", map[string]string{
		"message":    msg,
		"signature":  sig,
		"public_key": pk,
		"level":      "128f",
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("slh-dsa/verify: status %d body %s", rr.Code, rr.Body)
	}
	var verResp map[string]any
	json.NewDecoder(rr.Body).Decode(&verResp)
	if verResp["valid"] != true {
		t.Errorf("expected valid=true, got %v", verResp["valid"])
	}
}

func TestSLHDSAVerify_TamperedMessage(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	msg := "original message"
	rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{"message": msg}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign: status %d", rr.Code)
	}
	var signResp map[string]any
	json.NewDecoder(rr.Body).Decode(&signResp)

	rr = do(t, h, "POST", "/slh-dsa/verify", map[string]string{
		"message":    "tampered message",
		"signature":  signResp["signature"].(string),
		"public_key": signResp["public_key"].(string),
		"level":      "128f",
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: status %d", rr.Code)
	}
	var verResp map[string]any
	json.NewDecoder(rr.Body).Decode(&verResp)
	if verResp["valid"] == true {
		t.Error("tampered message should not verify")
	}
}

func TestSLHDSASign_AllLevels(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	// Test all supported level strings round-trip through the API.
	levels := []string{"128f", "128s"}
	msg := "level test message"
	for _, lvl := range levels {
		t.Run(lvl, func(t *testing.T) {
			rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{
				"message": msg,
				"level":   lvl,
			}, token)
			if rr.Code != http.StatusOK {
				t.Fatalf("sign level %s: status %d body %s", lvl, rr.Code, rr.Body)
			}
			var signResp map[string]any
			json.NewDecoder(rr.Body).Decode(&signResp)

			rr = do(t, h, "POST", "/slh-dsa/verify", map[string]string{
				"message":    msg,
				"signature":  signResp["signature"].(string),
				"public_key": signResp["public_key"].(string),
				"level":      lvl,
			}, "")
			if rr.Code != http.StatusOK {
				t.Fatalf("verify level %s: status %d", lvl, rr.Code)
			}
			var verResp map[string]any
			json.NewDecoder(rr.Body).Decode(&verResp)
			if verResp["valid"] != true {
				t.Errorf("level %s: expected valid=true, got %v", lvl, verResp["valid"])
			}
		})
	}
}

func TestSLHDSASign_InvalidLevel(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{
		"message": "test",
		"level":   "999x",
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid level: expected 400, got %d", rr.Code)
	}
}

func TestSLHDSAVerify_RequiresNoAuth(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	// Sign to get a real signature.
	rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{"message": "auth test"}, token)
	if rr.Code != http.StatusOK {
		t.Fatal("sign failed")
	}
	var signResp map[string]any
	json.NewDecoder(rr.Body).Decode(&signResp)

	// Verify without any token — must succeed (public endpoint).
	rr = do(t, h, "POST", "/slh-dsa/verify", map[string]string{
		"message":    "auth test",
		"signature":  signResp["signature"].(string),
		"public_key": signResp["public_key"].(string),
	}, "") // empty token
	if rr.Code != http.StatusOK {
		t.Errorf("/slh-dsa/verify must be public; got status %d", rr.Code)
	}
}

func TestSLHDSASign_RequiresAuth(t *testing.T) {
	_, h := newTestServer(t)

	// No token → 401.
	rr := do(t, h, "POST", "/slh-dsa/sign", map[string]string{"message": "test"}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("/slh-dsa/sign without token: expected 401, got %d", rr.Code)
	}
}

// ── Keystore endpoints (not configured — 503) ─────────────────────────────────

func TestKeystoreNotConfigured_Returns503(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	for _, path := range []string{
		"/keystore",
		"/keystore/some-key",
	} {
		rr := do(t, h, "GET", path, nil, adminToken)
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s without keystore: expected 503, got %d", path, rr.Code)
		}
	}
}

// ── GET /keys ─────────────────────────────────────────────────────────────────

func TestListKeys_EmptyInitially(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	rr := do(t, h, "GET", "/keys", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /keys: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("count: %v", resp["count"])
	}
	if resp["backend"] != "in-memory" {
		t.Errorf("backend: %v", resp["backend"])
	}
}

func TestListKeys_AfterGenerate(t *testing.T) {
	_, h := newTestServer(t)
	token := getToken(t, h)

	do(t, h, "POST", "/keys/generate", map[string]string{}, token)
	do(t, h, "POST", "/keys/generate", map[string]string{}, token)

	rr := do(t, h, "GET", "/keys", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /keys: status %d", rr.Code)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["count"].(float64) != 2 {
		t.Errorf("count: %v (want 2)", resp["count"])
	}
	keys, ok := resp["keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Errorf("keys array: %v", resp["keys"])
	}
}

func TestListKeys_RequiresAuth(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(t, h, "GET", "/keys", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /keys without token: expected 401, got %d", rr.Code)
	}
}

// ── Key export / import ───────────────────────────────────────────────────────

func TestKeyExport_ExportAndImport(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"read", "write", "admin"})

	// Generate a key.
	rr := do(t, h, "POST", "/keys/generate", map[string]string{}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: status %d", rr.Code)
	}
	var genResp map[string]any
	json.NewDecoder(rr.Body).Decode(&genResp)
	keyID := genResp["key_id"].(string)

	// Export.
	pw := "test-export-password-2026"
	rr = do(t, h, "POST", "/keys/"+keyID+"/export",
		map[string]string{"password": pw}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("export: status %d body %s", rr.Code, rr.Body)
	}
	var envelope map[string]any
	json.NewDecoder(rr.Body).Decode(&envelope)

	if envelope["version"] == nil || envelope["wrapped_key"] == nil {
		t.Fatalf("export missing fields: %v", envelope)
	}
	if envelope["kdf"] != "argon2id" {
		t.Errorf("kdf: %v", envelope["kdf"])
	}

	// Import under a new key_id.
	rr = do(t, h, "POST", "/keys/import", map[string]any{
		"key_id":   "imported-key-test",
		"password": pw,
		"wrapped":  envelope,
	}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("import: status %d body %s", rr.Code, rr.Body)
	}
	var importResp map[string]any
	json.NewDecoder(rr.Body).Decode(&importResp)
	if importResp["imported"] != true {
		t.Errorf("imported: %v", importResp["imported"])
	}
	// Public keys must match (same underlying key).
	if importResp["public_key"] != genResp["public_key"] {
		t.Errorf("imported public_key differs from original:\norig: %v\ngot:  %v",
			genResp["public_key"], importResp["public_key"])
	}
}

func TestKeyExport_WrongPasswordFails(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"read", "write", "admin"})

	rr := do(t, h, "POST", "/keys/generate", map[string]string{}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: status %d", rr.Code)
	}
	var genResp map[string]any
	json.NewDecoder(rr.Body).Decode(&genResp)
	keyID := genResp["key_id"].(string)

	rr = do(t, h, "POST", "/keys/"+keyID+"/export",
		map[string]string{"password": "correct"}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("export: %d", rr.Code)
	}
	var envelope map[string]any
	json.NewDecoder(rr.Body).Decode(&envelope)

	// Wrong password.
	rr = do(t, h, "POST", "/keys/import", map[string]any{
		"key_id":   "bad-import",
		"password": "incorrect",
		"wrapped":  envelope,
	}, adminToken)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("wrong password: expected 400, got %d", rr.Code)
	}
}

func TestKeyExport_MissingPassword(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	rr := do(t, h, "POST", "/keys/generate", map[string]string{}, adminToken)
	var genResp map[string]any
	json.NewDecoder(rr.Body).Decode(&genResp)

	rr = do(t, h, "POST", "/keys/"+genResp["key_id"].(string)+"/export",
		map[string]string{"password": ""}, adminToken)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing password: expected 400, got %d", rr.Code)
	}
}

func TestKeyExport_NotFound(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	rr := do(t, h, "POST", "/keys/nonexistent-key-id/export",
		map[string]string{"password": "pw"}, adminToken)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ── Post-quantum CA ───────────────────────────────────────────────────────────

func TestCAInit_CreatesRootCert(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	rr := do(t, h, "POST", "/ca/init",
		map[string]string{"subject": "CN=Test CA,O=Example"}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/init: status %d body %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "initialised" {
		t.Errorf("status: %v", resp["status"])
	}
}

func TestCAInit_EmptySubject(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	rr := do(t, h, "POST", "/ca/init", map[string]string{"subject": ""}, adminToken)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty subject: expected 400, got %d", rr.Code)
	}
}

func TestCASign_IssuesLeafCert(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	// Init first.
	rr := do(t, h, "POST", "/ca/init",
		map[string]string{"subject": "CN=Signing CA"}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/init: %d", rr.Code)
	}

	// Issue a leaf cert.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("fake-public-key-material-here"))
	rr = do(t, h, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=leaf.example.com",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
		"ttl_days":        90,
	}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/sign: status %d body %s", rr.Code, rr.Body)
	}
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)
	if cert["signature"] == nil || cert["signature"] == "" {
		t.Error("leaf cert has no signature")
	}
	if cert["subject"] != "CN=leaf.example.com" {
		t.Errorf("subject: %v", cert["subject"])
	}
	if cert["is_ca"] != false {
		t.Errorf("is_ca should be false for leaf cert, got %v", cert["is_ca"])
	}
}

func TestCASign_BeforeInit(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write"})

	fakeKey := base64.StdEncoding.EncodeToString([]byte("key"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=premature.example.com",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("sign before init: expected 503, got %d", rr.Code)
	}
}

func TestCAVerify_ValidCert(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})
	writeToken := getTokenWithRoles(t, h, []string{"write"})

	// Init + issue.
	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Verify CA"}, adminToken)
	fakeKey := base64.StdEncoding.EncodeToString([]byte("fake-pk"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=verify.example.com",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
	}, writeToken)
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)

	// Verify (public endpoint).
	rr = do(t, h, "POST", "/ca/verify", map[string]any{"certificate": cert}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/verify: status %d body %s", rr.Code, rr.Body)
	}
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != true {
		t.Errorf("valid: %v error: %v", vResp["valid"], vResp["error"])
	}
}

func TestCAVerify_TamperedCert(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Tamper CA"}, adminToken)
	fakeKey := base64.StdEncoding.EncodeToString([]byte("real-pk"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=real.example.com",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)

	// Tamper.
	cert["subject"] = "CN=attacker.example.com"

	rr = do(t, h, "POST", "/ca/verify", map[string]any{"certificate": cert}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("verify tampered: status %d", rr.Code)
	}
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != false {
		t.Errorf("tampered cert should not verify, got valid=%v", vResp["valid"])
	}
}

func TestCARevoke_RevokedCertFailsVerify(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	// Init + issue.
	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Revoke Test CA"}, adminToken)
	fakeKey := base64.StdEncoding.EncodeToString([]byte("revoke-test-pk"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject": "CN=will-be-revoked.example.com", "public_key": fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)

	// Verify before revocation — must succeed.
	rr = do(t, h, "POST", "/ca/verify", map[string]any{"certificate": cert}, "")
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != true {
		t.Fatalf("pre-revoke verify: valid=%v", vResp["valid"])
	}

	// Revoke by serial.
	serial := cert["serial"].(string)
	rr = do(t, h, "POST", "/ca/revoke", map[string]string{"serial": serial}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/revoke: status %d body %s", rr.Code, rr.Body)
	}
	var revokeResp map[string]any
	json.NewDecoder(rr.Body).Decode(&revokeResp)
	if revokeResp["revoked"] != true {
		t.Errorf("revoked: %v", revokeResp["revoked"])
	}

	// Verify after revocation — must fail.
	rr = do(t, h, "POST", "/ca/verify", map[string]any{"certificate": cert}, "")
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != false {
		t.Errorf("post-revoke verify: expected invalid, got valid=%v", vResp["valid"])
	}
}

func TestCACRL_EmptyAndPopulated(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=CRL Test CA"}, adminToken)

	// Empty CRL right after init.
	rr := do(t, h, "GET", "/ca/crl", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /ca/crl: status %d", rr.Code)
	}
	var crl map[string]any
	json.NewDecoder(rr.Body).Decode(&crl)
	entries := crl["entries"].([]any)
	if len(entries) != 0 {
		t.Errorf("expected empty CRL, got %d entries", len(entries))
	}

	// Issue + revoke.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("crl-test-pk"))
	rr = do(t, h, "POST", "/ca/sign", map[string]any{
		"subject": "CN=crl-test.example.com", "public_key": fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)
	serial := cert["serial"].(string)
	do(t, h, "POST", "/ca/revoke", map[string]string{"serial": serial}, adminToken)

	// CRL should now contain one entry.
	rr = do(t, h, "GET", "/ca/crl", nil, "")
	json.NewDecoder(rr.Body).Decode(&crl)
	entries = crl["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected 1 CRL entry, got %d", len(entries))
	}
	entry := entries[0].(map[string]any)
	if entry["serial"] != serial {
		t.Errorf("CRL entry serial: %v (want %v)", entry["serial"], serial)
	}
}

func TestCARevoke_BeforeInit(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	rr := do(t, h, "POST", "/ca/revoke", map[string]string{"serial": "abc123"}, adminToken)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("revoke before init: expected 503, got %d", rr.Code)
	}
}

func TestCACertificate_ReturnsRootCert(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	// Before init: 503.
	rr := do(t, h, "GET", "/ca/certificate", nil, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("before init: expected 503, got %d", rr.Code)
	}

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Public CA"}, adminToken)

	// After init: public endpoint returns root cert.
	rr = do(t, h, "GET", "/ca/certificate", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/certificate after init: status %d body %s", rr.Code, rr.Body)
	}
	var cert map[string]any
	json.NewDecoder(rr.Body).Decode(&cert)
	if cert["is_ca"] != true {
		t.Errorf("is_ca: %v", cert["is_ca"])
	}
	if cert["subject"] != "CN=Public CA" {
		t.Errorf("subject: %v", cert["subject"])
	}
}

// ── Hybrid PKI — intermediate CA & chain verify ───────────────────────────────

func TestCAIntermediate_CreateAndSignLeaf(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	// Initialise root CA.
	rr := do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Root CA"}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/init: %d %s", rr.Code, rr.Body)
	}

	// Create an intermediate CA.
	rr = do(t, h, "POST", "/ca/intermediate", map[string]any{
		"subject":  "CN=Intermediate CA",
		"ttl_days": 3650,
	}, adminToken)
	if rr.Code != http.StatusCreated {
		t.Fatalf("ca/intermediate: expected 201, got %d body=%s", rr.Code, rr.Body)
	}
	var intResp map[string]any
	json.NewDecoder(rr.Body).Decode(&intResp)
	serial, _ := intResp["serial"].(string)
	if serial == "" {
		t.Fatal("intermediate response missing serial")
	}
	cert, ok := intResp["certificate"].(map[string]any)
	if !ok {
		t.Fatal("intermediate response missing certificate")
	}
	if cert["is_ca"] != true {
		t.Errorf("intermediate cert is_ca: %v", cert["is_ca"])
	}
	if cert["issuer"] != "CN=Root CA" {
		t.Errorf("intermediate cert issuer: %v", cert["issuer"])
	}

	// Sign a leaf certificate via the intermediate.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("leaf-public-key-bytes"))
	rr = do(t, h, "POST", "/ca/intermediate/"+serial+"/sign", map[string]any{
		"subject":         "CN=leaf.example.com",
		"public_key":      fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/intermediate/{serial}/sign: expected 200, got %d body=%s", rr.Code, rr.Body)
	}
	var leaf map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf)
	if leaf["subject"] != "CN=leaf.example.com" {
		t.Errorf("leaf subject: %v", leaf["subject"])
	}
	if leaf["issuer"] != "CN=Intermediate CA" {
		t.Errorf("leaf issuer: %v (want CN=Intermediate CA)", leaf["issuer"])
	}
	if leaf["is_ca"] == true {
		t.Error("leaf cert should not be a CA")
	}
}

func TestCAIntermediate_BeforeInit(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"admin"})

	rr := do(t, h, "POST", "/ca/intermediate", map[string]any{"subject": "CN=Sub CA"}, adminToken)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 before ca/init, got %d", rr.Code)
	}
}

func TestCAIntermediateSign_UnknownSerial(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})
	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Root CA"}, adminToken)

	fakeKey := base64.StdEncoding.EncodeToString([]byte("pk"))
	rr := do(t, h, "POST", "/ca/intermediate/nonexistentserial/sign", map[string]any{
		"subject": "CN=x", "public_key": fakeKey, "public_key_type": "ML-KEM-768",
	}, adminToken)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown serial, got %d", rr.Code)
	}
}

func TestCAChainVerify_DirectLeaf(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Root CA"}, adminToken)

	// Issue a leaf directly from the root.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("pk-chain-direct"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject": "CN=direct-leaf.example.com", "public_key": fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/sign: %d %s", rr.Code, rr.Body)
	}
	var leaf map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf)

	// chain-verify with no intermediates.
	rr = do(t, h, "POST", "/ca/chain-verify", map[string]any{
		"certificate": leaf,
		"chain":       []any{},
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/chain-verify: %d %s", rr.Code, rr.Body)
	}
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != true {
		t.Errorf("chain-verify direct leaf: valid=%v error=%v", vResp["valid"], vResp["error"])
	}
}

func TestCAChainVerify_WithIntermediate(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Root CA"}, adminToken)

	// Create intermediate.
	rr := do(t, h, "POST", "/ca/intermediate", map[string]any{
		"subject": "CN=Intermediate CA",
	}, adminToken)
	var intResp map[string]any
	json.NewDecoder(rr.Body).Decode(&intResp)
	intSerial := intResp["serial"].(string)
	intCert := intResp["certificate"]

	// Issue leaf via intermediate.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("pk-chain-int"))
	rr = do(t, h, "POST", "/ca/intermediate/"+intSerial+"/sign", map[string]any{
		"subject": "CN=leaf-via-int.example.com", "public_key": fakeKey,
		"public_key_type": "ML-KEM-768",
	}, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("intermediate sign: %d %s", rr.Code, rr.Body)
	}
	var leaf map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf)

	// Chain-verify: leaf + [intCert] → root.
	rr = do(t, h, "POST", "/ca/chain-verify", map[string]any{
		"certificate": leaf,
		"chain":       []any{intCert},
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/chain-verify with intermediate: %d %s", rr.Code, rr.Body)
	}
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != true {
		t.Errorf("chain-verify with intermediate: valid=%v error=%v", vResp["valid"], vResp["error"])
	}
}

func TestCAChainVerify_TamperedLeafFails(t *testing.T) {
	_, h := newTestServer(t)
	adminToken := getTokenWithRoles(t, h, []string{"write", "admin"})

	do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Root CA"}, adminToken)

	fakeKey := base64.StdEncoding.EncodeToString([]byte("pk-tamper"))
	rr := do(t, h, "POST", "/ca/sign", map[string]any{
		"subject": "CN=legit.example.com", "public_key": fakeKey, "public_key_type": "ML-KEM-768",
	}, adminToken)
	var leaf map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf)

	// Tamper.
	leaf["subject"] = "CN=attacker.example.com"

	rr = do(t, h, "POST", "/ca/chain-verify", map[string]any{
		"certificate": leaf, "chain": []any{},
	}, "")
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != false {
		t.Errorf("tampered leaf should fail chain-verify, got valid=%v", vResp["valid"])
	}
}

// ── Per-subject rate limiting ─────────────────────────────────────────────────

// TestSubjectRateLimit_Enforced verifies that a single JWT subject is blocked
// once it exhausts its per-subject quota, even though the global per-IP
// limit is not yet reached.
func TestSubjectRateLimit_Enforced(t *testing.T) {
	// Create a server with a tiny subject limit (2 req) so the test is fast.
	srv, err := api.New(api.WithSubjectRateLimit(2, 60*time.Second))
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(srv.Close)
	h := srv.Handler()

	tok := getToken(t, h)

	// First two authenticated requests — must succeed.
	for i := range 2 {
		rr := do(t, h, "GET", "/keys", nil, tok)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d body=%s", i, rr.Code, rr.Body)
		}
	}

	// Third request exceeds the subject quota — must be 429.
	rr := do(t, h, "GET", "/keys", nil, tok)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after subject limit, got %d body=%s", rr.Code, rr.Body)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header must be present on 429")
	}
}

// TestSubjectRateLimit_IndependentSubjects verifies that two different JWT
// subjects each have their own rate-limit bucket and do not interfere.
func TestSubjectRateLimit_IndependentSubjects(t *testing.T) {
	srv, err := api.New(api.WithSubjectRateLimit(1, 60*time.Second))
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(srv.Close)
	h := srv.Handler()

	// Issue two tokens for different users.
	rr := do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "alice", "roles": []string{"read"},
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("alice token: %d %s", rr.Code, rr.Body)
	}
	var r1 map[string]any
	json.NewDecoder(rr.Body).Decode(&r1)
	aliceTok := r1["token"].(string)

	rr = do(t, h, "POST", "/auth/token", map[string]any{
		"user_id": "bob", "roles": []string{"read"},
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("bob token: %d %s", rr.Code, rr.Body)
	}
	var r2 map[string]any
	json.NewDecoder(rr.Body).Decode(&r2)
	bobTok := r2["token"].(string)

	// Each gets 1 allowed request.
	if rr = do(t, h, "GET", "/keys", nil, aliceTok); rr.Code != http.StatusOK {
		t.Errorf("alice first: expected 200, got %d", rr.Code)
	}
	if rr = do(t, h, "GET", "/keys", nil, bobTok); rr.Code != http.StatusOK {
		t.Errorf("bob first: expected 200, got %d", rr.Code)
	}

	// Both are now exhausted — second requests must be 429.
	if rr = do(t, h, "GET", "/keys", nil, aliceTok); rr.Code != http.StatusTooManyRequests {
		t.Errorf("alice second: expected 429, got %d", rr.Code)
	}
	if rr = do(t, h, "GET", "/keys", nil, bobTok); rr.Code != http.StatusTooManyRequests {
		t.Errorf("bob second: expected 429, got %d", rr.Code)
	}
}

// TestSubjectRateLimit_UnauthenticatedUnaffected verifies that unauthenticated
// public endpoints are not governed by the per-subject rate limiter.
func TestSubjectRateLimit_UnauthenticatedUnaffected(t *testing.T) {
	// Very tight subject limit — but these are public (no auth) endpoints.
	srv, err := api.New(api.WithSubjectRateLimit(0, 60*time.Second))
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(srv.Close)
	h := srv.Handler()

	// Public endpoints don't go through requireAuth — subject limiter is not invoked.
	for range 5 {
		rr := do(t, h, "GET", "/health/live", nil, "")
		if rr.Code != http.StatusOK {
			t.Errorf("public endpoint affected by subject limiter: got %d", rr.Code)
		}
	}
}

// TestIPRateLimit_Enforced verifies that the global per-IP middleware is
// enforced at the transport layer before reaching any handler.
func TestIPRateLimit_Enforced(t *testing.T) {
	srv, err := api.New(
		api.WithIPRateLimit(2, 60*time.Second),
		api.WithSubjectRateLimit(1000, 60*time.Second), // subject limit very high
	)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(srv.Close)
	h := srv.Handler()

	// First two requests (any endpoint) — pass.
	for i := range 2 {
		rr := do(t, h, "GET", "/health/live", nil, "")
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rr.Code)
		}
	}

	// Third request — IP limit exceeded.
	rr := do(t, h, "GET", "/health/live", nil, "")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 from IP limiter, got %d", rr.Code)
	}
}

// ── CA persistence ────────────────────────────────────────────────────────────

// TestCAPersistence_SurvivesRestart simulates a server restart with
// CA_STORE_PATH configured.  After the "restart" (new Server loaded from the
// same file) the CA must be fully functional: same subject, same signing key,
// CRL intact, and able to issue and verify new certificates.
func TestCAPersistence_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/ca.qsc"
	t.Setenv("CA_STORE_PATH", storePath)
	t.Setenv("CA_STORE_PASSWORD", "test-password-123")

	// ── First server (writes the CA store) ──────────────────────────────────
	srv1, err := api.New()
	if err != nil {
		t.Fatalf("api.New (srv1): %v", err)
	}
	h1 := srv1.Handler()

	adminTok := getTokenWithRoles(t, h1, []string{"write", "admin"})

	// Initialise CA.
	rr := do(t, h1, "POST", "/ca/init", map[string]string{"subject": "CN=Persistent Root CA"}, adminTok)
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/init: %d %s", rr.Code, rr.Body)
	}

	// Issue a leaf.
	fakeKey := base64.StdEncoding.EncodeToString([]byte("pk-persist"))
	rr = do(t, h1, "POST", "/ca/sign", map[string]any{
		"subject": "CN=leaf.example.com", "public_key": fakeKey, "public_key_type": "ML-KEM-768",
	}, adminTok)
	var leaf1 map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf1)
	serial1 := leaf1["serial"].(string)

	// Revoke the leaf.
	do(t, h1, "POST", "/ca/revoke", map[string]string{"serial": serial1}, adminTok)

	// Create an intermediate CA.
	rr = do(t, h1, "POST", "/ca/intermediate", map[string]any{"subject": "CN=Persistent Intermediate CA"}, adminTok)
	var intResp map[string]any
	json.NewDecoder(rr.Body).Decode(&intResp)
	intSerial := intResp["serial"].(string)

	srv1.Close()

	// ── Second server (reads the CA store) ──────────────────────────────────
	srv2, err := api.New()
	if err != nil {
		t.Fatalf("api.New (srv2): %v", err)
	}
	defer srv2.Close()
	h2 := srv2.Handler()

	adminTok2 := getTokenWithRoles(t, h2, []string{"write", "admin"})

	// Root CA certificate must be the same.
	rr = do(t, h2, "GET", "/ca/certificate", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ca/certificate after restart: %d %s", rr.Code, rr.Body)
	}
	var rootCert map[string]any
	json.NewDecoder(rr.Body).Decode(&rootCert)
	if rootCert["subject"] != "CN=Persistent Root CA" {
		t.Errorf("subject after restart: %v", rootCert["subject"])
	}

	// CRL must contain the revoked serial.
	rr = do(t, h2, "GET", "/ca/crl", nil, "")
	var crlResp map[string]any
	json.NewDecoder(rr.Body).Decode(&crlResp)
	entries := crlResp["entries"].([]any)
	found := false
	for _, e := range entries {
		if entry, ok := e.(map[string]any); ok && entry["serial"] == serial1 {
			found = true
		}
	}
	if !found {
		t.Errorf("revoked serial %s not in CRL after restart", serial1)
	}

	// Intermediate CA must be restored.
	fakeKey2 := base64.StdEncoding.EncodeToString([]byte("pk-int-persist"))
	rr = do(t, h2, "POST", "/ca/intermediate/"+intSerial+"/sign", map[string]any{
		"subject": "CN=post-restart-leaf.example.com", "public_key": fakeKey2,
		"public_key_type": "ML-KEM-768",
	}, adminTok2)
	if rr.Code != http.StatusOK {
		t.Fatalf("intermediate sign after restart: %d %s", rr.Code, rr.Body)
	}
	var leaf2 map[string]any
	json.NewDecoder(rr.Body).Decode(&leaf2)
	if leaf2["issuer"] != "CN=Persistent Intermediate CA" {
		t.Errorf("post-restart leaf issuer: %v", leaf2["issuer"])
	}

	// The revoked serial must still fail chain-verify.
	rr = do(t, h2, "POST", "/ca/verify", map[string]any{"certificate": leaf1}, "")
	var vResp map[string]any
	json.NewDecoder(rr.Body).Decode(&vResp)
	if vResp["valid"] != false {
		t.Error("revoked cert should be invalid after restart")
	}
}

func TestCAPersistence_NoStorePathNoEffect(t *testing.T) {
	// When CA_STORE_PATH is not set the server behaves exactly as before.
	t.Setenv("CA_STORE_PATH", "")
	srv, err := api.New()
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	defer srv.Close()
	h := srv.Handler()
	adminTok := getTokenWithRoles(t, h, []string{"admin"})
	rr := do(t, h, "POST", "/ca/init", map[string]string{"subject": "CN=Ephemeral CA"}, adminTok)
	if rr.Code != http.StatusOK {
		t.Errorf("ca/init without store: %d", rr.Code)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustJSON(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		t.Fatal(err)
	}
	return &buf
}
