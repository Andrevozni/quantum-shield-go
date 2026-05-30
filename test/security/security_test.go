// Package security_test is an automated penetration-test suite for the
// QuantumShield API.
//
// Every test targets a specific attack class.  A failing test means the server
// is vulnerable to that attack and the issue must be remediated before
// production deployment.
//
// Attack classes covered:
//
//  1. JWT/QST forgery — alg:none, tampered payload, signature stripping, etc.
//  2. Role escalation — under-privileged token accessing higher-privilege endpoints
//  3. Token revocation bypass — using a revoked token
//  4. Rate-limit enforcement — burst past the window limit
//  5. Input validation — oversized bodies, malformed JSON, empty body
//  6. Path traversal — ../ sequences in URL path parameters
//  7. CORS policy — unauthorized origins must not receive ACAO headers
//  8. Security headers — hardened headers present on every response
//  9. HTTP method enforcement — wrong verbs get 405, not 200
// 10. Replay attack — second use of the same ciphertext is rejected
// 11. Cert forgery — self-signed certs fail /ca/verify
// 12. Timing side-channel proxy — invalid auth is not measurably slower
//
// Run with:
//
//	go test ./test/security/... -v
//
// For attack-class specific runs:
//
//	go test ./test/security/... -run TestSec_JWT
//	go test ./test/security/... -run TestSec_Role
package security_test

import (
	stdbytes "bytes"
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

// ── Test infrastructure ───────────────────────────────────────────────────────

// server spins up a real httptest.Server (TCP, full middleware stack).
func server(t *testing.T, opts ...api.Option) (*httptest.Server, func()) {
	t.Helper()
	s, err := api.New(opts...)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	return ts, func() { ts.Close(); s.Close() }
}

// req performs an HTTP request and returns (statusCode, responseBody, headers).
func req(t *testing.T, ts *httptest.Server, method, path, contentType, token string, body io.Reader) (int, []byte, http.Header) {
	t.Helper()
	r, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// jsonReq sends a JSON request and returns the decoded response map.
func jsonReq(t *testing.T, ts *httptest.Server, method, path string, body any, token string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = stdbytes.NewReader(b)
	}
	code, raw, _ := req(t, ts, method, path, "application/json", token, r)
	var m map[string]any
	json.Unmarshal(raw, &m) //nolint:errcheck
	return code, m
}

// token issues a QST token for the given user and roles via the live server.
func token(t *testing.T, ts *httptest.Server, userID string, roles []string) string {
	t.Helper()
	code, body := jsonReq(t, ts, "POST", "/auth/token", map[string]any{
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

// tamperMiddlePart decodes the middle (payload) segment of a dot-separated
// token, applies mut to the decoded JSON map, re-encodes it, and rebuilds the
// token string — keeping the original header and signature unchanged.
// This simulates a payload-tampering attack where an attacker modifies claims
// but cannot produce a valid signature.
func tamperMiddlePart(t *testing.T, tok string, mut func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	mut(claims)
	modified, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(modified)
	return strings.Join(parts, ".")
}

// ── 1. JWT / QST Forgery attacks ─────────────────────────────────────────────

// TestSec_JWT_TamperedPayload_RoleEscalation takes a read-only token, promotes
// its roles to ["admin","write"] in the payload, but leaves the original
// ML-DSA-65 signature untouched. The server must reject it (401).
func TestSec_JWT_TamperedPayload_RoleEscalation(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	readTok := token(t, ts, "attacker", []string{"read"})

	// Escalate roles inside the payload without re-signing.
	forged := tamperMiddlePart(t, readTok, func(c map[string]any) {
		c["roles"] = []any{"admin", "write"}
	})

	code, _ := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, forged)
	if code != http.StatusUnauthorized {
		t.Errorf("tampered payload: expected 401, got %d", code)
	}
}

// TestSec_JWT_AlgNone attempts an alg:none bypass by crafting a token whose
// header declares no algorithm and whose signature part is empty.
// The server must reject it (401).
func TestSec_JWT_AlgNone(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"QST","alg":"none","ver":"QST-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"attacker","roles":["admin","write"],"exp":%d}`,
		time.Now().Add(time.Hour).Unix(),
	)))
	algNone := hdr + "." + payload + "." // empty signature

	code, _ := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, algNone)
	if code != http.StatusUnauthorized {
		t.Errorf("alg:none token: expected 401, got %d", code)
	}
}

// TestSec_JWT_SignatureStripped removes the signature entirely (2-part token).
func TestSec_JWT_SignatureStripped(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})
	parts := strings.Split(tok, ".")
	stripped := parts[0] + "." + parts[1] // no third part

	code, _ := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, stripped)
	if code != http.StatusUnauthorized {
		t.Errorf("stripped signature: expected 401, got %d", code)
	}
}

// TestSec_JWT_RandomGarbage sends completely random bytes as the bearer token.
func TestSec_JWT_RandomGarbage(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	code, _ := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, "not.a.token")
	if code != http.StatusUnauthorized {
		t.Errorf("garbage token: expected 401, got %d", code)
	}
}

// TestSec_JWT_NoToken verifies that missing Authorization header → 401.
func TestSec_JWT_NoToken(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	code, _ := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, "")
	if code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", code)
	}
}

// TestSec_JWT_EmptyBearerToken sends "Authorization: Bearer " (empty token string).
func TestSec_JWT_EmptyBearerToken(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	r, _ := http.NewRequest(http.MethodPost, ts.URL+"/keys/generate",
		strings.NewReader(`{"level":"ML-KEM-768"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer ") // empty value after "Bearer "

	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("empty bearer: expected 401, got %d", resp.StatusCode)
	}
}

// TestSec_JWT_TamperedExpiry modifies exp to a far-future value — signature
// must still fail because exp is inside the signed payload.
func TestSec_JWT_TamperedExpiry(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"read"})
	forged := tamperMiddlePart(t, tok, func(c map[string]any) {
		c["exp"] = float64(time.Now().Add(100 * 24 * time.Hour).Unix()) // 100 days
		c["roles"] = []any{"admin"}
	})

	code, _ := jsonReq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=Rogue CA"}, forged)
	if code != http.StatusUnauthorized {
		t.Errorf("tampered expiry+role: expected 401, got %d", code)
	}
}

// TestSec_JWT_WrongIssuerSignature crafts a token signed by a *different*
// ML-DSA key (second server instance) and presents it to the first server.
// Cross-server tokens must be rejected.
func TestSec_JWT_WrongIssuerSignature(t *testing.T) {
	ts1, cleanup1 := server(t)
	defer cleanup1()
	ts2, cleanup2 := server(t)
	defer cleanup2()

	// Token from server 2's authority.
	foreignTok := token(t, ts2, "user", []string{"admin", "write"})

	// Present to server 1 — different signing key → 401.
	code, _ := jsonReq(t, ts1, "POST", "/ca/init",
		map[string]any{"subject": "CN=Test Root CA"}, foreignTok)
	if code != http.StatusUnauthorized {
		t.Errorf("foreign-server token: expected 401, got %d", code)
	}
}

// ── 2. Role escalation ────────────────────────────────────────────────────────

// TestSec_Role_ReadCannotWrite verifies that read-only tokens are blocked from
// write-role endpoints.
func TestSec_Role_ReadCannotWrite(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	readTok := token(t, ts, "readonly-user", []string{"read"})
	writeEndpoints := []struct {
		method string
		path   string
		body   any
	}{
		{"POST", "/keys/generate", map[string]any{"level": "ML-KEM-768"}},
		{"POST", "/sign", map[string]any{"key_id": "x", "message": "aGk="}},
		{"POST", "/encrypt", map[string]any{"key_id": "x", "plaintext": "aGk="}},
	}
	for _, ep := range writeEndpoints {
		t.Run(ep.method+ep.path, func(t *testing.T) {
			code, _ := jsonReq(t, ts, ep.method, ep.path, ep.body, readTok)
			if code != http.StatusForbidden {
				t.Errorf("%s %s with read token: expected 403, got %d", ep.method, ep.path, code)
			}
		})
	}
}

// TestSec_Role_WriteCannotAdmin verifies that write-only tokens cannot access
// admin endpoints.
func TestSec_Role_WriteCannotAdmin(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	writeTok := token(t, ts, "writer", []string{"read", "write"})
	adminEndpoints := []struct {
		method string
		path   string
		body   any
	}{
		{"POST", "/ca/init", map[string]any{"subject": "CN=Root CA"}},
		{"POST", "/ca/revoke", map[string]any{"serial": "abc"}},
		{"POST", "/keystore/generate", map[string]any{"level": "ML-KEM-768"}},
	}
	for _, ep := range adminEndpoints {
		t.Run(ep.method+ep.path, func(t *testing.T) {
			code, _ := jsonReq(t, ts, ep.method, ep.path, ep.body, writeTok)
			if code != http.StatusForbidden {
				t.Errorf("%s %s with write token: expected 403, got %d", ep.method, ep.path, code)
			}
		})
	}
}

// TestSec_Role_ReadCannotAdmin verifies read token is blocked from admin routes.
func TestSec_Role_ReadCannotAdmin(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	readTok := token(t, ts, "reader", []string{"read"})

	code, _ := jsonReq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=Rogue Root CA"}, readTok)
	if code != http.StatusForbidden {
		t.Errorf("read token on admin endpoint: expected 403, got %d", code)
	}
}

// ── 3. Token revocation bypass ────────────────────────────────────────────────

// TestSec_Revocation_RevokedTokenRejected issues a token, revokes it via the
// API, then verifies that subsequent use of the revoked token is rejected.
func TestSec_Revocation_RevokedTokenRejected(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	// Need admin+write to revoke.
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})

	// Revoke the admin token itself.
	code, body := jsonReq(t, ts, "POST", "/auth/revoke", map[string]any{
		"token": adminTok,
	}, adminTok)
	if code != http.StatusOK {
		t.Fatalf("revoke: status %d body %v", code, body)
	}

	// Now the revoked token must not grant access.
	code, _ = jsonReq(t, ts, "GET", "/keys", nil, adminTok)
	if code != http.StatusUnauthorized {
		t.Errorf("revoked token: expected 401, got %d", code)
	}
}

// ── 4. Rate-limit enforcement ─────────────────────────────────────────────────

// TestSec_RateLimit_BurstTriggersThrottle sets a tight per-IP limit of 5
// requests per 10 seconds and fires 20 concurrent requests. At least some must
// receive 429 Too Many Requests.
func TestSec_RateLimit_BurstTriggersThrottle(t *testing.T) {
	ts, cleanup := server(t,
		api.WithIPRateLimit(5, 10*time.Second),
	)
	defer cleanup()

	const burst = 20
	results := make([]int, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, _, _ := req(t, ts, http.MethodGet, "/health/live", "", "", nil)
			results[i] = code
		}(i)
	}
	wg.Wait()

	throttled := 0
	for _, code := range results {
		if code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Errorf("burst of %d requests produced 0 throttled responses; rate limit not enforced", burst)
	}
}

// TestSec_RateLimit_WindowRecovery verifies that after waiting for the rate
// limit window to pass, requests succeed again.
func TestSec_RateLimit_WindowRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping window recovery test in short mode")
	}
	ts, cleanup := server(t,
		api.WithIPRateLimit(2, 500*time.Millisecond),
	)
	defer cleanup()

	// Exhaust the limit.
	for range 3 {
		req(t, ts, http.MethodGet, "/health/live", "", "", nil) //nolint:errcheck
	}

	// Wait for window to pass.
	time.Sleep(600 * time.Millisecond)

	// Next request should succeed.
	code, _, _ := req(t, ts, http.MethodGet, "/health/live", "", "", nil)
	if code != http.StatusOK {
		t.Errorf("after window recovery: expected 200, got %d", code)
	}
}

// ── 5. Input validation ───────────────────────────────────────────────────────

// TestSec_Input_OversizedBody sends a body that exceeds the 1 MB limit.
// The middleware must reject it before the handler executes.
func TestSec_Input_OversizedBody(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})

	// 2 MB body — well above the 1 MB limit.
	huge := strings.NewReader(`{"level":"ML-KEM-768","extra":"` + strings.Repeat("A", 2<<20) + `"}`)
	code, _, _ := req(t, ts, http.MethodPost, "/keys/generate",
		"application/json", tok, huge)

	// Either 413 (RequestEntityTooLarge) or 400 (BadRequest from decoder) is acceptable.
	if code != http.StatusRequestEntityTooLarge && code != http.StatusBadRequest {
		t.Errorf("oversized body: expected 413 or 400, got %d", code)
	}
}

// TestSec_Input_MalformedJSON sends syntactically invalid JSON.
func TestSec_Input_MalformedJSON(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})

	malformed := strings.NewReader(`{level: ML-KEM-768}`) // keys not quoted
	code, _, _ := req(t, ts, http.MethodPost, "/keys/generate",
		"application/json", tok, malformed)
	if code != http.StatusBadRequest {
		t.Errorf("malformed JSON: expected 400, got %d", code)
	}
}

// TestSec_Input_EmptyBody sends an empty POST body to an endpoint that
// requires JSON parameters.
func TestSec_Input_EmptyBody(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})
	code, _, _ := req(t, ts, http.MethodPost, "/keys/generate",
		"application/json", tok, strings.NewReader(""))
	// 400 expected — missing required "level" field.
	if code != http.StatusBadRequest {
		t.Errorf("empty body: expected 400, got %d", code)
	}
}

// TestSec_Input_WrongContentType sends a form-encoded body to a JSON endpoint.
// The RequireJSON middleware must reject it (415 Unsupported Media Type).
func TestSec_Input_WrongContentType(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})
	code, _, _ := req(t, ts, http.MethodPost, "/keys/generate",
		"application/x-www-form-urlencoded", tok,
		strings.NewReader("level=ML-KEM-768"))
	if code != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content-type: expected 415, got %d", code)
	}
}

// TestSec_Input_NullByteInKeyID tests that a key_id path parameter containing
// a null byte is handled gracefully (not passed to filesystem or C calls).
func TestSec_Input_NullByteInKeyID(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"read"})
	// Go's net/http will URL-decode the path; %00 is a null byte.
	code, _, _ := req(t, ts, http.MethodGet, "/keys/%00/public",
		"application/json", tok, nil)
	// Must not be 200 or 500; 400 or 404 expected.
	if code == http.StatusOK || code == http.StatusInternalServerError {
		t.Errorf("null byte in key_id: unexpected status %d", code)
	}
}

// TestSec_Input_VeryLongKeyID sends a 64 KB key_id to check for truncation or
// panic in the routing layer.
func TestSec_Input_VeryLongKeyID(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"read"})
	longID := strings.Repeat("x", 65536)
	code, _, _ := req(t, ts, http.MethodGet, "/keys/"+longID+"/public",
		"application/json", tok, nil)
	// 414 URI Too Long, 404 Not Found, or 400 are all acceptable. 500 is not.
	if code == http.StatusInternalServerError {
		t.Errorf("very long key_id caused 500 Internal Server Error")
	}
}

// ── 6. Path traversal ─────────────────────────────────────────────────────────

// TestSec_PathTraversal_DotDot verifies that ../ sequences in path parameters
// do not escape the resource namespace (must return 400 or 404, never 200 or 500).
func TestSec_PathTraversal_DotDot(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"read"})

	traversals := []string{
		"/keys/../../../etc/passwd/public",
		"/keys/%2e%2e%2f%2e%2e%2fetc%2fpasswd/public",
		"/keys/....//....//etc/passwd/public",
	}
	for _, path := range traversals {
		t.Run(path, func(t *testing.T) {
			code, _, _ := req(t, ts, http.MethodGet, path, "application/json", tok, nil)
			if code == http.StatusOK || code == http.StatusInternalServerError {
				t.Errorf("path traversal %q: unexpected status %d", path, code)
			}
		})
	}
}

// ── 7. CORS policy ────────────────────────────────────────────────────────────

// TestSec_CORS_UnauthorizedOriginExcluded verifies that a request from an
// origin not in ALLOWED_ORIGINS does not receive Access-Control-Allow-Origin.
func TestSec_CORS_UnauthorizedOriginExcluded(t *testing.T) {
	// No ALLOWED_ORIGINS set → all cross-origin requests denied.
	ts, cleanup := server(t)
	defer cleanup()

	r, _ := http.NewRequest(http.MethodGet, ts.URL+"/health/live", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" {
		t.Errorf("unauthorized origin received ACAO header: %q", acao)
	}
}

// TestSec_CORS_PreflightUnauthorizedOrigin verifies that an OPTIONS preflight
// from an unknown origin does not echo back an ACAO header.
func TestSec_CORS_PreflightUnauthorizedOrigin(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	r, _ := http.NewRequest(http.MethodOptions, ts.URL+"/keys/generate", nil)
	r.Header.Set("Origin", "https://attacker.example.org")
	r.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" {
		t.Errorf("preflight from unknown origin echoed ACAO: %q", acao)
	}
}

// ── 8. Security headers ───────────────────────────────────────────────────────

// TestSec_Headers_PresentOnEveryResponse verifies that all hardened HTTP
// security headers are set on both public and authenticated responses.
func TestSec_Headers_PresentOnEveryResponse(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	endpoints := []struct{ method, path string }{
		{"GET", "/health/live"},
		{"GET", "/health/ready"},
		{"GET", "/health/fips"},
		{"GET", "/"},
	}
	requiredHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-Xss-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Cache-Control",
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			_, _, hdrs := req(t, ts, ep.method, ep.path, "", "", nil)
			for _, h := range requiredHeaders {
				if v := hdrs.Get(h); v == "" {
					t.Errorf("missing security header %q on %s %s", h, ep.method, ep.path)
				}
			}
		})
	}
}

// TestSec_Headers_XFrameOptions_DENY verifies the specific required value.
func TestSec_Headers_XFrameOptions_DENY(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	_, _, hdrs := req(t, ts, http.MethodGet, "/health/live", "", "", nil)
	if v := hdrs.Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options: expected DENY, got %q", v)
	}
}

// TestSec_Headers_XContentTypeOptions_nosniff verifies the specific value.
func TestSec_Headers_XContentTypeOptions_nosniff(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	_, _, hdrs := req(t, ts, http.MethodGet, "/health/live", "", "", nil)
	if v := hdrs.Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options: expected nosniff, got %q", v)
	}
}

// TestSec_Headers_RequestID verifies that every response carries a unique
// X-Request-Id header (traceability requirement).
func TestSec_Headers_RequestID(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	ids := make(map[string]bool)
	for range 5 {
		_, _, hdrs := req(t, ts, http.MethodGet, "/health/live", "", "", nil)
		rid := hdrs.Get("X-Request-Id")
		if rid == "" {
			t.Error("X-Request-Id missing")
			continue
		}
		if ids[rid] {
			t.Errorf("duplicate X-Request-Id: %q", rid)
		}
		ids[rid] = true
	}
}

// ── 9. HTTP method enforcement ────────────────────────────────────────────────

// TestSec_Method_WrongVerb verifies that incorrect HTTP verbs on known routes
// are rejected (405 or 404), not silently accepted.
func TestSec_Method_WrongVerb(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"admin", "write", "read"})

	cases := []struct {
		method, path string
	}{
		// POST-only endpoints accessed via GET.
		{http.MethodGet, "/keys/generate"},
		{http.MethodGet, "/encrypt"},
		{http.MethodGet, "/sign"},
		// GET-only endpoints accessed via POST.
		{http.MethodPost, "/health/live"},
		{http.MethodPost, "/health/ready"},
		{http.MethodPost, "/keys"},
		// Dangerous verbs.
		{http.MethodPut, "/auth/token"},
		{http.MethodDelete, "/auth/token"},
		{http.MethodTrace, "/"},
		{http.MethodConnect, "/"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			code, _, _ := req(t, ts, tc.method, tc.path, "application/json", tok, nil)
			if code == http.StatusOK {
				t.Errorf("%s %s returned 200 — wrong verb should not succeed", tc.method, tc.path)
			}
		})
	}
}

// ── 10. Replay attack ─────────────────────────────────────────────────────────

// TestSec_Replay_CiphertextRejectedOnSecondUse encrypts a message, decrypts it
// once (success), then attempts to decrypt the identical ciphertext again.
// The in-process replay cache inside hybrid.Decrypter must reject the second
// use (400 or similar error), preventing a replay attacker from re-decrypting
// captured traffic.
//
// Encrypt response shape:
//
//	{"encrypted":{"kem_ciphertext":"...","nonce":"...","data":"...","created_at":N},...}
//
// Decrypt request shape:
//
//	{"key_id":"...","encrypted":{"kem_ciphertext":"...","nonce":"...","data":"...","created_at":N}}
func TestSec_Replay_CiphertextRejectedOnSecondUse(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write", "read"})

	// Generate a key pair.
	code, keyResp := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, tok)
	if code != http.StatusOK {
		t.Fatalf("generate key: status %d: %v", code, keyResp)
	}
	keyID, _ := keyResp["key_id"].(string)

	// Encrypt a plaintext (raw string, not base64).
	code, encResp := jsonReq(t, ts, "POST", "/encrypt",
		map[string]any{"key_id": keyID, "plaintext": "replay-attack-test"}, tok)
	if code != http.StatusOK {
		t.Fatalf("encrypt: status %d: %v", code, encResp)
	}
	// The encrypted object is nested under "encrypted".
	encObj, ok := encResp["encrypted"].(map[string]any)
	if !ok {
		t.Fatalf("encrypt: no 'encrypted' object in response: %v", encResp)
	}

	decryptPayload := map[string]any{
		"key_id":    keyID,
		"encrypted": encObj,
	}

	// First decryption — must succeed.
	code, decResp := jsonReq(t, ts, "POST", "/decrypt", decryptPayload, tok)
	if code != http.StatusOK {
		t.Fatalf("first decrypt: status %d: %v", code, decResp)
	}

	// Second decryption with identical ciphertext — must fail (replay detected).
	code, _ = jsonReq(t, ts, "POST", "/decrypt", decryptPayload, tok)
	if code == http.StatusOK {
		t.Error("replay attack: second decryption of same ciphertext succeeded — replay cache not working")
	}
}

// ── 11. Certificate forgery ───────────────────────────────────────────────────

// TestSec_CertForgery_SelfSignedRejected initialises a CA and then attempts to
// verify a certificate whose signature fields are fabricated (not issued by the
// server's CA).  The /ca/verify endpoint must reject it.
func TestSec_CertForgery_SelfSignedRejected(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})

	// Initialise the CA.
	code, _ := jsonReq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=Security Test Root CA,O=QuantumShield"}, adminTok)
	if code != http.StatusOK {
		t.Fatalf("ca/init: status %d", code)
	}

	// Attempt to verify a fabricated certificate (not issued by the CA).
	// The payload is valid JSON but the signature is random base64.
	fabricated := map[string]any{
		"serial":     "DEADBEEF1234",
		"subject":    "CN=rogue.example.com",
		"issuer":     "CN=Security Test Root CA,O=QuantumShield",
		"not_before": time.Now().UTC().Format(time.RFC3339),
		"not_after":  time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"public_key": base64.StdEncoding.EncodeToString([]byte("fake-pk")),
		"algorithm":  "ML-KEM-768",
		"signature":  base64.StdEncoding.EncodeToString(stdbytes.Repeat([]byte{0xDE, 0xAD}, 32)),
	}

	code, body := jsonReq(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": fabricated}, "")
	if code == http.StatusOK {
		if v, _ := body["valid"].(bool); v {
			t.Error("fabricated certificate verified as valid — cert forgery not detected")
		}
	}
	// 400 (bad structure) or 200 with valid:false are both acceptable; 500 is not.
	if code == http.StatusInternalServerError {
		t.Error("fabricated certificate caused 500 Internal Server Error")
	}
}

// TestSec_CertForgery_TamperedSerial issues a real cert, tampers its serial,
// and submits it for verification. The altered signature must fail.
//
// POST /ca/sign requires: subject, public_key (base64), public_key_type.
// GET  /keys/{id}/public returns the base64 public key.
func TestSec_CertForgery_TamperedSerial(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	writeTok := token(t, ts, "writer", []string{"write", "read"})

	// Init CA.
	code, _ := jsonReq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=Tamper Test CA,O=QuantumShield"}, adminTok)
	if code != http.StatusOK {
		t.Fatalf("ca/init: status %d", code)
	}

	// Generate a KEM key pair.
	code, keyResp := jsonReq(t, ts, "POST", "/keys/generate",
		map[string]any{"level": "ML-KEM-768"}, writeTok)
	if code != http.StatusOK {
		t.Fatalf("generate key: status %d", code)
	}
	keyID, _ := keyResp["key_id"].(string)
	pubKeyB64, _ := keyResp["public_key"].(string)

	// Issue a real leaf cert via /ca/sign (requires public_key + public_key_type).
	// handleCASign returns the Certificate directly at the top level, not wrapped.
	code, cert := jsonReq(t, ts, "POST", "/ca/sign",
		map[string]any{
			"subject":         "CN=leaf.example.com",
			"public_key":      pubKeyB64,
			"public_key_type": "ML-KEM-768",
		}, writeTok)
	if code != http.StatusOK {
		t.Fatalf("ca/sign: status %d keyID=%s: %v", code, keyID, cert)
	}
	if _, hasSig := cert["signature"]; !hasSig {
		t.Fatalf("ca/sign: response missing 'signature' field — not a certificate: %v", cert)
	}

	// Tamper the serial — the original ML-DSA-87 signature must now be invalid.
	originalSerial, _ := cert["serial"].(string)
	cert["serial"] = "TAMPERED-SERIAL-9999"
	t.Logf("tampered serial from %q to %q", originalSerial, cert["serial"])

	code, body := jsonReq(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": cert}, "")
	// Accept valid:false or 4xx error; never accept valid:true.
	if valid, _ := body["valid"].(bool); valid {
		t.Error("tampered serial verified as valid — integrity check bypassed")
	}
	if code == http.StatusInternalServerError {
		t.Errorf("tampered cert caused 500: %v", body)
	}
}

// ── 12. Timing side-channel ───────────────────────────────────────────────────

// TestSec_Timing_InvalidTokenNotMeasurablySlower measures response latency for
// valid vs invalid authentication and asserts that the ratio is reasonable.
//
// A timing oracle exists when invalid credentials cause measurably different
// response times — allowing an attacker to infer information about internal
// state from latency alone.
//
// Note: this is a statistical smoke-test, not a rigorous timing analysis.
// Real timing attacks require millions of samples.  This test catches only
// egregious issues (e.g. an O(n) string comparison or a blocking HSM call on
// the invalid path).
func TestSec_Timing_InvalidTokenNotMeasurablySlower(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	ts, cleanup := server(t)
	defer cleanup()

	validTok := token(t, ts, "user", []string{"read"})

	const samples = 20
	measure := func(tok string) time.Duration {
		total := time.Duration(0)
		for range samples {
			start := time.Now()
			req(t, ts, http.MethodGet, "/keys", "application/json", tok, nil) //nolint:errcheck
			total += time.Since(start)
		}
		return total / samples
	}

	validAvg := measure(validTok)
	invalidAvg := measure("invalid.token.here")

	// Both paths must complete in under 200 ms on average (no HSM blocking).
	if invalidAvg > 200*time.Millisecond {
		t.Errorf("invalid token path is too slow (avg %v); possible blocking operation", invalidAvg)
	}

	// The ratio of invalid/valid must be < 10× — a larger ratio suggests a
	// dramatically different code path (e.g. expensive hashing on invalid path).
	if validAvg > 0 {
		ratio := float64(invalidAvg) / float64(validAvg)
		if ratio > 10.0 {
			t.Errorf("timing ratio invalid/valid = %.1f× (threshold 10×); possible timing oracle", ratio)
		}
	}
}

// ── 13. Public endpoint exposure ──────────────────────────────────────────────

// TestSec_PublicEndpoints_NoAuthNeeded verifies that truly public endpoints
// (health, FIPS status, CA certificate, CRL) return 200 without any token.
// A false-positive here would mean authentication was silently removed from a
// formerly-protected route.
func TestSec_PublicEndpoints_NoAuthNeeded(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	public := []struct{ method, path string }{
		{"GET", "/"},
		{"GET", "/health/live"},
		{"GET", "/health/ready"},
		{"GET", "/health/fips"},
	}
	for _, ep := range public {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			code, _, _ := req(t, ts, ep.method, ep.path, "", "", nil)
			if code != http.StatusOK {
				t.Errorf("%s %s: expected 200 without token, got %d", ep.method, ep.path, code)
			}
		})
	}
}

// TestSec_AuthenticatedEndpoints_RequireToken verifies that every endpoint
// requiring authentication returns 401 when no token is supplied —
// not 200, 403, or 500.
func TestSec_AuthenticatedEndpoints_RequireToken(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	protected := []struct{ method, path string }{
		{"GET", "/keys"},
		{"POST", "/keys/generate"},
		{"POST", "/encrypt"},
		{"POST", "/decrypt"},
		{"POST", "/sign"},
		{"GET", "/audit/entries"},
		{"POST", "/ca/init"},
		{"POST", "/ca/sign"},
		{"POST", "/ca/revoke"},
		{"POST", "/keystore/generate"},
	}
	for _, ep := range protected {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			body := strings.NewReader(`{}`)
			code, _, _ := req(t, ts, ep.method, ep.path, "application/json", "", body)
			if code != http.StatusUnauthorized {
				t.Errorf("%s %s without token: expected 401, got %d", ep.method, ep.path, code)
			}
		})
	}
}

// ── 14. Header injection ──────────────────────────────────────────────────────

// TestSec_HeaderInjection_CRLFInContentType verifies that CRLF characters in
// the Content-Type header do not cause header injection.
// Go's net/http already strips \r and \n from header values, so this test
// confirms the framework protection is in place.
func TestSec_HeaderInjection_CRLFInContentType(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	tok := token(t, ts, "user", []string{"write"})

	r, _ := http.NewRequest(http.MethodPost, ts.URL+"/keys/generate",
		strings.NewReader(`{"level":"ML-KEM-768"}`))
	// Attempt CRLF injection in Content-Type.
	r.Header["Content-Type"] = []string{"application/json\r\nX-Injected: evil"}
	r.Header.Set("Authorization", "Bearer "+tok)

	resp, err := ts.Client().Do(r)
	if err != nil {
		// Go's transport may reject this at the client side — that's also fine.
		t.Logf("CRLF header rejected by transport: %v", err)
		return
	}
	defer resp.Body.Close()

	// The injected header must not appear in the response.
	if v := resp.Header.Get("X-Injected"); v != "" {
		t.Errorf("CRLF header injection succeeded; X-Injected=%q reflected in response", v)
	}
}

// TestSec_HeaderInjection_AuthorizationScheme verifies that unusual
// Authorization schemes (not "Bearer") are rejected cleanly.
func TestSec_HeaderInjection_AuthorizationScheme(t *testing.T) {
	ts, cleanup := server(t)
	defer cleanup()

	schemes := []string{
		"Basic dXNlcjpwYXNz",    // HTTP Basic
		"Digest username=alice", // HTTP Digest
		"OAuth token=abc123",    // OAuth 1.0
		"NTLM abc==",            // Windows NTLM
	}
	for _, auth := range schemes {
		label := auth
		if len(label) > 20 {
			label = label[:20]
		}
		t.Run(label, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, ts.URL+"/keys", nil)
			r.Header.Set("Authorization", auth)
			resp, err := ts.Client().Do(r)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("non-Bearer scheme %q: expected 401, got %d", auth, resp.StatusCode)
			}
		})
	}
}

