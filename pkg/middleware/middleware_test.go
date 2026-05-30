package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mw "github.com/quantum-shield/quantum-shield-go/pkg/middleware"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func do(method, path, ct, body string, h http.Handler) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// ── SecurityHeaders ───────────────────────────────────────────────────────────

func TestSecurityHeaders_AllPresent(t *testing.T) {
	h := mw.SecurityHeaders(http.HandlerFunc(okHandler))
	rr := do("GET", "/", "", "", h)

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-Xss-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'none'",
		"Referrer-Policy":           "no-referrer",
		"Cache-Control":             "no-store, no-cache, must-revalidate",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
		"Server":                    "QuantumShield",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %s: got %q, want %q", k, got, v)
		}
	}
}

func TestSecurityHeaders_PassThrough(t *testing.T) {
	h := mw.SecurityHeaders(http.HandlerFunc(okHandler))
	rr := do("GET", "/", "", "", h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ── RequireJSON ───────────────────────────────────────────────────────────────

func TestRequireJSON_AcceptsJSON(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("POST", "/", "application/json", `{}`, h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireJSON_AcceptsJSONWithCharset(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("POST", "/", "application/json; charset=utf-8", `{}`, h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireJSON_RejectsFormPost(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("POST", "/", "application/x-www-form-urlencoded", "a=b", h)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rr.Code)
	}
}

func TestRequireJSON_RejectsMultipart(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("POST", "/", "multipart/form-data; boundary=xxx", "data", h)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rr.Code)
	}
}

func TestRequireJSON_GETPassesWithoutCT(t *testing.T) {
	// GET without Content-Type should pass — no body check
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("GET", "/", "", "", h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireJSON_PUTRejectsText(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("PUT", "/", "text/plain", "hello", h)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rr.Code)
	}
}

func TestRequireJSON_PATCHRejectsXML(t *testing.T) {
	h := mw.RequireJSON(http.HandlerFunc(okHandler))
	rr := do("PATCH", "/", "application/xml", "<x/>", h)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rr.Code)
	}
}

// ── MaxBodySize ───────────────────────────────────────────────────────────────

func TestMaxBodySize_SmallBodyOK(t *testing.T) {
	h := mw.MaxBodySize(http.HandlerFunc(okHandler))
	rr := do("POST", "/", "application/json", `{"x":1}`, h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMaxBodySize_NilBodyOK(t *testing.T) {
	h := mw.MaxBodySize(http.HandlerFunc(okHandler))
	rr := do("GET", "/", "", "", h)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ── CORS ──────────────────────────────────────────────────────────────────────

func corsHandler(origins string) http.Handler {
	t := &testing.T{} // dummy — we just need env var set
	_ = t
	// set env for the test
	return mw.CORS(http.HandlerFunc(okHandler))
}

func TestCORS_NoOriginHeader(t *testing.T) {
	h := mw.CORS(http.HandlerFunc(okHandler))
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO should be absent when no Origin sent, got %q", got)
	}
}

func TestCORS_OptionsPreflightAlwaysNoContent(t *testing.T) {
	h := mw.CORS(http.HandlerFunc(okHandler))
	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// preflight always returns 204 — but no ACAO header for unknown origin
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestCORS_UnknownOriginNoACAO(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://trusted.example.com")
	h := mw.CORS(http.HandlerFunc(okHandler))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unknown origin must not get ACAO, got %q", got)
	}
}

func TestCORS_KnownOriginGetsACAO(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com")
	h := mw.CORS(http.HandlerFunc(okHandler))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("expected ACAO=https://app.example.com, got %q", got)
	}
	if got := rr.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("Vary header must include Origin, got %q", got)
	}
}

func TestCORS_EmptyAllowedOriginsNoACAO(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "")
	h := mw.CORS(http.HandlerFunc(okHandler))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("empty allow list must not set ACAO, got %q", got)
	}
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := mw.NewRateLimiter(5, 60*time.Second)
	h := rl.Limit(http.HandlerFunc(okHandler))
	for i := range 5 {
		rr := do("GET", "/", "", "", h)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rr.Code)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := mw.NewRateLimiter(3, 60*time.Second)
	h := rl.Limit(http.HandlerFunc(okHandler))
	for range 3 {
		do("GET", "/", "", "", h)
	}
	rr := do("GET", "/", "", "", h)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

func TestRateLimiter_RetryAfterHeader(t *testing.T) {
	rl := mw.NewRateLimiter(1, 60*time.Second)
	h := rl.Limit(http.HandlerFunc(okHandler))
	do("GET", "/", "", "", h) // consume the 1 allowed
	rr := do("GET", "/", "", "", h)
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header must be set on 429")
	}
}

func TestRateLimiter_WindowResets(t *testing.T) {
	rl := mw.NewRateLimiter(2, 100*time.Millisecond)
	h := rl.Limit(http.HandlerFunc(okHandler))
	do("GET", "/", "", "", h)
	do("GET", "/", "", "", h)
	// 3rd should be blocked
	if rr := do("GET", "/", "", "", h); rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 before reset, got %d", rr.Code)
	}
	time.Sleep(150 * time.Millisecond) // window expired
	// should be allowed again
	if rr := do("GET", "/", "", "", h); rr.Code != http.StatusOK {
		t.Errorf("expected 200 after window reset, got %d", rr.Code)
	}
}

func TestRateLimiter_PerIP(t *testing.T) {
	// Two different IPs should have independent buckets
	rl := mw.NewRateLimiter(1, 60*time.Second)
	h := rl.Limit(http.HandlerFunc(okHandler))

	make2Requests := func(ip string) (int, int) {
		r1 := httptest.NewRequest("GET", "/", nil)
		r1.RemoteAddr = ip + ":1234"
		rr1 := httptest.NewRecorder()
		h.ServeHTTP(rr1, r1)

		r2 := httptest.NewRequest("GET", "/", nil)
		r2.RemoteAddr = ip + ":1235"
		rr2 := httptest.NewRecorder()
		h.ServeHTTP(rr2, r2)
		return rr1.Code, rr2.Code
	}

	c1a, c1b := make2Requests("10.0.0.1")
	c2a, c2b := make2Requests("10.0.0.2")

	if c1a != 200 || c2a != 200 {
		t.Errorf("first request per IP should be 200: ip1=%d ip2=%d", c1a, c2a)
	}
	if c1b != 429 || c2b != 429 {
		t.Errorf("second request per IP should be 429: ip1=%d ip2=%d", c1b, c2b)
	}
}

// ── RateLimiter.Allow (keyed directly, not via middleware) ────────────────────

func TestRateLimiter_Allow_UnderLimit(t *testing.T) {
	rl := mw.NewRateLimiter(3, 60*time.Second)
	for i := range 3 {
		if !rl.Allow("subject-a") {
			t.Errorf("call %d: Allow should return true under limit", i)
		}
	}
}

func TestRateLimiter_Allow_BlocksAtLimit(t *testing.T) {
	rl := mw.NewRateLimiter(2, 60*time.Second)
	rl.Allow("subject-b")
	rl.Allow("subject-b")
	if rl.Allow("subject-b") {
		t.Error("Allow should return false when limit is reached")
	}
}

func TestRateLimiter_Allow_IndependentKeys(t *testing.T) {
	rl := mw.NewRateLimiter(1, 60*time.Second)
	// Exhaust key A — key B should still be allowed
	if !rl.Allow("key-a") {
		t.Fatal("first Allow for key-a should succeed")
	}
	if rl.Allow("key-a") {
		t.Error("second Allow for key-a should be denied")
	}
	// key-b is a fresh bucket — must be allowed
	if !rl.Allow("key-b") {
		t.Error("Allow for key-b should succeed (separate bucket)")
	}
}

func TestRateLimiter_Allow_ResetAfterWindow(t *testing.T) {
	rl := mw.NewRateLimiter(1, 80*time.Millisecond)
	if !rl.Allow("tok-x") {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow("tok-x") {
		t.Error("second call within window should be denied")
	}
	time.Sleep(100 * time.Millisecond)
	if !rl.Allow("tok-x") {
		t.Error("call after window expiry should be allowed again")
	}
}

// ── JSONError / JSON / JSONStatus ─────────────────────────────────────────────

func TestJSONError_ContentType(t *testing.T) {
	rr := httptest.NewRecorder()
	mw.JSONError(rr, "bad", http.StatusBadRequest)
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestJSON_DefaultOK(t *testing.T) {
	rr := httptest.NewRecorder()
	mw.JSON(rr, map[string]string{"k": "v"})
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"k"`) {
		t.Errorf("body missing key: %s", rr.Body)
	}
}

func TestJSONStatus_CustomCode(t *testing.T) {
	rr := httptest.NewRecorder()
	mw.JSONStatus(rr, http.StatusCreated, map[string]string{"ok": "1"})
	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

// ── RequestID ─────────────────────────────────────────────────────────────────

// TestRequestID_GeneratedWhenAbsent verifies that a random X-Request-ID is added
// to the response when the client does not supply one, and that the same ID is
// stored in the request context.
func TestRequestID_GeneratedWhenAbsent(t *testing.T) {
	var ctxID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = mw.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw.RequestID(inner)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	respID := rr.Header().Get("X-Request-ID")
	if respID == "" {
		t.Fatal("X-Request-ID response header must not be empty")
	}
	if ctxID == "" {
		t.Fatal("request context must contain the request ID")
	}
	if respID != ctxID {
		t.Errorf("response header %q != context value %q", respID, ctxID)
	}
}

// TestRequestID_PropagatedFromClient verifies that when the client already sends
// an X-Request-ID the same value is echoed in the response and in the context.
func TestRequestID_PropagatedFromClient(t *testing.T) {
	const clientID = "trace-abc-123"
	var ctxID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = mw.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw.RequestID(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", clientID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-ID"); got != clientID {
		t.Errorf("response header: got %q, want %q", got, clientID)
	}
	if ctxID != clientID {
		t.Errorf("context value: got %q, want %q", ctxID, clientID)
	}
}

// TestRequestID_UniquePerRequest verifies that successive requests without a
// client-supplied ID receive distinct generated IDs.
func TestRequestID_UniquePerRequest(t *testing.T) {
	h := mw.RequestID(http.HandlerFunc(okHandler))
	seen := make(map[string]struct{})

	const n = 50
	for i := range n {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
		id := rr.Header().Get("X-Request-ID")
		if id == "" {
			t.Fatalf("request %d: got empty X-Request-ID", i)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("request %d: duplicate ID %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// TestRequestIDFromContext_MissingReturnsEmpty verifies the helper returns ""
// when no ID is present in the context (e.g., handler bypasses the middleware).
func TestRequestIDFromContext_MissingReturnsEmpty(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := mw.RequestIDFromContext(r.Context()); id != "" {
			t.Errorf("expected empty ID, got %q", id)
		}
		w.WriteHeader(http.StatusOK)
	})
	// Bypass the middleware entirely
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	inner.ServeHTTP(rr, req)
}
