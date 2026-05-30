package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ── stub server ───────────────────────────────────────────────────────────────

// newStubServer creates a minimal HTTP stub that exercises the qs client logic.
func newStubServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	respond := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("POST /keys/generate", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		alg, _ := req["algorithm"].(string)
		respond(w, map[string]any{
			"key_id":    "test-key-1",
			"algorithm": alg,
			"public_key": "aGVsbG8=",
		})
	})

	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{
			"keys":    []string{"key-a", "key-b"},
			"count":   2,
			"backend": "in-memory",
		})
	})

	mux.HandleFunc("GET /keys/{key_id}/public", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("key_id")
		respond(w, map[string]any{"key_id": id, "public_key": "cGstYnl0ZXM="})
	})

	mux.HandleFunc("POST /sign", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		respond(w, map[string]any{
			"key_id":    req["key_id"],
			"algorithm": req["algorithm"],
			"signature": "c2lnbmF0dXJlLWJ5dGVz",
		})
	})

	mux.HandleFunc("POST /verify-signature", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		// Accept only the known test signature.
		valid := req["signature"] == "c2lnbmF0dXJlLWJ5dGVz"
		respond(w, map[string]any{"valid": valid})
	})

	mux.HandleFunc("POST /encrypt", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		respond(w, map[string]any{
			"ciphertext":      "Y2lwaGVydGV4dA==",
			"ciphertext_type": "ML-KEM-768+AES-256-GCM",
		})
	})

	mux.HandleFunc("POST /decrypt", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]any{"plaintext": "aGVsbG8="})
	})

	mux.HandleFunc("POST /ca/init", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		subject, _ := req["subject"].(string)
		respond(w, map[string]any{
			"certificate": map[string]any{
				"serial":    "deadbeef01234567deadbeef01234567",
				"subject":   subject,
				"issuer":    subject,
				"algorithm": "ML-DSA-87",
				"is_ca":     true,
				"version":   1,
				"signature": "c2ln",
			},
		})
	})

	mux.HandleFunc("POST /ca/sign", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		subject, _ := req["subject"].(string)
		respond(w, map[string]any{
			"certificate": map[string]any{
				"serial":          "abcdef0123456789abcdef0123456789",
				"subject":         subject,
				"issuer":          "CN=Root CA",
				"algorithm":       "ML-DSA-87",
				"public_key_type": req["public_key_type"],
				"is_ca":           false,
				"version":         1,
				"signature":       "c2ln",
			},
		})
	})

	mux.HandleFunc("POST /ca/verify", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		cert, _ := req["certificate"].(map[string]any)
		// Valid if subject is not "tampered".
		valid := cert != nil && cert["subject"] != "tampered"
		if valid {
			respond(w, map[string]any{"valid": true})
		} else {
			respond(w, map[string]any{"valid": false, "error": "signature verification failed"})
		}
	})

	mux.HandleFunc("GET /ca/crl", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{
			"issuer":      "CN=Root CA",
			"version":     1,
			"this_update": "2026-01-01T00:00:00Z",
			"entries":     []any{},
		})
	})

	mux.HandleFunc("GET /ca/certificate", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{
			"serial":    "root000000000000root000000000000",
			"subject":   "CN=Root CA",
			"issuer":    "CN=Root CA",
			"algorithm": "ML-DSA-87",
			"is_ca":     true,
			"version":   1,
			"signature": "c2ln",
		})
	})

	mux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		respond(w, map[string]any{
			"token":      "qs.test.token",
			"subject":    req["user_id"],
			"expires_at": "2026-06-01T00:00:00Z",
		})
	})

	// Catch-all: return JSON 404 for any unregistered path.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ── helper ────────────────────────────────────────────────────────────────────

func makeClient(t *testing.T, srv *httptest.Server) *client {
	t.Helper()
	return newClient(srv.URL, "test-token", false, false)
}

// capture replaces stdout with a buffer, runs f, then restores.
// Returns the captured output as a string.

// ── tests ─────────────────────────────────────────────────────────────────────

func TestClient_do_Success(t *testing.T) {
	srv := newStubServer(t)
	c := makeClient(t, srv)

	data, code, err := c.do("GET", "/health/live", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if code != 200 {
		t.Errorf("code: %d", code)
	}
	if data["status"] != "ok" {
		t.Errorf("status: %v", data["status"])
	}
}

func TestClient_do_404(t *testing.T) {
	srv := newStubServer(t)
	c := makeClient(t, srv)

	data, code, err := c.do("GET", "/no-such-endpoint", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 404 {
		t.Errorf("expected 404, got %d %v", code, data)
	}
}

func TestClient_do_BearerHeader(t *testing.T) {
	var gotAuth string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer stub.Close()

	c := newClient(stub.URL, "my-secret-token", false, false)
	c.do("GET", "/anything", nil) //nolint:errcheck
	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("Authorization header: %q", gotAuth)
	}
}

func TestClient_do_NoTokenOmitsHeader(t *testing.T) {
	var gotAuth string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer stub.Close()

	c := newClient(stub.URL, "", false, false)
	c.do("GET", "/anything", nil) //nolint:errcheck
	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

func TestReadArgOrStdin_DirectValue(t *testing.T) {
	got := readArgOrStdin([]string{"hello"}, "msg")
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestReadArgOrStdin_FileRef(t *testing.T) {
	// Write a temp file with content.
	f, err := os.CreateTemp("", "qs-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprint(f, "file-content")
	f.Close()

	got := readArgOrStdin([]string{"@" + f.Name()}, "msg")
	if got != "file-content" {
		t.Errorf("got %q, want %q", got, "file-content")
	}
}

func TestPrintCert_AllFields(t *testing.T) {
	// printCert should not panic with all expected fields present.
	cert := map[string]any{
		"serial":          "abc123",
		"subject":         "CN=test.example.com",
		"issuer":          "CN=Root CA",
		"algorithm":       "ML-DSA-87",
		"public_key_type": "ML-KEM-768",
		"is_ca":           false,
		"not_before":      "2026-01-01T00:00:00Z",
		"not_after":       "2027-01-01T00:00:00Z",
		"version":         float64(1),
		"signature":       strings.Repeat("A", 200),
	}
	// Just verify it doesn't panic (output goes to stdout).
	printCert(cert)
}

func TestPrintCert_Minimal(t *testing.T) {
	// printCert must not panic when optional fields are absent.
	printCert(map[string]any{"subject": "CN=min"})
}

func TestEnvOr_ReturnsEnv(t *testing.T) {
	t.Setenv("QS_TEST_KEY", "from-env")
	if got := envOr("QS_TEST_KEY", "default"); got != "from-env" {
		t.Errorf("got %q, want %q", got, "from-env")
	}
}

func TestEnvOr_ReturnsFallback(t *testing.T) {
	t.Setenv("QS_TEST_KEY_ABSENT", "")
	if got := envOr("QS_TEST_KEY_ABSENT", "fallback"); got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

func TestRequire2xx_Pass(t *testing.T) {
	// Must not panic / exit for 2xx codes.
	for _, code := range []int{200, 201, 204} {
		require2xx(code, nil, "test")
	}
}

// TestKeyGenerate_SendsAlgorithm verifies the client sends the requested algorithm.
func TestKeyGenerate_SendsAlgorithm(t *testing.T) {
	var gotBody map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"key_id": "k1", "algorithm": gotBody["algorithm"],
		})
	}))
	defer stub.Close()

	c := newClient(stub.URL, "tok", false, true /* json */)
	// Simulate key generate with ML-KEM-1024
	data, code, err := c.do("POST", "/keys/generate", map[string]any{"algorithm": "ML-KEM-1024"})
	if err != nil || code != 200 {
		t.Fatalf("do: %v %d", err, code)
	}
	if data["algorithm"] != "ML-KEM-1024" {
		t.Errorf("algorithm: %v", data["algorithm"])
	}
	if gotBody["algorithm"] != "ML-KEM-1024" {
		t.Errorf("server received algorithm: %v", gotBody["algorithm"])
	}
}

// TestTokenIssue_SendsRoles verifies role list is forwarded correctly.
func TestTokenIssue_SendsRoles(t *testing.T) {
	var gotBody map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"token": "tok123", "subject": gotBody["user_id"]})
	}))
	defer stub.Close()

	c := newClient(stub.URL, "", false, false)
	roles := []string{"read", "write", "admin"}
	c.do("POST", "/auth/token", map[string]any{"user_id": "alice", "roles": roles}) //nolint:errcheck

	gotRoles, _ := gotBody["roles"].([]any)
	if len(gotRoles) != 3 {
		t.Errorf("expected 3 roles, got %v", gotRoles)
	}
}
