// Package middleware provides HTTP middleware for the QuantumShield API.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MB

// ── Security headers ──────────────────────────────────────────────────────────

// SecurityHeaders adds hardened HTTP response headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Server", "QuantumShield")
		next.ServeHTTP(w, r)
	})
}

// ── Content-Type enforcement ──────────────────────────────────────────────────

// RequireJSON rejects POST/PUT/PATCH requests with a non-JSON Content-Type
// and enforces a 1 MB body size limit on all requests with a body.
// This blocks CSRF via form POST, HPP via urlencoded bodies, and body-exhaustion DoS.
func RequireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enforce Content-Type on methods that carry a body
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			// Reject missing or non-JSON Content-Type.
			// Empty Content-Type is also rejected: a browser form POST without
			// Content-Type could bypass CSRF checks if this were allowed.
			if ct == "" || !strings.HasPrefix(ct, "application/json") {
				JSONError(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
			// Cap body size — prevents memory exhaustion and slow-body (Slowloris) attacks.
			// http.MaxBytesReader replaces r.Body and makes Read() return an error
			// after maxBodyBytes, which json.Decoder then propagates.
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize wraps any handler to enforce 1 MB body limit on all methods.
// Use in addition to RequireJSON for GET-with-body edge cases.
func MaxBodySize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// BodySizeError reports whether err is an http.MaxBytesError (body too large).
func BodySizeError(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// ── CORS ──────────────────────────────────────────────────────────────────────

// CORS adds cross-origin headers for explicitly allowed origins only.
// Allowed origins are read from the ALLOWED_ORIGINS environment variable
// (comma-separated). If empty, no cross-origin access is permitted.
func CORS(next http.Handler) http.Handler {
	allowed := parseAllowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && len(allowed) > 0 {
			if _, ok := allowed[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Add("Vary", "Origin")
			}
			// Unknown origin → no ACAO header → browser enforces same-origin
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseAllowedOrigins() map[string]struct{} {
	raw := os.Getenv("ALLOWED_ORIGINS")
	if raw == "" {
		return nil
	}
	m := make(map[string]struct{})
	for _, o := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			m[trimmed] = struct{}{}
		}
	}
	return m
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

// bucket holds a sliding-window counter for one IP.
type bucket struct {
	mu        sync.Mutex
	timestamps []time.Time
}

// RateLimiter is a sliding-window rate limiter keyed on an arbitrary string
// (typically a client IP address or a JWT subject claim).
// A background goroutine evicts idle buckets every cleanupInterval to prevent
// unbounded memory growth when the server sees many unique keys.
type RateLimiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

const cleanupInterval = 5 * time.Minute

// NewRateLimiter creates a RateLimiter allowing limit requests per window per IP.
// Starts a background cleanup goroutine; it exits when the process does.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
	}
	go rl.cleanup()
	return rl
}

// cleanup removes buckets whose last request is older than one window.
// Runs every cleanupInterval in the background.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.window)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			b.mu.Lock()
			// Bucket is idle when all timestamps have expired
			idle := len(b.timestamps) == 0 ||
				b.timestamps[len(b.timestamps)-1].Before(cutoff)
			b.mu.Unlock()
			if idle {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit returns a middleware that enforces per-IP rate limits.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			JSONError(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Allow reports whether the given key is within the rate limit and records
// the attempt. key may be any string (IP address, JWT subject, API key ID, …).
// Returns true and consumes one slot when the key is under its limit;
// returns false without consuming a slot when the limit is exceeded.
func (rl *RateLimiter) Allow(key string) bool {
	return rl.allow(key)
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{}
		rl.buckets[key] = b
	}
	rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Evict old timestamps
	i := 0
	for i < len(b.timestamps) && b.timestamps[i].Before(cutoff) {
		i++
	}
	b.timestamps = b.timestamps[i:]

	if len(b.timestamps) >= rl.limit {
		return false
	}
	b.timestamps = append(b.timestamps, now)
	return true
}

// clientIP extracts the real client IP (never trusts X-Forwarded-For without config).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ── Bearer token auth ─────────────────────────────────────────────────────────

// Verifier is the interface the auth.Authority satisfies.
type Verifier interface {
	VerifyToken(token string) (subject string, roles []string, err error)
}

type contextKey string

const (
	SubjectKey   contextKey = "subject"
	RolesKey     contextKey = "roles"
	RequestIDKey contextKey = "request_id"
)

// ── Request ID ────────────────────────────────────────────────────────────────

// RequestID propagates or generates an X-Request-ID header.
// If the incoming request already carries X-Request-ID that value is reused
// (allowing end-to-end tracing through a proxy). Otherwise a new 16-byte
// random ID is generated. The ID is stored in the request context and echoed
// in the response header so callers can correlate log lines.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			b := make([]byte, 12) // 96 bits — collision probability negligible
			rand.Read(b)           //nolint:errcheck — crypto/rand.Read never fails on modern OS
			id = base64.RawURLEncoding.EncodeToString(b)
		}
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext returns the request ID stored in ctx, or "" if absent.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(RequestIDKey).(string)
	return id
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// JSONError writes a JSON error response.
func JSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// JSON writes a JSON response with status 200.
func JSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// JSONStatus writes a JSON response with the given status code.
func JSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
